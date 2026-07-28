//! The credential broker: the only component that sees secrets.
//!
//! Two interfaces, deliberately asymmetric:
//!
//! - **A Rust API** ([`Broker`], implementing `CredentialSource`) used by the
//!   daemon in-process, for credentials that must be injected.
//! - **A per-agent unix socket** exposing exactly ONE operation — "give me
//!   headers for this MCP server" — reachable from inside a container.
//!
//! The socket protocol is minimal on purpose. It is the only part of hive that
//! model-authored code can talk to, so it does the smallest useful thing: it
//! cannot list keys, cannot name an agent, and cannot reach a model-provider
//! token.
//!
//! # Identity
//!
//! An agent is identified by WHICH SOCKET it connected to, never by anything it
//! says. Every agent container runs as uid 1001, so `SO_PEERCRED` cannot tell
//! them apart — a single shared socket would let any agent request any other
//! agent's secrets, and no amount of protocol design fixes that. One listener
//! per agent, bind-mounted individually, makes mount topology the identity.
//!
//! # What "at rest" means here
//!
//! Secrets are 0600 files owned by the daemon user. They are NOT encrypted, and
//! that is a considered position rather than an omission: encrypting them with a
//! key stored on the same disk protects against nothing that an attacker who can
//! read the files cannot also do. The boundary is file permissions and root. If
//! that is insufficient for your threat model, the answer is a real KMS or a
//! hardware token, not a local key file.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use hive_core::credential::{CredentialKey, CredentialSource, Secret};

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("no credential stored for '{0}'")]
    NotFound(String),
    #[error("agent '{agent}' is not authorised for '{key}'")]
    NotAuthorised { agent: String, key: String },
    #[error("credential file {path} is readable by others (mode {mode:o}); refusing to use it")]
    Permissive { path: PathBuf, mode: u32 },
    #[error("invalid credential key '{0}': must not contain path separators or '..'")]
    InvalidKey(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Which keys an agent may ask for.
///
/// Computed by the daemon from the agent's own spec. The broker enforces it, so
/// a bug in reconciliation can hand out a wrong grant but cannot make the broker
/// ignore one.
#[derive(Debug, Clone, Default)]
pub struct Grant {
    pub agent: String,
    pub keys: BTreeSet<String>,
}

impl Grant {
    pub fn new(agent: impl Into<String>, keys: impl IntoIterator<Item = String>) -> Self {
        Self { agent: agent.into(), keys: keys.into_iter().collect() }
    }
}

pub struct Broker {
    root: PathBuf,
    audit_path: PathBuf,
}

impl Broker {
    /// `root` holds one file per credential. Created 0700 if absent.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, BrokerError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let audit_path = root.join("audit.jsonl");
        Ok(Self { root, audit_path })
    }

    /// Reject anything that could escape the store directory.
    ///
    /// Keys come from spec files, which are meant to be committable and
    /// shareable — so they are attacker-influenced in exactly the way a path
    /// traversal needs. `mcp/../../etc/shadow` must not resolve.
    fn path_for(&self, key: &CredentialKey) -> Result<PathBuf, BrokerError> {
        let k = key.as_str();
        if k.is_empty()
            || k.starts_with('/')
            || k.split('/').any(|seg| seg == ".." || seg == "." || seg.is_empty())
        {
            return Err(BrokerError::InvalidKey(k.to_string()));
        }
        Ok(self.root.join(k.replace('/', "__")))
    }

    pub fn put(&self, key: &CredentialKey, value: &[u8]) -> Result<(), BrokerError> {
        let path = self.path_for(key)?;
        // Restrictive permissions from creation, not applied afterwards.
        // Creating 0644 and chmod'ing leaves a window in which the secret is
        // world-readable — short, but entirely real on a box running other
        // people's code.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(value)?;
        f.sync_all()?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<String>, BrokerError> {
        let mut out = Vec::new();
        for e in fs::read_dir(&self.root)? {
            let name = e?.file_name().to_string_lossy().into_owned();
            if name == "audit.jsonl" {
                continue;
            }
            out.push(name.replace("__", "/"));
        }
        out.sort();
        Ok(out)
    }

    pub fn remove(&self, key: &CredentialKey) -> Result<(), BrokerError> {
        fs::remove_file(self.path_for(key)?)?;
        Ok(())
    }

    fn read_checked(&self, key: &CredentialKey) -> Result<Vec<u8>, BrokerError> {
        let path = self.path_for(key)?;
        if !path.exists() {
            return Err(BrokerError::NotFound(key.as_str().to_string()));
        }
        // A secret readable by group or other is not a secret. Refuse rather
        // than warn: a warning in a log nobody reads is how a permissive
        // credential file survives for months.
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(BrokerError::Permissive { path, mode });
        }
        Ok(fs::read(&path)?)
    }

    /// Append to the audit log. Best-effort: failing to audit must not fail the
    /// request, or a full disk takes every agent offline at once.
    fn audit(&self, agent: &str, key: &str, outcome: &str) {
        let line = format!(
            r#"{{"agent":{},"key":{},"outcome":{}}}"#,
            json_str(agent),
            json_str(key),
            json_str(outcome)
        );
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.audit_path)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Fetch on behalf of an agent, enforcing its grant.
    pub fn fetch_for(&self, grant: &Grant, key: &CredentialKey) -> Result<Secret, BrokerError> {
        if !grant.keys.contains(key.as_str()) {
            self.audit(&grant.agent, key.as_str(), "denied");
            return Err(BrokerError::NotAuthorised {
                agent: grant.agent.clone(),
                key: key.as_str().to_string(),
            });
        }
        match self.read_checked(key) {
            Ok(v) => {
                self.audit(&grant.agent, key.as_str(), "granted");
                Ok(Secret::new(v))
            }
            Err(e) => {
                self.audit(&grant.agent, key.as_str(), "error");
                Err(e)
            }
        }
    }
}

/// Minimal JSON string escaping for the audit log.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl CredentialSource for Broker {
    type Error = BrokerError;

    fn has(&self, key: &CredentialKey) -> Result<bool, Self::Error> {
        Ok(self.path_for(key)?.exists())
    }

    fn fetch(&self, agent: &str, key: &CredentialKey) -> Result<Secret, Self::Error> {
        // The in-process path, used by the daemon for credentials that must be
        // injected. Still audited: "the daemon did it" is exactly the claim an
        // audit log exists to substantiate.
        let v = self.read_checked(key)?;
        self.audit(agent, key.as_str(), "granted:in-process");
        Ok(Secret::new(v))
    }
}

// ---------------------------------------------------------------------------
// The agent-facing socket
// ---------------------------------------------------------------------------

/// What an in-container helper may ask for. One operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Headers for an MCP server, by the name the harness knows it as.
    ///
    /// Note it does NOT carry an agent name. The listener already knows which
    /// agent this is; accepting a claimed identity would make the per-socket
    /// design decorative.
    Headers { server: String },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum Response {
    /// The shape Claude Code expects on stdout.
    Headers { headers: std::collections::BTreeMap<String, String> },
    Error { error: String },
}

/// Maps an MCP server name to the credential key holding its token.
pub type ServerKeys = std::collections::BTreeMap<String, String>;

/// Handle one request. Split out so it is testable without a socket.
pub fn handle_request(broker: &Broker, grant: &Grant, servers: &ServerKeys, line: &str) -> Response {
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return Response::Error { error: format!("malformed request: {e}") },
    };
    match req {
        Request::Headers { server } => {
            let Some(key) = servers.get(&server) else {
                return Response::Error {
                    error: format!("no credential configured for MCP server '{server}'"),
                };
            };
            match broker.fetch_for(grant, &CredentialKey::new(key.clone())) {
                Ok(secret) => match secret.as_str() {
                    Ok(token) => Response::Headers {
                        headers: std::collections::BTreeMap::from([(
                            "Authorization".to_string(),
                            // Trimmed: a token read from a file usually carries a
                            // trailing newline, which would otherwise be sent
                            // inside the header value and rejected as malformed.
                            format!("Bearer {}", token.trim()),
                        )]),
                    },
                    Err(_) => Response::Error { error: "credential is not valid UTF-8".into() },
                },
                Err(e) => Response::Error { error: e.to_string() },
            }
        }
    }
}

/// Serve one agent's socket until the process exits.
///
/// Blocking, one connection at a time. Connections are trivial and rare — one
/// per MCP connection — and Claude Code's helper timeout is 10 seconds, which is
/// enormous next to a file read. Concurrency here would be complexity with no
/// workload to justify it.
pub fn serve(
    socket: &Path,
    broker: &Broker,
    grant: &Grant,
    servers: &ServerKeys,
) -> Result<(), BrokerError> {
    use std::os::unix::net::UnixListener;

    // A stale socket file from a previous run makes bind() fail with EADDRINUSE.
    if socket.exists() {
        fs::remove_file(socket)?;
    }
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket)?;
    // The container runs as uid 1001, which is not this process's uid, so the
    // socket must be permissive at the filesystem layer. That is acceptable HERE
    // and only here: this socket is bind-mounted into exactly one container, and
    // the single operation it exposes is scoped to that agent's grant.
    fs::set_permissions(socket, fs::Permissions::from_mode(0o666))?;

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        let resp = handle_request(broker, grant, servers, line.trim());
        let body = serde_json::to_string(&resp)
            .unwrap_or_else(|_| r#"{"error":"failed to serialise response"}"#.to_string());
        let _ = writeln!(stream, "{body}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hive-broker-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn grant(agent: &str, keys: &[&str]) -> Grant {
        Grant::new(agent, keys.iter().map(|s| s.to_string()))
    }

    #[test]
    fn secrets_are_written_restrictively_from_the_start() {
        let b = Broker::open(tmpdir("a")).unwrap();
        let k = CredentialKey::new("nsec/alice");
        b.put(&k, b"secret").unwrap();
        let mode = fs::metadata(b.path_for(&k).unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got mode {mode:o}");
    }

    #[test]
    fn a_permissive_credential_file_is_refused_not_warned_about() {
        let b = Broker::open(tmpdir("b")).unwrap();
        let k = CredentialKey::new("nsec/bob");
        b.put(&k, b"secret").unwrap();
        fs::set_permissions(b.path_for(&k).unwrap(), fs::Permissions::from_mode(0o644)).unwrap();
        let err = b.fetch_for(&grant("bob", &["nsec/bob"]), &k).unwrap_err();
        assert!(matches!(err, BrokerError::Permissive { .. }), "got {err:?}");
    }

    #[test]
    fn keys_cannot_escape_the_store_directory() {
        // Keys come from spec files, which are meant to be committed and shared
        // — attacker-influenced in exactly the way traversal needs.
        let b = Broker::open(tmpdir("c")).unwrap();
        for bad in ["../../etc/shadow", "/etc/shadow", "mcp/../../x", "", "a//b", "."] {
            assert!(
                b.path_for(&CredentialKey::new(bad)).is_err(),
                "key {bad:?} was accepted"
            );
        }
    }

    #[test]
    fn an_agent_cannot_fetch_a_key_outside_its_grant() {
        // The containment property: a bug elsewhere can hand out a wrong grant,
        // but it cannot make the broker ignore one.
        let b = Broker::open(tmpdir("d")).unwrap();
        b.put(&CredentialKey::new("nsec/alice"), b"alice-secret").unwrap();
        let err = b
            .fetch_for(&grant("bob", &["nsec/bob"]), &CredentialKey::new("nsec/alice"))
            .unwrap_err();
        assert!(matches!(err, BrokerError::NotAuthorised { .. }));
    }

    #[test]
    fn the_socket_protocol_cannot_name_an_agent() {
        // If a request could carry an identity, the per-socket design would be
        // decorative: any agent could claim to be any other.
        let parsed: Request =
            serde_json::from_str(r#"{"op":"headers","server":"parachute","agent":"someone-else"}"#)
                .unwrap();
        assert_eq!(parsed, Request::Headers { server: "parachute".into() });
    }

    #[test]
    fn denied_requests_are_audited_without_leaking_the_secret() {
        // The audit log's purpose is the DENIED entries; granted ones are
        // routine. A broker that logged only successes would be silent about
        // exactly the events worth reading.
        let d = tmpdir("e");
        let b = Broker::open(&d).unwrap();
        b.put(&CredentialKey::new("nsec/alice"), b"alice-secret").unwrap();
        let _ = b.fetch_for(&grant("bob", &[]), &CredentialKey::new("nsec/alice"));
        let log = fs::read_to_string(d.join("audit.jsonl")).unwrap();
        assert!(log.contains(r#""outcome":"denied""#), "audit missing denial: {log}");
        assert!(!log.contains("alice-secret"), "audit leaked the secret");
    }

    #[test]
    fn headers_come_back_in_the_shape_claude_code_expects() {
        let b = Broker::open(tmpdir("f")).unwrap();
        b.put(&CredentialKey::new("mcp/parachute"), b"tok-123\n").unwrap();
        let servers = ServerKeys::from([("parachute".into(), "mcp/parachute".into())]);
        let resp = handle_request(
            &b,
            &grant("alice", &["mcp/parachute"]),
            &servers,
            r#"{"op":"headers","server":"parachute"}"#,
        );
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"headers":{"Authorization":"Bearer tok-123"}}"#
        );
    }

    #[test]
    fn an_unknown_server_is_an_error_not_an_empty_header_set() {
        // Empty headers produce a 401 at the first tool call, which reads as an
        // expired token rather than as a misconfiguration.
        let b = Broker::open(tmpdir("g")).unwrap();
        let resp = handle_request(
            &b,
            &grant("alice", &[]),
            &ServerKeys::new(),
            r#"{"op":"headers","server":"nope"}"#,
        );
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[test]
    fn malformed_input_does_not_panic_the_broker() {
        // This socket is reachable from model-authored code. It must be dull.
        let b = Broker::open(tmpdir("h")).unwrap();
        for junk in ["", "{", "null", "[]", r#"{"op":"nonexistent"}"#, "\u{1}"] {
            let resp = handle_request(&b, &grant("a", &[]), &ServerKeys::new(), junk);
            assert!(matches!(resp, Response::Error { .. }), "junk {junk:?} not rejected");
        }
    }
}
