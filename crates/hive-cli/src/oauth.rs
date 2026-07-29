//! The MCP authorization-code flow, for `hive mcp login`.
//!
//! # Why hive does this at all
//!
//! Buzz cannot. Its `McpServer` is `{name, command, args, env}` — stdio only,
//! no `url`, no `headers` — and the backend-provider deploy payload carries no
//! MCP field whatsoever. So an HTTP MCP server can never be configured from the
//! desktop, in either extension seam. If agents are to reach one, hive has to
//! own the credential.
//!
//! # Why an interactive flow rather than a static token
//!
//! A hand-minted bearer token is derived from whoever minted it, carries that
//! person's authority, and expires without warning — at which point the agent
//! starts failing tool calls and the error reads as a broken server. The
//! authorization-code flow gets a token scoped to the *agent's* grant, plus a
//! refresh token.
//!
//! Refresh is only useful because of an existing design choice: the broker
//! serves credentials **per connection** rather than injecting them once at
//! container start. So a token can be refreshed between one tool call and the
//! next without recreating the container. A design that baked credentials into
//! the environment could not do this.
//!
//! # Why curl instead of an HTTP crate
//!
//! Same reasoning `hive_core::docker` gives for driving Docker through its CLI:
//! no large dependency tracking a moving API, and every request is a command
//! that can be logged verbatim and re-run by hand when a server misbehaves.
//! Token values are the one thing never logged.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Everything discovery has to produce before an authorization request can be
/// built. Discovered, never configured: an authorization server that moves its
/// endpoints would otherwise silently break every stored config.
#[derive(Debug, Clone)]
pub struct AuthServer {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    /// The canonical resource identifier the token must be bound to (RFC 8707).
    /// Taken from the protected-resource metadata rather than from the URL the
    /// user typed, so a token cannot be minted for the wrong audience because
    /// someone reached the same server by a different hostname.
    pub resource: String,
    pub scopes_supported: Vec<String>,
}

/// What a successful flow yields. `refresh_token` is optional because not every
/// server issues one; when absent the credential simply expires and login must
/// be repeated.
#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}

/// GET a URL and parse JSON. Non-2xx is an error carrying the body, because an
/// OAuth server's error body is the only useful diagnostic it gives you.
fn get_json(url: &str) -> Result<Value> {
    let out = Command::new(curl()?)
        .args(["-sS", "-L", "--max-time", "20", "-w", "\n%{http_code}", url])
        .output()
        .with_context(|| format!("GET {url}"))?;
    finish(url, &out.stdout, &out.stderr)
}

fn post_form(url: &str, fields: &BTreeMap<&str, String>) -> Result<Value> {
    let mut cmd = Command::new(curl()?);
    cmd.args(["-sS", "--max-time", "20", "-w", "\n%{http_code}", "-X", "POST"]);
    // --data-urlencode, not --data: a code_verifier is base64url and a scope
    // contains spaces; both corrupt silently if sent raw, and the server's
    // complaint ("invalid_grant") points at the code rather than the encoding.
    for (k, v) in fields {
        cmd.arg("--data-urlencode").arg(format!("{k}={v}"));
    }
    cmd.arg(url);
    let out = cmd.output().with_context(|| format!("POST {url}"))?;
    finish(url, &out.stdout, &out.stderr)
}

fn post_json(url: &str, body: &Value) -> Result<Value> {
    let out = Command::new(curl()?)
        .args([
            "-sS", "--max-time", "20", "-w", "\n%{http_code}",
            "-X", "POST", "-H", "Content-Type: application/json",
            "--data-binary", "@-",
        ])
        .arg(url)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().expect("piped").write_all(body.to_string().as_bytes())?;
            c.wait_with_output()
        })
        .with_context(|| format!("POST {url}"))?;
    finish(url, &out.stdout, &out.stderr)
}

/// Split curl's `-w "\n%{http_code}"` suffix off the body, then parse.
fn finish(url: &str, stdout: &[u8], stderr: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(stdout);
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", text.as_ref()));
    let code: u16 = code.trim().parse().unwrap_or(0);
    if code == 0 {
        bail!("{url}: no response ({})", String::from_utf8_lossy(stderr).trim());
    }
    if !(200..300).contains(&code) {
        bail!("{url}: HTTP {code} {}", body.trim());
    }
    serde_json::from_str(body).with_context(|| format!("{url}: response was not JSON: {}", body.trim()))
}

fn curl() -> Result<String> {
    for p in ["/usr/bin/curl", "/opt/homebrew/bin/curl", "/usr/local/bin/curl"] {
        if std::path::Path::new(p).is_file() {
            return Ok(p.to_string());
        }
    }
    Ok("curl".to_string())
}

/// Walk the discovery chain the MCP specification defines:
/// unauthenticated request → `WWW-Authenticate: Bearer resource_metadata=…`
/// → protected-resource metadata (RFC 9728) → authorization-server metadata
/// (RFC 8414).
///
/// The `resource_metadata` pointer is read from the challenge rather than
/// guessed from a well-known path: a vault served under a path prefix
/// (`/vault/<name>/mcp`) advertises its metadata under that same prefix, and
/// the origin-root well-known path 404s.
pub fn discover(mcp_url: &str) -> Result<AuthServer> {
    let out = Command::new(curl()?)
        .args([
            "-sS", "-i", "--max-time", "20", "-X", "POST",
            "-H", "Content-Type: application/json", "-d", "{}",
        ])
        .arg(mcp_url)
        .output()
        .with_context(|| format!("probing {mcp_url}"))?;
    let head = String::from_utf8_lossy(&out.stdout);

    let meta_url = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))
        .and_then(|l| l.split_once("resource_metadata="))
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
        .with_context(|| {
            format!(
                "{mcp_url} did not advertise resource_metadata in a WWW-Authenticate header. \
                 Either it is not an OAuth-protected MCP server, or it accepted the \
                 unauthenticated probe — check whether it needs credentials at all."
            )
        })?;

    let prm = get_json(&meta_url)?;
    let resource = prm["resource"].as_str().unwrap_or(mcp_url).to_string();
    let issuer = prm["authorization_servers"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .context("protected-resource metadata listed no authorization_servers")?
        .to_string();
    let scopes_supported = prm["scopes_supported"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let asm = get_json(&format!("{}/.well-known/oauth-authorization-server", issuer.trim_end_matches('/')))?;

    Ok(AuthServer {
        authorization_endpoint: asm["authorization_endpoint"]
            .as_str()
            .context("authorization server declared no authorization_endpoint")?
            .to_string(),
        token_endpoint: asm["token_endpoint"]
            .as_str()
            .context("authorization server declared no token_endpoint")?
            .to_string(),
        registration_endpoint: asm["registration_endpoint"].as_str().map(String::from),
        issuer,
        resource,
        scopes_supported,
    })
}

/// Register a client on the fly (RFC 7591).
///
/// hive has no pre-registered client id and should not need one: an agent host
/// that required manual client registration per vault would make adding an MCP
/// server a support ticket rather than a command.
pub fn register_client(auth: &AuthServer, redirect_uri: &str) -> Result<String> {
    let Some(endpoint) = auth.registration_endpoint.as_deref() else {
        bail!(
            "{} supports no dynamic client registration; register a client manually \
             and pass --client-id",
            auth.issuer
        );
    };
    let body = serde_json::json!({
        "client_name": "hive",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        // `none` because this is a public client: hive runs on a box the user
        // controls and cannot keep a client secret meaningfully. PKCE is what
        // actually protects the exchange.
        "token_endpoint_auth_method": "none",
    });
    let resp = post_json(endpoint, &body)?;
    resp["client_id"]
        .as_str()
        .map(String::from)
        .context("registration response contained no client_id")
}

/// RFC 7636 S256 verifier/challenge pair.
fn pkce() -> (String, String) {
    // 32 bytes of entropy from the OS, via getrandom(2) through /dev/urandom.
    // Not a PRNG seeded from the clock: two agents enrolled in the same second
    // must not derive the same verifier.
    let mut raw = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
    use std::io::Read;
    f.read_exact(&mut raw).expect("read /dev/urandom");
    let verifier = b64url(&raw);
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// base64url without padding (RFC 4648 §5). Hand-rolled to avoid a dependency
/// for forty lines of table lookup; `=` padding is omitted because RFC 7636
/// requires it to be.
fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        if c.len() > 1 {
            out.push(T[(n >> 6 & 63) as usize] as char);
        }
        if c.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Run the interactive half: bind a loopback listener, print (and try to open)
/// the authorization URL, and block until the browser redirects back.
///
/// Loopback rather than a fixed port: the port is part of the redirect URI that
/// was registered moments earlier, so nothing is hardcoded and two concurrent
/// logins cannot collide.
pub fn bind_callback() -> Result<(TcpListener, String)> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding a loopback callback listener")?;
    let port = listener.local_addr()?.port();
    Ok((listener, format!("http://127.0.0.1:{port}/callback")))
}

pub fn authorize(
    listener: TcpListener,
    redirect_uri: &str,
    auth: &AuthServer,
    client_id: &str,
    scopes: &[String],
    open_browser: bool,
) -> Result<(String, String)> {
    let port = listener.local_addr()?.port();
    let (verifier, challenge) = pkce();
    let state = b64url(&Sha256::digest(format!("{port}{challenge}").as_bytes()))[..16].to_string();

    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&resource={}",
        auth.authorization_endpoint,
        urlenc(client_id),
        urlenc(redirect_uri),
        urlenc(&challenge),
        urlenc(&state),
        urlenc(&auth.resource),
    );
    if !scopes.is_empty() {
        url.push_str(&format!("&scope={}", urlenc(&scopes.join(" "))));
    }

    println!("\nAuthorize hive in your browser:\n\n  {url}\n");
    if open_browser {
        // Best-effort. A headless box has no browser and that is not an error —
        // the URL above is printed first precisely so it stays usable there.
        let _ = Command::new("open").arg(&url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    }
    println!("Waiting for the redirect on 127.0.0.1:{port} …");

    let (mut sock, _) = listener.accept().context("waiting for the OAuth redirect")?;
    let mut reader = BufReader::new(sock.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let query = request_line
        .split_whitespace()
        .nth(1)
        .and_then(|p| p.split_once('?').map(|(_, q)| q.to_string()))
        .unwrap_or_default();
    let params: BTreeMap<&str, &str> =
        query.split('&').filter_map(|kv| kv.split_once('=')).collect();

    let reply = |sock: &mut std::net::TcpStream, msg: &str| {
        let _ = write!(
            sock,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body style=\"font-family:system-ui;padding:3rem\"><h2>{msg}</h2><p>You can close this tab.</p></body></html>"
        );
    };

    if let Some(err) = params.get("error") {
        reply(&mut sock, "Authorization failed");
        bail!("authorization server refused: {err}");
    }
    // Compare state before touching the code: without this a redirect from an
    // unrelated flow would be accepted and exchanged.
    if params.get("state").map(|s| *s != state).unwrap_or(true) {
        reply(&mut sock, "Authorization failed");
        bail!("state mismatch — the redirect did not belong to this login attempt");
    }
    let code = params
        .get("code")
        .map(|c| percent_decode(c))
        .context("redirect carried no authorization code")?;
    reply(&mut sock, "hive is authorized");

    Ok((code, format!("{verifier}\u{1}{redirect_uri}")))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Exchange the authorization code for tokens.
pub fn exchange(auth: &AuthServer, client_id: &str, code: &str, verifier_and_redirect: &str) -> Result<Tokens> {
    let (verifier, redirect_uri) = verifier_and_redirect
        .split_once('\u{1}')
        .context("internal: malformed verifier bundle")?;
    let mut f = BTreeMap::new();
    f.insert("grant_type", "authorization_code".to_string());
    f.insert("code", code.to_string());
    f.insert("redirect_uri", redirect_uri.to_string());
    f.insert("client_id", client_id.to_string());
    f.insert("code_verifier", verifier.to_string());
    // RFC 8707. Without it a server that issues audience-bound tokens returns
    // one the resource will reject, and the failure appears later as a 401 from
    // the MCP server rather than here.
    f.insert("resource", auth.resource.clone());

    let resp = post_form(&auth.token_endpoint, &f)?;
    Ok(Tokens {
        access_token: resp["access_token"]
            .as_str()
            .context("token response contained no access_token")?
            .to_string(),
        refresh_token: resp["refresh_token"].as_str().map(String::from),
        expires_in: resp["expires_in"].as_u64(),
        scope: resp["scope"].as_str().map(String::from),
    })
}

/// Where a refresh token is parked so the broker can find it later. Kept beside
/// the access token under a `+refresh` suffix rather than in a sidecar file, so
/// `hive secret rm` on the credential removes both halves and cannot leave a
/// refresh token behind that still mints access.
pub fn refresh_key(credential: &str) -> String {
    format!("{credential}+refresh")
}

/// Metadata a later `refresh` needs, stored next to the credential.
pub fn meta_key(credential: &str) -> String {
    format!("{credential}+oauth")
}

pub fn meta_json(auth: &AuthServer, client_id: &str) -> String {
    serde_json::json!({
        "token_endpoint": auth.token_endpoint,
        "client_id": client_id,
        "resource": auth.resource,
        "issuer": auth.issuer,
    })
    .to_string()
}

/// Not used by the CLI directly — exposed so the broker can refresh on the
/// per-connection path without duplicating the token-endpoint contract.
pub fn refresh(token_endpoint: &str, client_id: &str, refresh_token: &str, resource: &str) -> Result<Tokens> {
    let mut f = BTreeMap::new();
    f.insert("grant_type", "refresh_token".to_string());
    f.insert("refresh_token", refresh_token.to_string());
    f.insert("client_id", client_id.to_string());
    f.insert("resource", resource.to_string());
    let resp = post_form(token_endpoint, &f)?;
    Ok(Tokens {
        access_token: resp["access_token"]
            .as_str()
            .context("refresh response contained no access_token")?
            .to_string(),
        // A server that rotates refresh tokens returns a new one; when it does
        // not, the old one stays valid and must be kept rather than cleared.
        refresh_token: resp["refresh_token"].as_str().map(String::from),
        expires_in: resp["expires_in"].as_u64(),
        scope: resp["scope"].as_str().map(String::from),
    })
}

/// Spec directory helper shared with the `mcp` subcommand.
pub fn spec_path(spec_dir: &std::path::Path, agent: &str) -> PathBuf {
    spec_dir.join(format!("{agent}.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_unpadded_and_uses_the_url_alphabet() {
        // RFC 7636 requires unpadded base64url. Standard base64 would emit '+'
        // and '/', which a server percent-decodes into different bytes — and
        // the failure surfaces as "invalid_grant" against a verifier that looks
        // correct in the logs.
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        let all = b64url(&(0u8..=255).collect::<Vec<_>>());
        assert!(!all.contains('+') && !all.contains('/') && !all.contains('='));
    }

    #[test]
    fn a_verifier_is_not_reused_between_logins() {
        // Two agents enrolled against the same server must not share a verifier;
        // if they did, one agent's redirect could be exchanged by the other.
        let (a, _) = pkce();
        let (b, _) = pkce();
        assert_ne!(a, b);
        assert!(a.len() >= 43, "RFC 7636 requires at least 43 characters");
    }

    #[test]
    fn the_challenge_is_the_hash_of_the_verifier_not_the_raw_entropy() {
        // S256 hashes the ASCII verifier string. Hashing the pre-encoding bytes
        // produces a challenge the server cannot reproduce, and the exchange
        // fails with a generic invalid_grant.
        let (v, c) = pkce();
        assert_eq!(c, b64url(&Sha256::digest(v.as_bytes())));
    }

    #[test]
    fn refresh_and_metadata_keys_hang_off_the_credential_name() {
        // `hive secret rm mcp/parachute` must be able to find and remove every
        // derived key; a refresh token left behind still mints access tokens.
        assert_eq!(refresh_key("mcp/parachute"), "mcp/parachute+refresh");
        assert_eq!(meta_key("mcp/parachute"), "mcp/parachute+oauth");
    }

    #[test]
    fn percent_decoding_handles_the_plus_and_escape_forms() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn urlencoding_escapes_everything_outside_the_unreserved_set() {
        // A scope contains spaces and a resource is a URL; both corrupt the
        // authorization request if passed through raw.
        assert_eq!(urlenc("a b"), "a%20b");
        assert_eq!(urlenc("https://x/y"), "https%3A%2F%2Fx%2Fy");
        assert_eq!(urlenc("-_.~"), "-_.~");
    }
}
