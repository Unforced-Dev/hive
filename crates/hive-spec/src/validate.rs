//! Spec validation.
//!
//! Every rule here prevents a failure that was observed in production. The
//! common shape of those failures is *silence*: the agent starts, connects,
//! looks healthy, and does the wrong thing — or nothing — until someone
//! investigates. Validation converts them into errors at write time.

use crate::{AgentSpec, McpTransport};

/// Environment variables that are refused outright.
///
/// Each silently moves Claude billing off the subscription and onto metered
/// API usage. Measured against the shipped CLI, not inferred:
/// `ANTHROPIC_API_KEY` outranks the OAuth token entirely; `apiKeyHelper` and
/// `ANTHROPIC_AUTH_TOKEN` suppress the oauth beta header and reclassify the
/// session. The failure is invisible until a bill arrives.
pub const BANNED_ENV: &[&str] =
    &["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_API_KEY_HELPER"];

/// Environment the runtime computes. A caller-supplied value is either ignored
/// or actively wrong.
///
/// The state-dir entries matter more than they look: each harness's config
/// directory must sit inside the mounted volume, or its config is written to
/// the container filesystem and destroyed on the next recreate. That failure
/// is invisible until a redeploy, at which point the agent silently reverts to
/// unauthenticated.
pub const RESERVED_ENV: &[&str] = &[
    "BUZZ_PRIVATE_KEY",
    "BUZZ_RELAY_URL",
    "BUZZ_AUTH_TAG",
    "BUZZ_ACP_AGENT_OWNER",
    "BUZZ_ACP_AGENT_COMMAND",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
];

/// Word fragments that suggest a literal secret has been pasted into a spec.
/// Specs are plain files meant to be readable, diffable and shareable; secrets
/// belong in the broker.
const SECRET_WORDS: &[&str] = &["token", "secret", "password", "apikey", "api_key", "nsec"];

const VALID_RESPOND_TO: &[&str] = &["owner-only", "allowlist", "anyone", "nobody"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("{field}: {message}")]
    Invalid { field: String, message: String },
}

impl ValidationError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid { field: field.into(), message: message.into() }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn validate(spec: &AgentSpec) -> ValidationReport {
    let mut r = ValidationReport::default();

    // ---- identity ----
    if !is_hex64(&spec.identity.pubkey) {
        r.errors.push(ValidationError::new(
            "identity.pubkey",
            "must be 64 lowercase hex characters",
        ));
    }
    if !spec.identity.relay_url.starts_with("ws://")
        && !spec.identity.relay_url.starts_with("wss://")
    {
        r.errors.push(ValidationError::new(
            "identity.relay_url",
            "must be a ws:// or wss:// URL",
        ));
    }

    // Without an owner the harness drops every event and sits idle — no error,
    // no log line, just an agent that never answers. Catch it here rather than
    // letting someone debug a silent agent.
    if spec.identity.owner_pubkey.is_none() && spec.identity.auth_tag.is_none() {
        r.errors.push(ValidationError::new(
            "identity",
            "one of owner_pubkey or auth_tag is required — without either, \
             the harness silently drops every event and the agent never responds",
        ));
    }
    if let Some(owner) = &spec.identity.owner_pubkey
        && !is_hex64(owner)
    {
        r.errors.push(ValidationError::new(
            "identity.owner_pubkey",
            "must be 64 lowercase hex characters",
        ));
    }
    if spec.identity.owner_pubkey.is_some() && spec.identity.auth_tag.is_none() {
        r.warnings.push(
            "identity: using owner_pubkey without auth_tag — the agent needs its own \
             relay membership. A NIP-OA auth_tag would let it derive access from its \
             owner's membership instead, so revoking the human revokes the agent."
                .into(),
        );
    }

    if let Some(c) = &spec.identity.credential
        && looks_like_a_secret(c)
    {
        r.errors.push(ValidationError::new(
            "identity.credential",
            "this is a broker KEY, not the private key itself — store the value with \
             `hive secret put` and name it here",
        ));
    }

    // ---- harness ----
    match (&spec.harness.id, &spec.harness.command) {
        (None, None) => r.errors.push(ValidationError::new(
            "harness",
            "one of id (catalog) or command (explicit) is required",
        )),
        (Some(_), Some(_)) => r.errors.push(ValidationError::new(
            "harness",
            "set id or command, not both",
        )),
        (None, Some(_)) if spec.harness.image.is_none() => r.errors.push(ValidationError::new(
            "harness.image",
            "an explicit command requires an explicit image that contains it — \
             the catalog cannot know which image carries an unknown harness",
        )),
        _ => {}
    }

    // ---- agent ----
    if let Some(rt) = &spec.agent.respond_to {
        if !VALID_RESPOND_TO.contains(&rt.as_str()) {
            r.errors.push(ValidationError::new(
                "agent.respond_to",
                format!("must be one of {}", VALID_RESPOND_TO.join(", ")),
            ));
        }
        if rt == "allowlist" && spec.agent.respond_to_allowlist.is_empty() {
            r.errors.push(ValidationError::new(
                "agent.respond_to_allowlist",
                "respond_to = \"allowlist\" requires a non-empty allowlist",
            ));
        }
        if rt == "anyone" {
            r.warnings.push(
                "agent.respond_to = \"anyone\": any relay member can trigger this agent, \
                 running code on your box and spending the owner's model quota"
                    .into(),
            );
        }
    }
    if let Some(p) = spec.agent.parallelism
        && p == 0
    {
        r.errors.push(ValidationError::new("agent.parallelism", "must be at least 1"));
    }

    // ---- resources ----
    // Each pool slot can hold a full harness process, and a cross-harness call
    // adds another. 24 slots under a 2g cap produced initialize timeouts and a
    // crash loop on a real box; the symptom was "the agent never replied".
    if let Some(p) = spec.agent.parallelism
        && let Some(gb) = parse_memory_gb(&spec.resources.memory)
        && f64::from(p) > gb * 4.0
    {
        r.warnings.push(format!(
            "agent.parallelism = {p} with resources.memory = {} — each slot may hold a \
             full harness process; this ratio has produced initialize timeouts and \
             crash loops. Consider fewer slots or more memory.",
            spec.resources.memory
        ));
    }
    if spec.resources.cpus <= 0.0 {
        r.errors.push(ValidationError::new("resources.cpus", "must be greater than zero"));
    }

    // ---- mcp ----
    for (i, m) in spec.mcp.iter().enumerate() {
        let f = |s: &str| format!("mcp[{i}].{s}");
        if m.name.trim().is_empty() {
            r.errors.push(ValidationError::new(f("name"), "must not be empty"));
        }
        match m.transport {
            McpTransport::Http if m.url.is_none() => {
                r.errors.push(ValidationError::new(f("url"), "http transport requires a url"));
            }
            McpTransport::Stdio if m.command.is_none() => {
                r.errors
                    .push(ValidationError::new(f("command"), "stdio transport requires a command"));
            }
            _ => {}
        }
        if let Some(c) = &m.credential
            && looks_like_secret_value(c)
        {
            r.errors.push(ValidationError::new(
                f("credential"),
                "looks like a literal secret — this field takes a broker KEY \
                 (e.g. \"mcp/parachute\"). Store the value with `hive secret set`.",
            ));
        }
    }

    // ---- env ----
    for key in spec.env.keys() {
        if BANNED_ENV.iter().any(|b| b.eq_ignore_ascii_case(key)) {
            r.errors.push(ValidationError::new(
                format!("env.{key}"),
                "refused: silently switches model billing off the subscription \
                 and onto metered API usage",
            ));
        }
        if RESERVED_ENV.iter().any(|b| b.eq_ignore_ascii_case(key)) {
            r.errors.push(ValidationError::new(
                format!("env.{key}"),
                "reserved: computed by the runtime. Overriding a state-dir variable \
                 puts config outside the mounted volume, where it is destroyed on \
                 the next redeploy.",
            ));
        }
        let lower = key.to_ascii_lowercase();
        if SECRET_WORDS.iter().any(|w| lower.contains(w)) {
            r.errors.push(ValidationError::new(
                format!("env.{key}"),
                "spec files hold no secrets — use `hive secret set` and reference \
                 the broker key",
            ));
        }
    }

    // ---- credential files ----
    for f in &spec.files {
        if !f.target.starts_with(STATE_MOUNT) {
            // Outside the volume the file lives on the container filesystem and
            // is destroyed on the next recreate. The agent comes back
            // unauthenticated, hours later, for reasons nobody connects to the
            // spec edit that caused it.
            r.errors.push(ValidationError::new(
                "file.target",
                format!(
                    "{} is outside {STATE_MOUNT}: it would be destroyed on the next \
                     redeploy and the agent would silently revert to unauthenticated",
                    f.target
                ),
            ));
        }
        if looks_like_a_secret(&f.credential) {
            r.errors.push(ValidationError::new(
                "file.credential",
                "this is a broker KEY, not the secret itself — store the value with \
                 `hive secret put` and name it here",
            ));
        }
        if f.mode_bits() & 0o077 != 0 {
            r.errors.push(ValidationError::new(
                "file.mode",
                format!(
                    "mode {} lets other users in the container read a credential; \
                     use 0600",
                    f.mode
                ),
            ));
        }
    }

    // ---- shared volumes ----
    for v in &spec.volumes {
        if v.target.starts_with(STATE_MOUNT) {
            // Mounting over the state volume replaces every harness's config
            // and credentials with someone else's — the exact opposite of the
            // per-agent isolation the state volume exists to provide.
            r.errors.push(ValidationError::new(
                "volume.target",
                format!(
                    "{} is inside {STATE_MOUNT}, which is this agent's PRIVATE state. \
                     Mounting a shared volume there would give every agent that names \
                     it the same skills, credentials and harness state.",
                    v.target
                ),
            ));
        }
        if !v.target.starts_with('/') {
            r.errors.push(ValidationError::new(
                "volume.target",
                format!("{} must be an absolute path", v.target),
            ));
        }
        if v.name.trim().is_empty() {
            r.errors.push(ValidationError::new("volume.name", "must not be empty"));
        }
    }

    r
}

/// Where the agent's private state volume is mounted. Duplicated from
/// `hive-core::backend` rather than imported: this crate deliberately depends on
/// nothing, and the value is part of the on-disk contract either way.
const STATE_MOUNT: &str = "/home/agent/state";

/// Heuristic for "someone pasted the actual secret here".
fn looks_like_a_secret(s: &str) -> bool {
    // Broker keys are short paths like `codex/auth`. Real credentials are long,
    // or carry a recognisable prefix.
    s.len() > 60
        || s.starts_with("nsec1")
        || s.starts_with("sk-")
        || s.starts_with("ey")
        || s.contains("BEGIN ")
}

/// Heuristic for a pasted secret where a key was expected. Broker keys look
/// like `mcp/parachute`; credentials look like `sk-ant-…` or a JWT.
fn looks_like_secret_value(s: &str) -> bool {
    s.starts_with("sk-")
        || s.starts_with("nsec1")
        || s.starts_with("eyJ") // JWT header
        || s.len() > 64
}

fn parse_memory_gb(s: &str) -> Option<f64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        'g' | 'G' => (&s[..s.len() - 1], 1.0),
        'm' | 'M' => (&s[..s.len() - 1], 1.0 / 1024.0),
        _ => (s, 1.0 / (1024.0 * 1024.0 * 1024.0)),
    };
    num.trim().parse::<f64>().ok().map(|n| n * mult)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::collections::BTreeMap;

    const PK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn base() -> AgentSpec {
        AgentSpec {
            identity: Identity {
                pubkey: PK.into(),
                relay_url: "wss://buzz.example.org".into(),
                owner_pubkey: Some(PK.into()),
                auth_tag: None,
                credential: None,
            },
            harness: Harness { id: Some("claude".into()), command: None, image: None, auth: HarnessAuth::Broker },
            agent: AgentConfig { observer: true, ..Default::default() },
            resources: Resources::default(),
            network: Network::default(),
            mcp: vec![],
            files: vec![],
            volumes: vec![],
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn baseline_spec_is_valid() {
        let r = base().validate();
        assert!(r.is_ok(), "{:?}", r.errors);
    }

    // Scar tissue: an agent with neither owner_pubkey nor auth_tag starts,
    // connects, and silently drops every event.
    #[test]
    fn missing_owner_is_an_error_not_a_silent_idle_agent() {
        let mut s = base();
        s.identity.owner_pubkey = None;
        s.identity.auth_tag = None;
        let r = s.validate();
        assert!(!r.is_ok());
        assert!(r.errors.iter().any(|e| e.to_string().contains("owner_pubkey or auth_tag")));
    }

    // Scar tissue: ANTHROPIC_API_KEY outranks the OAuth token and moves billing
    // to metered API usage with no visible signal.
    #[test]
    fn banned_env_is_refused() {
        for k in BANNED_ENV {
            let mut s = base();
            s.env.insert((*k).into(), "x".into());
            assert!(!s.validate().is_ok(), "{k} should be refused");
        }
    }

    // Scar tissue: CODEX_HOME once pointed outside the mounted volume, so codex
    // credentials vanished on every recreate. Invisible until a redeploy.
    #[test]
    fn reserved_state_dirs_cannot_be_overridden() {
        for k in ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"] {
            let mut s = base();
            s.env.insert(k.into(), "/tmp/wrong".into());
            assert!(!s.validate().is_ok(), "{k} should be reserved");
        }
    }

    #[test]
    fn a_shared_volume_cannot_be_mounted_over_private_agent_state() {
        // THE isolation rule. /home/agent/state holds this agent's skills,
        // credentials and per-harness config. A shared volume mounted there
        // would give every agent naming it the same .claude, .codex, .grok and
        // .kimi — which is exactly what per-agent volumes exist to prevent.
        let mut s = base();
        s.volumes.push(SharedVolume {
            name: "team".into(),
            target: "/home/agent/state/claude".into(),
            read_only: false,
        });
        let r = validate(&s);
        assert!(
            r.errors.iter().any(|e| e.to_string().contains("PRIVATE state")),
            "sharing agent state was allowed: {:?}",
            r.errors
        );
    }

    #[test]
    fn a_shared_workspace_outside_state_is_fine() {
        // The supported shape: two agents, different harnesses, one tree of
        // files, separate skills and credentials.
        let mut s = base();
        s.volumes.push(SharedVolume {
            name: "uni-workspace".into(),
            target: "/home/agent/work".into(),
            read_only: false,
        });
        assert!(validate(&s).is_ok(), "{:?}", validate(&s).errors);
    }

    #[test]
    fn a_credential_file_outside_the_state_volume_is_refused() {
        // Written to the container filesystem it is destroyed on the next
        // recreate, and the agent comes back unauthenticated hours later for
        // reasons nobody connects to the spec edit.
        let mut s = base();
        s.files.push(CredentialFile {
            credential: "codex/auth".into(),
            target: "/home/agent/.codex/auth.json".into(),
            mode: "0600".into(),
        });
        let r = validate(&s);
        assert!(
            r.errors.iter().any(|e| e.to_string().contains("destroyed on the next redeploy")),
            "{:?}",
            r.errors
        );
    }

    #[test]
    fn a_permissive_credential_file_mode_is_refused() {
        let mut s = base();
        s.files.push(CredentialFile {
            credential: "codex/auth".into(),
            target: "/home/agent/state/codex/auth.json".into(),
            mode: "0644".into(),
        });
        assert!(!validate(&s).is_ok());
    }

    #[test]
    fn file_mode_is_a_string_so_0600_does_not_become_decimal_600() {
        // TOML has no octal literal. `mode = 0600` parses as the integer 600,
        // which is 0o1130 — world-writable. Keeping it a string is the fix, and
        // this pins it.
        let f = CredentialFile {
            credential: "codex/auth".into(),
            target: "/home/agent/state/codex/auth.json".into(),
            mode: "0600".into(),
        };
        assert_eq!(f.mode_bits(), 0o600);
        assert_ne!(f.mode_bits(), 600);
    }

    #[test]
    fn a_literal_secret_in_a_file_entry_is_refused() {
        let mut s = base();
        s.files.push(CredentialFile {
            credential: "sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            target: "/home/agent/state/codex/auth.json".into(),
            mode: "0600".into(),
        });
        assert!(!validate(&s).is_ok(), "a pasted secret was accepted as a broker key");
    }

    #[test]
    fn secrets_are_refused_in_env_and_in_mcp_credentials() {
        let mut s = base();
        s.env.insert("MY_TOKEN".into(), "hunter2".into());
        assert!(!s.validate().is_ok());

        let mut s = base();
        s.mcp.push(Mcp {
            name: "parachute".into(),
            transport: McpTransport::Http,
            url: Some("https://v.example/mcp".into()),
            command: None,
            args: vec![],
            credential: Some("eyJhbGciOiJSUzI1NiJ9.abc.def".into()),
        });
        let r = s.validate();
        assert!(!r.is_ok());
        assert!(r.errors.iter().any(|e| e.to_string().contains("broker KEY")));
    }

    #[test]
    fn http_mcp_requires_url_stdio_requires_command() {
        let mut s = base();
        s.mcp.push(Mcp {
            name: "x".into(),
            transport: McpTransport::Http,
            url: None,
            command: None,
            args: vec![],
            credential: None,
        });
        assert!(!s.validate().is_ok());
    }

    #[test]
    fn explicit_command_requires_explicit_image() {
        let mut s = base();
        s.harness = Harness { id: None, command: Some("opencode acp".into()), image: None, auth: HarnessAuth::Broker };
        assert!(!s.validate().is_ok());

        s.harness.image = Some("hive/harness-opencode:1.4.2".into());
        assert!(s.validate().is_ok());
    }

    // Scar tissue: 24 pool slots under a 2g cap produced initialize timeouts
    // and a crash loop, surfacing only as "the agent never replied".
    #[test]
    fn implausible_parallelism_for_memory_warns() {
        let mut s = base();
        s.agent.parallelism = Some(24);
        s.resources.memory = "2g".into();
        let r = s.validate();
        assert!(r.is_ok(), "should warn, not fail");
        assert!(r.warnings.iter().any(|w| w.contains("parallelism")));
    }

    #[test]
    fn respond_to_anyone_warns_and_allowlist_needs_entries() {
        let mut s = base();
        s.agent.respond_to = Some("anyone".into());
        assert!(!s.validate().warnings.is_empty());

        let mut s = base();
        s.agent.respond_to = Some("allowlist".into());
        assert!(!s.validate().is_ok());
    }

    #[test]
    fn observer_defaults_on_because_remote_agents_are_otherwise_invisible() {
        let parsed: AgentSpec = AgentSpec::from_toml(
            r#"
            [identity]
            pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            relay_url = "wss://buzz.example.org"
            owner_pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            [harness]
            id = "claude"
            "#,
        )
        .expect("parses");
        assert!(parsed.agent.observer);
    }

    #[test]
    fn hash_is_stable_and_changes_with_content() {
        let a = base();
        let mut b = base();
        assert_eq!(a.hash(), b.hash());
        b.agent.model = Some("opus".into());
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn roundtrips_through_toml() {
        let s = base();
        let text = s.to_toml().expect("serialises");
        let back = AgentSpec::from_toml(&text).expect("parses");
        assert_eq!(s, back);
    }
}
