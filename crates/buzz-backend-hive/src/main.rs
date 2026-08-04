//! `buzz-backend-hive` — hive as a Buzz provider.
//!
//! Buzz Desktop discovers any executable named `buzz-backend-<id>` on PATH and
//! speaks one JSON object in / one JSON object out, one process per operation
//! (Buzz `docs/remote-agents.md` §Provider Protocol). This binary answers that
//! contract with hive underneath.
//!
//! **Why a backend at all, when hive deliberately sat in the harness seam.**
//! The reason it did was that a backend would compete with Buzz's own location
//! mechanism. That was true when there was no backend contract to conform to.
//! There is one now — versioned, fixture-pinned, zero-registration — so
//! implementing it is conforming rather than competing: Buzz decides *where* an
//! agent runs, hive answers *how*. It also gets hive agents into the same
//! Desktop list as Kubernetes ones, which is the only place a person actually
//! chooses between them.
//!
//! **This is an adapter, not a new mechanism.** Both halves already exist and
//! both are already idempotent by name:
//!
//!   1. `hive spec-put <name>` installs an environment spec and hived
//!      reconciles a container for it.
//!   2. `buzz-host install <name>` supervises a process against an identity —
//!      its own help says "a provider can send the same payload twice without
//!      leaving two processes on one identity".
//!
//! The split is deliberate and is why there is no `[identity]` block in a hive
//! spec: the environment is the container, the identity lives with the
//! supervisor outside it. A deploy therefore touches both, in that order — an
//! environment with no supervisor is inert, a supervisor with no environment
//! fails loudly at exec.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// The wire-contract version from Buzz `docs/remote-agents.md`. Declaring it is
/// not decoration: the desktop refuses to hand `private_key_nsec` to a provider
/// whose `protocol_version` it does not speak, and a *missing* value is an
/// error rather than a presumed 1. Bump only alongside a real wire change.
const PROTOCOL_VERSION: i64 = 1;

/// Identity variables the provider MUST construct from the top-level payload
/// fields rather than read out of `env_vars`.
///
/// Load-bearing in two directions. Reading them from `env_vars` yields an
/// identityless agent, because the desktop strips them before merge. And
/// letting a user-supplied key *reach* them would let `env_vars` overwrite the
/// identity the desktop resolved — so they are stripped on the way in and
/// written from the payload on the way out, in that order.
const RESERVED_ENV: &[&str] = &[
    "BUZZ_PRIVATE_KEY",
    "NOSTR_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
    "BUZZ_RELAY_URL",
    "HIVE_ENV",
    "HIVE_HARNESS",
];

fn main() {
    // In-band failure is `{"ok": false, ...}` on stdout with exit 0. A non-zero
    // exit is treated by the desktop as failure *even if stdout parsed*, so
    // exiting non-zero here would discard a perfectly good error message.
    let response = match run() {
        Ok(v) => v,
        Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
    };
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{response}");
    let _ = out.flush();
}

fn run() -> Result<Value> {
    augment_path();

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("reading the request from stdin")?;
    if input.trim().is_empty() {
        bail!("request is not valid JSON: empty stdin");
    }
    let req: Value = serde_json::from_str(&input).context("request is not valid JSON")?;

    match req.get("op").and_then(Value::as_str) {
        Some("info") => Ok(op_info()),
        Some("deploy") => op_deploy(&req),
        Some(other) => bail!("unsupported op {other:?}; this provider speaks info and deploy"),
        None => bail!("request has no \"op\" field"),
    }
}

/// Put the tools we shell out to back on PATH.
///
/// The desktop may be launched from the macOS GUI, in which case it inherits
/// launchd's minimal `/usr/bin:/bin:/usr/sbin:/sbin` and a provider that shells
/// out finds none of its own tooling. The spec makes self-augmentation the
/// provider's job (§Invocation), and this is the same trap buzz-host already
/// works around for the units it supervises.
fn augment_path() {
    let current = std::env::var("PATH").unwrap_or_default();
    let mut parts: Vec<String> = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy().into_owned();
        parts.push(format!("{home}/.local/bin"));
    }
    parts.push("/opt/homebrew/bin".into());
    parts.push("/usr/local/bin".into());
    for p in current.split(':') {
        if !p.is_empty() {
            parts.push(p.to_string());
        }
    }
    parts.dedup();
    // SAFETY-equivalent note: single-threaded, before any thread is spawned.
    unsafe { std::env::set_var("PATH", parts.join(":")) };
}

fn op_info() -> Value {
    json!({
        "ok": true,
        "name": "hive",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": PROTOCOL_VERSION,
        "description": "Runs agents as hive environments: a container per agent, \
                        with per-agent MCP servers and broker-held credentials.",
        "config_schema": {
            "type": "object",
            "required": ["harness"],
            "properties": {
                "harness": {
                    "title": "Harness",
                    "description": "Which coding harness runs inside the container. \
                                    `hive harnesses` lists what this build will run.",
                    "type": "string",
                    "default": "claude"
                },
                "hive_env": {
                    "title": "Environment name",
                    "description": "Container to run in. Defaults to the agent's own name. \
                                    Two agents naming the same environment share a container \
                                    and its MCP servers — supported, but not the default.",
                    "type": "string"
                },
                "daemon_container": {
                    "title": "hived container",
                    "description": "Where hived runs. On macOS and Windows hived must be \
                                    containerised, so the spec directory is a volume rather \
                                    than a host path.",
                    "type": "string",
                    "default": "hived"
                }
            }
        }
    })
}

fn op_deploy(req: &Value) -> Result<Value> {
    let agent = req
        .get("agent")
        .and_then(Value::as_object)
        .context("deploy request has no \"agent\" object")?;
    let cfg = req
        .get("provider_config")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // I1: the identity is never empty. Refusing here beats deploying a
    // container that will fail to authenticate for a reason nobody can see.
    let nsec = non_empty(agent, "private_key_nsec")
        .context("deploy refused: the agent payload carries no private_key_nsec")?;
    let relay_url = non_empty(agent, "relay_url")
        .context("deploy refused: the agent payload carries no relay_url")?;

    let raw_name = agent
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = sanitize_name(raw_name)
        .with_context(|| format!("deploy refused: cannot derive a unit name from {raw_name:?}"))?;

    let harness = cfg
        .get("harness")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("claude")
        .to_string();
    let env_name = match cfg.get("hive_env").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => sanitize_name(s)?,
        _ => name.clone(),
    };
    let daemon = cfg
        .get("daemon_container")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("hived")
        .to_string();

    // 1. The environment. Validated before it lands, so hived is never asked to
    //    reconcile something it can only hold and log about.
    let spec_toml = render_spec(&name, &harness);
    let spec = hive_spec::AgentSpec::from_toml(&spec_toml)
        .context("the spec this provider generated does not parse")?;
    let report = spec.validate();
    if !report.errors.is_empty() {
        let errs: Vec<String> = report.errors.iter().map(|e| e.to_string()).collect();
        bail!(
            "the spec this provider generated is not valid: {}",
            errs.join("; ")
        );
    }
    install_spec(&env_name, &spec_toml, &daemon)?;

    // 2. The identity, under supervision. Same name both sides, so a repeated
    //    deploy replaces rather than duplicates.
    let description = render_description(agent, &env_name, &nsec, &relay_url)?;
    buzz_host_install(&name, &description)?;

    Ok(json!({"ok": true, "agent_id": name}))
}

fn non_empty(o: &Map<String, Value>, key: &str) -> Result<String> {
    match o.get(key).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => bail!("missing or empty {key:?}"),
    }
}

/// A name that is safe as both a filename and a container name.
///
/// The same rule `hive spec-put` enforces, applied here so a rejection names
/// the provider rather than surfacing as a traversal attempt one layer down.
fn sanitize_name(raw: &str) -> Result<String> {
    let out: String = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        bail!("name is empty after sanitising");
    }
    Ok(out)
}

fn render_spec(name: &str, harness: &str) -> String {
    format!(
        "# Created by buzz-backend-hive for Buzz agent {name:?}.\n\
         # An environment: a container to run a harness in. The identity lives\n\
         # with the supervisor outside it, which is why there is no [identity]\n\
         # block — see buzz-host.\n\
         #\n\
         # Add MCP servers with `hive mcp add <n> --url <url> --agent {name}`.\n\
         \n\
         [harness]\n\
         id = \"{harness}\"\n\
         \n\
         [agent]\n\
         mode = \"environment\"\n"
    )
}

/// Write the spec where hived will see it.
///
/// Prefers `hive spec-put`, which is the only path that does not assume the
/// spec directory is on the caller's filesystem — on macOS hived must run in a
/// container, so `/etc/hive/agents` is a volume and a direct write fails with
/// a permission error on a directory the host does not have. Falls back to
/// `docker exec` into the daemon so a machine without the hive CLI installed
/// still deploys.
fn install_spec(env_name: &str, spec_toml: &str, daemon: &str) -> Result<()> {
    if let Ok(()) = pipe_into("hive", &["spec-put", env_name], spec_toml) {
        return Ok(());
    }
    // Write-then-rename inside the daemon: hived watches this directory and a
    // partially written file is a spec it will try to parse.
    let target = format!("/etc/hive/agents/{env_name}.toml");
    let tmp = format!("{target}.tmp");
    let script = format!("cat > {tmp} && mv {tmp} {target}");
    pipe_into(
        "docker",
        &["exec", "-i", daemon, "sh", "-c", &script],
        spec_toml,
    )
    .with_context(|| format!("installing the spec for {env_name:?} via {daemon}"))
}

/// Build the supervisor's agent description.
///
/// The identity variables are written from the **top-level payload fields**,
/// and `env_vars` is stripped of them first. Both directions matter: the
/// desktop removes them from `env_vars` before it sends the payload, so reading
/// them there yields an identityless agent; and a user-supplied key that
/// reconstructed one would silently displace the identity the desktop resolved.
fn render_description(
    agent: &Map<String, Value>,
    env_name: &str,
    nsec: &str,
    relay_url: &str,
) -> Result<String> {
    let mut env = Map::new();

    // User env first, so the authoritative values below cannot be displaced.
    if let Some(user) = agent.get("env_vars").and_then(Value::as_object) {
        for (k, v) in user {
            if !is_posix_env_key(k) {
                // Refuse rather than skip: a key like `BUZZ_AUTH_TAG=x` is not a
                // typo, and silently dropping it hides the attempt.
                bail!("env_vars key {k:?} is not a POSIX-shaped environment variable name");
            }
            if RESERVED_ENV.contains(&k.as_str()) {
                continue;
            }
            if let Some(s) = v.as_str() {
                env.insert(k.clone(), json!(s));
            }
        }
    }

    env.insert("BUZZ_PRIVATE_KEY".into(), json!(nsec));
    env.insert("BUZZ_RELAY_URL".into(), json!(relay_url));
    if let Some(tag) = agent
        .get("auth_tag")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        env.insert("BUZZ_AUTH_TAG".into(), json!(tag));
    }
    env.insert("HIVE_ENV".into(), json!(env_name));

    // The chain is buzz-host -> buzz-acp -> harness, and for a hive agent the
    // harness is `hive-acp`, which docker-execs into the environment installed
    // above. So this is fixed, not taken from the payload.
    //
    // The payload's own `agent_command` names the ACP agent to run *inside* the
    // container (claude, codex, …). That belongs in the hive spec's [harness]
    // block — which `provider_config.harness` already set — and writing it here
    // instead would replace hive-acp and bypass the container entirely.
    env.insert("BUZZ_ACP_AGENT_COMMAND".into(), json!("hive-acp"));

    for (src, dst) in [
        ("model", "BUZZ_ACP_MODEL"),
        ("respond_to", "BUZZ_ACP_RESPOND_TO"),
    ] {
        if let Some(s) = agent
            .get(src)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            env.insert(dst.into(), json!(s));
        }
    }
    if let Some(n) = agent
        .get("parallelism")
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
    {
        env.insert("BUZZ_ACP_AGENTS".into(), json!(n.to_string()));
    }

    Ok(serde_json::to_string(&json!({
        "program": resolve_buzz_acp()?,
        "args": [],
        "env": Value::Object(env),
    }))?)
}

/// Absolute path to `buzz-acp`, because the supervisor requires a real file.
///
/// `buzz-host install` rejects a bare command name with "is not a file on this
/// machine", and it is right to: a unit that resolved its program through PATH
/// would run whatever a later PATH edit put there, under an agent's identity.
/// Found by deploying for real — the unit tests all passed against a bare name.
fn resolve_buzz_acp() -> Result<String> {
    if let Some(p) = std::env::var_os("BUZZ_ACP_PATH") {
        let p = p.to_string_lossy().into_owned();
        if std::path::Path::new(&p).is_file() {
            return Ok(p);
        }
        bail!("BUZZ_ACP_PATH is set to {p:?}, which is not a file");
    }

    let mut candidates = vec!["/Applications/Buzz.app/Contents/MacOS/buzz-acp".to_string()];
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy();
        candidates.push(format!("{home}/.local/bin/buzz-acp"));
        candidates.push(format!(
            "{home}/Applications/Buzz.app/Contents/MacOS/buzz-acp"
        ));
    }
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        if !dir.is_empty() {
            candidates.push(format!("{dir}/buzz-acp"));
        }
    }
    for c in &candidates {
        if std::path::Path::new(c).is_file() {
            return Ok(c.clone());
        }
    }
    bail!(
        "cannot find buzz-acp. Looked in Buzz.app, ~/.local/bin and every PATH entry. \
         Set BUZZ_ACP_PATH to its location."
    )
}

/// `[A-Za-z_][A-Za-z0-9_]*` — the same shape the desktop validates before merge.
fn is_posix_env_key(k: &str) -> bool {
    let mut chars = k.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Hand the description to the supervisor **on stdin**.
///
/// Never as an argument. The description carries the agent's nsec, and argv is
/// readable by any process of the same uid — that was a real leak in this repo
/// (`hive-acp` built `-e NAME=value` pairs) and the fix is not worth undoing
/// here.
fn buzz_host_install(name: &str, description: &str) -> Result<()> {
    pipe_into("buzz-host", &["install", name], description)
        .with_context(|| format!("installing supervisor unit {name:?}"))
}

fn pipe_into(program: &str, args: &[&str], stdin_data: &str) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program}"))?;
    child
        .stdin
        .as_mut()
        .context("child stdin was not piped")?
        .write_all(stdin_data.as_bytes())
        .with_context(|| format!("writing to {program} stdin"))?;
    let out = child
        .wait_with_output()
        .with_context(|| format!("waiting for {program}"))?;
    if !out.status.success() {
        // stderr is capped by the desktop and scrubbed of secrets before
        // storage, but keep it short regardless.
        let err = String::from_utf8_lossy(&out.stderr);
        let err: String = err.trim().chars().take(500).collect();
        bail!("{program} failed: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_with(env_vars: Value) -> Map<String, Value> {
        json!({
            "name": "Probe Agent",
            "relay_url": "wss://relay.example",
            "private_key_nsec": "nsec1test",
            "auth_tag": "tag-1",
            "env_vars": env_vars,
        })
        .as_object()
        .unwrap()
        .clone()
    }

    /// The whole point of the reserved-key rule: a user-supplied identity
    /// variable must not become the agent's identity.
    #[test]
    fn user_env_cannot_displace_the_identity() {
        let agent = agent_with(json!({
            "BUZZ_PRIVATE_KEY": "nsec1attacker",
            "BUZZ_RELAY_URL": "wss://attacker.example",
            "HARMLESS": "kept",
        }));
        let desc =
            render_description(&agent, "env1", "nsec1real", "wss://real.example").expect("render");
        let v: Value = serde_json::from_str(&desc).unwrap();
        let env = v.get("env").unwrap();

        assert_eq!(env.get("BUZZ_PRIVATE_KEY").unwrap(), "nsec1real");
        assert_eq!(env.get("BUZZ_RELAY_URL").unwrap(), "wss://real.example");
        assert_eq!(env.get("HARMLESS").unwrap(), "kept");
    }

    /// A smuggled `KEY=value` name is refused, not silently dropped — dropping
    /// it hides that someone tried.
    #[test]
    fn non_posix_env_key_is_refused() {
        let agent = agent_with(json!({"BUZZ_AUTH_TAG=x": "smuggled"}));
        let err = render_description(&agent, "env1", "nsec1real", "wss://r.example")
            .expect_err("should refuse");
        assert!(format!("{err:#}").contains("POSIX"), "got: {err:#}");
    }

    #[test]
    fn identity_is_written_from_the_payload_even_with_no_user_env() {
        let agent = agent_with(json!({}));
        let desc =
            render_description(&agent, "env1", "nsec1real", "wss://real.example").expect("render");
        let v: Value = serde_json::from_str(&desc).unwrap();
        let env = v.get("env").unwrap();
        assert_eq!(env.get("BUZZ_PRIVATE_KEY").unwrap(), "nsec1real");
        assert_eq!(env.get("BUZZ_AUTH_TAG").unwrap(), "tag-1");
        assert_eq!(env.get("HIVE_ENV").unwrap(), "env1");
    }

    /// The supervised program is `buzz-acp` and the ACP agent under it is
    /// `hive-acp` — that ordering is the whole chain, and a deploy that put
    /// `hive-acp` in the `program` slot was rejected by the supervisor with
    /// "is not a file on this machine". Pinned because every unit test passed
    /// while that was wrong; only a real deploy caught it.
    #[test]
    fn the_supervised_program_is_buzz_acp_with_hive_acp_as_the_harness() {
        let agent = agent_with(json!({}));
        let desc =
            render_description(&agent, "env1", "nsec1real", "wss://real.example").expect("render");
        let v: Value = serde_json::from_str(&desc).unwrap();

        let program = v.get("program").unwrap().as_str().unwrap();
        assert!(
            program.ends_with("/buzz-acp"),
            "program must be an absolute path to buzz-acp, got {program:?}"
        );
        assert!(
            std::path::Path::new(program).is_absolute(),
            "the supervisor rejects a bare command name, got {program:?}"
        );
        assert_eq!(
            v.get("env").unwrap().get("BUZZ_ACP_AGENT_COMMAND").unwrap(),
            "hive-acp"
        );
    }

    /// The payload's `agent_command` names the harness *inside* the container.
    /// Writing it into the unit would replace hive-acp and bypass the container.
    #[test]
    fn payload_agent_command_does_not_displace_hive_acp() {
        let mut agent = agent_with(json!({}));
        agent.insert("agent_command".into(), json!("claude-agent-acp"));
        let desc =
            render_description(&agent, "env1", "nsec1real", "wss://real.example").expect("render");
        let v: Value = serde_json::from_str(&desc).unwrap();
        assert_eq!(
            v.get("env").unwrap().get("BUZZ_ACP_AGENT_COMMAND").unwrap(),
            "hive-acp"
        );
    }

    /// The nsec must reach the supervisor on stdin, so it must be in the
    /// description body and nowhere else this provider constructs.
    #[test]
    fn the_description_carries_the_secret_and_the_argv_does_not() {
        let agent = agent_with(json!({}));
        let desc =
            render_description(&agent, "env1", "nsec1real", "wss://r.example").expect("render");
        assert!(desc.contains("nsec1real"));
        // `buzz_host_install` passes only these two as arguments.
        let argv = ["install", "probe-agent"];
        assert!(!argv.iter().any(|a| a.contains("nsec")));
    }

    #[test]
    fn names_become_safe_filenames() {
        assert_eq!(sanitize_name("Probe Agent").unwrap(), "probe-agent");
        assert_eq!(sanitize_name("../../etc/passwd").unwrap(), "etc-passwd");
        assert_eq!(sanitize_name("UPPER_case-9").unwrap(), "upper_case-9");
        assert!(sanitize_name("   ").is_err());
        assert!(sanitize_name("---").is_err());
    }

    #[test]
    fn info_declares_a_protocol_version() {
        let info = op_info();
        assert_eq!(info.get("protocol_version").unwrap(), PROTOCOL_VERSION);
        assert_eq!(info.get("ok").unwrap(), true);
        assert!(info.get("config_schema").is_some());
    }

    #[test]
    fn generated_spec_is_valid_to_hive() {
        let toml = render_spec("probe-agent", "claude");
        let spec = hive_spec::AgentSpec::from_toml(&toml).expect("parses");
        assert!(
            spec.validate().errors.is_empty(),
            "{:?}",
            spec.validate().errors
        );
    }
}
