//! `buzz-backend-hive` — the Buzz desktop provider shim.
//!
//! Buzz's desktop discovers `buzz-backend-*` executables and speaks a tiny
//! JSON-on-stdin protocol to them: `{"op":"info"}` and `{"op":"deploy"}`. This
//! shim runs on the DESKTOP, translates a deploy request into a hive spec, and
//! ships it to the hive host over SSH. `hived` on the far side notices the new
//! spec and reconciles it.
//!
//! It writes a file and stores a credential; it does not create containers. That
//! keeps the desktop's role declarative and means an agent deployed this way is
//! identical to one deployed by editing a spec by hand.
//!
//! # Two constraints inherited from the desktop
//!
//! **Config keys are filtered.** `validate_provider_config` rejects any key
//! containing `secret`, `password`, `token`, `key` or `credential`. A field named
//! `claude_token_path` is silently dropped; `claude_auth_file` survives. This is
//! why the schema below reads slightly awkwardly.
//!
//! **One agent, one relay, one container.** `buzz-acp` takes a scalar
//! `BUZZ_RELAY_URL`, so the same agent identity on two relays is two processes.
//! The desktop models this as `{pubkey, relay_url}`. Without a relay suffix in
//! the name, deploying an agent to a second relay REPLACES its first container
//! instead of running alongside it, because the redeploy path reads them as the
//! same agent. The primary relay keeps the bare name so the common single-relay
//! case stays readable.

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    // Every failure path must still emit valid JSON on stdout: the desktop
    // parses whatever it gets, and a bare panic message surfaces as an
    // unexplained provider error.
    let response = match run() {
        Ok(v) => v,
        Err(e) => json!({ "error": e.to_string() }),
    };
    println!("{response}");
}

fn run() -> Result<Value> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let req: Value = if line.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&line).context("parsing request")?
    };

    match req.get("op").and_then(Value::as_str) {
        Some("info") => Ok(info()),
        Some("deploy") => deploy(&req),
        other => bail!("unknown op {:?}", other.unwrap_or("<missing>")),
    }
}

fn info() -> Value {
    json!({
        "id": "hive",
        "name": "hive (isolated container per agent)",
        "version": VERSION,
        // REQUIRED. The desktop's WhereToRunSection probes this provider, reads
        // config_schema, and renders one form field per property, pre-filled
        // from `default`. Without it the UI shows no fields at all and every
        // value silently falls back to this program's defaults.
        //
        // Types matter: coerceConfigValues() converts "integer"/"number" with
        // Number() and "boolean" with value === "true" before sending. Declaring
        // the wrong type delivers a string where a bool or int is expected.
        "config_schema": {
            "type": "object",
            "required": ["ssh_host"],
            "properties": {
                "ssh_host": {
                    "type": "string",
                    "title": "hive host",
                    "description": "user@host running hived. Uses your existing SSH key; no daemon is exposed to the network.",
                    "default": "root@hive-host"
                },
                "spec_dir": {
                    "type": "string",
                    "title": "Spec directory",
                    "description": "Where hived watches for agent specs on that host.",
                    "default": "/etc/hive/agents"
                },
                "harness": {
                    "type": "string",
                    "title": "Harness",
                    "description": "claude, codex, goose, grok, opencode, kimi, amp, omp or cursor. Run `hive harnesses` on the host for the current list.",
                    "default": "claude"
                },
                "memory": {
                    "type": "string",
                    "title": "Memory limit",
                    "description": "A CEILING, not a reservation — an idle agent uses ~60MB. Roomier than one harness needs, because an agent may shell out to a second one.",
                    "default": "3g"
                },
                "cpus": {
                    "type": "number",
                    "title": "CPU limit",
                    "default": 2.0
                },
                "observer": {
                    "type": "boolean",
                    "title": "Publish observer frames",
                    "description": "ON by default. The harness defaults it off, which makes a remote agent work perfectly while appearing to do nothing — a local agent is observed over stdio, and a container has no stdio to observe.",
                    "default": true
                },
                "mcp_url": {
                    "type": "string",
                    "title": "MCP server URL",
                    "description": "Optional HTTP MCP server. Its credential is served per-connection from the broker and never enters the container. Leave empty to skip.",
                    "default": ""
                },
                // NOT `mcp_token_key` or similar: any config key containing
                // secret/password/token/key/credential is dropped by the
                // desktop before it reaches this program.
                "mcp_auth_ref": {
                    "type": "string",
                    "title": "MCP credential name",
                    "description": "Name of the stored credential in the hive broker, e.g. mcp/parachute. Store it with: hive secret put mcp/parachute",
                    "default": ""
                }
            }
        }
    })
}

fn deploy(req: &Value) -> Result<Value> {
    let agent = req.get("agent").cloned().unwrap_or_else(|| json!({}));
    let cfg = req.get("provider_config").cloned().unwrap_or_else(|| json!({}));

    let get = |k: &str| cfg.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let ssh_host = {
        let h = get("ssh_host");
        if h.is_empty() { "root@hive-host".to_string() } else { h }
    };
    let spec_dir = {
        let d = get("spec_dir");
        if d.is_empty() { "/etc/hive/agents".to_string() } else { d }
    };

    let display_name = agent.get("name").and_then(Value::as_str).unwrap_or("agent");
    let nsec = agent
        .get("private_key_nsec")
        .and_then(Value::as_str)
        .context("agent.private_key_nsec is required")?;
    let relay_url = agent
        .get("relay_url")
        .and_then(Value::as_str)
        .context("agent.relay_url is required")?;
    let pubkey = agent.get("pubkey").and_then(Value::as_str).unwrap_or("");
    let owner = agent
        .get("owner_pubkey")
        .and_then(Value::as_str)
        .unwrap_or("");

    // Passed in rather than read inside agent_name: a function whose result
    // depends on ambient environment is one you cannot test without mutating
    // the process, and in Rust 2024 that is an unsafe operation.
    let primary = std::env::var("HIVE_PRIMARY_RELAY").ok();
    let name = agent_name(display_name, relay_url, primary.as_deref());
    // The IDENTITY key is keyed on the base slug, without the relay suffix, so
    // deploying the same agent to a second relay reuses one stored private key
    // instead of writing a second copy that goes stale on rotation.
    let identity_key = format!("nsec/{}", slugify(display_name));

    let mut warnings: Vec<String> = Vec::new();
    if owner.is_empty() && agent.get("auth_tag").is_none() {
        // Not fatal here — hived's validation will refuse it — but saying so at
        // deploy time is far more useful than a container that starts and
        // ignores everyone.
        warnings.push(
            "no owner_pubkey or auth_tag: the agent would start and respond to nobody".into(),
        );
    }

    let spec = build_spec(&agent, &cfg, pubkey, relay_url, owner, &identity_key);

    // The nsec goes to the broker over SSH stdin, never as an argument:
    // arguments land in shell history and in `ps` output for every user on the
    // box. It is not written into the spec, which is meant to be committable.
    ssh_stdin(&ssh_host, &["hive", "secret", "put", &identity_key], nsec)
        .context("storing the agent key in the hive broker")?;

    // `cat > file` rather than scp: one connection, no temp file on either side,
    // and it works when the remote has no scp.
    let target = format!("{spec_dir}/{name}.toml");
    ssh_stdin(&ssh_host, &["sh", "-c", &format!("mkdir -p {spec_dir} && cat > {target}")], &spec)
        .context("writing the agent spec")?;

    warnings.push(format!(
        "spec written to {ssh_host}:{target}. hived will reconcile it on its next pass; \
         run `hive status` on the host to watch."
    ));

    Ok(json!({ "agent_id": name, "warnings": warnings }))
}

/// Agent name, including a relay suffix for non-primary relays.
///
/// See the module docs: without this, an agent deployed to a second relay
/// replaces its first container rather than running alongside it.
fn agent_name(display_name: &str, relay_url: &str, primary_relay: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let slug = slugify(display_name);

    match primary_relay {
        Some(primary) if primary != relay_url => {
            let tag = hex::encode(&Sha256::digest(relay_url.as_bytes())[..4]);
            format!("{slug}-{tag}")
        }
        _ => slug,
    }
}

/// Agent name without the relay suffix. Also the identity key's basis, so the
/// two cannot drift apart.
fn slugify(display_name: &str) -> String {
    let slug: String = display_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .replace("--", "-");
    if slug.is_empty() { "agent".to_string() } else { slug }
}

fn build_spec(
    agent: &Value,
    cfg: &Value,
    pubkey: &str,
    relay_url: &str,
    owner: &str,
    identity_key: &str,
) -> String {
    let s = |k: &str| cfg.get(k).and_then(Value::as_str).unwrap_or("");
    let harness = if s("harness").is_empty() { "claude" } else { s("harness") };
    let memory = if s("memory").is_empty() { "3g" } else { s("memory") };
    let cpus = cfg.get("cpus").and_then(Value::as_f64).unwrap_or(2.0);
    let observer = cfg.get("observer").and_then(Value::as_bool).unwrap_or(true);

    let mut out = String::new();
    out.push_str("# Written by buzz-backend-hive. Safe to edit and to commit:\n");
    out.push_str("# it contains no secrets, only names of credentials the broker holds.\n\n");
    out.push_str("[identity]\n");
    out.push_str(&format!("pubkey = {}\n", toml_str(pubkey)));
    out.push_str(&format!("relay_url = {}\n", toml_str(relay_url)));
    // Named explicitly rather than left to default to nsec/<file-name>: the file
    // name carries a relay suffix for non-primary relays, and the identity does
    // not vary by relay.
    out.push_str(&format!("credential = {}\n", toml_str(identity_key)));
    if let Some(tag) = agent.get("auth_tag").and_then(Value::as_str) {
        out.push_str(&format!("auth_tag = {}\n", toml_str(tag)));
    } else if !owner.is_empty() {
        out.push_str(&format!("owner_pubkey = {}\n", toml_str(owner)));
    }

    out.push_str(&format!("\n[harness]\nid = {}\n", toml_str(harness)));

    out.push_str("\n[agent]\n");
    out.push_str(&format!("observer = {observer}\n"));
    if let Some(m) = agent.get("model").and_then(Value::as_str) {
        out.push_str(&format!("model = {}\n", toml_str(m)));
    }
    if let Some(p) = agent.get("system_prompt").and_then(Value::as_str) {
        out.push_str(&format!("system_prompt = {}\n", toml_str(p)));
    }

    out.push_str(&format!("\n[resources]\nmemory = {}\ncpus = {cpus}\npids = 512\n", toml_str(memory)));

    let url = s("mcp_url");
    if !url.is_empty() {
        out.push_str("\n[[mcp]]\nname = \"mcp\"\ntransport = \"http\"\n");
        out.push_str(&format!("url = {}\n", toml_str(url)));
        let auth = s("mcp_auth_ref");
        if !auth.is_empty() {
            out.push_str(&format!("credential = {}\n", toml_str(auth)));
        }
    }
    out
}

/// TOML-quote a string. Basic strings escape backslash and quote; a spec is
/// generated from user-supplied names, so this cannot be a bare format!().
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Run a command on the hive host, feeding `input` to its stdin.
fn ssh_stdin(host: &str, argv: &[&str], input: &str) -> Result<()> {
    let ssh = find_ssh()?;
    let mut child = Command::new(ssh)
        // Fail rather than hang on an unknown host: this runs under a GUI with
        // no terminal to answer a prompt on, so an interactive question is an
        // indefinite hang with no visible cause.
        .args(["-o", "BatchMode=yes", host])
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning ssh")?;
    child
        .stdin
        .take()
        .context("ssh stdin")?
        .write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("ssh {host}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Locate ssh without trusting PATH.
///
/// A GUI-launched process on macOS inherits a minimal launchd environment whose
/// PATH often lacks the directories a developer's shell has. The same command
/// then works perfectly in a terminal and not at all from the app.
fn find_ssh() -> Result<String> {
    for p in ["/usr/bin/ssh", "/usr/local/bin/ssh", "/opt/homebrew/bin/ssh"] {
        if std::path::Path::new(p).is_file() {
            return Ok(p.to_string());
        }
    }
    Ok("ssh".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_declares_a_config_schema_or_the_desktop_renders_nothing() {
        // Without config_schema the settings UI shows no fields at all and every
        // value silently falls back to this program's defaults.
        let i = info();
        assert!(i["config_schema"]["properties"].is_object());
        assert_eq!(i["id"], "hive");
    }

    #[test]
    fn no_config_key_contains_a_word_the_desktop_strips() {
        // validate_provider_config drops any key containing these substrings, so
        // a field named `mcp_token` would vanish between the UI and here — and
        // the symptom is a setting that will not stick.
        let i = info();
        let props = i["config_schema"]["properties"].as_object().unwrap();
        for k in props.keys() {
            for banned in ["secret", "password", "token", "key", "credential"] {
                assert!(
                    !k.contains(banned),
                    "config key '{k}' contains '{banned}' and will be dropped by the desktop"
                );
            }
        }
    }

    #[test]
    fn a_second_relay_gets_its_own_agent_name() {
        // buzz-acp takes a scalar relay URL, so the same identity on two relays
        // is two containers. Without the suffix the second deploy replaces the
        // first rather than running beside it.
        let primary = Some("wss://primary.example");
        let a = agent_name("Uni", "wss://primary.example", primary);
        let b = agent_name("Uni", "wss://other.example", primary);
        assert_eq!(a, "uni", "the primary relay keeps the bare name");
        assert_ne!(a, b, "a second relay must not collide with the first");
        assert!(b.starts_with("uni-"));
    }

    #[test]
    fn the_generated_spec_contains_no_secret() {
        // The spec is meant to be committable. The nsec goes to the broker over
        // stdin and must never reach the file.
        let agent = json!({
            "name": "Uni",
            "private_key_nsec": "nsec1verysecret",
            "relay_url": "wss://relay.example",
            "owner_pubkey": "b".repeat(64),
        });
        let spec = build_spec(&agent, &json!({}), &"a".repeat(64), "wss://relay.example", &"b".repeat(64), "nsec/uni");
        assert!(!spec.contains("nsec1verysecret"), "the spec leaked the private key");
        assert!(spec.contains("owner_pubkey"));
    }

    #[test]
    fn the_generated_spec_parses_and_validates() {
        // Emitting TOML by hand is a good way to produce something that reads
        // fine and does not parse. Round-trip it through the real parser.
        let agent = json!({
            "name": "Uni",
            "private_key_nsec": "nsec1x",
            "relay_url": "wss://relay.example",
            "owner_pubkey": "b".repeat(64),
        });
        let cfg = json!({ "harness": "claude", "mcp_url": "https://v.example/mcp", "mcp_auth_ref": "mcp/parachute" });
        let spec = build_spec(&agent, &cfg, &"a".repeat(64), "wss://relay.example", &"b".repeat(64), "nsec/uni");
        let parsed = hive_spec::AgentSpec::from_toml(&spec)
            .unwrap_or_else(|e| panic!("generated spec does not parse: {e}\n---\n{spec}"));
        let report = parsed.validate();
        assert!(report.errors.is_empty(), "generated spec is invalid: {:?}\n{spec}", report.errors);
        assert_eq!(parsed.mcp.len(), 1);
    }

    #[test]
    fn names_with_quotes_do_not_break_the_generated_toml() {
        // Display names come from the desktop and are arbitrary user text.
        let agent = json!({
            "name": "weird",
            "private_key_nsec": "x",
            "relay_url": "wss://relay.example",
            "system_prompt": "say \"hello\"\nand \\ that",
            "owner_pubkey": "b".repeat(64),
        });
        let spec = build_spec(&agent, &json!({}), &"a".repeat(64), "wss://relay.example", &"b".repeat(64), "nsec/uni");
        let parsed = hive_spec::AgentSpec::from_toml(&spec)
            .unwrap_or_else(|e| panic!("quoting broke the spec: {e}\n---\n{spec}"));
        assert!(parsed.agent.system_prompt.unwrap().contains('"'));
    }
}
