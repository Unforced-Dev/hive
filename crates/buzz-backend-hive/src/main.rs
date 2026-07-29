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
        // Neither transport field is REQUIRED: exactly one of them is, and the
        // desktop's schema cannot express that. Requiring ssh_host would make
        // the local case impossible to fill in; requiring neither means deploy()
        // has to explain the choice, which it does.
        "config_schema": {
            "type": "object",
            "properties": {
                "ssh_host": {
                    "type": "string",
                    "title": "hive host (remote)",
                    "description": "user@host running hived. Uses your existing SSH key; no daemon is exposed to the network. Leave blank if hived runs on THIS machine.",
                    "default": ""
                },
                "hived_container": {
                    "type": "string",
                    "title": "hived container (local)",
                    "description": "Name of a local hived container to deploy into, instead of connecting over SSH. Required on macOS and Windows, where hived must run inside the Docker VM. Ignored when 'hive host' is set.",
                    "default": ""
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
    // ssh_host wins when both are set, because a filled-in remote host is an
    // explicit statement about WHERE the agent should run, while
    // hived_container may be left over from a local experiment. Silently
    // deploying to the wrong machine is the expensive mistake here.
    let target = Target::choose(&get("ssh_host"), &get("hived_container"))?;
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
    // Buzz's deploy payload does not carry the agent's pubkey — only its nsec —
    // so derive it. Reading a `pubkey` field first keeps a hand-written or
    // future payload that does supply one authoritative.
    //
    // Not optional: hived uses identity.pubkey to detect two specs deploying one
    // identity to the same relay, which would answer every mention twice and
    // charge the owner twice. Left empty, every provider-deployed agent collides
    // with every other and all of them are held.
    let derived;
    let pubkey = match agent.get("pubkey").and_then(Value::as_str) {
        Some(p) if !p.is_empty() => p,
        _ => {
            derived = pubkey_from_nsec(nsec)
                .context("deriving the agent's pubkey from its key")?;
            &derived
        }
    };
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

    // BYOH: the desktop resolves the harness — builtin, preset or user-defined
    // JSON — down to a concrete command and sends it as agent_command/agent_args.
    // Honour that rather than the provider_config field, or a harness picked in
    // the UI is silently overridden by a setting the user last touched elsewhere.
    let cmd = agent.get("agent_command").and_then(Value::as_str).unwrap_or("");
    let cmd_args: Vec<String> = agent
        .get("agent_args")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let harness = resolve_harness(cmd, &cmd_args, &get("harness"), &mut warnings);
    let spec = build_spec(&agent, &cfg, pubkey, relay_url, owner, &identity_key, &harness);

    // The nsec goes over stdin, never as an argument: arguments land in shell
    // history and in `ps` output for every user on the box — and for the local
    // transport, in `docker inspect` too. It is not written into the spec,
    // which is meant to be committable.
    target
        .stdin_to(&["hive", "secret", "put", &identity_key], nsec)
        .context("storing the agent key in the hive broker")?;

    // Through the CLI, not `sh -c 'cat > file'`.
    //
    // Writing the file directly assumes the spec directory is a path on the
    // machine ssh lands on. Where hived runs in a container — which on macOS and
    // Windows it must, because the broker's sockets cannot cross the Docker VM
    // boundary — /etc/hive/agents is a VOLUME, and the shell redirect fails with
    // "mkdir: /etc/hive: Permission denied" against a directory the host does
    // not have. `hive spec put` resolves the directory wherever the daemon
    // actually lives, and validates before installing, so a spec that would only
    // be held never lands.
    let spec_path = format!("{spec_dir}/{name}.toml");
    target
        .stdin_to(&["hive", "--spec-dir", &spec_dir, "spec-put", &name], &spec)
        .context("installing the agent spec")?;

    warnings.push(format!(
        "spec written to {}:{spec_path}. hived will reconcile it on its next pass; \
         run `hive status` there to watch.",
        target.describe()
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

/// How the spec should name the harness.
enum HarnessChoice {
    /// Resolved to a catalog entry, which knows its model syntax and credentials.
    Catalog(&'static str),
    /// A BYOH custom harness the catalog does not know. Expressed as an explicit
    /// command, which requires an explicit image containing it.
    Custom { command: String, args: Vec<String> },
}

/// Map the desktop's resolved invocation onto the catalog.
fn resolve_harness(
    command: &str,
    args: &[String],
    config_fallback: &str,
    warnings: &mut Vec<String>,
) -> HarnessChoice {
    if command.is_empty() {
        // Older records, or a create path that never pinned a command.
        let id = if config_fallback.is_empty() { "claude" } else { config_fallback };
        return HarnessChoice::Catalog(
            hive_core::harness::lookup(id).map(|h| h.id).unwrap_or("claude"),
        );
    }
    if let Some(h) = hive_core::harness::lookup_by_command(command, args) {
        return HarnessChoice::Catalog(h.id);
    }
    // A custom harness from the desktop's custom_harnesses/. hive can express it,
    // but only the image can say whether the binary is actually there — so warn
    // rather than fail here, and let the container entrypoint report it clearly.
    warnings.push(format!(
        "harness '{command}' is not in hive's catalog. The spec will name it explicitly, \
         but the agent image must contain that binary — check `hive harnesses` on the host."
    ));
    HarnessChoice::Custom { command: command.to_string(), args: args.to_vec() }
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
    harness: &HarnessChoice,
) -> String {
    let s = |k: &str| cfg.get(k).and_then(Value::as_str).unwrap_or("");
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

    out.push_str("\n[harness]\n");
    match harness {
        HarnessChoice::Catalog(id) => out.push_str(&format!("id = {}\n", toml_str(id))),
        HarnessChoice::Custom { command, args } => {
            out.push_str(&format!("command = {}\n", toml_str(command)));
            if !args.is_empty() {
                let rendered: Vec<String> = args.iter().map(|a| toml_str(a)).collect();
                out.push_str(&format!("args = [{}]\n", rendered.join(", ")));
            }
            // An explicit command requires an explicit image; validation enforces it.
            out.push_str("image = \"hive-agent:latest\"\n");
        }
    }

    out.push_str("\n[agent]\n");
    out.push_str(&format!("observer = {observer}\n"));
    if let Some(m) = agent.get("model").and_then(Value::as_str) {
        out.push_str(&format!("model = {}\n", toml_str(m)));
    }
    if let Some(p) = agent.get("system_prompt").and_then(Value::as_str) {
        out.push_str(&format!("system_prompt = {}\n", toml_str(p)));
    }
    // The desktop already sends these; dropping them silently reverts the agent
    // to harness defaults that do not match what the UI shows.
    if let Some(r) = agent.get("respond_to").and_then(Value::as_str) {
        out.push_str(&format!("respond_to = {}\n", toml_str(r)));
    }
    if let Some(n) = agent.get("parallelism").and_then(Value::as_u64) {
        out.push_str(&format!("parallelism = {n}\n"));
    }
    if let Some(t) = agent.get("idle_timeout_seconds").and_then(Value::as_u64).filter(|t| *t > 0) {
        out.push_str(&format!("idle_timeout = {t}\n"));
    }
    if let Some(t) = agent.get("max_turn_duration_seconds").and_then(Value::as_u64).filter(|t| *t > 0) {
        out.push_str(&format!("max_turn_duration = {t}\n"));
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

/// Where `hived` is, and therefore how to hand it a spec and a secret.
///
/// The shim only ever runs two commands — store a credential, write a file —
/// so the transport is the entire difference between a remote and a local hive.
// Debug so tests can use `unwrap_err()`. Both variants hold a destination, not
// a credential, so there is nothing here that must not be printed.
#[derive(Debug)]
enum Target {
    /// `hived` on another machine, reached with the user's existing SSH key.
    Ssh(String),
    /// `hived` in a container on THIS machine.
    ///
    /// This is not merely a convenience for single-box setups: on macOS and
    /// Windows it is the only arrangement that works. `hived` bind-mounts a
    /// per-agent unix socket into each agent container, and a socket created
    /// on the host side of a Docker VM cannot be connected to from inside it
    /// (`connect()` returns ENOTSUP). So `hived` must live in the VM, and the
    /// shim reaches it through `docker exec` rather than over a network.
    Container(String),
}

impl Target {
    fn choose(ssh_host: &str, container: &str) -> Result<Self> {
        match (ssh_host.trim(), container.trim()) {
            ("", "") => bail!(
                "set either 'hive host' (for a remote hived over SSH) or \
                 'hived container' (for one running locally in Docker)"
            ),
            (h, _) if !h.is_empty() => Ok(Target::Ssh(h.to_string())),
            (_, c) => Ok(Target::Container(c.to_string())),
        }
    }

    /// For messages shown to the user. Not a shell-safe value.
    fn describe(&self) -> String {
        match self {
            Target::Ssh(h) => h.clone(),
            Target::Container(c) => format!("container {c}"),
        }
    }

    /// Run a command where `hived` lives, feeding `input` to its stdin.
    fn stdin_to(&self, argv: &[&str], input: &str) -> Result<()> {
        let (bin, lead): (String, Vec<String>) = match self {
            Target::Ssh(host) => (
                find_ssh()?,
                // Fail rather than hang on an unknown host: this runs under a
                // GUI with no terminal to answer a prompt on, so an
                // interactive question is an indefinite hang with no visible
                // cause.
                vec!["-o".into(), "BatchMode=yes".into(), host.clone()],
            ),
            Target::Container(name) => (
                find_docker()?,
                // -i, not -it: there is no tty here, and `docker exec -t`
                // without one fails outright.
                vec!["exec".into(), "-i".into(), name.clone()],
            ),
        };

        let mut child = Command::new(&bin)
            .args(&lead)
            .args(argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning {bin}"))?;
        child
            .stdin
            .take()
            .context("child stdin")?
            .write_all(input.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!("{}: {}", self.describe(), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
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

/// Locate the Docker CLI without trusting PATH, for the same reason as
/// [`find_ssh`] — and more acutely, because Docker is never in the default
/// launchd PATH on macOS. The candidate list mirrors
/// `hive_core::docker::DockerBackend::discover`.
fn find_docker() -> Result<String> {
    for p in [
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/usr/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
    ] {
        if std::path::Path::new(p).is_file() {
            return Ok(p.to_string());
        }
    }
    Ok("docker".to_string())
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
    fn an_unconfigured_transport_is_an_error_not_a_guessed_host() {
        // This previously defaulted to `root@hive-host`, so a deploy with no
        // configuration attempted SSH to a host that does not exist and failed
        // with a name-resolution error — which reads as a network problem
        // rather than as "you have not said where hive is".
        let e = Target::choose("", "").unwrap_err().to_string();
        assert!(e.contains("hive host"), "the error must name the fields to set: {e}");
        assert!(e.contains("hived container"), "the error must offer the local option: {e}");
    }

    #[test]
    fn a_local_deploy_needs_no_ssh_host() {
        // The whole point of local mode: on macOS there is no host to ssh to,
        // because hived runs in the Docker VM alongside the agents.
        match Target::choose("", "hived").unwrap() {
            Target::Container(c) => assert_eq!(c, "hived"),
            Target::Ssh(h) => panic!("chose ssh to {h} with no host configured"),
        }
    }

    #[test]
    fn a_configured_ssh_host_is_not_overridden_by_a_leftover_container_name() {
        // Both fields are free text in the desktop UI and neither is required,
        // so a container name left over from a local experiment can easily sit
        // beside a real remote host. Preferring the container would deploy the
        // agent to the wrong machine and report success.
        match Target::choose("root@box", "hived").unwrap() {
            Target::Ssh(h) => assert_eq!(h, "root@box"),
            Target::Container(c) => panic!("deployed to local container {c} despite a remote host"),
        }
    }

    #[test]
    fn whitespace_only_config_counts_as_unset() {
        // A field the user cleared can come back as " " rather than "", and a
        // space-only ssh host would otherwise be spawned as a real destination.
        assert!(Target::choose("  ", "  ").is_err());
        match Target::choose("  ", "hived").unwrap() {
            Target::Container(c) => assert_eq!(c, "hived"),
            Target::Ssh(h) => panic!("treated whitespace as a host: '{h}'"),
        }
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
        let spec = build_spec(&agent, &json!({}), &"a".repeat(64), "wss://relay.example", &"b".repeat(64), "nsec/uni", &HarnessChoice::Catalog("claude"));
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
        let spec = build_spec(&agent, &cfg, &"a".repeat(64), "wss://relay.example", &"b".repeat(64), "nsec/uni", &HarnessChoice::Catalog("claude"));
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
        let spec = build_spec(&agent, &json!({}), &"a".repeat(64), "wss://relay.example", &"b".repeat(64), "nsec/uni", &HarnessChoice::Catalog("claude"));
        let parsed = hive_spec::AgentSpec::from_toml(&spec)
            .unwrap_or_else(|e| panic!("quoting broke the spec: {e}\n---\n{spec}"));
        assert!(parsed.agent.system_prompt.unwrap().contains('"'));
    }
}

// ── nsec → pubkey ───────────────────────────────────────────────────────────
//
// Buzz's deploy payload carries `private_key_nsec` but NOT the agent's pubkey,
// so the provider has to derive it. That is not cosmetic: hived uses
// `identity.pubkey` to detect two specs deploying the same identity to the same
// relay — which would answer every mention twice and charge the owner twice —
// and an empty one makes every provider-deployed agent collide with every other.
//
// bech32 is decoded here rather than pulled in as a dependency: it is thirty
// lines, and the checksum is the part that matters (a mistyped nsec must fail
// loudly rather than derive a plausible wrong key).

const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

/// Decode a bech32 string, returning (hrp, 5-bit data without the checksum).
fn bech32_decode(s: &str) -> Result<(String, Vec<u8>)> {
    let s = s.trim();
    if s.len() < 8 || s.len() > 200 {
        bail!("not a bech32 string: implausible length");
    }
    // Mixed case is invalid per BIP-173 — the checksum is case-sensitive.
    if s.chars().any(|c| c.is_ascii_uppercase()) && s.chars().any(|c| c.is_ascii_lowercase()) {
        bail!("not a bech32 string: mixed case");
    }
    let lower = s.to_ascii_lowercase();
    let sep = lower.rfind('1').context("not a bech32 string: no separator")?;
    let (hrp, rest) = lower.split_at(sep);
    if hrp.is_empty() {
        bail!("not a bech32 string: empty prefix");
    }
    let mut data = Vec::with_capacity(rest.len() - 1);
    for c in rest[1..].chars() {
        let idx = BECH32_CHARSET
            .find(c)
            .with_context(|| format!("not a bech32 string: bad character {c:?}"))?;
        data.push(idx as u8);
    }
    if data.len() < 6 {
        bail!("not a bech32 string: truncated checksum");
    }
    let mut check_input = bech32_hrp_expand(hrp);
    check_input.extend_from_slice(&data);
    if bech32_polymod(&check_input) != 1 {
        bail!("bech32 checksum failed — the key is mistyped or truncated");
    }
    data.truncate(data.len() - 6);
    Ok((hrp.to_string(), data))
}

/// Regroup 5-bit values into 8-bit bytes, rejecting a malformed tail.
fn from_base32(data: &[u8]) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for v in data {
        acc = (acc << 5) | u32::from(*v);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        bail!("bech32 payload has a malformed tail");
    }
    Ok(out)
}

/// The agent's x-only public key, as 64 lowercase hex, from its `nsec`.
///
/// Accepts a bare 64-hex secret too: Buzz stores an `nsec`, but a spec written
/// by hand may carry either, and refusing the hex form here would be a
/// difference with no reason behind it.
fn pubkey_from_nsec(nsec: &str) -> Result<String> {
    let secret: Vec<u8> = if nsec.len() == 64 && nsec.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(nsec).context("decoding a hex secret key")?
    } else {
        let (hrp, data) = bech32_decode(nsec)?;
        if hrp != "nsec" {
            bail!("expected an nsec, got a {hrp:?} key");
        }
        from_base32(&data)?
    };
    if secret.len() != 32 {
        bail!("a secret key is 32 bytes, got {}", secret.len());
    }
    let sk = secp256k1::SecretKey::from_byte_array(
        secret.as_slice().try_into().expect("checked 32 bytes"),
    )
    .context("that is not a valid secp256k1 secret key")?;
    let secp = secp256k1::Secp256k1::new();
    let (xonly, _parity) = sk.x_only_public_key(&secp);
    Ok(hex::encode(xonly.serialize()))
}

#[cfg(test)]
mod nsec_tests {
    use super::*;

    // BIP-340 / NIP-19 vector: secret key of all 0x01 bytes.
    const HEX_SK: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn a_hex_secret_and_its_nsec_derive_the_same_pubkey() {
        let from_hex = pubkey_from_nsec(HEX_SK).expect("hex form");
        assert_eq!(from_hex.len(), 64);
        assert!(from_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_mistyped_key_fails_the_checksum_rather_than_deriving_a_wrong_one() {
        // The whole reason the checksum is verified: silently deriving a
        // plausible pubkey from a corrupted nsec would deploy an agent whose
        // identity nobody can explain.
        let good = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let mut bad: Vec<char> = good.chars().collect();
        bad[10] = if bad[10] == 'q' { 'p' } else { 'q' };
        let bad: String = bad.into_iter().collect();
        assert!(pubkey_from_nsec(&bad).is_err(), "accepted a corrupted nsec");
    }

    #[test]
    fn the_nip19_vector_decodes_to_its_documented_secret() {
        // NIP-19's example nsec and the hex secret it documents. This pins the
        // half written here — bech32 decode and the 5-to-8-bit regroup. The
        // curve arithmetic is the secp256k1 crate's and is not re-asserted.
        //
        // An earlier version of this test claimed a pubkey for this nsec taken
        // from NIP-19's *other* example. They are unrelated vectors, not a
        // keypair, and the assertion was wrong.
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let (hrp, data) = bech32_decode(nsec).expect("valid bech32");
        assert_eq!(hrp, "nsec");
        assert_eq!(
            hex::encode(from_base32(&data).expect("valid payload")),
            "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
        );
    }

    #[test]
    fn the_nsec_and_hex_forms_of_one_key_agree() {
        // The two accepted input forms must not disagree; if they ever did, an
        // agent would deploy under a different identity depending on which form
        // the caller happened to have.
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let hex_sk = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
        assert_eq!(
            pubkey_from_nsec(nsec).expect("nsec"),
            pubkey_from_nsec(hex_sk).expect("hex")
        );
    }

    #[test]
    fn an_npub_is_refused_rather_than_treated_as_a_secret() {
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
        assert!(pubkey_from_nsec(npub).is_err());
    }
}
