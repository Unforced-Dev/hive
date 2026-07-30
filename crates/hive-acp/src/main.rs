//! `hive-acp` — run an ACP harness inside a container, and get out of the way.
//!
//! # What this is for
//!
//! Buzz has two extension seams, and which one hive occupies decides a lot.
//!
//! A **backend provider** answers "where does this agent run": it receives the
//! deploy payload — nsec, relay url, `agent_command`, `env_vars` — and starts
//! `buzz-acp` somewhere. A **harness** answers "what does it run in". The old
//! shim took the provider seam and therefore had to reimplement remote
//! deployment over ssh, which is not a container-runtime problem.
//!
//! As a harness, `harness=hive` composes with whatever Buzz already does about
//! location, because the deploy payload carries `agent_command` and `env_vars`
//! verbatim: a provider that puts `buzz-acp` on another host will spawn
//! `hive-acp` there with `HIVE_ENV` intact, and neither end needs to know about
//! the other. Location stays Buzz's axis; the environment becomes hive's.
//!
//! So this is a Tier-3 custom harness (BYOH, buzz v0.5.0). `buzz-acp` spawns it
//! exactly as it would spawn `claude-agent-acp`, and it speaks ACP on stdio.
//! Below, it runs the real harness inside that agent's container — with hive's
//! isolation, MCP servers and broker-held credentials already in place.
//!
//! # Why it intercepts exactly one method
//!
//! ACP's `McpServer` is a union — `McpServerHttp`, `McpServerSse`,
//! `McpServerAcp`, `McpServerStdio` — and the HTTP variant carries a `headers`
//! array. Buzz implements only the stdio one, which is why an HTTP MCP server
//! cannot be configured from the desktop. The protocol was never the limit.
//!
//! So `session/new` is rewritten on its way down: hive appends the agent's own
//! MCP servers, with credentials fetched from the broker, to whatever Buzz
//! sent. Verified against `claude-agent-acp`, which advertises
//! `mcpCapabilities {http, sse}` and duly listed every Parachute tool.
//!
//! That is worth doing here rather than by writing harness config files,
//! because it is protocol rather than per-harness plumbing: it works for any
//! harness advertising `mcpCapabilities.http`, not only the one whose config
//! format hive happens to know.
//!
//! The same request carries a `cwd`, and that one is a genuine impedance
//! mismatch rather than a missing feature: the client picks a directory on the
//! machine *it* is running on, and the harness is on the other side of a
//! container boundary where that path means nothing. `claude-agent-acp`
//! validates it and rejects the session outright, so a client that never asked
//! for a container gets `cwd does not exist on the machine running the agent`
//! and no session. hive substitutes the agent's workspace — but only when the
//! path is genuinely absent inside the container, so a deliberately
//! bind-mounted host path still resolves to itself.
//!
//! **Everything else is copied verbatim, in both directions.** A proxy that
//! re-frames JSON-RPC it has no reason to read can corrupt a stream it was only
//! meant to carry, so anything that is not a `session/new` request — including
//! every response and notification coming back up — is passed through
//! untouched, and a line that does not parse as JSON is forwarded as bytes
//! rather than dropped.
//!
//! Routing between several backends, and switching harness mid-conversation,
//! would need real session bookkeeping. That is a different program.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use hive_core::harness::CATALOG;
use hive_spec::AgentSpec;

/// Locate the Docker CLI without trusting PATH.
///
/// This process is spawned by a GUI application. On macOS that means a minimal
/// launchd environment whose PATH does not include Homebrew — so `docker` is
/// simply not found, while the identical command works in the developer's
/// shell. Same list as `hive_core::docker::DockerBackend::discover`.
fn find_docker() -> String {
    for p in [
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/usr/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
    ] {
        if std::path::Path::new(p).is_file() {
            return p.to_string();
        }
    }
    "docker".to_string()
}

struct Config {
    agent: String,
    container: String,
    /// The harness entrypoint and its arguments, from hive's catalog.
    argv: Vec<String>,
    /// HTTP MCP servers from this agent's spec, injected at `session/new`.
    mcp: Vec<McpEntry>,
    /// Env vars this harness's model-provider credential can arrive in.
    credential_env: Vec<String>,
    /// Where a file-shaped credential for this harness would be, if it has one.
    credential_file: Option<String>,
    /// The spec's own harness id, when `HIVE_HARNESS` overrode it.
    overridden: Option<String>,
    /// The parsed spec, kept so a hold can be explained before waiting on a
    /// container that is never going to appear.
    spec: AgentSpec,
    /// Where hived lives, for the same reason.
    daemon: String,
}

#[derive(Clone)]
struct McpEntry {
    name: String,
    url: String,
    /// Broker key. `None` for a server that needs no credential.
    credential: Option<String>,
}

/// Ask the broker for a server's headers, from inside the container.
///
/// The broker listens on a unix socket bind-mounted into the agent's container,
/// which this process — running on the host, possibly on the far side of a
/// Docker VM — cannot reach. `hive-headers` already lives in the image for
/// exactly this conversation, so it is reused rather than reimplemented: the
/// fetch stays grant-checked and audited, and there is one code path that talks
/// to the broker instead of two.
///
/// A failure is logged and the server is attached WITHOUT credentials rather
/// than dropped. An MCP server the agent can see and gets 401 from is a
/// diagnosable problem; a server that silently vanished is not.
fn fetch_headers(container: &str, server: &str) -> Vec<(String, String)> {
    let out = Command::new(find_docker())
        .args(["exec", "-e"])
        .arg(format!("CLAUDE_CODE_MCP_SERVER_NAME={server}"))
        .args([container, "hive-headers"])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            eprintln!(
                "hive-acp: no credentials for MCP server {server:?}: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return Vec::new();
        }
        Err(e) => {
            eprintln!("hive-acp: could not reach the broker for {server:?}: {e}");
            return Vec::new();
        }
    };
    let body = String::from_utf8_lossy(&out.stdout);
    // The helper prints the headers FLAT — `{name: value, …}` — because that is
    // what Claude Code requires of a headersHelper on stdout, and the helper has
    // exactly one output format for both callers.
    //
    // It used to print the broker's `{"headers": {…}}` envelope, and this
    // function read the nested map. That worked HERE and silently broke the
    // other caller: Claude Code discards a helper response whose values are not
    // strings, so `{"headers": {…}}` produced an unauthenticated request, a 401,
    // and a server recorded as needing interactive OAuth. Both callers now read
    // the same flat shape; `hive_headers::flatten` is the only place that knows
    // about the envelope.
    let parsed: serde_json::Value = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hive-acp: broker returned unparseable headers for {server:?}: {e}");
            return Vec::new();
        }
    };
    let Some(map) = parsed.as_object() else {
        eprintln!("hive-acp: broker response for {server:?} was not a JSON object");
        return Vec::new();
    };
    // Tolerate the old envelope so a new hive-acp against an older agent image
    // keeps working. Mixed versions are the normal state during a rollout, and
    // the failure this would otherwise cause is the silent 401 again.
    if let Some(nested) = map.get("headers").and_then(|h| h.as_object()) {
        return nested
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
    }
    map.iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

/// Is this an existing directory *inside the container*?
///
/// Used to tell a path the container genuinely has — a bind-mounted host
/// directory, say — from one that only exists on the client's machine.
fn dir_exists_in(container: &str, path: &str) -> bool {
    Command::new(find_docker())
        .args(["exec", container, "test", "-d", path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Where the harness should work when the client's `cwd` is a host path.
///
/// `HIVE_ACP_WORKSPACE` wins, so an operator whose image is laid out
/// differently is not stuck. Otherwise `/home/agent/work`, which hive's agent
/// image creates for exactly this; then the image's own `WORKDIR`. The last
/// resort is `/`, which every container has — a wrong-but-present directory
/// still starts a session the operator can inspect, where a missing one just
/// reproduces the failure this function exists to prevent.
fn resolve_workspace(container: &str) -> String {
    if let Some(v) = std::env::var("HIVE_ACP_WORKSPACE").ok().filter(|s| !s.is_empty()) {
        return v;
    }
    if dir_exists_in(container, "/home/agent/work") {
        return "/home/agent/work".to_string();
    }
    let out = Command::new(find_docker())
        .args(["inspect", "--format", "{{.Config.WorkingDir}}", container])
        .output();
    if let Ok(o) = out {
        let dir = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if o.status.success() && !dir.is_empty() {
            return dir;
        }
    }
    "/".to_string()
}

/// Adapt a `session/new` request to the container it is really headed for.
///
/// Returns `None` for anything that is not a `session/new` request, including
/// lines that are not JSON — the caller then forwards the original bytes.
///
/// Buzz's own `mcpServers` are preserved and hive's are appended, rather than
/// replaced: a stdio server configured in the desktop and an HTTP server
/// configured in hive are not alternatives, and silently dropping the former
/// would make hive's involvement look like a Buzz bug.
fn rewrite_session_new(line: &str, mcp: &[McpEntry], container: &str) -> Option<String> {
    inject(
        line,
        mcp,
        &|e: &McpEntry| match &e.credential {
            Some(_) => fetch_headers(container, &e.name),
            None => Vec::new(),
        },
        // Resolving the workspace costs two `docker` calls, so it is deferred
        // until something actually needs it — which is only when the client
        // sent a cwd the container does not have.
        &|| resolve_workspace(container),
        &|path: &str| dir_exists_in(container, path),
    )
}

/// The pure half: everything except talking to the broker.
///
/// Split out so the rewrite can be tested without Docker — the parts most
/// likely to be wrong are the passthrough conditions, not the header fetch.
fn inject(
    line: &str,
    mcp: &[McpEntry],
    headers_for: &dyn Fn(&McpEntry) -> Vec<(String, String)>,
    workspace: &dyn Fn() -> String,
    dir_exists: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let mut msg: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if msg.get("method")?.as_str()? != "session/new" {
        return None;
    }
    let params = msg.get_mut("params")?.as_object_mut()?;
    let mut rewrote = false;

    // The client chose this directory on its own machine. Replace it only when
    // the container really lacks it — a spec that bind-mounts the very path
    // Buzz is pointing at is a working setup, and redirecting that to the
    // agent's workspace would quietly ignore what the operator asked for.
    let stale_cwd = params
        .get("cwd")
        .and_then(|c| c.as_str())
        .filter(|cwd| !dir_exists(cwd))
        .map(String::from);
    if let Some(cwd) = stale_cwd {
        let target = workspace();
        eprintln!("hive-acp: cwd {cwd:?} is not in the container; using {target:?}");
        params.insert("cwd".into(), serde_json::Value::String(target));
        rewrote = true;
    }

    if !mcp.is_empty() {
        let servers = params
            .entry("mcpServers")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()?;
        for e in mcp {
            let headers: Vec<serde_json::Value> = headers_for(e)
                .into_iter()
                .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                .collect();
            // `type: "http"` selects the McpServerHttp variant of ACP's
            // McpServer union. `headers` is required by the schema even when
            // empty.
            servers.push(serde_json::json!({
                "type": "http",
                "name": e.name,
                "url": e.url,
                "headers": headers,
            }));
            eprintln!("hive-acp: attached MCP server {} -> {}", e.name, e.url);
        }
        rewrote = true;
    }

    // Nothing to change: let the caller forward the original bytes rather than
    // a re-serialized copy that differs in key order and spacing.
    if !rewrote {
        return None;
    }
    let mut s = msg.to_string();
    s.push('\n');
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> McpEntry {
        McpEntry {
            name: name.into(),
            url: format!("https://vault.example/{name}/mcp"),
            credential: Some(format!("mcp/{name}")),
        }
    }
    fn creds(_: &McpEntry) -> Vec<(String, String)> {
        vec![("Authorization".into(), "Bearer TOKEN".into())]
    }
    fn none(_: &McpEntry) -> Vec<(String, String)> {
        Vec::new()
    }

    /// A container whose only directory is the agent workspace — so any cwd the
    /// client sends is a host path, which is the case that matters.
    fn only_workspace(path: &str) -> bool {
        path == "/home/agent/work"
    }
    fn workspace() -> String {
        "/home/agent/work".to_string()
    }
    /// A container that has whatever it is asked for: nothing needs rewriting.
    fn everything(_: &str) -> bool {
        true
    }

    /// The common case in these tests: MCP injection with a cwd that is already
    /// valid inside the container, so only `mcpServers` moves.
    fn inject_mcp_only(
        line: &str,
        mcp: &[McpEntry],
        headers_for: &dyn Fn(&McpEntry) -> Vec<(String, String)>,
    ) -> Option<String> {
        inject(line, mcp, headers_for, &workspace, &everything)
    }

    #[test]
    fn only_session_new_is_touched() {
        // Everything else — prompts, cancels, and every response coming back —
        // must reach the far side byte-for-byte. Rewriting a message this
        // program has no reason to read is how a proxy corrupts a stream it was
        // only meant to carry.
        let e = [entry("parachute")];
        for line in [
            r#"{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"s"}}"#,
        ] {
            assert!(inject_mcp_only(line, &e, &none).is_none(), "rewrote: {line}");
        }
    }

    #[test]
    fn a_line_that_is_not_json_is_passed_through_rather_than_dropped() {
        // ACP framing is not something to assume. If messages ever stop being
        // newline-delimited, this must degrade to a transparent pipe instead of
        // silently swallowing traffic.
        assert!(inject_mcp_only("not json at all", &[entry("p")], &none).is_none());
        assert!(inject_mcp_only("", &[entry("p")], &none).is_none());
    }

    #[test]
    fn an_agent_with_no_mcp_servers_is_never_rewritten() {
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"mcpServers":[]}}"#;
        assert!(inject_mcp_only(line, &[], &creds).is_none());
    }

    #[test]
    fn the_clients_own_mcp_servers_are_kept_and_hives_are_appended() {
        // A stdio server configured in Buzz and an HTTP server configured in
        // hive are not alternatives. Dropping the client's would look like a
        // Buzz bug rather than something hive did.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/w","mcpServers":[{"name":"buzzy","command":"x","args":[],"env":[]}]}}"#;
        let out = inject_mcp_only(line, &[entry("parachute")], &creds).expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let servers = v["params"]["mcpServers"].as_array().unwrap();
        assert_eq!(servers.len(), 2, "{out}");
        assert_eq!(servers[0]["name"], "buzzy");
        assert_eq!(servers[1]["name"], "parachute");
        assert_eq!(servers[1]["type"], "http");
        assert_eq!(v["params"]["cwd"], "/w", "unrelated params must survive");
    }

    #[test]
    fn the_injected_server_matches_the_mcpserverhttp_variant() {
        // ACP selects the variant by `type`, and `headers` is required by the
        // schema even when empty. Emitting the stdio shape here means the
        // harness never reaches the server at all.
        let out = inject_mcp_only(
            r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}"#,
            &[entry("parachute")],
            &creds,
        )
        .expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let s = &v["params"]["mcpServers"][0];
        assert_eq!(s["type"], "http");
        assert_eq!(s["url"], "https://vault.example/parachute/mcp");
        assert_eq!(s["headers"][0]["name"], "Authorization");
        assert_eq!(s["headers"][0]["value"], "Bearer TOKEN");
    }

    #[test]
    fn a_server_whose_credential_cannot_be_fetched_is_still_attached() {
        // Attached-and-401 is diagnosable; silently absent is not. The agent
        // reports an authorization failure naming the server, which points at
        // the broker rather than at a mystery.
        let out = inject_mcp_only(
            r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}"#,
            &[entry("parachute")],
            &none,
        )
        .expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["params"]["mcpServers"][0]["name"], "parachute");
        assert!(v["params"]["mcpServers"][0]["headers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn the_rewritten_line_stays_newline_terminated() {
        // The child reads line-delimited JSON. Dropping the terminator makes
        // the harness wait for the rest of a message that already arrived.
        let out = inject_mcp_only(
            r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}"#,
            &[entry("p")],
            &none,
        )
        .expect("rewritten");
        assert!(out.ends_with('\n'), "{out:?}");
    }

    #[test]
    fn a_client_cwd_the_container_lacks_becomes_the_workspace() {
        // The regression this exists for: Buzz sends the directory it is
        // sitting in on the host, `claude-agent-acp` checks it inside the
        // container, and rejects the session with `cwd does not exist on the
        // machine running the agent` — which reads as a hive failure with no
        // hint that a path was the problem.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/private/tmp","mcpServers":[]}}"#;
        let out = inject(line, &[], &none, &workspace, &only_workspace).expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["params"]["cwd"], "/home/agent/work");
    }

    #[test]
    fn a_cwd_the_container_really_has_is_left_alone() {
        // A spec can bind-mount a host directory into the container at the same
        // path. Redirecting that to the workspace would silently ignore the
        // mount the operator configured on purpose.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/srv/shared"}}"#;
        assert!(
            inject(line, &[], &none, &workspace, &everything).is_none(),
            "a valid cwd and no MCP servers is nothing to rewrite"
        );
    }

    #[test]
    fn the_cwd_is_fixed_even_for_an_agent_with_no_mcp_servers() {
        // These are independent reasons to rewrite. Gating the cwd fix on
        // having MCP servers would leave the plainest possible agent — no MCP
        // at all — as the one that cannot open a session.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/Users/someone/code"}}"#;
        let out = inject(line, &[], &creds, &workspace, &only_workspace).expect("rewritten");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["params"]["cwd"], "/home/agent/work");
        assert!(v["params"].get("mcpServers").is_none(), "invented an mcpServers key");
    }

    #[test]
    fn a_stale_cwd_on_any_other_method_is_not_touched() {
        // Only `session/new` declares a cwd. Rewriting a field that happens to
        // share the name on some other method would corrupt it.
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"cwd":"/private/tmp"}}"#;
        assert!(inject(line, &[entry("p")], &creds, &workspace, &only_workspace).is_none());
    }

    #[test]
    fn the_workspace_is_not_resolved_when_the_cwd_is_already_good() {
        // Resolving it costs two `docker` calls per session. This asserts the
        // laziness rather than trusting the call order to stay that way.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/srv/shared"}}"#;
        let calls = std::cell::Cell::new(0);
        let counting = || {
            calls.set(calls.get() + 1);
            "/home/agent/work".to_string()
        };
        let _ = inject(line, &[entry("p")], &creds, &counting, &everything);
        assert_eq!(calls.get(), 0, "resolved the workspace it did not need");
    }
}

/// Every credential key the broker currently holds.
fn stored_secrets(daemon: &str) -> Vec<String> {
    Command::new(find_docker())
        .args(["exec", daemon, "hive", "secret", "list"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Name the credentials this spec needs that the broker does not hold.
///
/// hived HOLDS an agent whose credentials are missing rather than starting one
/// that cannot work — correct, and invisible: the reason goes to the daemon's
/// log, while the caller sits waiting for a container that is never coming and
/// eventually reports a timeout. This turns that into a sentence naming the key.
fn missing_credentials(daemon: &str, spec: &AgentSpec, agent: &str) -> Vec<String> {
    let Ok(reqs) = hive_core::agent::requirements(spec, agent) else {
        return Vec::new();
    };
    let out = Command::new(find_docker())
        .args(["exec", daemon, "hive", "secret", "list"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    if !out.status.success() {
        return Vec::new();
    }
    let held: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    reqs.iter()
        .map(|r| r.key.as_str().to_string())
        .filter(|k| !held.iter().any(|h| h == k))
        .collect()
}

/// Block until the container is running, or give up and let the exec fail.
///
/// Returns rather than erroring on timeout: the `docker exec` that follows
/// produces a better message than anything this function could invent, and a
/// container that is merely slow should not be reported as absent.
fn wait_for_container(container: &str) {
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(90);
    let deadline = std::time::Instant::now() + PATIENCE;
    let mut announced = false;
    loop {
        let running = Command::new(find_docker())
            .args(["inspect", "--format", "{{.State.Running}}", container])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false);
        if running || std::time::Instant::now() >= deadline {
            if announced && running {
                eprintln!("hive-acp: {container} is up");
            }
            return;
        }
        if !announced {
            eprintln!("hive-acp: waiting for {container} — hived reconciles on a timer");
            announced = true;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// The harness to run: `--harness` first, then `HIVE_HARNESS`.
fn chosen_harness() -> Option<String> {
    flag("harness").or_else(|| std::env::var("HIVE_HARNESS").ok().filter(|s| !s.is_empty()))
}

/// Where operator-wide environment defaults live.
///
/// On the secrets volume rather than the spec directory, because hived reads
/// every `*.toml` in the latter as an agent and would try to reconcile this
/// one.
const DEFAULTS_PATH: &str = "/var/lib/hive/defaults.toml";

/// TOML appended to every environment hive creates. Empty when absent.
fn read_defaults(daemon: &str) -> String {
    Command::new(find_docker())
        .args(["exec", daemon, "cat", DEFAULTS_PATH])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            if text.trim().is_empty() { text } else { format!("\n{}", text.trim_end()) }
        })
        .unwrap_or_default()
}

/// Create an environment that does not exist yet, through the daemon.
///
/// Deliberately minimal. An environment is a container to run a harness in:
/// identity belongs to whatever spawned this process, credentials are named
/// rather than stored in a spec, and MCP servers are added afterwards with
/// `hive mcp add`. So the generated file says only which harness and which
/// mode, and everything else is a considered addition rather than a default
/// somebody has to discover and undo.
///
/// `HIVE_HARNESS` picks the harness when set, so the Buzz entry that named a
/// harness also gets one configured for it.
fn create_environment(daemon: &str, name: &str) -> Result<()> {
    let harness = chosen_harness().unwrap_or_else(|| "claude".to_string());

    // Reuse a credential this box already holds, in the FORM the harness reads
    // it.
    //
    // Defaulting to broker+env is right for claude, whose credential is a token
    // in CLAUDE_CODE_OAUTH_TOKEN — and wrong for codex and grok, whose normal
    // auth is a JSON file. A spec that asks for `harness/codex` when what exists
    // is `codex/auth` is held forever for a credential nobody is going to
    // create, and the new agent simply never starts.
    //
    // Both key spellings are tried because both are in use: `harness/<id>` is
    // what hive asks for by default, `<id>/auth` is what a file credential gets
    // called when it is stored by hand.
    let def = CATALOG.iter().find(|h| h.id == harness);
    let held = stored_secrets(daemon);

    // A harness that owns and rewrites its credential file cannot be handed a
    // copy of somebody else's. Declaring `auth = "file"` for one of those is
    // worse than declaring nothing: hived injects a snapshot, the harness finds
    // it stale, cannot refresh a token whose refresh half has already been
    // rotated elsewhere, and deletes it — leaving an unauthenticated container
    // whose spec says a credential was delivered.
    let auth_block = if def.is_some_and(|d| d.credential_file_rotates) {
        eprintln!(
            "hive-acp: {harness} manages its own credential and rotates it, so it cannot be \
             injected. Log in once inside this environment:\n\
             \x20   hive shell {name} -- grok login --device-auth"
        );
        // Not `broker`: hived would hold the agent forever waiting for a key
        // that by design lives in the state volume, and hold it so hard the
        // container needed to log in never starts.
        "auth = \"interactive\"\n".to_string()
    } else {
        match def
            .and_then(|d| d.credential_file)
            .and_then(|path| {
                [format!("harness/{harness}"), format!("{harness}/auth")]
                    .into_iter()
                    .find(|k| held.iter().any(|h| h == k))
                    .map(|key| (key, path))
            }) {
            Some((key, path)) => {
                eprintln!("hive-acp: {harness} authenticates from a file; using {key}");
                format!(
                    "auth = \"file\"\n\
                     \n\
                     [[file]]\n\
                     credential = {key:?}\n\
                     target     = {path:?}\n\
                     mode       = \"0600\"\n"
                )
            }
            None => String::new(),
        }
    };

    // Anything the operator wants every new environment to have.
    //
    // Without this a generated environment has no MCP servers at all, so the
    // vault every agent is supposed to reach is reachable only from the one
    // environment somebody configured by hand. Defaults are appended verbatim
    // and validated by `spec-put`, so a broken defaults file fails at creation
    // with a reason rather than producing an agent that quietly lacks its
    // tools.
    //
    // NOT in the spec directory: hived treats every *.toml there as an agent,
    // so a defaults file next to the specs would be reconciled as one.
    let defaults = read_defaults(daemon);
    if !defaults.trim().is_empty() {
        eprintln!("hive-acp: applying environment defaults from {DEFAULTS_PATH}");
    }

    let spec = format!(
        "# Created by hive-acp for Buzz agent {name:?}.\n\
         # An environment: a container to run a harness in. The identity lives\n\
         # with buzz-acp outside it, which is why there is no [identity] block.\n\
         #\n\
         # Add MCP servers with `hive mcp add <name> --url <url> --agent {name}`.\n\
         \n\
         [harness]\n\
         id = {harness:?}\n\
         {auth_block}\
         \n\
         [agent]\n\
         mode = \"environment\"\n\
         {defaults}"
    );

    eprintln!("hive-acp: {name:?} has no environment yet; creating one (harness {harness})");
    let mut child = Command::new(find_docker())
        .args(["exec", "-i", daemon, "hive", "spec-put", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("creating an environment for {name} via {daemon}"))?;
    child
        .stdin
        .take()
        .context("child stdin")?
        .write_all(spec.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "could not create an environment for {name}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // hived reconciles on a timer, so the container does not exist yet. The
    // caller only needs the SPEC to read a harness and MCP list out of; the
    // container is waited for where it is actually used.
    Ok(())
}

/// A `--harness <id>` / `--env <name>` flag, if present on the command line.
///
/// Reading these from ARGV and not only from the environment is load-bearing on
/// the deploy path. Buzz layers a harness definition's `env` into a LOCAL spawn
/// (`readiness.rs`, "definition env"), but `build_deploy_payload` merges only
/// global, persona and per-agent env — the definition's is dropped. So a
/// harness entry that carries `HIVE_HARNESS` in `env` works perfectly on this
/// computer and silently becomes the default harness when deployed to another
/// one: three agents created as claude, codex and grok all came up as claude,
/// with nothing in any log to say why.
///
/// `agent_args` IS in the deploy payload, so it survives the trip.
fn flag(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(v) = a.strip_prefix(&format!("--{name}="))
            && !v.is_empty()
        {
            return Some(v.to_string());
        }
        if a == &format!("--{name}")
            && let Some(v) = args.get(i + 1)
            && !v.is_empty()
        {
            return Some(v.clone());
        }
        i += 1;
    }
    None
}

/// Which hive environment to run in — `HIVE_ENV`, or the older `HIVE_AGENT`.
///
/// It selects a **container**: image, state volume, network, credentials, MCP
/// servers. It says nothing about who the agent is. In `mode = "environment"`
/// the container has no Nostr key at all — `buzz-acp` holds it on the host and
/// Buzz strips it from the harness environment before spawning.
///
/// So `HIVE_AGENT` named the wrong thing. "Agent" is what Buzz calls the entity
/// with the identity, and several Buzz agents pointing at one `HIVE_AGENT` were
/// silently one container sharing skills, sessions and credentials — a bug the
/// name actively hid. `HIVE_ENV` says what it selects.
///
/// The old name still works, with a warning rather than a break: it is written
/// into harness definitions that already exist, and a rename that takes an
/// agent offline mid-conversation to make a point is not an improvement.
fn env_name() -> String {
    let read = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    if let Some(v) = flag("env").or_else(|| read("HIVE_ENV")) {
        return v;
    }
    if let Some(v) = read("HIVE_AGENT") {
        eprintln!(
            "hive-acp: HIVE_AGENT is deprecated, use HIVE_ENV. It selects a container, not an \
             identity — and two Buzz agents sharing one value share one container."
        );
        return v;
    }
    // The name the supervisor gave this agent.
    //
    // A deployed agent should not need an environment variable set by hand
    // before it can run, and asking for one invites the mistake it was meant to
    // prevent: reusing a neighbour's value, and silently sharing that
    // container's sessions, skills and credentials. buzz-host publishes its
    // unit name, which is already unique per agent on that machine.
    if let Some(v) = read("BUZZ_HOST_UNIT") {
        eprintln!("hive-acp: HIVE_ENV unset; using this agent's unit name {v:?}");
        return v;
    }

    // Nothing has named this agent, which means it does not exist yet: the
    // desktop is asking a harness what models it supports while the user is
    // still filling in the dialog. Failing here leaves the model list empty
    // with no way to fill it — there is nothing to set HIVE_ENV *to* before the
    // agent exists, and pinning one in the harness definition is exactly what
    // put every agent in a single shared container in the first place.
    //
    // So discovery gets a scratch environment. One PER HARNESS, because
    // `session/new` needs that harness's own credentials before it will answer
    // — a single shared probe container would report claude's models for every
    // entry, or fail outright for the ones it cannot authenticate.
    let scratch = format!("probe-{}", chosen_harness().unwrap_or_else(|| "claude".into()));
    eprintln!(
        "hive-acp: no HIVE_ENV and no supervisor — using the shared discovery environment \
         {scratch:?}. A real agent sets HIVE_ENV, or is deployed by something that names it."
    );
    scratch
}

/// Resolve everything from the environment name plus its spec.
///
/// The harness is read from the spec rather than from an environment variable
/// because the spec is what hived reconciled the container from. Taking it from
/// the environment would let the two disagree — and the symptom would be a
/// harness that starts, answers `initialize`, and has none of the credentials
/// the container was built for.
/// Read an environment's spec through the daemon, or locally when visible.
///
/// Where hived runs in a container — which on macOS and Windows it must,
/// because the broker's unix sockets cannot cross the Docker VM boundary — the
/// spec directory is a volume this process cannot see. Requiring the operator
/// to bind-mount it onto the host as well would mean two sources of truth for
/// the same file, and the one this program read would be the one nobody edited.
fn read_spec(spec_dir: &str, daemon: &str, name: &str) -> Option<String> {
    let path = std::path::Path::new(spec_dir).join(format!("{name}.toml"));
    if let Ok(t) = std::fs::read_to_string(&path) {
        return Some(t);
    }
    let out = Command::new(find_docker())
        .args(["exec", daemon, "cat"])
        .arg(&path)
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

fn resolve() -> Result<Config> {
    let mut agent = env_name();

    let spec_dir =
        std::env::var("HIVE_SPEC_DIR").unwrap_or_else(|_| "/etc/hive/agents".to_string());
    let daemon = std::env::var("HIVE_DAEMON_CONTAINER").unwrap_or_else(|_| "hived".to_string());

    // Creating an environment is for a REAL agent, never for a model-discovery
    // probe.
    //
    // The desktop re-probes the harness on every keystroke while someone types
    // into the HIVE_ENV field, so provisioning unconditionally created one
    // environment per keystroke: typing "uni" left behind `u` and `un`, each
    // with a spec, a container and a volume, all within the same second.
    //
    // A deployed agent carries BUZZ_HOST_UNIT — its supervisor named it. A
    // probe does not. So a probe naming an environment that does not exist
    // falls back to the shared discovery one rather than conjuring it.
    let text = match read_spec(&spec_dir, &daemon, &agent) {
        Some(t) => t,
        None => {
            let deployed =
                std::env::var("BUZZ_HOST_UNIT").ok().filter(|s| !s.is_empty()).is_some();
            if !deployed {
                let scratch =
                    format!("probe-{}", chosen_harness().unwrap_or_else(|| "claude".into()));
                eprintln!(
                    "hive-acp: {agent:?} does not exist and nothing has deployed it, so this is \
                     a discovery probe — using {scratch:?} instead of creating it. Deploy the \
                     agent, or create the environment with `hive spec-put`."
                );
                agent = scratch;
            }
            match read_spec(&spec_dir, &daemon, &agent) {
                Some(t) => t,
                None => {
                    // Either a real deployment whose environment does not exist
                    // yet, or the discovery environment on its first ever use.
                    create_environment(&daemon, &agent)?;
                    read_spec(&spec_dir, &daemon, &agent).with_context(|| {
                        format!(
                            "created {agent} but still cannot read its spec via {daemon}. \
                             Is hived running? `hive status`"
                        )
                    })?
                }
            }
        }
    };
    let spec: AgentSpec = toml::from_str(&text)
        .with_context(|| format!("{agent} does not have a valid agent spec"))?;

    // A spec names either a catalog id or an explicit command. The escape hatch
    // is honoured here too: a harness the catalog does not know still runs, it
    // just brings its own image, and refusing it would make hive-acp stricter
    // than hived about the very same spec.
    // `HIVE_HARNESS` overrides the spec's harness id.
    //
    // The image carries every harness in the catalog, so one container can run
    // any of them — which is what lets a single `hive-acp` binary back several
    // Buzz harness entries (`hive (claude)`, `hive (codex)`, …) instead of one
    // per agent. Buzz's harness picker then stays the harness picker, and each
    // entry reports the models its own harness actually supports rather than a
    // merged list hive would have to maintain.
    //
    // What it does NOT move is credentials. hived provisions the container from
    // the spec, so the only model-provider credential present is the spec
    // harness's. Overriding to a harness the container cannot authenticate is
    // allowed — refusing would make it impossible to start a container in order
    // to log in — but it is called out below rather than left to surface as an
    // unexplained "authentication required" three steps later.
    let override_id = chosen_harness();
    let effective_id = override_id.as_deref().or(spec.harness.id.as_deref());

    let mut credential_env: Vec<String> = Vec::new();
    let mut credential_file: Option<String> = None;
    let argv: Vec<String> = match (effective_id, &spec.harness.command) {
        (Some(id), _) => {
            let def = CATALOG.iter().find(|h| h.id == id).with_context(|| {
                format!(
                    "harness {id:?} is not in hive's catalog. \
                     `hive harnesses` lists the ids this build knows."
                )
            })?;
            if let Some(reason) = &def.unsupported {
                bail!("harness {id:?} is deliberately absent from the image: {reason:?}");
            }
            credential_env = def.credential_env.iter().map(|s| s.to_string()).collect();
            credential_file = def.credential_file.map(String::from);
            let mut v = vec![def.command.to_string()];
            v.extend(def.args.iter().map(|s| s.to_string()));
            v
        }
        // An explicit command wins only when no id is in play at all. A spec
        // that names both, plus an override, would otherwise silently run the
        // command and ignore the harness that was just picked.
        (None, Some(cmd)) => cmd.split_whitespace().map(String::from).collect(),
        (None, None) => bail!(
            "{agent} names neither [harness].id nor [harness].command, so there is nothing to run"
        ),
    };

    let overridden = match (&override_id, &spec.harness.id) {
        (Some(o), Some(s)) if o != s => Some(s.clone()),
        _ => None,
    };

    // Only HTTP servers are attached over ACP. A stdio server in a spec is
    // hived's business — it is spawned inside the container — and duplicating
    // it here would start a second copy.
    let mcp = spec
        .mcp
        .iter()
        .filter(|m| m.url.is_some())
        .map(|m| McpEntry {
            name: m.name.clone(),
            url: m.url.clone().unwrap_or_default(),
            credential: m.credential.clone(),
        })
        .collect();

    Ok(Config {
        container: std::env::var("HIVE_CONTAINER").unwrap_or_else(|_| format!("hive-{agent}")),
        daemon: std::env::var("HIVE_DAEMON_CONTAINER").unwrap_or_else(|_| "hived".to_string()),
        spec,
        agent,
        argv,
        mcp,
        credential_env,
        credential_file,
        overridden,
    })
}

/// Warn when the chosen harness has no credential in the container.
///
/// Only worth saying when the harness was overridden: for the spec's own
/// harness, hived already refuses to start the agent without its credential, so
/// a missing one there is not this program's news to break.
fn warn_if_unauthenticated(cfg: &Config) {
    let Some(spec_harness) = &cfg.overridden else {
        return;
    };
    if cfg.credential_env.is_empty() && cfg.credential_file.is_none() {
        return;
    }

    // Subscription auth is the normal way these tools are used, and for codex
    // it is a file rather than an env var. Checking only the environment
    // reported a working container as unauthenticated — the warning fired, and
    // then codex authenticated from auth.json and listed its models. A false
    // alarm here is worse than none: it teaches the reader to ignore the line
    // that will one day be true.
    let env_present = cfg.credential_env.iter().any(|var| {
        Command::new(find_docker())
            .args(["exec", &cfg.container, "printenv", var])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    });
    let file_present = cfg
        .credential_file
        .as_deref()
        .is_some_and(|path| file_exists_in(&cfg.container, path));
    if env_present || file_present {
        return;
    }

    let harness = cfg.argv.first().map(String::as_str).unwrap_or("the harness");
    let mut wanted = cfg.credential_env.clone();
    if let Some(path) = &cfg.credential_file {
        wanted.push(path.clone());
    }
    eprintln!(
        "hive-acp: harness overridden to {harness} but this container was provisioned for \
         {spec_harness}, and none of {} is present. The harness will report that authentication \
         is required. Give {harness} its own agent, or add its credential to {}'s spec.",
        wanted.join(" / "),
        cfg.agent,
    );
}

/// Is this an existing regular file inside the container?
fn file_exists_in(container: &str, path: &str) -> bool {
    Command::new(find_docker())
        .args(["exec", container, "test", "-f", path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn main() -> Result<()> {
    // stderr, never stdout: stdout is the ACP channel and one stray line of
    // logging corrupts the stream. The failure looks like a harness that
    // connects and then ignores everything.
    let cfg = match resolve() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hive-acp: {e:#}");
            std::process::exit(78); // EX_CONFIG
        }
    };

    eprintln!(
        "hive-acp: env={} container={} harness={}",
        cfg.agent,
        cfg.container,
        cfg.argv.join(" ")
    );
    warn_if_unauthenticated(&cfg);

    // -i, no -t. There is no terminal here, and `docker exec -t` fails outright
    // when stdin is a pipe — which it always is, because buzz-acp owns it.
    let mut cmd = Command::new(find_docker());
    cmd.arg("exec").arg("-i");
    // Forward the environment buzz-acp set for this harness. That is how the
    // relay URL, the agent's identity and Buzz's per-agent settings reach the
    // harness; without it the harness starts unconfigured and idles.
    for (k, v) in std::env::vars() {
        if k.starts_with("BUZZ_") || k.starts_with("ACP_") {
            cmd.arg("-e").arg(format!("{k}={v}"));
        }
    }
    cmd.arg(&cfg.container);
    cmd.args(&cfg.argv);

    // A freshly created environment has a spec but not yet a container: hived
    // reconciles on a timer. Without this the first session after creating an
    // agent fails with "no such container" and the second one works, which
    // reads as flakiness rather than as a wait.
    // Say why before waiting, not after. hived holds an agent whose credentials
    // are missing, so the container never appears and the wait always burns its
    // full patience before failing with a timeout that names nothing.
    let missing = missing_credentials(&cfg.daemon, &cfg.spec, &cfg.agent);
    if !missing.is_empty() {
        eprintln!(
            "hive-acp: {} is held — the broker has no {}. Store it with `hive secret put {}`, \
             or give this environment a file credential if that is how the harness authenticates.",
            cfg.agent,
            missing.join(" or "),
            missing.first().map(String::as_str).unwrap_or("<key>"),
        );
    }
    wait_for_container(&cfg.container);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "starting the harness in {}. Is the container running? `hive status`",
                cfg.container
            )
        })?;

    let mut to_child = child.stdin.take().context("child stdin")?;
    let mut from_child = child.stdout.take().context("child stdout")?;

    // Two directions, two threads, raw bytes. Copying in fixed chunks rather
    // than by line: a line-oriented copy would block a partial message until a
    // newline arrived, which stalls a streaming `session/update` mid-token.
    let up = std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        let mut out = std::io::stdout().lock();
        loop {
            match from_child.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.write_all(&buf[..n]).is_err() || out.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mcp = cfg.mcp.clone();
    let container = cfg.container.clone();
    let down = std::thread::spawn(move || {
        // Line-oriented only in this direction, and only to find `session/new`.
        // A line that is not JSON, or is any other method, is written through
        // byte-for-byte — so a framing change or an unknown method degrades to
        // the transparent behaviour rather than to a corrupted stream.
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let out = match rewrite_session_new(&line, &mcp, &container) {
                Some(modified) => modified,
                None => line.clone(),
            };
            if to_child.write_all(out.as_bytes()).is_err() || to_child.flush().is_err() {
                break;
            }
        }
        // Closing the child's stdin is what tells the harness the client is
        // gone. Without it the harness waits for input that will never come and
        // has to be killed rather than exiting.
        drop(to_child);
    });

    let status = child.wait().context("waiting for the harness")?;
    let _ = up.join();
    // The downstream thread is parked in a blocking read on our own stdin and
    // only unblocks when the parent closes it. Not joined: waiting for it would
    // hang this process after the harness has already exited.
    drop(down);

    // Propagate rather than flattening. buzz-acp distinguishes a harness that
    // exited cleanly from one that crashed, and reporting 0 for a crash makes a
    // crash-looping agent look like a healthy one that keeps finishing.
    std::process::exit(status.code().unwrap_or(1));
}
