//! Turning an [`AgentSpec`] into a [`ContainerPlan`].
//!
//! This is where the spec's vocabulary meets `buzz-acp`'s. Every environment
//! variable named here was read out of `crates/buzz-acp/src/config.rs` rather
//! than from documentation — several are near-duplicates of each other, one is
//! deprecated, and setting the wrong one of a pair fails silently.

use std::collections::BTreeMap;

use hive_spec::AgentSpec;

use crate::backend::*;
use crate::credential::{CredentialKey, Delivery, Requirement};
use crate::docker::labels_for;
use crate::harness::{self, HarnessDef};
use crate::mcp::{self, Auth, McpServer, Transport};

/// Where the broker socket is mounted inside the container, and therefore the
/// only path the headers helper needs to know.
pub const BROKER_SOCKET_IN_CONTAINER: &str = "/run/hive/broker.sock";

/// The helper Claude Code executes to obtain MCP headers. Shipped in the image.
pub const HEADERS_HELPER: &str = "/usr/local/bin/hive-headers";

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("unknown harness '{0}'; known harnesses: {1}")]
    UnknownHarness(String, String),
    #[error("harness '{id}' is not available: {reason}")]
    HarnessUnavailable { id: String, reason: String },
    #[error("agent '{0}' has neither owner_pubkey nor auth_tag; it would start and ignore everyone")]
    NoOwner(String),
    #[error(transparent)]
    Mcp(#[from] mcp::McpError),
}

/// Resolve the harness for a spec, refusing the ones hive deliberately omits.
pub fn resolve_harness(spec: &AgentSpec) -> Result<&'static HarnessDef, PlanError> {
    let id = spec.harness.id.as_deref().unwrap_or("claude");
    let def = harness::lookup(id).ok_or_else(|| {
        PlanError::UnknownHarness(
            id.to_string(),
            harness::available_ids().collect::<Vec<_>>().join(", "),
        )
    })?;
    if let Some(reason) = def.unsupported {
        return Err(PlanError::HarnessUnavailable {
            id: id.to_string(),
            reason: format!("{reason}. {}", def.note),
        });
    }
    Ok(def)
}

/// The credentials this agent needs, and how each is delivered.
///
/// Computed before anything is created so the reconciler can refuse to start an
/// agent whose credentials are missing, rather than starting one that runs and
/// cannot work.
pub fn requirements(spec: &AgentSpec, agent: &str) -> Result<Vec<Requirement>, PlanError> {
    let h = resolve_harness(spec)?;
    let mut reqs = vec![Requirement {
        key: CredentialKey::new(format!("nsec/{agent}")),
        // The agent's Nostr identity. Necessarily an env var: buzz-acp reads
        // BUZZ_PRIVATE_KEY at startup and there is no file or helper form.
        delivery: Delivery::Env { var: "BUZZ_PRIVATE_KEY".into() },
        purpose: "the agent's Nostr identity; without it it cannot join the relay at all",
    }];

    // The model-provider credential for this harness. The first name in the
    // catalog's list is the preferred one.
    if let Some(var) = h.credential_env.first() {
        reqs.push(Requirement {
            key: CredentialKey::new(format!("harness/{}", h.id)),
            delivery: Delivery::Env { var: (*var).to_string() },
            purpose: "the model provider credential; without it the agent joins and cannot think",
        });
    }

    // MCP credentials. On Claude these go through the broker and never enter the
    // container; everywhere else they must be injected.
    for m in &spec.mcp {
        let Some(key) = &m.credential else { continue };
        reqs.push(Requirement {
            key: CredentialKey::new(key.clone()),
            delivery: if h.id == "claude" {
                Delivery::Broker { socket: BROKER_SOCKET_IN_CONTAINER.into() }
            } else {
                Delivery::Env { var: mcp_token_env(&m.name) }
            },
            purpose: "an MCP server credential; without it the agent starts without that tool",
        });
    }
    Ok(reqs)
}

/// The environment variable a non-Claude harness reads an MCP token from.
///
/// Derived from the server name so two servers cannot collide. Codex's
/// `bearer_token_env_var` names this rather than embedding the value.
pub fn mcp_token_env(server: &str) -> String {
    format!(
        "HIVE_MCP_{}",
        server.to_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    )
}

/// Compute the container environment for an agent.
///
/// Secrets are NOT included — the caller merges those in from the broker, so
/// this function stays pure and testable and never handles a credential.
pub fn environment(spec: &AgentSpec, h: &HarnessDef, agent: &str) -> Result<BTreeMap<String, String>, PlanError> {
    let mut env = BTreeMap::new();

    env.insert("BUZZ_RELAY_URL".into(), spec.identity.relay_url.clone());

    // Owner attestation. NIP-OA is preferred: the agent then derives relay
    // access from its owner's membership (NIP-AA virtual membership) instead of
    // needing its own enrollment.
    match (&spec.identity.auth_tag, &spec.identity.owner_pubkey) {
        (Some(tag), _) => {
            env.insert("BUZZ_AUTH_TAG".into(), tag.clone());
        }
        (None, Some(owner)) => {
            env.insert("BUZZ_ACP_AGENT_OWNER".into(), owner.clone());
        }
        // Without either, the harness starts, connects, and responds to nobody.
        // It looks completely healthy. Validation rejects this too; this is the
        // second gate, because the cost of missing it is hours.
        (None, None) => return Err(PlanError::NoOwner(agent.to_string())),
    }

    env.insert("BUZZ_ACP_AGENT_COMMAND".into(), h.command.to_string());
    if !h.args.is_empty() {
        env.insert("BUZZ_ACP_AGENT_ARGS".into(), h.args.join(" "));
    }

    let cfg = &spec.agent;

    if let Some(m) = &cfg.model {
        // Per-harness normalisation. Claude rejects `opus[1m]`; codex's
        // `[high]` suffix is reasoning depth and must survive.
        env.insert("BUZZ_ACP_MODEL".into(), h.normalize_model(m).to_string());
    }
    if let Some(p) = &cfg.system_prompt {
        env.insert("BUZZ_ACP_SYSTEM_PROMPT".into(), p.clone());
    }
    if let Some(n) = cfg.parallelism {
        // The in-process harness pool: one slot per concurrent CHANNEL, not per
        // subagent. Set too high, every slot runs `initialize` at startup and
        // they time out together — an agent that never answers, with nothing in
        // the logs that looks like an error.
        env.insert("BUZZ_ACP_AGENTS".into(), n.to_string());
    }
    if let Some(t) = cfg.idle_timeout {
        // NOT BUZZ_ACP_TURN_TIMEOUT: that is a deprecated alias which idle
        // timeout overrides when both are set. It warns at startup and is easy
        // to leave in place for months believing it does something.
        env.insert("BUZZ_ACP_IDLE_TIMEOUT".into(), t.to_string());
    }
    if let Some(t) = cfg.max_turn_duration {
        env.insert("BUZZ_ACP_MAX_TURN_DURATION".into(), t.to_string());
    }
    if let Some(r) = &cfg.respond_to {
        env.insert("BUZZ_ACP_RESPOND_TO".into(), r.clone());
        // The harness REFUSES TO START if --respond-to is outside this list.
        // Pinning it to exactly what the spec asked for means a mutated
        // environment cannot quietly widen who may trigger the agent: the
        // container fails to boot instead, which is loud and attributable.
        env.insert("BUZZ_ACP_ALLOWED_RESPOND_TO".into(), r.clone());
    }
    if !cfg.respond_to_allowlist.is_empty() {
        env.insert(
            "BUZZ_ACP_RESPOND_TO_ALLOWLIST".into(),
            cfg.respond_to_allowlist.join(","),
        );
    }
    if cfg.observer {
        // Defaults to FALSE in the harness. A local agent is observed over
        // stdio; a container has no stdio to observe, so without this a remote
        // agent works perfectly while appearing to do nothing at all.
        env.insert("BUZZ_ACP_RELAY_OBSERVER".into(), "true".into());
    }

    // Operator-supplied, validated non-secret. Last so a spec can override a
    // computed default deliberately — but validation refuses the state-directory
    // variables, which are load-bearing and not the operator's to change.
    for (k, v) in &spec.env {
        env.insert(k.clone(), v.clone());
    }
    Ok(env)
}

/// Files to inject between create and start.
pub fn config_files(spec: &AgentSpec, h: &HarnessDef) -> Result<Vec<InjectFile>, PlanError> {
    let servers: Vec<McpServer> = spec
        .mcp
        .iter()
        .map(|m| McpServer {
            name: m.name.clone(),
            transport: match m.transport {
                hive_spec::McpTransport::Http => {
                    Transport::Http { url: m.url.clone().unwrap_or_default() }
                }
                hive_spec::McpTransport::Stdio => Transport::Stdio {
                    command: m.command.clone().unwrap_or_default(),
                    args: m.args.clone(),
                },
            },
            auth: match (&m.credential, h.id) {
                (None, _) => Auth::None,
                // The secret never lands in the container: Claude asks the
                // broker for headers per connection.
                (Some(_), "claude") => Auth::Helper { program: HEADERS_HELPER.into() },
                // Names the variable; the value is in the environment but not
                // in the file, so the config stays readable and diffable.
                (Some(_), _) => Auth::BearerFromEnv { var: mcp_token_env(&m.name) },
            },
        })
        .collect();

    Ok(mcp::render(h, &servers, "")?
        .map(|f| InjectFile::for_agent(f.path, f.contents.into_bytes(), f.mode))
        .into_iter()
        .collect())
}

/// Assemble the full container plan.
///
/// `secrets` are the resolved credential values, keyed by environment variable
/// name. They are merged last and are the only secrets this function sees.
pub fn container_plan(
    spec: &AgentSpec,
    agent: &str,
    image: &str,
    secrets: BTreeMap<String, String>,
    broker_socket_dir: Option<&std::path::PathBuf>,
) -> Result<ContainerPlan, PlanError> {
    let h = resolve_harness(spec)?;
    let mut env = environment(spec, h, agent)?;
    env.extend(secrets);

    let mut volumes = standard_volumes(agent);
    // Mounted only when this agent actually has broker-delivered credentials.
    // An unnecessary socket in the container is one more thing reachable by
    // model-authored code.
    if h.id == "claude" && spec.mcp.iter().any(|m| m.credential.is_some()) {
        if let Some(dir) = broker_socket_dir {
            volumes.push(broker_mount(agent, dir));
        }
    }

    Ok(ContainerPlan {
        name: Names::container(agent),
        image: image.to_string(),
        // The container runs buzz-acp, which spawns the harness named by
        // BUZZ_ACP_AGENT_COMMAND. The image's ENTRYPOINT wraps this to create
        // state directories first.
        command: vec!["buzz-acp".into()],
        env,
        labels: labels_for(agent, &spec.hash(), h.id),
        network: Names::network(agent),
        volumes,
        memory: spec.resources.memory.clone(),
        cpus: spec.resources.cpus,
        pids_limit: spec.resources.pids,
        inject: config_files(spec, h)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_toml(extra: &str) -> AgentSpec {
        let base = format!(
            r#"
[identity]
pubkey = "{p}"
relay_url = "wss://relay.example"
owner_pubkey = "{p}"

[harness]
id = "claude"
{extra}
"#,
            p = "a".repeat(64),
            extra = extra
        );
        AgentSpec::from_toml(&base).expect("valid spec")
    }

    #[test]
    fn observer_is_turned_on_explicitly_because_the_harness_defaults_it_off() {
        // BUZZ_ACP_RELAY_OBSERVER has default_value_t = false upstream. A
        // container has no stdio to observe, so without this the agent works
        // and appears to do nothing.
        let s = spec_toml("");
        let h = resolve_harness(&s).unwrap();
        let env = environment(&s, h, "alice").unwrap();
        assert_eq!(env.get("BUZZ_ACP_RELAY_OBSERVER").map(String::as_str), Some("true"));
    }

    #[test]
    fn idle_timeout_uses_the_current_name_not_the_deprecated_alias() {
        // BUZZ_ACP_TURN_TIMEOUT is a deprecated alias that idle-timeout
        // overrides. Setting only the alias warns at startup and is easy to
        // believe in for months.
        let s = spec_toml("\n[agent]\nidle_timeout = 300\n");
        let h = resolve_harness(&s).unwrap();
        let env = environment(&s, h, "alice").unwrap();
        assert_eq!(env.get("BUZZ_ACP_IDLE_TIMEOUT").map(String::as_str), Some("300"));
        assert!(!env.contains_key("BUZZ_ACP_TURN_TIMEOUT"));
    }

    #[test]
    fn respond_to_is_also_pinned_as_the_allowed_set() {
        // BUZZ_ACP_ALLOWED_RESPOND_TO makes the harness refuse to start if the
        // mode is outside it. Pinning both means a mutated environment cannot
        // silently widen who can trigger the agent.
        let s = spec_toml("\n[agent]\nrespond_to = \"owner-only\"\n");
        let h = resolve_harness(&s).unwrap();
        let env = environment(&s, h, "alice").unwrap();
        assert_eq!(env.get("BUZZ_ACP_RESPOND_TO").map(String::as_str), Some("owner-only"));
        assert_eq!(env.get("BUZZ_ACP_ALLOWED_RESPOND_TO").map(String::as_str), Some("owner-only"));
    }

    #[test]
    fn an_auth_tag_is_preferred_over_a_bare_owner_pubkey() {
        // NIP-OA lets the agent derive relay access from its owner's membership
        // rather than needing its own enrollment.
        let mut s = spec_toml("");
        s.identity.auth_tag = Some("[\"auth\",\"owner\",\"cond\",\"sig\"]".into());
        let h = resolve_harness(&s).unwrap();
        let env = environment(&s, h, "alice").unwrap();
        assert!(env.contains_key("BUZZ_AUTH_TAG"));
        assert!(!env.contains_key("BUZZ_ACP_AGENT_OWNER"), "both would be ambiguous");
    }

    #[test]
    fn an_agent_with_no_owner_is_refused_rather_than_silently_idle() {
        let mut s = spec_toml("");
        s.identity.owner_pubkey = None;
        s.identity.auth_tag = None;
        let h = harness::lookup("claude").unwrap();
        assert!(matches!(environment(&s, h, "alice"), Err(PlanError::NoOwner(_))));
    }

    #[test]
    fn refused_harnesses_explain_themselves() {
        let mut s = spec_toml("");
        s.harness.id = Some("openclaw".into());
        let err = resolve_harness(&s).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Gateway"), "error should say why: {msg}");
    }

    #[test]
    fn unknown_harnesses_list_the_ones_that_exist() {
        let mut s = spec_toml("");
        s.harness.id = Some("nonesuch".into());
        let msg = resolve_harness(&s).unwrap_err().to_string();
        assert!(msg.contains("grok") && msg.contains("claude"), "got: {msg}");
    }

    #[test]
    fn the_nsec_is_always_required_before_anything_starts() {
        // Without it the agent cannot join the relay at all — better to refuse
        // to deploy than to deploy something inert.
        let s = spec_toml("");
        let reqs = requirements(&s, "alice").unwrap();
        assert!(reqs.iter().any(|r| r.key.as_str() == "nsec/alice"));
    }

    #[test]
    fn claude_mcp_credentials_go_through_the_broker_and_others_do_not() {
        // The honest asymmetry: only Claude has a per-connection helper hook.
        let mut s = spec_toml("");
        s.mcp.push(hive_spec::Mcp {
            name: "parachute".into(),
            transport: hive_spec::McpTransport::Http,
            url: Some("https://vault.example/mcp".into()),
            command: None,
            args: vec![],
            credential: Some("mcp/parachute".into()),
        });

        let claude_reqs = requirements(&s, "alice").unwrap();
        let m = claude_reqs.iter().find(|r| r.key.as_str() == "mcp/parachute").unwrap();
        assert!(matches!(m.delivery, Delivery::Broker { .. }));

        s.harness.id = Some("codex".into());
        let codex_reqs = requirements(&s, "alice").unwrap();
        let m = codex_reqs.iter().find(|r| r.key.as_str() == "mcp/parachute").unwrap();
        assert!(matches!(m.delivery, Delivery::Env { .. }));
    }

    #[test]
    fn the_broker_socket_is_only_mounted_when_it_is_needed() {
        // An unused socket is one more thing reachable by model-authored code.
        let s = spec_toml("");
        let dir = std::path::PathBuf::from("/run/hive");
        let plan = container_plan(&s, "alice", "img", BTreeMap::new(), Some(&dir)).unwrap();
        assert!(
            !plan.volumes.iter().any(|v| v.target == BROKER_SOCKET_IN_CONTAINER),
            "no MCP credentials, so no socket"
        );
    }

    #[test]
    fn the_spec_hash_reaches_the_container_labels() {
        // The reconciler's entire change-detection rests on this round-trip.
        let s = spec_toml("");
        let plan = container_plan(&s, "alice", "img", BTreeMap::new(), None).unwrap();
        assert_eq!(
            plan.labels.get(crate::backend::LABEL_SPEC_HASH),
            Some(&s.hash())
        );
    }
}
