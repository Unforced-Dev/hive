//! `hived` — the hive daemon.
//!
//! Watches a directory of agent specs and makes reality match them. Composes
//! `hive-core` (which never sees a secret) with `hive-broker` (which is the only
//! thing that does); the wiring lives here so neither crate depends on the other.
//!
//! Deliberately threads and blocking I/O rather than async. The workload is a
//! handful of short-lived `docker` invocations on a timer, plus a socket that
//! sees one request per MCP connection. An async runtime would be a dependency
//! and a source of complexity in exchange for concurrency this does not need.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use hive_broker::{Broker, Grant, ServerKeys};
use hive_core::agent;
use hive_core::backend::{ContainerBackend, Names};
use hive_core::credential::{CredentialSource, Delivery};
use hive_core::docker::DockerBackend;
use hive_core::reconcile::{self, Desired, Readiness};
use hive_spec::AgentSpec;

#[derive(Parser, Debug)]
#[command(name = "hived", version, about = "Run persistent ACP agents in isolated containers")]
struct Args {
    /// Directory of `*.toml` agent specs. The single source of truth.
    #[arg(long, env = "HIVE_SPEC_DIR", default_value = "/etc/hive/agents")]
    spec_dir: PathBuf,

    /// Credential store. Created 0700.
    #[arg(long, env = "HIVE_SECRETS_DIR", default_value = "/var/lib/hive/secrets")]
    secrets_dir: PathBuf,

    /// Per-agent broker sockets. Bind-mounted individually into containers, so
    /// this path must be identical from the Docker daemon's point of view.
    #[arg(long, env = "HIVE_SOCKET_DIR", default_value = "/run/hive")]
    socket_dir: PathBuf,

    /// Control socket for the `hive` CLI.
    #[arg(long, env = "HIVE_CONTROL_SOCKET", default_value = "/run/hive/hived.sock")]
    control_socket: PathBuf,

    #[arg(long, env = "HIVE_IMAGE", default_value = "hive-agent:latest")]
    image: String,

    /// Seconds between reconciliation passes.
    #[arg(long, env = "HIVE_INTERVAL", default_value_t = 30)]
    interval: u64,

    /// Plan and log, change nothing.
    #[arg(long)]
    dry_run: bool,

    /// Run one pass and exit. Useful from a unit file or by hand.
    #[arg(long)]
    once: bool,
}

/// What the daemon knows about each agent, shared with the broker listeners.
#[derive(Default)]
struct Registry {
    agents: HashMap<String, AgentEntry>,
}

#[derive(Clone)]
struct AgentEntry {
    grant: Grant,
    /// MCP server name -> credential key, for the headers helper.
    servers: ServerKeys,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hived=info,hive_core=info,hive_broker=info".into()),
        )
        .init();

    let args = Args::parse();
    std::fs::create_dir_all(&args.socket_dir)
        .with_context(|| format!("creating {}", args.socket_dir.display()))?;
    // The container runs as uid 1001 and must traverse this directory to reach
    // its own socket.
    std::fs::set_permissions(&args.socket_dir, std::fs::Permissions::from_mode(0o755))?;

    let backend = DockerBackend::discover().context(
        "could not find the Docker CLI. hive drives Docker through its CLI so that \
         DOCKER_HOST (including ssh://) works and every operation is a command you can re-run",
    )?;
    let broker = Arc::new(Broker::open(&args.secrets_dir)?);
    let registry = Arc::new(Mutex::new(Registry::default()));

    tracing::info!(spec_dir = %args.spec_dir.display(), image = %args.image, "hived starting");

    {
        let registry = Arc::clone(&registry);
        let path = args.control_socket.clone();
        let spec_dir = args.spec_dir.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve_control(&path, registry, spec_dir) {
                tracing::error!(error = %e, "control socket stopped");
            }
        });
    }

    let mut listeners: BTreeSet<String> = BTreeSet::new();
    let mut last_refresh = std::time::Instant::now() - Duration::from_secs(3600);

    loop {
        // Renew OAuth credentials before they lapse.
        //
        // Parachute issues 15-MINUTE access tokens, and the refresh token was
        // already being STORED with nothing ever using it — so a credential
        // obtained at login was dead a quarter of an hour later and stayed dead.
        //
        // What this does NOT fix: a session holds the token it was given when
        // its MCP connector was created. Renewing the stored credential helps
        // the next connection, not a live one. Claude Code re-runs a
        // headersHelper on 401 and so recovers; anything that took a bare
        // header once does not.
        if last_refresh.elapsed() >= Duration::from_secs(REFRESH_EVERY) {
            last_refresh = std::time::Instant::now();
            refresh_expiring(&args);
        }

        if let Err(e) = pass(&args, &backend, &broker, &registry, &mut listeners) {
            // A failed pass must not kill the daemon: the next one may succeed,
            // and an exited daemon stops reconciling everything else too.
            tracing::error!(error = %e, "reconciliation pass failed");
        }
        if args.once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(args.interval));
    }
}

/// How often to look for credentials worth renewing.
const REFRESH_EVERY: u64 = 120;

/// Renew when this little is left, so a 15-minute token is replaced with
/// minutes to spare rather than at the moment something needs it.
const REFRESH_WHEN_UNDER: i64 = 5 * 60;

/// Seconds until a JWT expires, or `None` if it is not a JWT with an `exp`.
///
/// Opaque tokens are left alone: there is nothing to read, and refreshing one
/// on a timer would spend a rotating refresh token for no reason.
fn seconds_until_expiry(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    // base64url, no padding.
    let mut b = payload.replace('-', "+").replace('_', "/");
    while b.len() % 4 != 0 {
        b.push('=');
    }
    let raw = base64_decode(&b)?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let exp = v.get("exp")?.as_i64()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(exp - now)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Renew every stored OAuth credential that is close to expiring.
///
/// Shells out to the `hive` CLI in this same image rather than reimplementing
/// the flow: it already knows the token endpoint, the client id and the
/// resource, all stored beside the credential at login. Two implementations of
/// an OAuth refresh is one more than anybody wants to keep correct.
fn refresh_expiring(args: &Args) {
    let specs = match load_specs(&args.spec_dir) {
        Ok(s) => s,
        Err(_) => return,
    };
    for (agent, spec) in &specs {
        for m in &spec.mcp {
            let Some(cred) = &m.credential else { continue };
            // A refresh token beside the credential is what makes this possible
            // at all; a hand-placed secret has none and must be left alone.
            let refresh_path = args.secrets_dir.join(format!("{}+refresh", cred.replace('/', "__")));
            if !refresh_path.exists() {
                continue;
            }
            let token_path = args.secrets_dir.join(cred.replace('/', "__"));
            let Ok(tok) = std::fs::read_to_string(&token_path) else { continue };
            match seconds_until_expiry(tok.trim()) {
                Some(left) if left > REFRESH_WHEN_UNDER => continue,
                None => continue,
                Some(left) => {
                    tracing::info!(agent = %agent, server = %m.name, seconds_left = left, "renewing");
                }
            }
            let out = std::process::Command::new("hive")
                .args(["mcp", "refresh", &m.name, "--agent", agent])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    tracing::info!(agent = %agent, server = %m.name, "credential renewed")
                }
                Ok(o) => tracing::warn!(
                    agent = %agent, server = %m.name,
                    error = %String::from_utf8_lossy(&o.stderr).trim(),
                    "renewal failed — the agent will lose this server when the token lapses"
                ),
                Err(e) => tracing::warn!(agent = %agent, error = %e, "could not run `hive mcp refresh`"),
            }
        }
    }
}

/// One reconciliation pass.
fn pass(
    args: &Args,
    backend: &DockerBackend,
    broker: &Arc<Broker>,
    registry: &Arc<Mutex<Registry>>,
    listeners: &mut BTreeSet<String>,
) -> Result<()> {
    let specs = load_specs(&args.spec_dir)?;

    // Update the registry BEFORE anything starts, so a broker listener that
    // receives a request mid-pass answers from current state rather than from
    // the previous pass's grants.
    {
        let mut reg = registry.lock().expect("registry poisoned");
        reg.agents.clear();
        for (name, spec) in &specs {
            let keys: BTreeSet<String> = agent::requirements(spec, name)
                .map(|rs| rs.into_iter().map(|r| r.key.0).collect())
                .unwrap_or_default();
            let servers: ServerKeys = spec
                .mcp
                .iter()
                .filter_map(|m| m.credential.clone().map(|c| (m.name.clone(), c)))
                .collect();
            reg.agents.insert(
                name.clone(),
                AgentEntry { grant: Grant { agent: name.clone(), keys }, servers },
            );
        }
    }

    // A broker listener per agent that has broker-delivered credentials. Started
    // once and left running: the resolver closure consults the registry per
    // request, so a long-lived listener never serves stale grants and a deleted
    // agent is denied rather than served.
    for (name, spec) in &specs {
        let needs_broker = agent::requirements(spec, name)
            .map(|rs| rs.iter().any(|r| matches!(r.delivery, Delivery::Broker { .. })))
            .unwrap_or(false);
        if !needs_broker || listeners.contains(name) {
            continue;
        }
        // One directory per agent, holding one socket. The container mounts the
        // DIRECTORY — see `broker_mount` — so the daemon can recreate this
        // socket on restart without orphaning a running container's mount.
        let agent_dir = args.socket_dir.join(name);
        if let Err(e) = std::fs::create_dir_all(&agent_dir) {
            tracing::error!(agent = %name, error = %e, "cannot create the broker socket directory");
            continue;
        }
        // 0755: the agent container connects as uid 1001 and must traverse it.
        let _ = std::fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o755));
        let socket = agent_dir.join("broker.sock");
        let broker_for_thread = Arc::clone(broker);
        let registry_for_thread = Arc::clone(registry);
        let agent_name = name.clone();
        std::thread::spawn(move || {
            let r = hive_broker::serve(&socket, &broker_for_thread, || {
                let reg = registry_for_thread.lock().ok()?;
                reg.agents.get(&agent_name).map(|e| (e.grant.clone(), e.servers.clone()))
            });
            if let Err(e) = r {
                tracing::error!(agent = %agent_name, error = %e, "broker listener stopped");
            }
        });
        listeners.insert(name.clone());
        tracing::info!(agent = %name, "broker listener started");
    }

    let conflicts = duplicate_identities(&specs);

    // Desired state, with credential readiness resolved up front. An agent whose
    // credentials are missing is HELD rather than started: one that starts
    // without them joins the relay and answers wrongly, which is far harder to
    // attribute than a refusal that names the missing key.
    let mut desired = Vec::new();
    for (name, spec) in &specs {
        let reqs = match agent::requirements(spec, name) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(agent = %name, error = %e, "spec cannot be planned; skipping");
                continue;
            }
        };
        let missing: Vec<String> = reqs
            .iter()
            .filter(|r| !broker.has(&r.key).unwrap_or(false))
            .map(|r| r.key.0.clone())
            .collect();
        desired.push(Desired {
            name: name.clone(),
            spec_hash: spec.hash(),
            // A conflict outranks a missing credential: with two specs claiming
            // one identity, "which credential is missing" is not the question
            // worth answering.
            readiness: if let Some(why) = conflicts.get(name) {
                Readiness::Conflict(why.clone())
            } else if missing.is_empty() {
                Readiness::Ready
            } else {
                Readiness::MissingCredentials(missing)
            },
        });
    }

    let observed = backend.list()?;
    let actions = reconcile::plan(&desired, &observed);
    if actions.is_empty() {
        return Ok(());
    }
    for a in &actions {
        tracing::info!(agent = a.agent(), action = ?a, "planned");
    }
    if args.dry_run {
        return Ok(());
    }

    let outcomes = reconcile::apply(backend, actions, |name| {
        let spec = specs
            .get(name)
            .ok_or_else(|| reconcile::ApplyError::NoPlanFor(name.to_string()))?;
        let secrets = resolve_secrets(broker, spec, name);
        let files = resolve_secret_files(broker, spec, name);
        agent::container_plan(spec, name, &args.image, secrets, &files, Some(&args.socket_dir))
            .map_err(|e| reconcile::ApplyError::NoPlanFor(format!("{name}: {e}")))
    });

    for o in outcomes {
        match &o.error {
            None => tracing::info!(agent = o.action.agent(), action = ?o.action, "applied"),
            Some(e) => tracing::error!(agent = o.action.agent(), error = %e, "failed"),
        }
    }
    Ok(())
}

/// Fetch the credentials that must be injected as environment variables.
///
/// Broker-delivered credentials are deliberately absent: those never enter the
/// container, which is the entire point of the helper.
fn resolve_secrets(broker: &Broker, spec: &AgentSpec, name: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(reqs) = agent::requirements(spec, name) else {
        return out;
    };
    for r in reqs {
        let Delivery::Env { var } = &r.delivery else { continue };
        match broker.fetch(name, &r.key) {
            Ok(secret) => match secret.as_str() {
                // Trimmed: a token read from a file usually carries a trailing
                // newline, which becomes part of the value in the environment
                // and is rejected by whatever consumes it.
                Ok(v) => {
                    out.insert(var.clone(), v.trim().to_string());
                }
                Err(_) => tracing::error!(key = %r.key.0, "credential is not valid UTF-8"),
            },
            // Not fatal here: readiness was checked above, so reaching this means
            // the credential vanished mid-pass. The agent is held on the next
            // pass rather than started half-configured.
            Err(e) => tracing::error!(key = %r.key.0, error = %e, "credential unavailable"),
        }
    }
    out
}

/// Fetch credentials delivered as FILES, keyed by broker key.
///
/// Kept separate from the env path because these are bytes, not strings: codex's
/// auth.json is JSON, and round-tripping it through a String would corrupt any
/// credential that is not valid UTF-8.
fn resolve_secret_files(
    broker: &Broker,
    spec: &AgentSpec,
    name: &str,
) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for f in &spec.files {
        let key = hive_core::credential::CredentialKey::new(f.credential.clone());
        match broker.fetch(name, &key) {
            Ok(secret) => {
                out.insert(f.credential.clone(), secret.expose().to_vec());
            }
            Err(e) => tracing::error!(key = %f.credential, error = %e, "credential file unavailable"),
        }
    }
    out
}

/// Load and validate every spec in the directory.
///
/// An invalid spec is skipped LOUDLY and does not prevent the others from
/// reconciling. One malformed file taking every agent offline is a worse failure
/// than one agent not starting.
fn load_specs(dir: &Path) -> Result<BTreeMap<String, AgentSpec>> {
    let mut out = BTreeMap::new();
    if !dir.exists() {
        tracing::warn!(dir = %dir.display(), "spec directory does not exist yet");
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // The FILE NAME is the agent name. It has to come from somewhere stable,
        // and a name inside the file could disagree with the file it lives in —
        // renaming the file would then silently create a second agent while the
        // first kept running.
        let Some(name) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "cannot read spec");
                continue;
            }
        };
        let spec = match AgentSpec::from_toml(&text) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "invalid spec; skipping");
                continue;
            }
        };
        let report = spec.validate();
        for w in &report.warnings {
            tracing::warn!(agent = %name, "{w}");
        }
        if !report.errors.is_empty() {
            for e in &report.errors {
                tracing::error!(agent = %name, "{e}");
            }
            tracing::error!(agent = %name, "spec rejected; not deploying");
            continue;
        }
        out.insert(name, spec);
    }
    Ok(out)
}

/// Names of specs that put ONE identity on ONE relay twice.
///
/// Sharing an identity across relays is supported and is the point of
/// `identity.credential` — `buzz-acp` takes a scalar relay URL, so the same
/// agent in two communities is legitimately two containers.
///
/// The same pubkey on the SAME relay is different: two processes answer as one
/// agent, so every mention gets two replies, both charged to the owner, and the
/// two turns interleave in the thread. It reads as the model repeating itself
/// rather than as a deployment mistake, which is why this is worth an explicit
/// check. No single spec is wrong, so per-spec validation cannot see it.
///
/// ALL participants are marked rather than picking a winner: they are
/// indistinguishable, and choosing by filename order would make the survivor
/// depend on what the files happen to be called.
///
/// They are HELD, not dropped. Dropping them would make an already-running
/// container look deleted, and the reconciler would tear down an agent that had
/// been working for weeks because someone added a bad new file next to it.
fn duplicate_identities(specs: &BTreeMap<String, AgentSpec>) -> HashMap<String, String> {
    let mut seen: HashMap<(&str, &str), Vec<&str>> = HashMap::new();
    for (name, spec) in specs {
        // Environments have no identity and therefore cannot collide. Treating
        // a missing one as a shared empty key would make every environment spec
        // a duplicate of every other and hold all of them.
        let Some(identity) = &spec.identity else { continue };
        seen.entry((identity.pubkey.as_str(), identity.relay_url.as_str()))
            .or_default()
            .push(name);
    }
    let mut conflicts = HashMap::new();
    for ((pubkey, relay), names) in seen {
        if names.len() > 1 {
            let why = format!(
                "the same identity is deployed to relay {relay} by {}. Each mention \
                 would get one reply per container, all charged to the owner. To run \
                 one identity on SEVERAL relays, give each spec a different relay_url \
                 and point them at one key with identity.credential.",
                names.join(" and ")
            );
            tracing::error!(agents = %names.join(", "), pubkey = %pubkey, relay = %relay, "{why}");
            for n in names {
                conflicts.insert(n.to_string(), why.clone());
            }
        }
    }
    conflicts
}

// ---------------------------------------------------------------------------
// Control socket
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ControlRequest {
    /// What the daemon currently believes.
    Status,
}

fn serve_control(path: &Path, registry: Arc<Mutex<Registry>>, spec_dir: PathBuf) -> Result<()> {
    use std::os::unix::net::UnixListener;

    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    // Owner-only. Unlike the per-agent broker sockets this one is NOT mounted
    // into any container, and nothing unprivileged should reach it.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        let body = match serde_json::from_str::<ControlRequest>(line.trim()) {
            Ok(ControlRequest::Status) => {
                let reg = registry.lock().expect("registry poisoned");
                let agents: Vec<_> = reg
                    .agents
                    .keys()
                    .map(|a| serde_json::json!({ "agent": a, "container": Names::container(a) }))
                    .collect();
                serde_json::json!({ "spec_dir": spec_dir, "agents": agents }).to_string()
            }
            Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
        };
        let _ = writeln!(stream, "{body}");
    }
    Ok(())
}
