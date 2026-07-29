//! `hive` — the command-line interface.
//!
//! Most subcommands work WITHOUT the daemon running. `validate`, `harnesses` and
//! most of `doctor` are offline, because the moment you need them is usually the
//! moment something is not running.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use hive_broker::Broker;
use hive_core::backend::{ContainerBackend, Names};
use hive_core::credential::CredentialKey;
use hive_core::docker::DockerBackend;
use hive_core::harness::CATALOG;
use hive_core::{agent, network};
use hive_spec::AgentSpec;

mod mcp;
mod oauth;

#[derive(Parser)]
#[command(name = "hive", version, about = "Run persistent ACP agents in isolated containers")]
struct Cli {
    #[arg(long, env = "HIVE_CONTROL_SOCKET", default_value = "/run/hive/hived.sock")]
    control_socket: PathBuf,

    #[arg(long, env = "HIVE_SECRETS_DIR", default_value = "/var/lib/hive/secrets")]
    secrets_dir: PathBuf,

    #[arg(long, env = "HIVE_SPEC_DIR", default_value = "/etc/hive/agents")]
    spec_dir: PathBuf,

    #[arg(long, env = "HIVE_IMAGE", default_value = "hive-agent:latest")]
    image: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a spec file without deploying it. Works offline.
    Validate { file: PathBuf },
    /// Which harnesses this build can run, and which it refuses.
    Harnesses,
    /// What the daemon currently believes.
    Status,
    /// Containers hive manages, from Docker directly rather than the daemon.
    Ps,
    /// Recent output from an agent's container.
    Logs {
        agent: String,
        #[arg(long, default_value_t = 100)]
        lines: usize,
    },
    /// Open a shell in an agent's container.
    ///
    /// `--scratch` starts a SEPARATE container from the same image with this
    /// agent's state volume mounted, and no relay connection. That is the one to
    /// use for an interactive login (`codex login`, `claude setup-token`): the
    /// credential lands in the volume and survives, and the reconciler cannot
    /// replace the container underneath you mid-flow. It also works when the
    /// agent itself is crash-looping and `exec` would fail.
    Shell {
        agent: String,
        /// A side container instead of the running agent.
        #[arg(long)]
        scratch: bool,
        /// Command to run instead of an interactive shell.
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Remove an agent's container so the next reconcile recreates it.
    ///
    /// Config and credentials are injected between create and start, so this is
    /// how a harness picks up a credential you added by hand. The state volume
    /// is untouched.
    Restart { agent: String },
    /// Check the things that are usually wrong.
    Doctor,
    /// Manage credentials.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// MCP servers on an agent, and the credentials they need.
    ///
    /// Buzz cannot configure an HTTP MCP server — its `McpServer` is stdio-only
    /// and the provider deploy payload carries no MCP field at all — so this is
    /// where they live.
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Print the firewall rules for hive's whole subnet pool, without applying them.
    ///
    /// Run this ONCE at setup. Every agent's network is allocated from the pool,
    /// so these rules cover every agent that will ever exist — there is no
    /// per-agent firewall step. Pass an agent name to scope the rules to just
    /// that one instead.
    Firewall {
        /// Scope to a single agent's subnet rather than the whole pool.
        #[arg(long)]
        agent: Option<String>,
        /// The host address agents may reach on :443.
        #[arg(long)]
        host_addr: String,
        /// The endpoint is a container's PUBLISHED port rather than a host
        /// process, so it is DNAT'd before the filter chains and needs
        /// conntrack matching.
        #[arg(long)]
        published: bool,
    },
}

#[derive(Subcommand)]
enum McpCmd {
    /// Show the MCP servers configured on an agent.
    List {
        #[arg(long)]
        agent: String,
    },
    /// Attach an HTTP MCP server. Re-running with the same name updates it
    /// rather than adding a second block the harness would resolve arbitrarily.
    Add {
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        agent: String,
        /// Broker key holding its credential. Defaults to `mcp/<name>`.
        #[arg(long)]
        credential: Option<String>,
        /// Restrict the agent to these tools. Empty means all of them.
        #[arg(long)]
        tool: Vec<String>,
    },
    /// Detach an MCP server. Its stored credential is left alone.
    Rm {
        name: String,
        #[arg(long)]
        agent: String,
    },
    /// Walk the OAuth flow for an attached server and store the result.
    ///
    /// Prefer this over `secret put` with a hand-minted token: the credential is
    /// scoped to what the resource advertises and comes with a refresh token, so
    /// it does not lapse mid-conversation.
    Login {
        name: String,
        #[arg(long)]
        agent: String,
        /// Comma- or space-separated. Defaults to every scope the resource
        /// advertises — narrowing is deliberate, because a token that silently
        /// lacks write fails at the first write tool call rather than here.
        #[arg(long)]
        scope: Option<String>,
        /// Print the URL without trying to launch a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Exchange a stored refresh token for a fresh access token.
    ///
    /// Rarely needed by hand — it exists so an expired credential can be
    /// renewed without walking the browser flow again, and so the same code
    /// path is exercised outside the broker.
    Refresh {
        name: String,
        #[arg(long)]
        agent: String,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a credential. Value is read from stdin so it never lands in shell
    /// history or in the process table.
    Put { key: String },
    List,
    Rm { key: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Validate { file } => validate(file),
        Command::Harnesses => harnesses(),
        Command::Status => status(&cli.control_socket),
        Command::Ps => ps(),
        Command::Logs { agent, lines } => logs(agent, *lines),
        Command::Shell { agent, scratch, cmd } => {
            shell(agent, *scratch, cmd, &cli.image, &cli.spec_dir)
        }
        Command::Restart { agent } => restart(agent),
        Command::Doctor => doctor(&cli),
        Command::Secret(c) => secret(&cli.secrets_dir, c),
        Command::Mcp(c) => match c {
            McpCmd::List { agent } => mcp::list(&cli.spec_dir, &agent),
            McpCmd::Add { name, url, agent, credential, tool } => {
                mcp::add(&cli.spec_dir, &agent, &name, &url, credential.as_deref(), &tool)
            }
            McpCmd::Rm { name, agent } => mcp::rm(&cli.spec_dir, &agent, &name),
            McpCmd::Refresh { name, agent } => mcp::refresh(&cli.spec_dir, &cli.secrets_dir, &agent, &name),
            McpCmd::Login { name, agent, scope, no_browser } => mcp::login(
                &cli.spec_dir,
                &cli.secrets_dir,
                &agent,
                &name,
                scope.as_deref(),
                !no_browser,
            ),
        },
        Command::Firewall { agent, host_addr, published } => {
            firewall(agent.as_deref(), host_addr, *published)
        }
    }
}

fn validate(file: &PathBuf) -> Result<()> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("reading {}", file.display()))?;
    let spec = AgentSpec::from_toml(&text).context("parsing spec")?;
    let report = spec.validate();

    for w in &report.warnings {
        println!("warning: {w}");
    }
    for e in &report.errors {
        println!("error:   {e}");
    }

    // Resolving the harness is a second, independent gate: a spec can be
    // structurally valid and name a harness this build deliberately refuses.
    let name = file.file_stem().and_then(|s| s.to_str()).unwrap_or("agent");
    match agent::resolve_harness(&spec) {
        Ok(h) => println!("harness: {} ({})", h.id, h.label),
        Err(e) => println!("error:   {e}"),
    }
    match agent::requirements(&spec, name) {
        Ok(reqs) => {
            println!("\ncredentials required:");
            for r in reqs {
                let how = match &r.delivery {
                    hive_core::credential::Delivery::Env { var } => {
                        format!("env {var} (visible to `docker inspect`)")
                    }
                    hive_core::credential::Delivery::File { path, .. } => {
                        format!("file {}", path.display())
                    }
                    hive_core::credential::Delivery::Broker { .. } => {
                        "broker socket (never enters the container)".to_string()
                    }
                };
                println!("  {:<24} {}", r.key.as_str(), how);
            }
        }
        Err(e) => println!("error:   {e}"),
    }

    if report.errors.is_empty() {
        println!("\nspec is valid  (hash {})", spec.hash());
        Ok(())
    } else {
        bail!("{} error(s)", report.errors.len())
    }
}

fn harnesses() -> Result<()> {
    println!("{:<10} {:<16} {}", "ID", "LABEL", "INVOCATION");
    for h in CATALOG {
        let inv = if h.args.is_empty() {
            h.command.to_string()
        } else {
            format!("{} {}", h.command, h.args.join(" "))
        };
        if h.is_available() {
            println!("{:<10} {:<16} {inv}", h.id, h.label);
        } else {
            // Listed rather than hidden: selecting one should produce a reason,
            // not "No such file or directory" from inside buzz-acp.
            println!("{:<10} {:<16} NOT INSTALLED — {}", h.id, h.label, h.unsupported.unwrap());
        }
    }
    Ok(())
}

fn control(socket: &PathBuf, request: &str) -> Result<String> {
    let stream = UnixStream::connect(socket).with_context(|| {
        format!("cannot reach hived at {}. Is the daemon running?", socket.display())
    })?;
    let mut w = &stream;
    writeln!(w, "{request}")?;
    w.flush()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn status(socket: &PathBuf) -> Result<()> {
    let resp = control(socket, r#"{"op":"status"}"#)?;
    let v: serde_json::Value = serde_json::from_str(&resp).context("parsing daemon response")?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

fn ps() -> Result<()> {
    // Straight from Docker, not from the daemon: when they disagree, the
    // daemon's view is the one that is wrong, and this is how you see that.
    let backend = DockerBackend::discover()?;
    let containers = backend.list()?;
    if containers.is_empty() {
        println!("no hive-managed containers");
        return Ok(());
    }
    println!("{:<16} {:<10} {:<9} {:<18} {}", "AGENT", "RUNNING", "RESTARTS", "SPEC HASH", "CONTAINER");
    for c in containers {
        println!(
            "{:<16} {:<10} {:<9} {:<18} {}",
            c.agent, c.running, c.restarts, c.spec_hash, c.name
        );
    }
    Ok(())
}

fn logs(agent: &str, lines: usize) -> Result<()> {
    let backend = DockerBackend::discover()?;
    print!("{}", backend.logs(&Names::container(agent), lines)?);
    Ok(())
}

/// Replace this process with `docker`, so the terminal is genuinely interactive.
///
/// `exec` rather than spawn-and-wait: an interactive login needs a real TTY with
/// working job control and signal handling, and a wrapper process in between
/// breaks Ctrl-C in ways that are maddening to debug.
/// `-i` always, `-t` only when stdin really is a terminal.
///
/// Passing `-t` without one fails outright — "cannot attach stdin to a
/// TTY-enabled container" — which breaks `hive shell agent -- cmd` in scripts
/// and over non-interactive SSH, the two places you most want it.
fn tty_flags() -> Vec<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        vec!["-i".into(), "-t".into()]
    } else {
        vec!["-i".into()]
    }
}

fn exec_docker(args: Vec<String>) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new("docker").args(&args).exec();
    bail!("could not exec docker: {err}")
}

/// Best-effort spec load. A missing or invalid spec must not stop you getting a
/// shell — that is very often the situation you need the shell to diagnose.
fn load_spec(spec_dir: &PathBuf, agent: &str) -> Option<AgentSpec> {
    let text = std::fs::read_to_string(spec_dir.join(format!("{agent}.toml"))).ok()?;
    AgentSpec::from_toml(&text).ok()
}

fn shell(
    agent: &str,
    scratch: bool,
    cmd: &[String],
    image: &str,
    spec_dir: &PathBuf,
) -> Result<()> {
    let container = Names::container(agent);
    let shell_cmd: Vec<String> = if cmd.is_empty() {
        vec!["bash".into()]
    } else {
        cmd.to_vec()
    };

    if !scratch {
        let mut args = vec!["exec".to_string()];
        args.extend(tty_flags());
        args.push(container.clone());
        args.extend(shell_cmd);
        return exec_docker(args);
    }

    // A side container sharing the agent's state volume. Notably it does NOT
    // carry the agent's identity or model credentials: this is for logging in
    // and looking around, not for impersonating the agent. Anything written
    // under /home/agent/state persists and the agent picks it up on its next
    // start — `hive restart <agent>` forces that.
    let mut args: Vec<String> = vec!["run".into(), "--rm".into()];
    args.extend(tty_flags());
    args.extend([
        "-v".into(),
        format!("{}:/home/agent/state", Names::volume(agent)),
        // Shares the agent's network, so anything reachable from the agent is
        // reachable here — and nothing else is.
        "--network".into(),
        Names::network(agent),
        "--entrypoint".into(),
        "/usr/local/bin/hive-entrypoint".into(),
    ]);

    // Mount the agent's shared volumes too. Without these you are looking at a
    // DIFFERENT filesystem than the agent sees, which is worse than no shell at
    // all: you would debug a working tree the agent never had.
    if let Some(spec) = load_spec(spec_dir, agent) {
        for v in &spec.volumes {
            args.push("-v".into());
            let ro = if v.read_only { ":ro" } else { "" };
            args.push(format!("{}:{}{}", v.name, v.target, ro));
        }
    }

    args.push(image.to_string());
    args.extend(shell_cmd);

    eprintln!("scratch container on {}'s state volume.", agent);
    eprintln!("anything you write under /home/agent/state persists;");
    eprintln!("run `hive restart {agent}` afterwards so the harness picks it up.\n");
    exec_docker(args)
}

fn restart(agent: &str) -> Result<()> {
    let backend = DockerBackend::discover()?;
    // Removed, not restarted. Config and credentials are injected between create
    // and start, so `docker restart` would reuse whatever was injected last
    // time — which after a credential rotation is a stale secret.
    backend.remove(&Names::container(agent))?;
    println!("removed {}; hived will recreate it on its next pass", Names::container(agent));
    Ok(())
}

fn secret(dir: &PathBuf, cmd: &SecretCmd) -> Result<()> {
    let broker = Broker::open(dir)?;
    match cmd {
        SecretCmd::Put { key } => {
            // From stdin, never an argument: arguments appear in shell history
            // and in `ps` output for every user on the box.
            //
            // read_to_end, NOT read_line. Credentials are routinely multi-line —
            // codex's auth.json is pretty-printed JSON — and reading one line
            // stored a single "{" that looked like a success and failed much
            // later as an unrelated harness error.
            let mut value = Vec::new();
            std::io::stdin().read_to_end(&mut value)?;
            // Trailing whitespace only: internal newlines are part of a JSON
            // credential and must survive.
            while value.last().is_some_and(|b| b.is_ascii_whitespace()) {
                value.pop();
            }
            if value.is_empty() {
                bail!("refusing to store an empty credential for '{key}'");
            }
            broker.put(&CredentialKey::new(key.clone()), &value)?;
            println!("stored {key} ({} bytes)", value.len());
        }
        SecretCmd::List => {
            // Names only. There is no subcommand that prints a stored value:
            // the broker hands secrets to agents, not to terminals.
            for k in broker.list()? {
                println!("{k}");
            }
        }
        SecretCmd::Rm { key } => {
            broker.remove(&CredentialKey::new(key.clone()))?;
            println!("removed {key}");
        }
    }
    Ok(())
}

fn firewall(agent: Option<&str>, host_addr: &str, published: bool) -> Result<()> {
    // Default to the POOL. Per-agent rules were the original design and it was
    // wrong: Docker assigns an arbitrary subnet per network, so every new agent
    // needed its own rules, and an agent whose rules were missing reached the
    // public internet but never the relay — alive-looking and silent. Allocating
    // from a pool means these rules are written once and cover every agent.
    let subnet = match agent {
        None => network::DEFAULT_SUBNET_POOL.to_string(),
        Some(a) => {
            // The subnet must come from Docker; guessing produces rules that
            // apply to nothing while reading as correct.
            let net = Names::network(a);
            let out = std::process::Command::new("docker")
                .args(["network", "inspect", &net, "--format",
                       "{{range .IPAM.Config}}{{.Subnet}}{{end}}"])
                .output()?;
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                bail!("network {net} has no subnet; does the agent exist?");
            }
            s
        }
    };

    let allow = if published {
        network::Allowed::PublishedPort {
            addr: host_addr.to_string(),
            port: 443,
            container_port: 443,
        }
    } else {
        network::Allowed::HostProcess { addr: host_addr.to_string(), port: 443 }
    };
    let policy = network::EgressPolicy { subnet: subnet.clone(), allow: vec![allow] };

    match agent {
        None => {
            println!("# egress policy for hive's whole subnet pool ({subnet})");
            println!("# Run this ONCE. Every agent network is allocated from this pool, so");
            println!("# these rules cover every agent that will ever exist.");
        }
        Some(a) => println!("# egress policy for {a} only ({subnet})"),
    }
    println!("# review before running; hive does not touch your firewall for you.\n");
    for r in policy.rules() {
        println!("# {}", r.why);
        println!("{r}\n");
    }
    println!("# verify with — and read the PACKET COUNTERS, not just the rules:");
    for c in policy.verify_commands() {
        println!("#   {c}");
    }
    Ok(())
}

fn doctor(cli: &Cli) -> Result<()> {
    let problems = std::cell::Cell::new(0);
    let check = |ok: bool, label: &str, detail: &str| {
        if ok {
            println!("  ok    {label}");
        } else {
            problems.set(problems.get() + 1);
            println!("  FAIL  {label}\n        {detail}");
        }
    };

    println!("docker");
    match DockerBackend::discover() {
        Ok(b) => {
            check(true, "CLI found", "");
            match b.list() {
                Ok(cs) => check(true, &format!("daemon reachable ({} hive containers)", cs.len()), ""),
                Err(e) => check(false, "daemon reachable", &e.to_string()),
            }
        }
        Err(e) => check(false, "CLI found", &e.to_string()),
    }

    println!("\nimage");
    let img = std::process::Command::new("docker")
        .args(["image", "inspect", &cli.image])
        .output();
    let have_image = img.map(|o| o.status.success()).unwrap_or(false);
    check(
        have_image,
        &format!("{} present", cli.image),
        "build it with images/agent/build.sh",
    );
    if have_image {
        // The harness manifest is written from the RUNNING image at build time,
        // so it reports what is installed rather than what was requested.
        let out = std::process::Command::new("docker")
            .args(["run", "--rm", "--entrypoint", "cat", &cli.image, "/etc/hive/harnesses.json"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                println!("        {}", String::from_utf8_lossy(&o.stdout).replace('\n', " "));
            }
            _ => println!("        (no /etc/hive/harnesses.json — image predates the manifest)"),
        }
    }

    println!("\nkernel");
    // THE isolation check. Without br_netfilter, agent-to-agent traffic on a
    // shared bridge never reaches iptables, and no firewall rule can block it.
    // hive puts every agent on its own network with icc disabled, which is what
    // makes this survivable — but it is worth knowing which world you are in.
    let br_netfilter = PathBuf::from("/proc/sys/net/bridge").exists();
    if br_netfilter {
        println!("  ok    br_netfilter present (bridge traffic traverses iptables)");
    } else {
        println!(
            "  note  br_netfilter ABSENT — no iptables rule can block container-to-container\n\
             \x20       traffic on a shared bridge. hive gives each agent its own network with\n\
             \x20       com.docker.network.bridge.enable_icc=false, which is the only control\n\
             \x20       that works here. Verify by probing a peer by RAW IP, never by name."
        );
    }

    println!("\nfirewall");
    // The failure this catches: an agent reaches the public internet but never
    // the relay, so it looks alive and simply never connects. Without a rule for
    // the pool, that is what every new agent does.
    let rules = std::process::Command::new("iptables")
        .args(["-L", "INPUT", "-n"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let pool_prefix = network::DEFAULT_SUBNET_POOL.trim_end_matches("0.0/16");
    if rules.contains(pool_prefix) {
        println!("  ok    rules present for the agent subnet pool ({})", network::DEFAULT_SUBNET_POOL);
    } else if rules.is_empty() {
        println!("  note  could not read iptables (need root?) — cannot verify egress rules");
    } else {
        problems.set(problems.get() + 1);
        println!(
            "  FAIL  no rules for the agent subnet pool ({})\n\
             \x20       Agents will reach the public internet but NOT your relay, which\n\
             \x20       looks like a working agent that never connects. Fix once with:\n\
             \x20         hive firewall --host-addr <your-host-ip> | grep '^iptables' | sh",
            network::DEFAULT_SUBNET_POOL
        );
    }

    println!("\npaths");
    check(
        cli.spec_dir.exists(),
        &format!("spec dir {}", cli.spec_dir.display()),
        "create it, or pass --spec-dir",
    );
    match Broker::open(&cli.secrets_dir) {
        Ok(b) => {
            let n = b.list().map(|l| l.len()).unwrap_or(0);
            check(true, &format!("secret store ({n} credentials)"), "");
        }
        Err(e) => check(false, "secret store", &e.to_string()),
    }
    check(
        cli.control_socket.exists(),
        "hived control socket",
        "the daemon is not running; most other commands still work",
    );

    if problems.get() == 0 {
        println!("\nno problems found");
        Ok(())
    } else {
        bail!("{} problem(s) found", problems.get())
    }
}
