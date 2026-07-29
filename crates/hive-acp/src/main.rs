//! `hive-acp` — run an ACP harness inside a container, and get out of the way.
//!
//! # What this is for
//!
//! Buzz has two extension seams, and which one hive occupies decides a lot.
//!
//! As a **backend provider** ("where to run"), hive competes with Buzz's own
//! notion of location — which is why the desktop shim had to reimplement remote
//! deployment over ssh. As a **harness**, `harness=hive` composes with whatever
//! Buzz already does about location: local, a remote provider, or this box
//! acting as a provider for a laptop. Location stays Buzz's axis; the
//! environment becomes hive's.
//!
//! So this is a Tier-3 custom harness (BYOH, buzz v0.5.0). `buzz-acp` spawns it
//! exactly as it would spawn `claude-agent-acp`, and it speaks ACP on stdio.
//! Below, it runs the real harness inside that agent's container — with hive's
//! isolation, MCP servers and broker-held credentials already in place.
//!
//! # Why it does not parse the protocol
//!
//! It could: intercept `initialize`, route by session id, and gain the ability
//! to switch harnesses mid-conversation. That is a real feature and it is not
//! this.
//!
//! Everything that would justify parsing is already decided before the first
//! byte moves. The agent is known from `HIVE_AGENT`, its harness from its spec,
//! its credentials and MCP servers from hived. There is nothing left to choose,
//! so there is nothing to intercept — and a proxy that re-frames JSON-RPC it
//! does not need to read is a proxy that can corrupt a stream it was only
//! supposed to carry. ACP's framing is also not something to assume: a byte
//! pipe is correct whether messages are newline-delimited or length-prefixed,
//! and stays correct when that changes.
//!
//! The moment routing between several backends is wanted, this becomes a real
//! router. Until then, being a pipe is the feature.

use std::io::{Read, Write};
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
}

/// Resolve everything from the agent name plus its spec.
///
/// The harness is read from the spec rather than from an environment variable
/// because the spec is what hived reconciled the container from. Taking it from
/// the environment would let the two disagree — and the symptom would be a
/// harness that starts, answers `initialize`, and has none of the credentials
/// the container was built for.
fn resolve() -> Result<Config> {
    let agent = std::env::var("HIVE_AGENT").ok().filter(|s| !s.is_empty()).context(
        "HIVE_AGENT is not set. hive-acp runs one specific agent's harness; set it in the \
         harness definition's env, or per-agent in Buzz's agent environment variables.",
    )?;

    let spec_dir =
        std::env::var("HIVE_SPEC_DIR").unwrap_or_else(|_| "/etc/hive/agents".to_string());
    let path = std::path::Path::new(&spec_dir).join(format!("{agent}.toml"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} — has this agent been deployed?", path.display()))?;
    let spec: AgentSpec =
        toml::from_str(&text).with_context(|| format!("{} is not a valid agent spec", path.display()))?;

    // A spec names either a catalog id or an explicit command. The escape hatch
    // is honoured here too: a harness the catalog does not know still runs, it
    // just brings its own image, and refusing it would make hive-acp stricter
    // than hived about the very same spec.
    let argv: Vec<String> = match (&spec.harness.id, &spec.harness.command) {
        (Some(id), _) => {
            let def = CATALOG.iter().find(|h| h.id == id.as_str()).with_context(|| {
                format!(
                    "{agent} names harness {id:?}, which is not in hive's catalog. \
                     `hive harnesses` lists the ids this build knows."
                )
            })?;
            if let Some(reason) = &def.unsupported {
                bail!("harness {id:?} is deliberately absent from the image: {reason:?}");
            }
            let mut v = vec![def.command.to_string()];
            v.extend(def.args.iter().map(|s| s.to_string()));
            v
        }
        (None, Some(cmd)) => cmd.split_whitespace().map(String::from).collect(),
        (None, None) => bail!(
            "{agent} names neither [harness].id nor [harness].command, so there is nothing to run"
        ),
    };

    Ok(Config {
        container: std::env::var("HIVE_CONTAINER").unwrap_or_else(|_| format!("hive-{agent}")),
        agent,
        argv,
    })
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
        "hive-acp: agent={} container={} harness={}",
        cfg.agent,
        cfg.container,
        cfg.argv.join(" ")
    );

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

    let down = std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        let mut stdin = std::io::stdin().lock();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if to_child.write_all(&buf[..n]).is_err() || to_child.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
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
