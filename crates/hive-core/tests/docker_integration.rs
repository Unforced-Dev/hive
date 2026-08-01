//! Integration tests against a real Docker daemon.
//!
//! Gated on `HIVE_DOCKER_TESTS=1` and skipped otherwise, so `cargo test` stays
//! runnable without a daemon. Run them with `./build.sh --docker`.
//!
//! These exist because the unit tests verify what hive *decides*, and every
//! expensive bug on this project has been in what Docker actually *does* —
//! ownership of a volume mountpoint, whether a firewall rule matches, whether an
//! injected file is readable. None of that is observable from a pure function.
//!
//! Note `docker exec` runs as the image's `USER` (agent). Wrapping commands in
//! `su` fails: a non-root user is prompted for a password.
//!
//! Every test cleans up after itself and uses a distinct name prefix, so a
//! failed run leaves at most its own debris.
//!
//! They must run SERIALLY (`--test-threads=1`, which `build.sh --docker` sets).
//! They share one Docker daemon, and `list()` observes global state — every
//! hive-managed container on the box, including ones another test is mid-way
//! through creating. In parallel this fails intermittently for reasons unrelated
//! to the code under test.

use hive_core::backend::*;
use hive_core::docker::{labels_for, DockerBackend};
use std::collections::BTreeMap;

const IMAGE: &str = "hive-agent:latest";

fn enabled() -> bool {
    std::env::var("HIVE_DOCKER_TESTS").as_deref() == Ok("1")
}

fn cleanup(b: &DockerBackend, agent: &str) {
    let _ = b.remove(&Names::container(agent));
    let _ = b.remove_volume(&Names::volume(agent));
    let _ = std::process::Command::new("docker")
        .args(["network", "rm", &Names::network(agent)])
        .output();
}

fn plan_running(
    agent: &str,
    hash: &str,
    inject: Vec<InjectFile>,
    command: Vec<String>,
) -> ContainerPlan {
    ContainerPlan {
        name: Names::container(agent),
        image: IMAGE.into(),
        command,
        env: BTreeMap::from([("HIVE_TEST".into(), "1".into())]),
        labels: labels_for(agent, hash, "claude"),
        network: Names::network(agent),
        volumes: standard_volumes(agent),
        memory: "512m".into(),
        cpus: 1.0,
        pids_limit: 256,
        inject,
    }
}

/// `sleep` rather than a harness: these tests are about the container, not about
/// ACP, and a harness would exit as soon as stdin closed.
fn plan_for(agent: &str, hash: &str, inject: Vec<InjectFile>) -> ContainerPlan {
    plan_running(agent, hash, inject, vec!["sleep".into(), "300".into()])
}

fn bring_up(b: &DockerBackend, plan: &ContainerPlan, agent: &str) {
    // Subnet from hive's pool, avoiding whatever else is on this daemon.
    let used = b.used_subnets().expect("subnets");
    let subnet = hive_core::network::allocate_subnet(hive_core::network::DEFAULT_SUBNET_POOL, &used);
    b.ensure_network(&Names::network(agent), subnet.as_deref()).expect("network");
    b.ensure_volume(&Names::volume(agent)).expect("volume");
    b.create_and_start(plan).expect("create+start");
}

fn exec(container: &str, args: &[&str]) -> String {
    let mut a = vec!["exec", container];
    a.extend_from_slice(args);
    let out = std::process::Command::new("docker").args(&a).output().expect("docker exec");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim()
    .to_string()
}

#[test]
fn injected_credentials_are_readable_by_the_agent_user() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }
    let b = DockerBackend::discover().expect("docker");
    let agent = "itest-inject";
    cleanup(&b, agent);

    let file = InjectFile::for_agent(
        "/home/agent/state/claude/.claude.json",
        br#"{"mcpServers":{}}"#.to_vec(),
        0o600,
    );
    bring_up(&b, &plan_for(agent, "h1", vec![file]), agent);
    let c = Names::container(agent);

    // The actual question: can the agent READ what was injected? Injected as
    // root it cannot, and the harness then starts unauthenticated rather than
    // failing — the most misleading outcome available.
    let stat = exec(&c, &["stat", "-c", "%U:%G %a", "/home/agent/state/claude/.claude.json"]);
    assert!(stat.starts_with("agent:agent"), "wrong ownership: {stat}");
    assert!(stat.ends_with("600"), "wrong mode: {stat}");

    let content = exec(&c, &["cat", "/home/agent/state/claude/.claude.json"]);
    assert!(content.contains("mcpServers"), "agent cannot read its own config: {content}");

    cleanup(&b, agent);
}

#[test]
fn injecting_into_a_new_subdirectory_leaves_it_writable_by_the_agent() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }
    let b = DockerBackend::discover().expect("docker");
    let agent = "itest-injdir";
    cleanup(&b, agent);

    // `docker cp` creates missing parents as root:root. The FILE then has the
    // right ownership inside a directory the agent cannot write, and the harness
    // fails later on its own state rather than on the credential — codex reports
    // "failed to initialize sqlite state runtime", which points at sqlite rather
    // than at a permission bug two layers up.
    let file = InjectFile::for_agent(
        "/home/agent/state/codex/auth.json",
        br#"{"tokens":{"id":"x"}}"#.to_vec(),
        0o600,
    );
    bring_up(&b, &plan_for(agent, "h1", vec![file]), agent);
    let c = Names::container(agent);

    let dir = exec(&c, &["stat", "-c", "%U:%G", "/home/agent/state/codex"]);
    assert!(dir.starts_with("agent:agent"), "parent dir not owned by the agent: {dir}");

    // The actual consequence: can the harness write its own state next to the
    // credential we injected?
    let wrote = exec(
        &c,
        &["sh", "-c", "touch /home/agent/state/codex/state.sqlite && echo ok"],
    );
    assert_eq!(wrote, "ok", "agent cannot write beside its injected credential: {wrote}");

    cleanup(&b, agent);
}

#[test]
fn the_state_volume_is_writable_by_the_agent() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }
    let b = DockerBackend::discover().expect("docker");
    let agent = "itest-state";
    cleanup(&b, agent);
    bring_up(&b, &plan_for(agent, "h1", vec![]), agent);

    // Docker creates a VOLUME mountpoint as root:root regardless of the USER in
    // the Dockerfile, and a fresh named volume inherits it. That made goose panic
    // on its session database and opencode die with EACCES. Regression test.
    let out = exec(
        &Names::container(agent),
        &["sh", "-c", "touch /home/agent/state/probe && echo ok"],
    );
    assert_eq!(out, "ok", "agent cannot write its own state volume: {out}");

    cleanup(&b, agent);
}

#[test]
fn agents_cannot_reach_each_other_even_by_raw_ip() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }
    let b = DockerBackend::discover().expect("docker");
    cleanup(&b, "itest-a");
    cleanup(&b, "itest-b");

    // The peer actually LISTENS. Probing a port nothing is bound to cannot
    // distinguish "blocked" from "nobody home" — both look like a failed
    // connection, so the test would pass on a wide-open network.
    bring_up(
        &b,
        &plan_running(
            "itest-b",
            "h1",
            vec![],
            vec![
                "node".into(),
                "-e".into(),
                "require('http').createServer((_,r)=>r.end('reached')).listen(8080)".into(),
            ],
        ),
        "itest-b",
    );
    bring_up(&b, &plan_for("itest-a", "h1", vec![]), "itest-a");

    // BY RAW IP, not by name. Name resolution failing is not isolation, it is
    // just DNS — a test that probes by name reports success while the network is
    // wide open. This is how the icc=false requirement was found originally.
    let ip = std::process::Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &Names::container("itest-b"),
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .expect("inspect");
    assert!(!ip.is_empty(), "no IP for peer container");

    // Sanity check FIRST: the peer must genuinely be serving, or a negative
    // result below proves nothing. Confirmed from inside the peer, over loopback.
    let self_check = exec(
        &Names::container("itest-b"),
        &["curl", "-s", "-m", "5", "http://127.0.0.1:8080/"],
    );
    assert_eq!(self_check, "reached", "peer is not serving; the isolation result would be vacuous");

    let probe = exec(
        &Names::container("itest-a"),
        &["curl", "-s", "-m", "5", &format!("http://{ip}:8080/")],
    );
    assert!(
        !probe.contains("reached"),
        "peer was REACHABLE across networks — agent isolation is not in effect: {probe}"
    );

    cleanup(&b, "itest-a");
    cleanup(&b, "itest-b");
}

#[test]
fn list_sees_only_hive_containers_and_carries_the_spec_hash() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }
    let b = DockerBackend::discover().expect("docker");
    let agent = "itest-list";
    cleanup(&b, agent);

    // A container hive did NOT create. Reconciliation must be blind to it —
    // otherwise the first pass after a restart deletes whatever else is running
    // on the box.
    let foreign = "itest-foreign-not-hive";
    let _ = std::process::Command::new("docker").args(["rm", "-f", foreign]).output();
    std::process::Command::new("docker")
        .args(["run", "-d", "--name", foreign, IMAGE, "sleep", "120"])
        .output()
        .expect("foreign container");

    bring_up(&b, &plan_for(agent, "deadbeef", vec![]), agent);

    let seen = b.list().expect("list");
    let mine = seen.iter().find(|o| o.agent == agent).expect("own container missing from list");
    assert_eq!(mine.spec_hash, "deadbeef", "spec hash not round-tripped through labels");
    assert!(mine.running);
    assert!(
        !seen.iter().any(|o| o.name == foreign),
        "list returned a container hive does not manage: {seen:?}"
    );

    let _ = std::process::Command::new("docker").args(["rm", "-f", foreign]).output();
    cleanup(&b, agent);
}

#[test]
fn removing_a_container_preserves_its_state_volume() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }
    let b = DockerBackend::discover().expect("docker");
    let agent = "itest-volume";
    cleanup(&b, agent);
    bring_up(&b, &plan_for(agent, "h1", vec![]), agent);

    exec(&Names::container(agent), &["sh", "-c", "echo secret > /home/agent/state/token"]);

    // A spec edit replaces the container. If that took the volume with it, the
    // agent would come back logged out — hours later, for reasons nobody would
    // connect to the edit.
    b.remove(&Names::container(agent)).expect("remove");
    b.create_and_start(&plan_for(agent, "h2", vec![])).expect("recreate");

    let survived = exec(&Names::container(agent), &["cat", "/home/agent/state/token"]);
    assert_eq!(survived, "secret", "state volume did not survive container replacement");

    cleanup(&b, agent);
}

#[test]
fn a_tool_the_agent_installs_survives_container_replacement() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }
    let b = DockerBackend::discover().expect("docker");
    let agent = "itest-tools";
    cleanup(&b, agent);
    bring_up(&b, &plan_for(agent, "h1", vec![]), agent);
    let c = Names::container(agent);

    // Installed the way an agent installs things: into $BUN_INSTALL and into
    // $HOME/.local, the two prefixes real installers pick by default. Written
    // through $HOME/.local rather than the state path directly, because the
    // link is half of what is under test.
    exec(
        &c,
        &[
            "sh",
            "-c",
            "printf '#!/bin/sh\\necho alive\\n' > \"$BUN_INSTALL/bin/faketool\" \
             && printf '#!/bin/sh\\necho alive\\n' > \"$HOME/.local/bin/fakelocal\" \
             && chmod +x \"$BUN_INSTALL/bin/faketool\" \"$HOME/.local/bin/fakelocal\"",
        ],
    );

    // The recreate an agent actually meets: a spec edit, or an ops change to a
    // create-time flag. Credentials and checkouts survive it because they are on
    // the volume; before this, the toolchain that produced them did not, and the
    // agent came back to `bun: command not found` seconds after being told its
    // work was intact.
    b.remove(&c).expect("remove");
    b.create_and_start(&plan_for(agent, "h2", vec![])).expect("recreate");

    // `command -v` rather than a path check: surviving on disk is not the claim,
    // resolving on PATH is.
    let out = exec(&c, &["sh", "-c", "faketool && fakelocal"]);
    assert_eq!(out, "alive\nalive", "agent-installed tools did not survive replacement: {out}");

    cleanup(&b, agent);
}
