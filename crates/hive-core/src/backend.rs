//! The container backend: what hive needs from a runtime, and nothing more.
//!
//! Docker is the only implementation today. The trait exists so that the
//! reconciler can be tested without one, and so a stronger isolation backend
//! (Firecracker, Kata) can be added if the threat model ever demands it — not
//! because a second backend is planned.
//!
//! Deliberately synchronous. Every operation here is a short-lived process
//! invocation, and an async trait would infect the whole crate to save nothing;
//! the daemon calls these from a blocking pool.
//!
//! # The isolation ceiling
//!
//! Docker is a namespace boundary, not a security boundary against hostile code.
//! It is the right tool for "my own agents, which I do not want reaching each
//! other or my network" and the wrong tool for running code from someone who
//! wants in. Nothing in this module changes that, and the README should not
//! imply otherwise.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Label namespace. Everything hive creates carries these, and hive touches
/// nothing that lacks them — the reconciler must never adopt or delete a
/// container a human created.
pub const LABEL_MANAGED: &str = "dev.hive.managed";
pub const LABEL_AGENT: &str = "dev.hive.agent";
pub const LABEL_SPEC_HASH: &str = "dev.hive.spec-hash";
pub const LABEL_HARNESS: &str = "dev.hive.harness";

/// A file to place inside a container before it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectFile {
    pub path: String,
    pub contents: Vec<u8>,
    pub mode: u32,
    /// Ownership INSIDE the container. Files land as root otherwise, and the
    /// agent user cannot read its own credentials — which presents as the
    /// harness starting unauthenticated rather than as a permission error.
    pub uid: u32,
    pub gid: u32,
}

impl InjectFile {
    /// The agent user in the hive image.
    pub const AGENT_UID: u32 = 1001;
    pub const AGENT_GID: u32 = 1001;

    pub fn for_agent(path: impl Into<String>, contents: impl Into<Vec<u8>>, mode: u32) -> Self {
        Self {
            path: path.into(),
            contents: contents.into(),
            mode,
            uid: Self::AGENT_UID,
            gid: Self::AGENT_GID,
        }
    }
}

/// Everything needed to create one agent container.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerPlan {
    pub name: String,
    pub image: String,
    /// The harness invocation, from the catalog.
    pub command: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub network: String,
    pub volumes: Vec<VolumeMount>,
    pub memory: String,
    pub cpus: f64,
    pub pids_limit: i64,
    /// Files written after create and before start. See [`ContainerBackend`].
    pub inject: Vec<InjectFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

/// A container as it currently exists, as observed — never as desired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub id: String,
    pub name: String,
    pub agent: String,
    /// The spec hash stamped at creation. Comparing this to the current spec's
    /// hash is how the reconciler decides "matches" vs "needs replacing",
    /// without diffing container config field by field — which never converges,
    /// because the runtime normalises values on the way in.
    pub spec_hash: String,
    pub running: bool,
    /// Restart count, for detecting a crash loop. An agent that restarts
    /// forever otherwise looks identical to one that is simply idle.
    pub restarts: u32,
    pub exit_code: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("container runtime not found: {0}")]
    RuntimeMissing(String),
    #[error("{operation} failed for '{target}': {stderr}")]
    Operation { operation: &'static str, target: String, stderr: String },
    #[error("unexpected output from {operation}: {detail}")]
    Unparseable { operation: &'static str, detail: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub trait ContainerBackend {
    /// Every container hive manages. Filtered by the managed label, so a
    /// container hive did not create is invisible to it.
    fn list(&self) -> Result<Vec<Observed>, BackendError>;

    /// Create the network if absent, applying the isolation options. Idempotent.
    ///
    /// `subnet` is allocated from hive's pool so that one set of firewall rules
    /// covers every agent. Letting Docker choose would mean per-agent rules, and
    /// an agent whose rules are missing reaches the internet but never the relay.
    fn ensure_network(&self, name: &str, subnet: Option<&str>) -> Result<(), BackendError>;

    /// Subnets already assigned to hive-managed networks, for pool allocation.
    fn used_subnets(&self) -> Result<Vec<String>, BackendError>;

    fn ensure_volume(&self, name: &str) -> Result<(), BackendError>;

    /// Create, inject files, and start — IN THAT ORDER.
    ///
    /// The ordering is the whole reason this is one method rather than three.
    /// Harnesses read their configuration and credentials once, at startup:
    /// inject after `start` and the agent has already come up unauthenticated
    /// and without its MCP servers. It then runs, answers, and is subtly wrong,
    /// which is far harder to notice than a container that fails to boot.
    ///
    /// A stopped container is still a filesystem, so `docker cp` into a
    /// created-not-started container works exactly as it does into a running one.
    fn create_and_start(&self, plan: &ContainerPlan) -> Result<String, BackendError>;

    fn stop(&self, name: &str) -> Result<(), BackendError>;

    /// Remove the container. Its state volume is NOT removed — see
    /// [`ContainerBackend::remove_volume`].
    fn remove(&self, name: &str) -> Result<(), BackendError>;

    /// Delete an agent's state volume. Separate from `remove` and never called
    /// during reconciliation.
    ///
    /// The volume holds every credential the agent has been given and any
    /// OAuth session it completed interactively. Replacing a container to pick
    /// up a config change must not destroy that — the agent would come back
    /// logged out, and the cause (a spec edit hours earlier) would not be
    /// obvious. Removing state is an explicit operator action.
    fn remove_volume(&self, name: &str) -> Result<(), BackendError>;

    fn logs(&self, name: &str, lines: usize) -> Result<String, BackendError>;
}

/// Names derived from an agent name. Centralised so the reconciler and the CLI
/// cannot disagree about what a given agent's container is called.
pub struct Names;

impl Names {
    pub fn container(agent: &str) -> String {
        format!("hive-{agent}")
    }
    pub fn network(agent: &str) -> String {
        // Per-agent, not shared: with a single shared bridge, enable_icc=false
        // would also block nothing useful while agents would still share a
        // broadcast domain. One network per agent is what makes the isolation
        // claim true.
        format!("hive-{agent}")
    }
    pub fn volume(agent: &str) -> String {
        format!("hive-{agent}-state")
    }
}

/// Where the state volume is mounted. Every harness's state directory lives
/// under this path in the image.
pub const STATE_MOUNT: &str = "/home/agent/state";

/// Standard mounts for an agent container.
pub fn standard_volumes(agent: &str) -> Vec<VolumeMount> {
    vec![VolumeMount {
        source: Names::volume(agent),
        target: STATE_MOUNT.into(),
        read_only: false,
    }]
}

/// The broker socket mount, when an agent has broker-delivered credentials.
///
/// A per-agent socket path rather than one shared socket: the broker identifies
/// the caller by which socket it arrived on. There is no other identity
/// available — a unix socket peer credential gives uid 1001 for every agent
/// container alike, so a shared socket could not tell them apart, and any agent
/// could ask for any agent's secrets.
pub fn broker_mount(agent: &str, host_socket_dir: &PathBuf) -> VolumeMount {
    VolumeMount {
        source: host_socket_dir.join(format!("{agent}.sock")).display().to_string(),
        target: "/run/hive/broker.sock".into(),
        read_only: false, // a socket needs write to connect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_files_are_owned_by_the_agent_user() {
        // Injected as root, the agent cannot read its own credentials, and the
        // harness starts unauthenticated rather than erroring.
        let f = InjectFile::for_agent("/home/agent/state/claude/.claude.json", b"{}".to_vec(), 0o600);
        assert_eq!(f.uid, 1001);
        assert_eq!(f.gid, 1001);
    }

    #[test]
    fn each_agent_gets_its_own_network() {
        // Shared network + enable_icc=false is not equivalent: the isolation
        // claim rests on there being nothing else on the bridge.
        assert_ne!(Names::network("alice"), Names::network("bob"));
    }

    #[test]
    fn broker_sockets_are_per_agent_because_that_is_the_only_identity() {
        // Every agent container runs as uid 1001, so SO_PEERCRED cannot
        // distinguish them. Mount topology is the identity.
        let dir = PathBuf::from("/run/hive");
        assert_ne!(broker_mount("alice", &dir).source, broker_mount("bob", &dir).source);
        assert_eq!(broker_mount("alice", &dir).target, broker_mount("bob", &dir).target);
    }
}
