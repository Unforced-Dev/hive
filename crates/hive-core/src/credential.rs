//! The seam between core and the credential broker.
//!
//! Core never holds a secret. It computes what an agent NEEDS and how each
//! credential must be delivered; something else — `hive-broker`, wired in by the
//! daemon — decides whether to hand it over. Core does not depend on the broker
//! crate, so a bug in reconciliation cannot read the store.
//!
//! # The honest limitation
//!
//! It is tempting to say "credentials never enter the container". That is only
//! true for MCP servers, and only on one harness. The split is real and worth
//! stating plainly rather than discovering later:
//!
//! - **Model-provider credentials** (`CLAUDE_CODE_OAUTH_TOKEN`, codex's
//!   `auth.json`, `XAI_API_KEY`) MUST enter the container. The harness process
//!   authenticates to the model API itself; there is no hook to intercept it.
//!   `headersHelper` is MCP-specific and does not apply.
//! - **MCP server credentials** need not, on Claude Code, via [`Delivery::Broker`].
//!   Every other harness in the catalog reads static config, so its MCP
//!   credentials are injected like model credentials.
//!
//! So [`Delivery::Env`] and [`Delivery::File`] are not legacy paths to be removed
//! — they are the only option for a large part of the surface. What hive can
//! honestly promise is a *smaller* blast radius, not zero: an agent's own model
//! token is in its container, and `docker inspect` on the host reveals anything
//! delivered by env.

use std::path::PathBuf;

/// A name for a credential the broker holds. NEVER the secret itself.
///
/// Specs carry these; a spec that carries a literal secret is refused by
/// validation, because specs are meant to be committable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialKey(pub String);

impl CredentialKey {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a credential reaches the process that needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// An environment variable on the container.
    ///
    /// Readable by anyone with Docker daemon access via `docker inspect`, and by
    /// any process in the container. Necessary for model-provider credentials.
    Env { var: String },

    /// A file written into the agent's state volume.
    ///
    /// Not visible to `docker inspect`, which is a genuine if modest
    /// improvement over env. Used for credentials that are only expressible as
    /// files — codex's `auth.json` being the one that matters, since its
    /// subscription auth has no environment-variable form.
    File { path: PathBuf, mode: u32 },

    /// Nothing enters the container.
    ///
    /// A unix socket is mounted in; the harness asks for headers per MCP
    /// connection and the broker answers. Claude Code's `headersHelper`, which
    /// is currently the only mechanism of this shape in any harness we ship.
    Broker { socket: PathBuf },
}

impl Delivery {
    /// Whether the secret itself ends up inside the container.
    pub fn exposes_secret_to_container(&self) -> bool {
        !matches!(self, Self::Broker { .. })
    }

    /// Whether `docker inspect` reveals it to anyone with daemon access.
    pub fn visible_to_docker_inspect(&self) -> bool {
        matches!(self, Self::Env { .. })
    }
}

/// One credential an agent requires, and how it will be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub key: CredentialKey,
    pub delivery: Delivery,
    /// What breaks without it, for error messages. An agent that starts and then
    /// cannot answer is much harder to diagnose than one that refuses to start.
    pub purpose: &'static str,
}

/// Implemented by `hive-broker`. Core calls it; core never links it.
pub trait CredentialSource {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Whether the broker holds this key, WITHOUT retrieving it.
    ///
    /// The reconciler uses this to refuse to start an agent whose credentials
    /// are missing, rather than starting one that fails on its first turn. It
    /// exists as a separate call so that check does not have to move secrets.
    fn has(&self, key: &CredentialKey) -> Result<bool, Self::Error>;

    /// Retrieve a secret for delivery. The only method that moves one.
    ///
    /// `agent` is passed so the broker can scope and audit per-agent: it is the
    /// broker's job to refuse a key an agent has no business holding, and to
    /// record that it was handed over. Core cannot enforce either.
    fn fetch(&self, agent: &str, key: &CredentialKey) -> Result<Secret, Self::Error>;
}

/// A secret in memory, zeroed on drop.
///
/// Best-effort: the value has already been copied by whatever produced it, and
/// Rust may have moved it. It narrows the window rather than closing it.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
        // Without this the fill is a dead store and the optimiser is entitled to
        // delete it. black_box is the safe way to say "assume this was observed";
        // a volatile write would be stronger but needs unsafe, which this crate
        // forbids. The guarantee is weak either way — the value was already
        // copied by whatever produced it, and Rust may have moved it since. This
        // narrows the window, it does not close it.
        std::hint::black_box(&self.0);
    }
}

// Debug and Display are deliberately NOT derived. A secret that formats itself
// ends up in a log line eventually — usually in the one error path nobody tested.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret([redacted; {} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_format_themselves() {
        // The failure this prevents is a secret in a log line, which happens via
        // a derived Debug on some struct three layers up that holds one.
        let s = Secret::new(b"sk-ant-oat01-very-secret".to_vec());
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("sk-ant"), "secret leaked into Debug: {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn only_broker_delivery_keeps_the_secret_out_of_the_container() {
        assert!(!Delivery::Broker { socket: "/run/hive/a.sock".into() }
            .exposes_secret_to_container());
        assert!(Delivery::Env { var: "XAI_API_KEY".into() }.exposes_secret_to_container());
        assert!(Delivery::File { path: "/s/auth.json".into(), mode: 0o600 }
            .exposes_secret_to_container());
    }

    #[test]
    fn file_delivery_is_hidden_from_docker_inspect_but_env_is_not() {
        // The reason codex's auth.json is injected as a file rather than
        // flattened into an env var: anyone with daemon access can read env.
        assert!(Delivery::Env { var: "CLAUDE_CODE_OAUTH_TOKEN".into() }
            .visible_to_docker_inspect());
        assert!(!Delivery::File { path: "/s/auth.json".into(), mode: 0o600 }
            .visible_to_docker_inspect());
    }
}
