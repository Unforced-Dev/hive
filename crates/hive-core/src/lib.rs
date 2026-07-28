//! hive core: turning an [`AgentSpec`] into a running container.
//!
//! Holds no secrets. Credentials reach a container through the
//! `CredentialSource` trait, implemented by `hive-broker` and wired in by the
//! daemon — core never links the broker, so a bug here cannot read the store.
//!
//! [`AgentSpec`]: hive_spec::AgentSpec

#![forbid(unsafe_code)]

pub mod harness;
pub mod network;

pub use harness::{HarnessDef, ModelSyntax, Unsupported};

#[cfg(test)]
mod image_contract {
    //! The agent image and the catalog must agree, and "agree" has to be
    //! checked rather than maintained by hand.
    //!
    //! The image's build-time assertion is what stops a harness from shipping
    //! missing — but only for the harnesses it names. If the catalog gains an
    //! entry and the Dockerfile's list does not, the assertion passes while the
    //! image lacks the binary, and we are back to exactly the silent failure the
    //! assertion exists to prevent. So the two lists are compared here.

    use crate::harness::{required_binaries, CATALOG};

    fn image_file(name: &str) -> String {
        let path = format!("{}/../../images/agent/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// Binaries the image needs that are not harnesses: the ACP bridge, and the
    /// CLI the agent shells out to in order to post its replies.
    const INFRA_BINARIES: &[&str] = &["buzz-acp", "buzz"];

    fn dockerfile_assertion_list() -> Vec<String> {
        let src = image_file("Dockerfile");
        let (_, after) = src.split_once("for b in ").expect("image is missing its assertion step");
        let (list, _) = after.split_once("; do").expect("malformed assertion loop");
        let mut v: Vec<String> = list
            .split_whitespace()
            .filter(|t| *t != "\\")
            .map(str::to_string)
            .collect();
        v.sort();
        v
    }

    #[test]
    fn image_asserts_on_exactly_the_catalog_binaries() {
        let mut expected: Vec<String> = required_binaries()
            .into_iter()
            .chain(INFRA_BINARIES.iter().copied())
            .map(str::to_string)
            .collect();
        expected.sort();

        assert_eq!(
            expected,
            dockerfile_assertion_list(),
            "\nThe agent image's assertion list has drifted from the harness catalog.\n\
             Add the harness to images/agent/Dockerfile — BOTH an install step and the\n\
             assertion loop — or remove it from the catalog. A catalog entry with no\n\
             install step ships an image that passes its own check and still cannot run\n\
             the harness.\n"
        );
    }

    #[test]
    fn smoke_test_probes_exactly_the_catalog_invocations() {
        // The smoke test is what proves a harness RUNS, as opposed to merely
        // being present — it is where `grok --no-auto-update` was caught. That
        // only holds while it probes the same command line the catalog will
        // actually spawn. A catalog arg change that does not reach this table
        // leaves the smoke test passing on an invocation nobody uses.
        let src = image_file("smoke.sh");
        let (_, rest) = src.split_once("# HARNESS_TABLE_BEGIN").expect("smoke table missing");
        let (table, _) = rest.split_once("# HARNESS_TABLE_END").expect("smoke table unterminated");

        let mut probed: Vec<(String, String)> = table
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("probe "))
            .map(|l| {
                let mut f = l.split_whitespace().skip(1);
                let id = f.next().expect("probe needs a name").to_string();
                (id, f.collect::<Vec<_>>().join(" "))
            })
            .collect();
        probed.sort();

        let mut expected: Vec<(String, String)> = CATALOG
            .iter()
            .filter(|h| h.is_available())
            .map(|h| {
                let mut inv = vec![h.command];
                inv.extend_from_slice(h.args);
                (h.id.to_string(), inv.join(" "))
            })
            .collect();
        expected.sort();

        assert_eq!(
            expected, probed,
            "\nimages/agent/smoke.sh has drifted from the harness catalog.\n\
             Every runnable harness must be probed with the EXACT command and args\n\
             the catalog spawns, or the smoke test certifies an invocation that is\n\
             never used.\n"
        );
    }
}
