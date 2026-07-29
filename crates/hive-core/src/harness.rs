//! The harness catalog: which ACP agents hive can run, and what each one needs.
//!
//! This is the authoritative list. The agent image asserts against it at build
//! time, `hive doctor` diffs a running image against it, and spec validation
//! resolves `harness.id` through it. Adding a harness here without adding it to
//! `images/agent/Dockerfile` will fail the image build — which is the intended
//! direction of the dependency.
//!
//! **Provenance.** Every entry marked verified was installed and executed in a
//! `node:24-bookworm-slim` container and its ACP subcommand output read, on
//! 2026-07-28. None of it is from documentation, which matters more than usual
//! here: two of the eight upstream Buzz presets do not work as written, and both
//! read fine on paper.
//!
//! **Architecture caveat.** Runtime verification was performed on linux/arm64.
//! The linux/amd64 artifacts were confirmed to exist and resolve, but were not
//! executed. The image build's assertion step closes that gap per-arch at build
//! time, which is why it is not optional.

use std::fmt;

/// How a harness interprets a model identifier.
///
/// Model ids are NOT portable between harnesses, and getting this wrong presents
/// as the agent silently ignoring the configured model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelSyntax {
    /// Bare aliases only. Claude advertises `opus` / `sonnet` and REJECTS
    /// `opus[1m]` — Buzz's model picker can offer a bracketed variant that the
    /// harness then refuses, so the suffix must be stripped before it is passed.
    Bare,
    /// The bracket suffix is meaningful and must be preserved. Codex advertises
    /// ids like `gpt-5.6-sol[high]` where `[high]` is REASONING DEPTH, not a
    /// variant tag. Stripping it here silently downgrades the model's effort —
    /// an earlier version of the provider stripped brackets unconditionally and
    /// would have done exactly that.
    Bracketed,
    /// Unverified. Pass the id through untouched rather than guess: a wrong
    /// transformation is worse than none, because it fails quietly.
    Passthrough,
}

/// Why a known harness is not runnable here. Selecting one should produce this
/// reason, not "No such file or directory".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// Installs fine, but the build cannot be reproduced.
    NotReproducible,
    /// The binary alone is not a working agent — it needs a separate daemon.
    NeedsExternalService,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReproducible => write!(f, "cannot be pinned to a version"),
            Self::NeedsExternalService => write!(f, "requires a separate service to be useful"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HarnessDef {
    /// Catalog id. Matches Buzz's `HarnessDefinition.id` where one exists, so a
    /// harness picked in the desktop resolves here by the same name.
    pub id: &'static str,
    pub label: &'static str,
    /// The ACP entrypoint: what buzz-acp spawns as `BUZZ_ACP_AGENT_COMMAND`.
    pub command: &'static str,
    pub args: &'static [&'static str],
    /// Every binary that must resolve on PATH for this harness to work. More
    /// than one when the agent can reasonably shell out to the underlying CLI —
    /// `claude` invoking `codex` is a real workflow, and the bare CLI is a
    /// separate binary from its ACP adapter.
    pub requires: &'static [&'static str],
    /// Environment variables carrying this harness's model-provider credential,
    /// in precedence order. These are what the broker mints; they are never
    /// written into a spec.
    pub credential_env: &'static [&'static str],
    /// Where this harness reads a *file*-shaped credential, when it has one.
    ///
    /// Subscription auth is the default way people use these tools, and for
    /// several of them it is a JSON blob on disk rather than a key in the
    /// environment — codex writes `auth.json`, and an API key is the fallback,
    /// not the norm. A harness whose credential can only be an env var leaves
    /// this `None`.
    ///
    /// Absolute, and under the state volume: a credential written anywhere else
    /// is destroyed on the next container recreate, after which the agent
    /// silently reverts to unauthenticated.
    pub credential_file: Option<&'static str>,
    pub model_syntax: ModelSyntax,
    /// Set when the harness is deliberately absent from the image.
    pub unsupported: Option<Unsupported>,
    pub note: &'static str,
}

impl HarnessDef {
    pub fn is_available(&self) -> bool {
        self.unsupported.is_none()
    }

    /// Apply this harness's model syntax to an id from the surface.
    pub fn normalize_model<'a>(&self, model: &'a str) -> &'a str {
        match self.model_syntax {
            ModelSyntax::Bare => model.split('[').next().unwrap_or(model).trim_end(),
            ModelSyntax::Bracketed | ModelSyntax::Passthrough => model,
        }
    }
}

/// Every harness hive knows about, including the two it deliberately refuses.
///
/// Refused entries are listed rather than omitted so that selecting one gives a
/// reason instead of a spawn failure — the failure mode we are most often
/// cleaning up after.
pub const CATALOG: &[HarnessDef] = &[
    HarnessDef {
        id: "claude",
        label: "Claude Code",
        command: "claude-agent-acp",
        args: &[],
        // `claude` too: the CLI is what an agent shells out to, and it is also
        // what `claude setup-token` runs against.
        requires: &["claude-agent-acp", "claude"],
        // NOT ANTHROPIC_API_KEY. It outranks the OAuth token and silently
        // switches a subscription agent to metered API billing — the image
        // refuses to set it at all, and spec validation bans it.
        credential_env: &["CLAUDE_CODE_OAUTH_TOKEN"],
        credential_file: None,
        model_syntax: ModelSyntax::Bare,
        unsupported: None,
        note: "Subscription auth via CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token`.",
    },
    HarnessDef {
        id: "codex",
        label: "Codex",
        command: "codex-acp",
        args: &[],
        requires: &["codex-acp", "codex"],
        credential_env: &["CODEX_API_KEY", "OPENAI_API_KEY"],
        credential_file: Some("/home/agent/state/codex/auth.json"),
        model_syntax: ModelSyntax::Bracketed,
        unsupported: None,
        note: "Subscription auth also works by injecting ~/.codex/auth.json into CODEX_HOME \
               (verified on this box, undocumented upstream). The bundled codex binary's \
               vendor path is arch-specific.",
    },
    HarnessDef {
        id: "goose",
        label: "goose",
        command: "goose",
        args: &["acp"],
        requires: &["goose"],
        credential_env: &["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOSE_PROVIDER"],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: None,
        note: "No subscription path. Can target any OpenAI-compatible endpoint, which makes it \
               the route to local/open models. With no keyring in a container it falls back to \
               a PLAINTEXT secrets.yaml under XDG_CONFIG_HOME.",
    },
    HarnessDef {
        id: "grok",
        label: "Grok Build",
        command: "grok",
        // --always-approve because a container has no TTY to approve at; the
        // isolation is the network and filesystem boundary, not a prompt.
        //
        // There is deliberately no update-suppressing flag: `--no-auto-update`
        // reads plausibly, is suggested in the wild, and does not exist — `grok
        // agent` rejects it outright and the harness never starts. Updates are
        // a separate `grok update` subcommand. Caught by the ACP smoke test,
        // which is the only reason it is not still in here.
        args: &["agent", "--always-approve", "stdio"],
        requires: &["grok"],
        credential_env: &["XAI_API_KEY"],
        credential_file: Some("/home/agent/state/grok/auth.json"),
        model_syntax: ModelSyntax::Passthrough,
        unsupported: None,
        note: "First-party xAI. GROK_HOME is both install dir and state dir, and grok WRITES to it \
               — sessions, settings, and auth.json, which it reads from there rather than from \
               ~/.grok. Read-only, session/new fails FS_PERMISSION_DENIED while separately \
               reporting no credentials. The image points it at per-agent state and symlinks the \
               shared 127 MB binary in.",
    },
    HarnessDef {
        id: "opencode",
        label: "opencode",
        command: "opencode",
        args: &["acp"],
        requires: &["opencode"],
        credential_env: &["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: None,
        note: "Multi-provider; `opencode providers` manages auth interactively.",
    },
    HarnessDef {
        id: "kimi",
        label: "Kimi Code",
        command: "kimi",
        args: &["acp"],
        requires: &["kimi"],
        credential_env: &["MOONSHOT_API_KEY", "KIMI_API_KEY", "KIMI_MODEL_API_KEY"],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: None,
        note: "First-party Moonshot, MIT. Smallest harness in the image at ~40 MB.",
    },
    HarnessDef {
        id: "amp",
        label: "Amp",
        command: "amp-acp",
        args: &[],
        requires: &["amp-acp", "amp"],
        credential_env: &["AMP_API_KEY"],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: None,
        note: "amp-acp is a third-party adapter over @ampcode/cli (@sourcegraph/amp is \
               deprecated). Its install is the one genuinely broken by npm's allow-scripts \
               gate: the postinstall only hardlinks the real binary out of a platform \
               optional-dep, so skipping it leaves no amp and npm still exits 0.",
    },
    HarnessDef {
        id: "omp",
        label: "Oh My Pi",
        command: "omp",
        args: &["acp"],
        requires: &["omp"],
        credential_env: &["XAI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: None,
        note: "Installed from the release binary, NOT npm: the npm package requires Bun, and \
               the unrelated npm package literally named `oh-my-pi` is a different project.",
    },
    HarnessDef {
        id: "cursor",
        label: "Cursor Agent",
        command: "cursor-agent",
        args: &["acp"],
        requires: &["cursor-agent"],
        credential_env: &["CURSOR_API_KEY"],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: None,
        note: "`acp` is a HIDDEN subcommand — absent from --help, but it resolves and is the \
               documented ACP entrypoint. Pinned by tarball URL because the piped installer \
               has no version flag.",
    },
    // ---- known to Buzz, deliberately not in the image -----------------------
    HarnessDef {
        id: "hermes",
        label: "Hermes",
        // The real entrypoint. Buzz's preset names `hermes-acp`, which the
        // installer never creates — worth reporting upstream.
        command: "hermes",
        args: &["acp", "--accept-hooks"],
        requires: &["hermes"],
        credential_env: &[],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: Some(Unsupported::NotReproducible),
        note: "Installs non-interactively and works, but clones the default branch with no \
               version-pin flag, so no two builds are the same image. 735 MB. Also: Buzz's \
               preset command `hermes-acp` does not exist after install.",
    },
    HarnessDef {
        id: "openclaw",
        label: "OpenClaw",
        command: "openclaw",
        args: &["acp"],
        requires: &["openclaw"],
        credential_env: &[],
        credential_file: None,
        model_syntax: ModelSyntax::Passthrough,
        unsupported: Some(Unsupported::NeedsExternalService),
        note: "`openclaw acp` is a bridge to a running OpenClaw Gateway, not a self-contained \
               agent. Tools execute inside the Gateway, so BUZZ_* env injected into the harness \
               process never reaches the execution environment.",
    },
];

pub fn lookup(id: &str) -> Option<&'static HarnessDef> {
    CATALOG.iter().find(|h| h.id == id)
}

/// Reverse lookup: find the catalog entry for a concrete invocation.
///
/// Buzz's BYOH layer resolves a harness — builtin, preset or user-defined JSON —
/// down to an `EffectiveHarnessDescriptor { command, args, env }`, and that is
/// what the desktop sends a provider on deploy. Mapping it back to a catalog id
/// means a harness picked in the UI resolves to the entry that knows its model
/// syntax and credential variables, rather than being re-specified by hand.
///
/// Args are compared because the same binary can be several harnesses:
/// `grok agent … stdio` is the ACP entrypoint, `grok` alone is an interactive UI.
pub fn lookup_by_command(command: &str, args: &[String]) -> Option<&'static HarnessDef> {
    CATALOG
        .iter()
        .find(|h| h.command == command && h.args.len() == args.len()
            && h.args.iter().zip(args).all(|(a, b)| a == b))
        // Fall back to the command alone: a desktop preset may add flags the
        // catalog does not carry, and matching the binary is still much better
        // than treating a known harness as custom.
        .or_else(|| CATALOG.iter().find(|h| h.command == command))
}

/// Ids that can actually be run, for error messages and `hive doctor`.
pub fn available_ids() -> impl Iterator<Item = &'static str> {
    CATALOG.iter().filter(|h| h.is_available()).map(|h| h.id)
}

/// Every binary the agent image must contain. The image build asserts on exactly
/// this set, so a harness added to the catalog cannot ship without one.
pub fn required_binaries() -> Vec<&'static str> {
    let mut v: Vec<_> = CATALOG
        .iter()
        .filter(|h| h.is_available())
        .flat_map(|h| h.requires.iter().copied())
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_desktop_resolved_invocation_maps_back_to_the_catalog() {
        // Buzz sends agent_command/agent_args, not a harness id. Without this
        // the id has to be re-specified by hand and can disagree with what the
        // desktop actually picked.
        let g = lookup_by_command("grok", &["agent".into(), "--always-approve".into(), "stdio".into()]);
        assert_eq!(g.map(|h| h.id), Some("grok"));
        assert_eq!(lookup_by_command("claude-agent-acp", &[]).map(|h| h.id), Some("claude"));
        // Extra flags still resolve to the right harness rather than falling
        // through to "custom".
        assert_eq!(lookup_by_command("goose", &["acp".into(), "--verbose".into()]).map(|h| h.id), Some("goose"));
        assert!(lookup_by_command("something-else", &[]).is_none());
    }

    #[test]
    fn catalog_ids_are_unique() {
        let mut ids: Vec<_> = CATALOG.iter().map(|h| h.id).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate harness id in catalog");
    }

    #[test]
    fn every_harness_declares_its_own_command_as_required() {
        // The `requires` list drives the image assertion. A harness whose own
        // command is missing from it would pass a build that cannot run it.
        for h in CATALOG {
            assert!(
                h.requires.contains(&h.command),
                "{} does not require its own command {}",
                h.id,
                h.command
            );
        }
    }

    #[test]
    fn claude_strips_the_bracket_suffix_because_the_harness_rejects_it() {
        // Buzz's picker can offer `opus[1m]`; claude-agent-acp advertises bare
        // aliases and refuses the bracketed form, so the agent ends up on a
        // default model with nothing logged.
        let claude = lookup("claude").unwrap();
        assert_eq!(claude.normalize_model("opus[1m]"), "opus");
        assert_eq!(claude.normalize_model("sonnet"), "sonnet");
    }

    #[test]
    fn codex_keeps_the_bracket_suffix_because_it_is_reasoning_depth() {
        // The mirror image of the test above, and the reason normalisation is
        // per-harness rather than global: stripping here silently downgrades
        // effort. A single unconditional rule breaks exactly one of these two.
        let codex = lookup("codex").unwrap();
        assert_eq!(codex.normalize_model("gpt-5.6-sol[high]"), "gpt-5.6-sol[high]");
    }

    #[test]
    fn unverified_harnesses_do_not_guess_at_model_syntax() {
        for h in CATALOG {
            if h.model_syntax == ModelSyntax::Passthrough {
                let m = "some-model[with-suffix]";
                assert_eq!(h.normalize_model(m), m, "{} mangled an unverified model id", h.id);
            }
        }
    }

    #[test]
    fn anthropic_api_key_is_never_a_claude_credential() {
        // It outranks CLAUDE_CODE_OAUTH_TOKEN and switches a subscription agent
        // to metered API billing without a word. Other harnesses may legitimately
        // use it; claude may not.
        let claude = lookup("claude").unwrap();
        assert!(!claude.credential_env.contains(&"ANTHROPIC_API_KEY"));
    }

    #[test]
    fn refused_harnesses_are_listed_with_a_reason_not_omitted() {
        // Omitting them would turn selecting one into "No such file or
        // directory" from deep inside buzz-acp, surfacing on the desktop as
        // "all 1 agents failed to start" — true and useless.
        for id in ["hermes", "openclaw"] {
            let h = lookup(id).expect("refused harness must still be in the catalog");
            assert!(!h.is_available());
            assert!(!h.note.is_empty(), "{id} refused without an explanation");
        }
        assert!(!available_ids().any(|id| id == "hermes"));
    }

    #[test]
    fn required_binaries_covers_the_shell_out_case() {
        // An agent invoking a second harness is a supported workflow, so the
        // bare CLIs must be present, not just the ACP adapters.
        let bins = required_binaries();
        for b in ["claude", "codex", "claude-agent-acp", "codex-acp"] {
            assert!(bins.contains(&b), "{b} missing from required binaries");
        }
        assert!(!bins.contains(&"hermes"), "refused harness leaked into the image assertion");
    }
}
