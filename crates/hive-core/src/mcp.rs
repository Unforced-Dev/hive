//! Writing MCP server configuration into a harness's own config file.
//!
//! # Why this exists at all
//!
//! ACP defines a way for a client to hand an agent its MCP servers, including an
//! HTTP shape that carries `headers`, and says explicitly that the CLIENT
//! supplies the credentials. `buzz-acp` cannot express it: its `McpServer` struct
//! is `{name, command, args, env}` — stdio only, no `url`, no `headers`. Two open
//! upstream PRs (#2900, #3196) let an agent hold SEVERAL servers; neither adds a
//! transport. So every HTTP MCP server — which is to say every OAuth MCP server,
//! including Parachute — is unreachable through the protocol.
//!
//! Until that type gains a variant, the only way to give a containerised agent an
//! HTTP MCP server is to write the harness's native config file directly. That is
//! what this module does. It is a workaround for a missing struct variant, and it
//! should shrink if upstream fixes it.
//!
//! # Merging, not writing
//!
//! These files are not ours. `.claude.json` also holds `userID`, `machineID` and
//! onboarding flags; overwriting it resets the harness to a first-run state, and
//! the agent then behaves as though it had never been configured. Every writer
//! here merges into what is already on disk.

use std::collections::BTreeMap;

use crate::harness::HarnessDef;

/// An MCP server to configure, already resolved from the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServer {
    pub name: String,
    pub transport: Transport,
    /// How the harness should authenticate. See [`Auth`].
    pub auth: Auth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Http { url: String },
    Stdio { command: String, args: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// No credential — the server is open, or uses an OAuth flow the harness
    /// completes itself and caches in its own state.
    None,
    /// The harness asks a helper program for headers on every connection. The
    /// secret is never written to disk or into the environment.
    ///
    /// Claude Code only, and the strongest option available anywhere in the
    /// catalog. The binary contract, read from claude-code 2.1.220:
    ///   - invoked through a SHELL, with no arguments
    ///   - **10 second timeout** (`timeout: 1e4`)
    ///   - must exit 0 AND write to stdout, or the connection fails
    ///   - receives `CLAUDE_CODE_MCP_SERVER_NAME` and `CLAUDE_CODE_MCP_SERVER_URL`
    ///     in its environment, so ONE helper serves every server
    ///   - stdout must be a FLAT JSON object of string values — the headers
    ///     themselves. Anything else is discarded in full, with no error: the
    ///     connection goes out unauthenticated, 401s, and the server is then
    ///     recorded as needing interactive OAuth, which is unreachable in a
    ///     container and points the diagnosis at the credential instead.
    Helper { program: String },
    /// The config names an ENVIRONMENT VARIABLE holding the token, rather than
    /// embedding the token itself. Codex's `bearer_token_env_var`. Weaker than a
    /// helper — the value is in the environment, so `docker inspect` reveals it —
    /// but the config file itself stays clean, so it can be read and diffed.
    BearerFromEnv { var: String },
    /// The token is written into the config file verbatim. Last resort.
    BearerLiteral { token: String },
}

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("harness '{0}' has no known MCP configuration format")]
    UnsupportedHarness(String),
    #[error("{harness} cannot express an HTTP MCP server")]
    UnsupportedTransport { harness: String },
    #[error("{harness} does not support {auth}; use {suggestion} instead")]
    UnsupportedAuth { harness: String, auth: &'static str, suggestion: &'static str },
    #[error("existing config at {path} is malformed: {source}")]
    Malformed { path: String, source: Box<dyn std::error::Error + Send + Sync> },
}

/// A file to write into the agent's state volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFile {
    pub path: String,
    pub contents: String,
    pub mode: u32,
}

/// Produce the config file for `harness`, merging `servers` into `existing`.
///
/// `existing` is the file's current contents, or empty on first run.
pub fn render(
    harness: &HarnessDef,
    servers: &[McpServer],
    existing: &str,
) -> Result<Option<ConfigFile>, McpError> {
    if servers.is_empty() {
        return Ok(None);
    }
    match harness.id {
        "claude" => render_claude(servers, existing).map(Some),
        "codex" => render_codex(servers, existing).map(Some),
        // Deliberately an error rather than a silent no-op. An agent that starts
        // without the tool it was configured with looks healthy and answers
        // wrongly — upstream buzz#3196 describes an agent that "reasoned itself
        // into a dead end mid-turn" for exactly this reason, and produced no
        // reply at all. Failing to deploy is far cheaper to diagnose.
        other => Err(McpError::UnsupportedHarness(other.to_string())),
    }
}

/// `$CLAUDE_CONFIG_DIR/.claude.json`.
fn render_claude(servers: &[McpServer], existing: &str) -> Result<ConfigFile, McpError> {
    let path = "/home/agent/state/claude/.claude.json";

    // MERGE. This file also holds userID, machineID and onboarding state;
    // clobbering it puts the harness back to first-run and it behaves as though
    // it was never set up.
    let mut root: serde_json::Value = if existing.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(existing).map_err(|e| McpError::Malformed {
            path: path.into(),
            source: Box::new(e),
        })?
    };
    if !root.is_object() {
        root = serde_json::json!({});
    }

    let obj = root.as_object_mut().expect("checked above");
    let entry = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if !entry.is_object() {
        *entry = serde_json::json!({});
    }
    let mcp = entry.as_object_mut().expect("checked above");

    for s in servers {
        // An HTTP server must not be defined here at all: hive-acp hands the
        // same server, under the same name, to the same harness at
        // `session/new`. Two definitions under one name do not merge and do not
        // conflict loudly — the agent simply ends up unable to use the tool.
        //
        // REMOVED rather than skipped. Skipping only stops NEW boxes acquiring
        // the collision; every box that ever ran an older hive keeps the stale
        // entry, because this file lives in the agent's state volume and
        // survives redeploys, image upgrades and container recreation. A fix
        // that leaves existing installs broken is not a fix.
        if matches!(s.transport, Transport::Http { .. }) {
            mcp.remove(s.name.as_str());
            continue;
        }
        let Transport::Stdio { command, args } = &s.transport else {
            continue; // pruned above
        };
        let mut e = serde_json::Map::new();
        e.insert("type".into(), "stdio".into());
        e.insert("command".into(), command.clone().into());
        e.insert("args".into(), serde_json::json!(args));
        match &s.auth {
            Auth::None => {}
            Auth::Helper { program } => {
                e.insert("headersHelper".into(), program.clone().into());
            }
            Auth::BearerLiteral { token } => {
                e.insert(
                    "headers".into(),
                    serde_json::json!({ "Authorization": format!("Bearer {token}") }),
                );
            }
            Auth::BearerFromEnv { .. } => {
                // Claude Code has no verified env-expansion syntax inside
                // mcpServers headers — grepping the shipped CLI found none. An
                // unexpanded ${VAR} fails as a 401 at the first tool call, which
                // is a slow and confusing way to find out. Use the helper.
                return Err(McpError::UnsupportedAuth {
                    harness: "claude".into(),
                    auth: "bearer-from-env",
                    suggestion: "a headersHelper",
                });
            }
        }
        mcp.insert(s.name.clone(), serde_json::Value::Object(e));
    }

    Ok(ConfigFile {
        path: path.into(),
        contents: serde_json::to_string_pretty(&root).expect("serialisable"),
        mode: 0o600,
    })
}

/// `$CODEX_HOME/config.toml`.
fn render_codex(servers: &[McpServer], existing: &str) -> Result<ConfigFile, McpError> {
    let path = "/home/agent/state/codex/config.toml";

    // toml_edit rather than parse-and-re-emit: it preserves comments, formatting
    // and key order in the parts of the file we are not touching. Codex writes
    // its own settings here, and reordering them on every reconcile would make
    // every deploy look like a change.
    let mut doc: toml_edit::DocumentMut = if existing.trim().is_empty() {
        toml_edit::DocumentMut::new()
    } else {
        existing.parse().map_err(|e: toml_edit::TomlError| McpError::Malformed {
            path: path.into(),
            source: Box::new(e),
        })?
    };

    for s in servers {
        let mut tbl = toml_edit::Table::new();
        match &s.transport {
            Transport::Http { url } => {
                tbl.insert("url", toml_edit::value(url.as_str()));
            }
            Transport::Stdio { command, args } => {
                tbl.insert("command", toml_edit::value(command.as_str()));
                let mut arr = toml_edit::Array::new();
                for a in args {
                    arr.push(a.as_str());
                }
                tbl.insert("args", toml_edit::value(arr));
            }
        }
        match &s.auth {
            Auth::None => {}
            // Names the variable; the secret never lands in the config file.
            Auth::BearerFromEnv { var } => {
                tbl.insert("bearer_token_env_var", toml_edit::value(var.as_str()));
            }
            Auth::BearerLiteral { .. } => {
                return Err(McpError::UnsupportedAuth {
                    harness: "codex".into(),
                    auth: "a literal bearer token",
                    suggestion: "bearer_token_env_var",
                });
            }
            Auth::Helper { .. } => {
                // headersHelper is a Claude Code feature. Codex has no equivalent.
                return Err(McpError::UnsupportedAuth {
                    harness: "codex".into(),
                    auth: "a headersHelper",
                    suggestion: "bearer_token_env_var",
                });
            }
        }
        // The parent must be seated as a real Table first. Assigning through
        // `doc["mcp_servers"][name]` instead creates an INLINE table, and the
        // file comes out as
        //   mcp_servers = { parachute.url = "..." }
        // which is valid TOML, parses to the same data, and is not the shape
        // codex's own config uses — so a hand-edit next to it produces a
        // duplicate-key error rather than a merge.
        let parent = doc
            .as_table_mut()
            .entry("mcp_servers")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_mut()
            .ok_or_else(|| McpError::Malformed {
                path: path.into(),
                source: "mcp_servers exists but is not a table".into(),
            })?;
        // Implicit: emit `[mcp_servers.parachute]` rather than a bare
        // `[mcp_servers]` header followed by the child section.
        parent.set_implicit(true);
        parent.insert(s.name.as_str(), toml_edit::Item::Table(tbl));
    }

    Ok(ConfigFile { path: path.into(), contents: doc.to_string(), mode: 0o600 })
}

/// MCP servers grouped by name, for the reconciler to diff against observed state.
pub fn by_name(servers: &[McpServer]) -> BTreeMap<&str, &McpServer> {
    servers.iter().map(|s| (s.name.as_str(), s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::lookup;

    fn local_stdio() -> McpServer {
        McpServer {
            name: "local".into(),
            transport: Transport::Stdio { command: "some-server".into(), args: vec![] },
            auth: Auth::None,
        }
    }

    fn parachute(auth: Auth) -> McpServer {
        McpServer {
            name: "parachute".into(),
            transport: Transport::Http { url: "https://vault.example/mcp".into() },
            auth,
        }
    }

    #[test]
    fn claude_config_is_merged_not_overwritten() {
        // .claude.json holds userID/machineID/onboarding. Overwriting it returns
        // the harness to a first-run state: it starts fine and behaves as though
        // it had never been configured, which reads as a model problem.
        let existing = r#"{"userID":"u-123","hasCompletedOnboarding":true}"#;
        let out = render(lookup("claude").unwrap(), &[local_stdio()], existing).unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(v["userID"], "u-123", "existing keys must survive");
        assert_eq!(v["hasCompletedOnboarding"], true);
        assert_eq!(v["mcpServers"]["local"]["command"], "some-server");
    }

    #[test]
    fn an_http_server_is_pruned_from_claudes_config_rather_than_written() {
        // hive-acp hands Claude the same server, under the same name, at
        // session/new. Two definitions under one name do not merge and do not
        // conflict loudly: the agent simply cannot use the tool.
        let out = render(
            lookup("claude").unwrap(),
            &[parachute(Auth::Helper { program: "/usr/local/bin/hive-headers".into() }), local_stdio()],
            "",
        )
        .unwrap()
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert!(v["mcpServers"].get("parachute").is_none(), "HTTP server written: {}", out.contents);
        assert!(v["mcpServers"].get("local").is_some(), "stdio server dropped: {}", out.contents);
    }

    #[test]
    fn an_http_entry_left_by_an_older_hive_is_removed_from_the_existing_file() {
        // The case that makes this a fix rather than a mitigation. `.claude.json`
        // lives in the agent's state volume and survives redeploys, image
        // upgrades and container recreation, so merely declining to write the
        // entry would leave every existing box broken forever.
        let existing = r#"{"mcpServers":{"parachute":{"type":"http","url":"https://vault.example/mcp","headersHelper":"/usr/local/bin/hive-headers"}}}"#;
        let out = render(
            lookup("claude").unwrap(),
            &[parachute(Auth::Helper { program: "/usr/local/bin/hive-headers".into() })],
            existing,
        )
        .unwrap()
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out.contents).unwrap();
        assert!(
            v["mcpServers"].get("parachute").is_none(),
            "the stale entry survived: {}",
            out.contents
        );
    }

    #[test]
    fn codex_names_the_env_var_and_keeps_the_secret_out_of_the_file() {
        let out = render(
            lookup("codex").unwrap(),
            &[parachute(Auth::BearerFromEnv { var: "PARACHUTE_TOKEN".into() })],
            "",
        )
        .unwrap()
        .unwrap();
        assert!(out.contents.contains("[mcp_servers.parachute]"), "got:\n{}", out.contents);
        assert!(out.contents.contains(r#"bearer_token_env_var = "PARACHUTE_TOKEN""#));
    }

    #[test]
    fn codex_merge_preserves_unrelated_settings_and_comments() {
        // Reconciliation runs repeatedly. If it reorders or strips codex's own
        // settings, every deploy shows a spurious diff and real changes hide in it.
        let existing = "# codex settings, hand-edited\nmodel = \"gpt-5.6-sol\"\n\n[history]\npersistence = \"save-all\"\n";
        let out = render(
            lookup("codex").unwrap(),
            &[parachute(Auth::None)],
            existing,
        )
        .unwrap()
        .unwrap();
        assert!(out.contents.contains("# codex settings, hand-edited"), "comment lost");
        assert!(out.contents.contains(r#"model = "gpt-5.6-sol""#));
        assert!(out.contents.contains("[history]"));
        assert!(out.contents.contains("[mcp_servers.parachute]"));
    }

    #[test]
    fn rendering_twice_is_idempotent() {
        // The reconciler re-renders on every pass. A writer that appends would
        // grow the file without bound and eventually produce a duplicate-key
        // TOML parse error — days later, on an agent nobody touched.
        let h = lookup("codex").unwrap();
        let first = render(h, &[parachute(Auth::None)], "").unwrap().unwrap();
        let second = render(h, &[parachute(Auth::None)], &first.contents).unwrap().unwrap();
        assert_eq!(first.contents, second.contents);
    }

    #[test]
    fn unconfigurable_harnesses_fail_loudly_rather_than_starting_toolless() {
        // An agent that starts without its MCP server looks healthy and answers
        // wrongly. Upstream buzz#3196 documents exactly this: the agent
        // "reasoned itself into a dead end mid-turn" and never replied.
        let err = render(lookup("goose").unwrap(), &[parachute(Auth::None)], "").unwrap_err();
        assert!(matches!(err, McpError::UnsupportedHarness(_)));
    }

    #[test]
    fn no_servers_means_no_file_rather_than_an_empty_one() {
        // Writing an empty config would clobber a harness's own settings with
        // nothing, which is the merge bug in a different costume.
        assert!(render(lookup("claude").unwrap(), &[], "{}").unwrap().is_none());
    }
}
