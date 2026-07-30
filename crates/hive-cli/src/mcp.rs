//! `hive mcp` — MCP servers on an agent, and the credentials they need.
//!
//! # Why this lives in hive rather than in the desktop
//!
//! Buzz cannot express an HTTP MCP server. Its `McpServer` is
//! `{name, command, args, env}` — stdio only — and the backend-provider deploy
//! payload has no MCP field at all. That is a boundary, not a gap to route
//! around, so hive owns MCP configuration outright.
//!
//! # Why the spec is edited in place
//!
//! Specs are meant to be hand-editable and committable — the README says so.
//! Anything that regenerates a whole spec destroys comments, ordering, and any
//! block the generator does not know about. `toml_edit` preserves the document,
//! so `hive mcp add` and a human editor can share one file.

use std::path::Path;

use anyhow::{bail, Context, Result};
use hive_broker::Broker;
use hive_core::credential::CredentialKey;
use toml_edit::{value, Array, DocumentMut, Item, Table};

use crate::oauth;

/// Read a spec, or explain which agent names do exist. A typo'd agent name is
/// the most common way to reach this, and "no such file" does not help.
fn load(spec_dir: &Path, agent: &str) -> Result<(std::path::PathBuf, DocumentMut)> {
    let path = oauth::spec_path(spec_dir, agent);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        let known: Vec<String> = std::fs::read_dir(spec_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let n = e.file_name().to_string_lossy().to_string();
                        n.strip_suffix(".toml").map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if known.is_empty() {
            anyhow::anyhow!("no agent specs in {} ({e})", spec_dir.display())
        } else {
            anyhow::anyhow!("no agent {agent:?} in {} — have: {}", spec_dir.display(), known.join(", "))
        }
    })?;
    let doc: DocumentMut = text
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;
    Ok((path, doc))
}

fn mcp_array<'a>(doc: &'a mut DocumentMut) -> &'a mut toml_edit::ArrayOfTables {
    if !doc.contains_key("mcp") {
        doc["mcp"] = Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    doc["mcp"]
        .as_array_of_tables_mut()
        .expect("mcp is an array of tables")
}

pub fn list(spec_dir: &Path, agent: &str) -> Result<()> {
    let (_, mut doc) = load(spec_dir, agent)?;
    let arr = mcp_array(&mut doc);
    if arr.is_empty() {
        println!("no MCP servers configured for {agent}");
        return Ok(());
    }
    println!("{:<16} {:<10} {:<44} {}", "NAME", "TRANSPORT", "URL", "CREDENTIAL");
    for t in arr.iter() {
        println!(
            "{:<16} {:<10} {:<44} {}",
            t.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
            t.get("transport").and_then(|v| v.as_str()).unwrap_or("http"),
            t.get("url").and_then(|v| v.as_str()).unwrap_or(""),
            t.get("credential").and_then(|v| v.as_str()).unwrap_or("-"),
        );
    }
    Ok(())
}

/// Add (or update) one server. `credential` defaults to `mcp/<name>` so the
/// common case needs no flag and the broker key is predictable from the spec.
pub fn add(
    spec_dir: &Path,
    agent: &str,
    name: &str,
    url: &str,
    credential: Option<&str>,
    tools: &[String],
) -> Result<()> {
    if name.is_empty() {
        bail!("an MCP server needs a name — it is how the harness refers to it");
    }
    let credential = credential.map(String::from).unwrap_or_else(|| format!("mcp/{name}"));
    let (path, mut doc) = load(spec_dir, agent)?;
    let arr = mcp_array(&mut doc);

    // Replace by name rather than appending: two blocks with one name is a
    // config the harness resolves arbitrarily, and `add` twice is a normal
    // thing to do while getting a URL right.
    let existing = arr.iter().position(|t| t.get("name").and_then(|v| v.as_str()) == Some(name));

    let mut t = Table::new();
    t["name"] = value(name);
    t["transport"] = value("http");
    t["url"] = value(url);
    t["credential"] = value(&credential);
    if !tools.is_empty() {
        let mut a = Array::new();
        for tool in tools {
            a.push(tool.as_str());
        }
        t["tools"] = value(a);
    }

    match existing {
        Some(i) => {
            *arr.get_mut(i).expect("index from position") = t;
            println!("updated {name} on {agent}");
        }
        None => {
            arr.push(t);
            println!("added {name} to {agent}");
        }
    }
    std::fs::write(&path, doc.to_string()).with_context(|| format!("writing {}", path.display()))?;
    println!("  credential: {credential}");
    println!("  next: hive mcp login {name} --agent {agent}");
    Ok(())
}

pub fn rm(spec_dir: &Path, agent: &str, name: &str) -> Result<()> {
    let (path, mut doc) = load(spec_dir, agent)?;
    let arr = mcp_array(&mut doc);
    let before = arr.len();
    arr.retain(|t| t.get("name").and_then(|v| v.as_str()) != Some(name));
    if arr.len() == before {
        bail!("{agent} has no MCP server named {name:?}");
    }
    std::fs::write(&path, doc.to_string()).with_context(|| format!("writing {}", path.display()))?;
    println!("removed {name} from {agent}");
    println!("note: its credential is still stored — `hive secret rm mcp/{name}` to drop it");
    Ok(())
}

/// Walk the OAuth flow for a server already present in the spec, and store the
/// result in the broker.
///
/// The URL is read from the spec rather than taken as an argument: logging in
/// against a different URL than the agent will use produces a token bound to
/// the wrong resource, and that failure surfaces much later as a 401 from the
/// MCP server.
pub fn login(
    spec_dir: &Path,
    secrets_dir: &Path,
    agent: &str,
    name: &str,
    scopes: Option<&str>,
    open_browser: bool,
) -> Result<()> {
    let (_, mut doc) = load(spec_dir, agent)?;
    let arr = mcp_array(&mut doc);
    let entry = arr
        .iter()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
        .with_context(|| format!("{agent} has no MCP server named {name:?} — add it first"))?;
    let url = entry
        .get("url")
        .and_then(|v| v.as_str())
        .with_context(|| format!("{name} has no url"))?
        .to_string();
    let credential = entry
        .get("credential")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("mcp/{name}"));

    println!("discovering {url} …");
    let auth = oauth::discover(&url)?;
    println!("  authorization server: {}", auth.issuer);
    println!("  resource:             {}", auth.resource);

    // Default to everything the resource advertises; `--scope ""` sends none.
    //
    // Letting the consent screen decide is the better model in principle — it
    // knows which scopes exist, which this user may hold, and how to ask, while
    // `scopes_supported` describes what the RESOURCE understands rather than
    // what the server will grant. Naming scopes from it caps the token at the
    // published set and cannot reach anything outside it.
    //
    // It is not the better DEFAULT, because a server that receives no scope is
    // free to grant nothing, and Parachute does exactly that: the consent
    // screen offers no choices and the resulting token is useless. A default
    // that depends on the server having an opinion fails silently on the ones
    // that do not.
    //
    // So: advertised scopes by default, and `--scope ""` for a server whose
    // consent screen should own the decision.
    let requested: Vec<String> = match scopes {
        Some(s) => s.split(&[',', ' '][..]).filter(|p| !p.is_empty()).map(String::from).collect(),
        None => auth.scopes_supported.clone(),
    };
    if requested.is_empty() {
        println!("  scopes:               (none requested — the consent screen decides)");
    } else {
        println!("  scopes:               {}", requested.join(" "));
    }

    // Bind BEFORE registering. The redirect URI carries the port, the server
    // records it at registration time, and it must match exactly at the
    // authorization step — registering a placeholder port and hoping produces
    // an "invalid redirect_uri" that points at nothing obvious.
    let (listener, redirect_uri) = oauth::bind_callback()?;
    let client_id = oauth::register_client(&auth, &redirect_uri)?;

    let (code, bundle) =
        oauth::authorize(listener, &redirect_uri, &auth, &client_id, &requested, open_browser)?;
    let tokens = oauth::exchange(&auth, &client_id, &code, &bundle)?;

    let broker = Broker::open(secrets_dir)?;
    broker.put(&CredentialKey::new(&credential), tokens.access_token.as_bytes())?;
    if let Some(rt) = tokens.refresh_token.as_deref() {
        broker.put(&CredentialKey::new(&oauth::refresh_key(&credential)), rt.as_bytes())?;
    }
    broker.put(
        &CredentialKey::new(&oauth::meta_key(&credential)),
        oauth::meta_json(&auth, &client_id).as_bytes(),
    )?;

    println!("\nstored {credential}");
    match tokens.expires_in {
        // Stated plainly because it is the difference between "this works" and
        // "this works until Thursday". A refresh token makes the expiry a
        // detail; without one it is the whole story.
        Some(s) if tokens.refresh_token.is_some() => {
            println!("  expires in {s}s, refresh token stored — the broker can renew it")
        }
        Some(s) => println!("  expires in {s}s and NO refresh token was issued — login again when it lapses"),
        None => println!("  no expiry advertised"),
    }
    if let Some(sc) = tokens.scope {
        println!("  granted scopes: {sc}");
    }
    println!("\n  hive restart {agent}   # so the harness picks it up");
    Ok(())
}

/// Renew an access token from the stored refresh token.
///
/// Reads the endpoint and client id from the metadata saved at login rather
/// than re-running discovery: a server that has since moved its endpoints
/// should fail loudly here, not silently mint against a different issuer.
pub fn refresh(spec_dir: &Path, secrets_dir: &Path, agent: &str, name: &str) -> Result<()> {
    let (_, mut doc) = load(spec_dir, agent)?;
    let arr = mcp_array(&mut doc);
    let credential = arr
        .iter()
        .find(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
        .and_then(|t| t.get("credential").and_then(|v| v.as_str()).map(String::from))
        .unwrap_or_else(|| format!("mcp/{name}"));

    let broker = Broker::open(secrets_dir)?;
    // The broker has no ungated read: every fetch is checked against a grant
    // and written to the audit log. Rather than reach around it, the operator
    // gets a named grant for exactly these two keys — so a manual refresh is
    // as visible in the audit trail as an agent's own fetch would be.
    let meta_k = oauth::meta_key(&credential);
    let refresh_k = oauth::refresh_key(&credential);
    let grant = hive_broker::Grant::new("hive-cli", [meta_k.clone(), refresh_k.clone()]);

    let meta_secret = broker
        .fetch_for(&grant, &CredentialKey::new(&meta_k))
        .context("no stored OAuth metadata — run `hive mcp login` first")?;
    let meta: serde_json::Value = serde_json::from_slice(meta_secret.expose())
        .context("stored OAuth metadata is not JSON")?;
    let rt = broker
        .fetch_for(&grant, &CredentialKey::new(&refresh_k))
        .context("no refresh token stored — this server issued none, so log in again")?;

    let tokens = oauth::refresh(
        meta["token_endpoint"].as_str().context("metadata has no token_endpoint")?,
        meta["client_id"].as_str().context("metadata has no client_id")?,
        rt.as_str()?.trim(),
        meta["resource"].as_str().unwrap_or_default(),
    )?;

    broker.put(&CredentialKey::new(&credential), tokens.access_token.as_bytes())?;
    // Only overwrite when the server rotated it. Clearing a still-valid refresh
    // token because this response omitted one would force a browser login.
    if let Some(new_rt) = tokens.refresh_token.as_deref() {
        broker.put(&CredentialKey::new(&oauth::refresh_key(&credential)), new_rt.as_bytes())?;
    }
    println!("refreshed {credential}");
    if let Some(s) = tokens.expires_in {
        println!("  expires in {s}s");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same shape as `hive_broker`'s test helper: a per-process directory under
    /// the system temp dir, wiped on entry. No dev-dependency — this crate
    /// graph deliberately has none.
    fn spec_with(tag: &str, body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let d = std::env::temp_dir().join(format!("hive-mcp-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("create tempdir");
        let p = d.join("uni.toml");
        std::fs::write(&p, body).expect("write");
        (d, p)
    }

    #[test]
    fn adding_a_server_preserves_comments_and_unrelated_blocks() {
        // The whole reason this uses toml_edit. A generator that rewrites the
        // document drops the operator's comments and any block it does not know
        // about — which is how the old desktop shim silently erased hand-added
        // MCP config on every redeploy.
        let (d, p) = spec_with(
            "preserve",
            "# hand-written, keep me\n[identity]\npubkey = \"aa\"\n\n[[volume]]\nname = \"shared\"\ntarget = \"/home/agent/work\"\n",
        );
        add(&d, "uni", "parachute", "https://x/mcp", None, &[]).expect("add");
        let out = std::fs::read_to_string(&p).expect("read");
        assert!(out.contains("# hand-written, keep me"), "comment was dropped:\n{out}");
        assert!(out.contains("[[volume]]"), "unrelated block was dropped:\n{out}");
        assert!(out.contains("credential = \"mcp/parachute\""), "{out}");
    }

    #[test]
    fn adding_the_same_name_twice_updates_rather_than_duplicating() {
        // Two blocks with one name is a config the harness resolves
        // arbitrarily, and re-running `add` while correcting a URL is normal.
        let (d, p) = spec_with("update", "[identity]\npubkey = \"aa\"\n");
        add(&d, "uni", "parachute", "https://old/mcp", None, &[]).expect("first");
        add(&d, "uni", "parachute", "https://new/mcp", None, &[]).expect("second");
        let out = std::fs::read_to_string(&p).expect("read");
        assert_eq!(out.matches("name = \"parachute\"").count(), 1, "{out}");
        assert!(out.contains("https://new/mcp"), "{out}");
        assert!(!out.contains("https://old/mcp"), "{out}");
    }

    #[test]
    fn several_servers_coexist_on_one_agent() {
        // The limit that made this necessary: the desktop shim could express
        // exactly one MCP server, hardcoded to the name "mcp".
        let (d, p) = spec_with("several", "[identity]\npubkey = \"aa\"\n");
        add(&d, "uni", "parachute", "https://a/mcp", None, &[]).expect("a");
        add(&d, "uni", "github", "https://b/mcp", None, &[]).expect("b");
        let out = std::fs::read_to_string(&p).expect("read");
        assert_eq!(out.matches("[[mcp]]").count(), 2, "{out}");
        assert!(out.contains("mcp/parachute") && out.contains("mcp/github"), "{out}");
    }

    #[test]
    fn removing_a_server_leaves_the_others() {
        let (d, p) = spec_with("removeone", "[identity]\npubkey = \"aa\"\n");
        add(&d, "uni", "a", "https://a/mcp", None, &[]).expect("a");
        add(&d, "uni", "b", "https://b/mcp", None, &[]).expect("b");
        rm(&d, "uni", "a").expect("rm");
        let out = std::fs::read_to_string(&p).expect("read");
        assert!(!out.contains("name = \"a\""), "{out}");
        assert!(out.contains("name = \"b\""), "{out}");
    }

    #[test]
    fn removing_a_name_that_is_not_there_is_an_error_not_a_silent_noop() {
        // A typo'd name that reports success leaves the operator believing an
        // MCP server was detached when it is still in the spec.
        let (d, _) = spec_with("rmmissing", "[identity]\npubkey = \"aa\"\n");
        add(&d, "uni", "a", "https://a/mcp", None, &[]).expect("a");
        assert!(rm(&d, "uni", "typo").is_err());
    }

    #[test]
    fn an_unknown_agent_lists_the_ones_that_exist() {
        // "No such file" sends people to look at permissions; the agent list
        // sends them to look at their spelling.
        let (d, _) = spec_with("unknown", "[identity]\npubkey = \"aa\"\n");
        let e = add(&d, "nope", "x", "https://x", None, &[]).unwrap_err().to_string();
        assert!(e.contains("uni"), "error should name known agents: {e}");
    }
}
