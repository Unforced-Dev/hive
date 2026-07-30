//! `hive-mcp-bridge` — an MCP server the harness speaks *stdio* to, which
//! forwards over HTTP and attaches credentials fetched fresh from the broker.
//!
//! # The problem this exists to solve
//!
//! ACP lets a client hand an agent an HTTP MCP server with `headers`, and
//! `hive-acp` did exactly that: fetch a token from the broker and inject it at
//! `session/new`. Those headers are then fixed for the LIFE OF THE SESSION.
//!
//! Parachute issues 15-minute access tokens. A Buzz agent's session lasts for
//! hours. So roughly a quarter-hour in, every call started failing, and nothing
//! could repair it from inside: Claude Code re-runs a `headersHelper` on 401 and
//! recovers, but a connector handed a bare header once has nothing to re-run.
//! Renewing the stored credential — which `hived` does — cannot help a session
//! that already holds the old value.
//!
//! Fetching the credential PER MESSAGE removes the failure mode rather than
//! shortening it. There is no window in which a stale token is held, because no
//! token is held at all.
//!
//! # Why stdio rather than a listening proxy
//!
//! A local HTTP proxy would work, but it needs a port, a lifecycle, and
//! something to start it — three things that can be wrong on a box nobody is
//! watching. A stdio server is spawned by the harness when it connects and dies
//! when it disconnects, so its lifetime is exactly the connection's. ACP's
//! `McpServer` union has always expressed stdio (`{name, command, args, env}`);
//! it is the transport `claude-agent-acp` supports best.
//!
//! # Why curl
//!
//! The reasoning `hive_cli::oauth` and `hive_core::docker` give: no large
//! dependency tracking a moving API, and every request is a command that can be
//! logged verbatim and re-run by hand. Token values are never logged.
//!
//! # Known limit
//!
//! Server-initiated messages are not delivered. Streamable HTTP allows a server
//! to push notifications on a long-lived stream; this bridge is
//! request/response, so a server that only answers what it is asked works fully
//! and one that pushes does not. Parachute is the former. This is a deliberate
//! bound, not an oversight — see `forward`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "hive-mcp-bridge", about = "Speak MCP over stdio, forward over HTTP")]
struct Args {
    /// Upstream MCP endpoint.
    #[arg(long)]
    url: String,

    /// The server's name, as the broker knows it. Used to look up its
    /// credential, so it must match the spec rather than any local alias.
    #[arg(long)]
    server: String,

    /// The agent's broker socket, bind-mounted into this container.
    #[arg(long, default_value = "/run/hive/broker.sock")]
    broker: PathBuf,

    /// Forward without credentials.
    ///
    /// A spec may attach an MCP server that needs none. Without this the bridge
    /// would ask the broker for a credential that was never configured and fail
    /// every message with "no credential configured", which reads as a broken
    /// broker rather than as a server that is simply open.
    #[arg(long)]
    anonymous: bool,

    /// Seconds to allow one upstream request. Generous: an MCP tool call can
    /// legitimately be slow, and a bridge that times out first turns a slow
    /// answer into a lost one.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

fn main() {
    let args = Args::parse();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // Streamable HTTP may assign a session id on the first response and expect
    // it back on every subsequent request. Held here rather than re-derived,
    // because the server is the only thing that can mint it.
    let mut session_id: Option<String> = None;

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // The id has to be recovered before anything can fail, so that a
        // failure can be reported as a JSON-RPC error against the right call
        // rather than as silence the harness waits out.
        let id = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("id").cloned());

        match forward(&args, line, &mut session_id) {
            Ok(Some(body)) => {
                for msg in split_response(&body) {
                    let _ = writeln!(stdout, "{msg}");
                }
                let _ = stdout.flush();
            }
            // A notification: accepted, nothing to say back. Emitting anything
            // here would be a response to a message that has no id, which a
            // client is entitled to treat as a protocol error.
            Ok(None) => {}
            Err(e) => {
                if let Some(id) = id {
                    let err = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32000, "message": e }
                    });
                    let _ = writeln!(stdout, "{err}");
                    let _ = stdout.flush();
                } else {
                    eprintln!("hive-mcp-bridge: {e}");
                }
            }
        }
    }
}

/// One request upstream, with credentials fetched for THIS message.
///
/// Returns `None` when the server accepted a notification with no body.
fn forward(args: &Args, body: &str, session_id: &mut Option<String>) -> Result<Option<String>, String> {
    let headers = if args.anonymous {
        Vec::new()
    } else {
        broker_headers(&args.broker, &args.server)?
    };

    let head_file = std::env::temp_dir().join(format!("hive-mcp-bridge-{}.head", std::process::id()));

    let mut cmd = Command::new(curl());
    cmd.args(["-sS", "--max-time"])
        .arg(args.timeout.to_string())
        .arg("-D")
        .arg(&head_file)
        .args(["-X", "POST"])
        .args(["-H", "Content-Type: application/json"])
        // Both, because streamable HTTP servers may answer either way and a
        // client that accepts only one gets a 406 from the other.
        .args(["-H", "Accept: application/json, text/event-stream"]);

    for (k, v) in &headers {
        cmd.arg("-H").arg(format!("{k}: {v}"));
    }
    if let Some(sid) = session_id.as_deref() {
        cmd.arg("-H").arg(format!("Mcp-Session-Id: {sid}"));
    }
    cmd.args(["--data-binary", "@-"])
        .arg(&args.url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawning curl: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("curl stdin was not piped")?
        .write_all(body.as_bytes())
        .map_err(|e| format!("writing request: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("running curl: {e}"))?;

    let head = std::fs::read_to_string(&head_file).unwrap_or_default();
    let _ = std::fs::remove_file(&head_file);

    if !out.status.success() {
        return Err(format!(
            "upstream request failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if let Some(sid) = header_value(&head, "mcp-session-id") {
        *session_id = Some(sid);
    }
    let status = status_code(&head).unwrap_or(0);
    if !(200..300).contains(&status) {
        // Say the status. "Unauthorized" alone is what sent this whole problem
        // looking at the credential last time, when the credential was fine.
        return Err(format!(
            "upstream returned HTTP {status}: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ));
    }

    let body = String::from_utf8_lossy(&out.stdout).to_string();
    if body.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(body))
}

/// Ask the broker for this server's headers, over the per-agent unix socket.
///
/// Same protocol and same socket as `hive-headers`. The request carries no
/// agent name: the listener already knows which agent this is, and accepting a
/// claimed identity would make the per-socket design decorative.
fn broker_headers(socket: &PathBuf, server: &str) -> Result<Vec<(String, String)>, String> {
    let stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot reach the hive broker at {} ({e}). The socket is bind-mounted per-agent, \
             so this usually means the agent's spec has no credential for this server.",
            socket.display()
        )
    })?;
    let t = Duration::from_secs(5);
    stream.set_read_timeout(Some(t)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(t)).map_err(|e| e.to_string())?;

    let req = serde_json::json!({ "op": "headers", "server": server });
    let mut w = &stream;
    writeln!(w, "{req}").map_err(|e| format!("writing broker request: {e}"))?;
    w.flush().map_err(|e| format!("flushing broker request: {e}"))?;

    let mut line = String::new();
    BufReader::new(&stream)
        .read_line(&mut line)
        .map_err(|e| format!("reading broker response: {e}"))?;

    let v: serde_json::Value =
        serde_json::from_str(line.trim()).map_err(|e| format!("malformed broker response: {e}"))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    let map = v
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or_else(|| format!("unexpected broker response: {}", line.trim()))?;
    Ok(map
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect())
}

/// Pull the JSON-RPC messages out of a response body.
///
/// A streamable-HTTP server may answer with `application/json` (one message) or
/// frame the same thing as SSE (`data:` lines). Both arrive here, so both are
/// handled rather than assuming the content type we saw in testing — that
/// assumption is cheap to make and expensive to discover.
fn split_response(body: &str) -> Vec<String> {
    let looks_like_sse = body
        .lines()
        .any(|l| l.starts_with("data:") || l.starts_with("event:"));
    if !looks_like_sse {
        let t = body.trim();
        return if t.is_empty() { Vec::new() } else { vec![t.to_string()] };
    }
    let mut out = Vec::new();
    // SSE allows a message to span several `data:` lines, joined with newlines.
    let mut current = String::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str(rest.trim_start());
        } else if line.trim().is_empty() && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    // A JSON-RPC message must be one line on stdio; a multi-line `data:` join
    // would otherwise be read as several truncated messages.
    out.into_iter().map(|m| m.replace('\n', "")).filter(|m| !m.trim().is_empty()).collect()
}

/// Last status line wins: `-D` accumulates one header block per redirect hop.
fn status_code(head: &str) -> Option<u16> {
    head.lines()
        .filter(|l| l.starts_with("HTTP/"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|c| c.parse().ok())
        .next_back()
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn curl() -> String {
    for p in ["/usr/bin/curl", "/opt/homebrew/bin/curl", "/usr/local/bin/curl"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    "curl".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_json_response_is_one_message() {
        let out = split_response("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n");
        assert_eq!(out, vec![r#"{"jsonrpc":"2.0","id":1,"result":{}}"#]);
    }

    #[test]
    fn an_sse_framed_response_is_unwrapped() {
        // The same message, framed as SSE. Forwarding the frame verbatim would
        // put `data: {...}` on stdout, which is not JSON-RPC and which the
        // harness drops without a word.
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        assert_eq!(split_response(body), vec![r#"{"jsonrpc":"2.0","id":1,"result":{}}"#]);
    }

    #[test]
    fn several_sse_events_become_several_messages() {
        let body = "data: {\"id\":1}\n\ndata: {\"id\":2}\n\n";
        assert_eq!(split_response(body), vec![r#"{"id":1}"#, r#"{"id":2}"#]);
    }

    #[test]
    fn a_message_split_across_data_lines_is_rejoined_onto_one_line() {
        // SSE permits this and stdio does not: a JSON-RPC message must be a
        // single line, or the harness reads two truncated ones.
        let body = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1}\n\n";
        let out = split_response(body);
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(!out[0].contains('\n'));
        assert!(serde_json::from_str::<serde_json::Value>(&out[0]).is_ok(), "not valid JSON: {out:?}");
    }

    #[test]
    fn an_empty_body_produces_no_messages() {
        // A 202 for a notification. Emitting anything would be a response to a
        // message with no id.
        assert!(split_response("").is_empty());
        assert!(split_response("\n\n").is_empty());
    }

    #[test]
    fn the_last_status_line_wins_across_redirect_hops() {
        let head = "HTTP/2 307 \r\nlocation: /elsewhere\r\n\r\nHTTP/2 200 \r\n\r\n";
        assert_eq!(status_code(head), Some(200));
    }

    #[test]
    fn the_session_id_is_found_whatever_its_capitalisation() {
        let head = "HTTP/2 200 \r\nMcp-Session-Id: abc123\r\n\r\n";
        assert_eq!(header_value(head, "mcp-session-id").as_deref(), Some("abc123"));
        assert_eq!(header_value(head, "nope"), None);
    }

    #[test]
    fn an_absent_session_header_is_none_rather_than_empty_string() {
        // An empty Mcp-Session-Id sent back upstream is not the same as sending
        // none, and some servers reject it.
        let head = "HTTP/2 200 \r\nMcp-Session-Id: \r\n\r\n";
        assert_eq!(header_value(head, "mcp-session-id"), None);
    }
}
