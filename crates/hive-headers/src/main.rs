//! `hive-headers` — the MCP headers helper, run INSIDE an agent container.
//!
//! Claude Code executes this once per MCP connection and reads auth headers from
//! its stdout. The secret never lands in the container's environment or
//! filesystem: this program asks the broker over a unix socket that is
//! bind-mounted into exactly this agent's container, and the broker answers
//! based on which socket the request arrived on.
//!
//! # The contract, read out of claude-code 2.1.220 rather than from docs
//!
//! ```text
//! Xn(t.headersHelper, [], {shell:!0, timeout:1e4, cwd:r, env:{...process.env,
//!     CLAUDE_CODE_MCP_SERVER_NAME: e, CLAUDE_CODE_MCP_SERVER_URL: t.url, ...}})
//! if (n.code !== 0 || !n.stdout) throw ...
//! ```
//!
//! Which means, precisely:
//!
//! - invoked through a SHELL with no arguments
//! - **10 second timeout** — the whole budget, including process startup
//! - must exit 0 **and** write to stdout; either alone is a failure
//! - `CLAUDE_CODE_MCP_SERVER_NAME` and `CLAUDE_CODE_MCP_SERVER_URL` are in the
//!   environment, so ONE helper serves every server and none of this is
//!   hardcoded per-server
//! - re-run automatically on 401/403, so a short-lived token is fine
//!
//! Rust rather than a shell script because the image has no `nc` or `socat`, and
//! rather than node because a helper on a 10s budget should not depend on a
//! runtime that may not be in a future base image.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Where the daemon bind-mounts this agent's socket.
const SOCKET: &str = "/run/hive/broker.sock";

/// Well inside Claude Code's 10s budget, and far longer than a local unix socket
/// round trip to a file read could plausibly need. The point is to fail fast
/// with a clear message rather than be killed at 10s with none.
const TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    match run() {
        Ok(headers) => {
            // stdout is the entire interface. Exit 0 with empty stdout is
            // treated as failure by the caller, so there is no "succeed quietly".
            println!("{headers}");
        }
        Err(e) => {
            // stderr is surfaced in Claude Code's MCP diagnostics. Say which
            // server and what failed — "headersHelper failed" alone sends people
            // looking at the MCP server rather than at the broker.
            let server = std::env::var("CLAUDE_CODE_MCP_SERVER_NAME")
                .unwrap_or_else(|_| "<unknown>".into());
            eprintln!("hive-headers: {server}: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String, String> {
    let server = std::env::var("CLAUDE_CODE_MCP_SERVER_NAME").map_err(|_| {
        "CLAUDE_CODE_MCP_SERVER_NAME is not set; this program is meant to be run by \
         Claude Code as a headersHelper, not directly"
            .to_string()
    })?;

    let stream = UnixStream::connect(SOCKET).map_err(|e| {
        format!(
            "cannot reach the hive broker at {SOCKET} ({e}). The socket is bind-mounted \
             per-agent, so this usually means the agent's spec has no MCP credential and \
             the mount was omitted."
        )
    })?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;

    let request = serde_json::json!({ "op": "headers", "server": server });
    let mut w = &stream;
    writeln!(w, "{request}").map_err(|e| format!("writing request: {e}"))?;
    w.flush().map_err(|e| format!("flushing request: {e}"))?;

    let mut line = String::new();
    BufReader::new(&stream)
        .read_line(&mut line)
        .map_err(|e| format!("reading response: {e}"))?;
    if line.trim().is_empty() {
        return Err("broker closed the connection without responding".into());
    }

    let value: serde_json::Value =
        serde_json::from_str(line.trim()).map_err(|e| format!("malformed response: {e}"))?;

    if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    // Pass the broker's response through unchanged rather than reconstructing
    // it. Re-serialising would mean this program and the broker each own half
    // the wire format, and they would drift.
    if value.get("headers").is_some() {
        return Ok(line.trim().to_string());
    }
    Err(format!("unexpected response shape: {}", line.trim()))
}
