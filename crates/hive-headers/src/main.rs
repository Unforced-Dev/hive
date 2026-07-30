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
//! - **stdout must be a FLAT JSON object whose every value is a string** — the
//!   headers themselves, not a wrapper around them. The parser rejects the whole
//!   response on the first non-string value ("must return a JSON object with
//!   string key-value pairs"), and a rejected response is not an error the user
//!   ever sees: the connection is simply attempted with NO auth header, 401s,
//!   and the server is then recorded as needing interactive OAuth. See
//!   [`flatten`].
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

    flatten(line.trim())
}

/// Turn the broker's `{"headers":{...}}` reply into the flat object Claude Code
/// requires on stdout.
///
/// These are two different wire formats and this function is the seam between
/// them. Passing the broker's reply through unchanged looks like the careful
/// choice — one owner for the format, no drift — but it is wrong: the broker's
/// envelope has to distinguish `headers` from `error`, and Claude Code's stdout
/// contract has no room for an envelope at all. Emitting the envelope means
/// emitting `{"headers": {...}}`, whose one value is an object, which trips the
/// "string key-value pairs" check and discards every header.
///
/// The failure that produces is silent and misleading, which is why this is
/// worth a function and a test rather than a line: no error is surfaced, the
/// request simply goes out unauthenticated, the 401 sends Claude Code into OAuth
/// discovery, and the server is recorded as "Needs authentication" — pointing at
/// the credential, which is valid, rather than at the shape of this output.
fn flatten(line: &str) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("malformed response: {e}"))?;

    if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }

    let headers = value
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or_else(|| format!("unexpected response shape: {line}"))?;

    // Check here rather than letting Claude Code reject the batch: it discards
    // ALL headers on one bad value, and says so only in its own debug log.
    if let Some((k, v)) = headers.iter().find(|(_, v)| !v.is_string()) {
        return Err(format!("header {k:?} is {} rather than a string", kind_of(v)));
    }

    serde_json::to_string(&serde_json::Value::Object(headers.clone()))
        .map_err(|e| format!("re-serialising headers: {e}"))
}

fn kind_of(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_is_the_headers_themselves_not_the_brokers_envelope() {
        // The regression this file exists to prevent. Emitting the envelope
        // sends the request out with no Authorization header at all: Claude
        // Code rejects a response whose values are not strings, and reports
        // nothing — the server just appears to need OAuth.
        let out = flatten(r#"{"headers":{"Authorization":"Bearer tok-123"}}"#).unwrap();
        assert_eq!(out, r#"{"Authorization":"Bearer tok-123"}"#);
        assert!(!out.contains("\"headers\""), "envelope leaked into stdout: {out}");
    }

    #[test]
    fn every_value_must_be_a_string_or_claude_code_drops_all_of_them() {
        // One non-string value discards the whole set, so catching it here —
        // where the message names the offending key — beats an unauthenticated
        // request and a 401 three steps later.
        let err = flatten(r#"{"headers":{"Authorization":"Bearer x","X-Retry":3}}"#).unwrap_err();
        assert!(err.contains("X-Retry"), "message should name the key: {err}");
        assert!(err.contains("number"), "message should say what it was: {err}");
    }

    #[test]
    fn a_broker_error_is_reported_as_an_error_not_as_headers() {
        let err = flatten(r#"{"error":"agent 'bob' is not authorised for 'mcp/x'"}"#).unwrap_err();
        assert!(err.contains("not authorised"), "got {err}");
    }

    #[test]
    fn an_empty_header_set_is_passed_through_rather_than_invented() {
        // Claude Code treats empty stdout as failure, but `{}` is a valid
        // object. Deciding here that no headers means an error would override
        // a broker that legitimately has none to send.
        assert_eq!(flatten(r#"{"headers":{}}"#).unwrap(), "{}");
    }

    #[test]
    fn junk_is_an_error_rather_than_a_panic() {
        for junk in ["", "{", "null", "[]", r#"{"headers":"nope"}"#, r#"{"other":1}"#] {
            assert!(flatten(junk).is_err(), "junk {junk:?} was accepted");
        }
    }
}
