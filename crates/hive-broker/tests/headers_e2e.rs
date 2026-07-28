//! End-to-end test of the credential path that never touches the container.
//!
//! Claude Code runs `hive-headers` inside the container; it connects to a socket
//! bind-mounted from the host; the broker answers based on which socket the
//! request arrived on. Every piece of that is easy to get subtly right in
//! isolation and wrong together, and the failure mode is a 401 at the first tool
//! call — which reads as an expired token rather than as broken plumbing.
//!
//! Gated on `HIVE_DOCKER_TESTS=1`; run with `./build.sh --docker`.
//!
//! NOTE ON PATHS: `docker run -v` resolves the host side against the DOCKER
//! DAEMON's filesystem, not this process's. The test harness therefore mounts
//! `/run/hive` at the same path inside and out, so a socket created here is the
//! same file the daemon bind-mounts there. Get this wrong and the mount silently
//! produces an empty directory rather than an error.

use hive_broker::{serve, Broker, Grant, ServerKeys};
use hive_core::credential::CredentialKey;
use std::path::PathBuf;

const IMAGE: &str = "hive-agent:latest";
const SOCKET_DIR: &str = "/run/hive";

fn enabled() -> bool {
    std::env::var("HIVE_DOCKER_TESTS").as_deref() == Ok("1")
}

fn docker(args: &[&str]) -> String {
    let out = std::process::Command::new("docker").args(args).output().expect("docker");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .trim()
    .to_string()
}

#[test]
fn a_container_gets_mcp_headers_without_the_secret_ever_entering_it() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }

    let agent = "etest-headers";
    let container = format!("hive-{agent}");
    let socket = PathBuf::from(SOCKET_DIR).join(format!("{agent}.sock"));
    let _ = docker(&["rm", "-f", &container]);

    let store = PathBuf::from(SOCKET_DIR).join("etest-store");
    let _ = std::fs::remove_dir_all(&store);
    let broker = Broker::open(&store).expect("broker");
    broker
        .put(&CredentialKey::new("mcp/parachute"), b"tok-secret-abc\n")
        .expect("put");

    // Serve on a thread; the listener blocks forever by design.
    let sock = socket.clone();
    std::thread::spawn(move || {
        let broker = Broker::open(&store).expect("broker");
        let grant = Grant::new("etest-headers", ["mcp/parachute".to_string()]);
        let servers = ServerKeys::from([("parachute".into(), "mcp/parachute".into())]);
        let _ = serve(&sock, &broker, &grant, &servers);
    });
    // Wait for bind rather than sleeping a fixed amount.
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(socket.exists(), "broker never bound its socket");

    let mount = format!("{}:/run/hive/broker.sock", socket.display());
    let out = docker(&["run", "-d", "--name", &container, "-v", &mount, IMAGE, "sleep", "120"]);
    assert!(!out.contains("Error"), "could not start container: {out}");

    // Exactly how Claude Code invokes it: through a shell, no arguments, with
    // the server name and URL in the environment.
    let result = docker(&[
        "exec",
        "-e",
        "CLAUDE_CODE_MCP_SERVER_NAME=parachute",
        "-e",
        "CLAUDE_CODE_MCP_SERVER_URL=https://vault.example/mcp",
        &container,
        "sh",
        "-c",
        "hive-headers",
    ]);

    assert!(
        result.contains("Bearer tok-secret-abc"),
        "helper did not return the credential: {result}"
    );
    // The trailing newline on the stored token must not end up inside the
    // header value.
    assert!(!result.contains("abc\\n"), "newline leaked into the header: {result}");

    // The whole point: the secret is nowhere in the container's environment, so
    // `docker inspect` — and anything with daemon access — cannot read it.
    let inspected = docker(&["inspect", &container]);
    assert!(
        !inspected.contains("tok-secret-abc"),
        "the secret is visible in docker inspect, which defeats the design"
    );

    let _ = docker(&["rm", "-f", &container]);
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn an_agent_cannot_obtain_a_server_outside_its_grant() {
    if !enabled() {
        eprintln!("skipping: set HIVE_DOCKER_TESTS=1");
        return;
    }

    let agent = "etest-denied";
    let container = format!("hive-{agent}");
    let socket = PathBuf::from(SOCKET_DIR).join(format!("{agent}.sock"));
    let _ = docker(&["rm", "-f", &container]);

    let store = PathBuf::from(SOCKET_DIR).join("etest-store-denied");
    let _ = std::fs::remove_dir_all(&store);
    let broker = Broker::open(&store).expect("broker");
    broker.put(&CredentialKey::new("mcp/secret"), b"must-not-leak").expect("put");

    let sock = socket.clone();
    std::thread::spawn(move || {
        let broker = Broker::open(&store).expect("broker");
        // The server is CONFIGURED but the grant does NOT include its key —
        // the case where a spec references a credential the agent has no claim
        // to. The broker must refuse even though it holds the secret.
        let grant = Grant::new("etest-denied", []);
        let servers = ServerKeys::from([("secret".into(), "mcp/secret".into())]);
        let _ = serve(&sock, &broker, &grant, &servers);
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(socket.exists(), "broker never bound its socket");

    let mount = format!("{}:/run/hive/broker.sock", socket.display());
    docker(&["run", "-d", "--name", &container, "-v", &mount, IMAGE, "sleep", "120"]);

    let result = docker(&[
        "exec",
        "-e",
        "CLAUDE_CODE_MCP_SERVER_NAME=secret",
        &container,
        "sh",
        "-c",
        "hive-headers",
    ]);

    assert!(!result.contains("must-not-leak"), "denied request leaked the secret: {result}");
    assert!(
        result.contains("not authorised") || result.contains("hive-headers:"),
        "expected a clear refusal, got: {result}"
    );

    let _ = docker(&["rm", "-f", &container]);
    let _ = std::fs::remove_file(&socket);
}
