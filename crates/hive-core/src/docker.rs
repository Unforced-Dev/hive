//! Docker implementation of [`ContainerBackend`], driven through the CLI.
//!
//! # Why the CLI and not the API
//!
//! Shelling out is unusual for a daemon, and it is a deliberate choice:
//!
//! - `DOCKER_HOST` works for free, including `ssh://`, so the same code path
//!   drives a local daemon and a remote box. That is what the desktop shim needs
//!   and it is the case most likely to be misconfigured.
//! - Every operation is a command that can be logged verbatim and re-run by hand.
//!   For a project whose main claim is that one person can audit the whole thing,
//!   "here is the exact command hive ran" is worth more than a typed client.
//! - No large dependency tracking a moving API version.
//!
//! The cost is output parsing, which is confined to [`DockerBackend::inspect`].

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::backend::*;
use crate::network;

pub struct DockerBackend {
    docker: PathBuf,
    /// `DOCKER_HOST` value, if the daemon is not local.
    host: Option<String>,
}

impl DockerBackend {
    /// Locate the Docker CLI without trusting `PATH`.
    ///
    /// A GUI-launched process on macOS inherits a minimal launchd environment
    /// whose PATH does not include `/usr/local/bin`, so `docker` is simply not
    /// found — while the same command works perfectly in the developer's shell.
    /// This matters for the desktop shim, which is exactly the case that gets
    /// launched from a GUI, and it is a genuinely confusing failure to debug.
    pub fn discover() -> Result<Self, BackendError> {
        let mut candidates: Vec<PathBuf> = vec![
            "/usr/local/bin/docker".into(),
            "/usr/bin/docker".into(),
            "/opt/homebrew/bin/docker".into(),
            // Docker Desktop, which does not always symlink into /usr/local/bin.
            "/Applications/Docker.app/Contents/Resources/bin/docker".into(),
        ];
        if let Some(p) = std::env::var_os("PATH") {
            candidates.extend(std::env::split_paths(&p).map(|d| d.join("docker")));
        }
        let docker = candidates
            .into_iter()
            .find(|p| p.is_file())
            .ok_or_else(|| BackendError::RuntimeMissing(
                "docker CLI not found in the usual locations or on PATH".into(),
            ))?;
        Ok(Self { docker, host: std::env::var("DOCKER_HOST").ok() })
    }

    pub fn with_host(mut self, host: Option<String>) -> Self {
        self.host = host;
        self
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.docker);
        if let Some(h) = &self.host {
            c.env("DOCKER_HOST", h);
        }
        c
    }

    fn run(&self, op: &'static str, target: &str, args: &[&str]) -> Result<String, BackendError> {
        let out = self.cmd().args(args).output()?;
        if !out.status.success() {
            return Err(BackendError::Operation {
                operation: op,
                target: target.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Whether a docker object exists, without treating absence as an error.
    fn exists(&self, kind: &str, name: &str) -> bool {
        self.cmd()
            .args([kind, "inspect", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn inspect(&self, ids: &[String]) -> Result<Vec<Observed>, BackendError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut args = vec!["inspect".to_string()];
        args.extend(ids.iter().cloned());
        let json = self.run(
            "inspect",
            "containers",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        )?;
        let parsed: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| BackendError::Unparseable {
                operation: "inspect",
                detail: e.to_string(),
            })?;
        let arr = parsed.as_array().ok_or(BackendError::Unparseable {
            operation: "inspect",
            detail: "expected a JSON array".into(),
        })?;

        Ok(arr
            .iter()
            .filter_map(|c| {
                let labels = c.pointer("/Config/Labels")?;
                Some(Observed {
                    id: c.get("Id")?.as_str()?.to_string(),
                    // Docker returns names with a leading slash.
                    name: c.get("Name")?.as_str()?.trim_start_matches('/').to_string(),
                    agent: labels.get(LABEL_AGENT)?.as_str()?.to_string(),
                    spec_hash: labels
                        .get(LABEL_SPEC_HASH)
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    running: c.pointer("/State/Running")?.as_bool()?,
                    restarts: c.get("RestartCount").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    exit_code: c.pointer("/State/ExitCode").and_then(|v| v.as_i64()),
                })
            })
            .collect())
    }

    /// Copy files into a container as a tar stream on stdin.
    ///
    /// A tar built in memory, rather than a temp file plus `docker cp`, because
    /// the tar header is the only place the destination uid/gid can be set. Left
    /// to `docker cp`, files arrive owned by root and the agent user cannot read
    /// its own credentials — which presents as a harness that starts and is
    /// unauthenticated, not as a permission error.
    fn inject(&self, container: &str, files: &[InjectFile]) -> Result<(), BackendError> {
        if files.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut buf);
            for f in files {
                let mut h = tar::Header::new_gnu();
                // Paths in the archive are relative; the copy is rooted at /.
                let rel = f.path.trim_start_matches('/');
                h.set_path(rel).map_err(BackendError::Io)?;
                h.set_size(f.contents.len() as u64);
                h.set_mode(f.mode);
                h.set_uid(f.uid as u64);
                h.set_gid(f.gid as u64);
                // A fixed mtime keeps the stream byte-identical across runs, so
                // re-injecting unchanged config is genuinely a no-op.
                h.set_mtime(0);
                h.set_cksum();
                ar.append(&h, f.contents.as_slice()).map_err(BackendError::Io)?;
            }
            ar.finish().map_err(BackendError::Io)?;
        }

        let mut child = self
            .cmd()
            .args(["cp", "-", &format!("{container}:/")])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().expect("piped").write_all(&buf)?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(BackendError::Operation {
                operation: "cp",
                target: container.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(())
    }
}

impl ContainerBackend for DockerBackend {
    fn list(&self) -> Result<Vec<Observed>, BackendError> {
        // Filtered by the managed label: a container hive did not create is
        // invisible to it, and therefore can never be adopted or deleted.
        let ids = self.run(
            "ps",
            "hive containers",
            &["ps", "-aq", "--filter", &format!("label={LABEL_MANAGED}=true")],
        )?;
        let ids: Vec<String> = ids.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        self.inspect(&ids)
    }

    fn ensure_network(&self, name: &str, subnet: Option<&str>) -> Result<(), BackendError> {
        if self.exists("network", name) {
            return Ok(());
        }
        let mut args: Vec<String> =
            vec!["network".into(), "create".into(), "--driver".into(), "bridge".into()];
        if let Some(s) = subnet {
            args.push("--subnet".into());
            args.push(s.to_string());
        }
        for (k, v) in network::network_create_options() {
            args.push("--opt".into());
            args.push(format!("{k}={v}"));
        }
        args.push(name.into());
        self.run("network create", name, &args.iter().map(String::as_str).collect::<Vec<_>>())?;
        Ok(())
    }

    fn used_subnets(&self) -> Result<Vec<String>, BackendError> {
        // EVERY docker network, not just hive's: Docker refuses an overlapping
        // subnet, so allocating around only our own would fail on a box that
        // runs anything else.
        let names = self.run("network ls", "networks", &["network", "ls", "--format", "{{.Name}}"])?;
        let mut out = Vec::new();
        for n in names.lines().map(str::trim).filter(|n| !n.is_empty()) {
            if let Ok(s) = self.run(
                "network inspect",
                n,
                &["network", "inspect", n, "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}"],
            ) && !s.is_empty()
            {
                out.push(s);
            }
        }
        Ok(out)
    }

    fn ensure_volume(&self, name: &str) -> Result<(), BackendError> {
        if self.exists("volume", name) {
            return Ok(());
        }
        self.run("volume create", name, &["volume", "create", name])?;
        Ok(())
    }

    fn create_and_start(&self, plan: &ContainerPlan) -> Result<String, BackendError> {
        let mut args: Vec<String> = vec!["create".into(), "--name".into(), plan.name.clone()];

        args.extend(["--network".into(), plan.network.clone()]);
        args.extend(["--memory".into(), plan.memory.clone()]);
        args.extend(["--cpus".into(), plan.cpus.to_string()]);
        args.extend(["--pids-limit".into(), plan.pids_limit.to_string()]);

        // Survive a host reboot without the daemon having to be up first. The
        // reconciler tolerates this: it reads RestartCount rather than assuming
        // it is the only thing that starts containers.
        args.extend(["--restart".into(), "unless-stopped".into()]);

        // A harness is a userspace process making HTTP calls; it needs no
        // capabilities and never needs to gain privileges. Dropping these costs
        // nothing and removes a whole class of escalation from a container that,
        // by design, executes model-authored code.
        args.extend(["--security-opt".into(), "no-new-privileges".into()]);
        args.extend(["--cap-drop".into(), "ALL".into()]);

        for (k, v) in &plan.env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        for (k, v) in &plan.labels {
            args.push("--label".into());
            args.push(format!("{k}={v}"));
        }
        for m in &plan.volumes {
            args.push("-v".into());
            let ro = if m.read_only { ":ro" } else { "" };
            args.push(format!("{}:{}{}", m.source, m.target, ro));
        }

        args.push(plan.image.clone());
        args.extend(plan.command.iter().cloned());

        let id = self.run(
            "create",
            &plan.name,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        )?;

        // ORDER IS LOAD-BEARING: create, inject, THEN start. Harnesses read
        // config and credentials once at startup. Injecting after start yields
        // an agent that is already up, unauthenticated, and missing its MCP
        // servers — and which then answers anyway.
        self.inject(&plan.name, &plan.inject)?;

        self.run("start", &plan.name, &["start", &plan.name])?;
        Ok(id)
    }

    fn stop(&self, name: &str) -> Result<(), BackendError> {
        self.run("stop", name, &["stop", "-t", "10", name])?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), BackendError> {
        // -f so a running container is removed too; -v is deliberately ABSENT so
        // named volumes survive. See ContainerBackend::remove_volume.
        self.run("rm", name, &["rm", "-f", name])?;
        Ok(())
    }

    fn remove_volume(&self, name: &str) -> Result<(), BackendError> {
        self.run("volume rm", name, &["volume", "rm", name])?;
        Ok(())
    }

    fn logs(&self, name: &str, lines: usize) -> Result<String, BackendError> {
        // Merged: buzz-acp writes its own diagnostics to stderr while the
        // harness writes to stdout, and reading either alone tells half a story.
        let out = self
            .cmd()
            .args(["logs", "--tail", &lines.to_string(), name])
            .output()?;
        let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(s)
    }
}

/// Labels for an agent's container.
pub fn labels_for(agent: &str, spec_hash: &str, harness: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_string(), "true".to_string()),
        (LABEL_AGENT.to_string(), agent.to_string()),
        (LABEL_SPEC_HASH.to_string(), spec_hash.to_string()),
        (LABEL_HARNESS.to_string(), harness.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_label_is_always_set_so_reconcile_cannot_touch_foreign_containers() {
        // The reconciler deletes containers that are not in the desired set. If
        // this label were ever omitted, hive would be blind to its own container
        // and would create a duplicate; if the FILTER were ever dropped, it
        // would delete containers a human created.
        let l = labels_for("alice", "abc123", "claude");
        assert_eq!(l.get(LABEL_MANAGED).map(String::as_str), Some("true"));
        assert_eq!(l.get(LABEL_AGENT).map(String::as_str), Some("alice"));
        assert_eq!(l.get(LABEL_SPEC_HASH).map(String::as_str), Some("abc123"));
    }
}
