# The hive daemon, containerized.
#
# # Why this exists
#
# On Linux `hived` is a normal system service and `packaging/hived.service` is
# the right way to run it. This image is for hosts where it CANNOT be one:
# macOS and Windows, where Docker is a Linux VM and the daemon must live on the
# VM's side of the boundary.
#
# The specific reason is the broker. `hived` creates one unix socket per agent
# and bind-mounts it into that agent's container — which is the whole identity
# mechanism, because every container runs as uid 1001 and peer credentials
# cannot tell them apart. A unix socket created on macOS and shared into the VM
# through virtiofs is visible but not connectable: `connect()` returns ENOTSUP.
# So a macOS-native hived would come up healthy, reconcile correctly, start
# agents — and every broker-delivered credential would fail. Working, except
# for the one feature whose whole point is keeping secrets out of containers.
#
# Running the daemon inside a container puts it on the same kernel as the
# agents it manages, and the sockets are ordinary Linux sockets again.
#
# # The mount that matters
#
#     -v /run/hive:/run/hive
#
# Path-matched, deliberately. `docker run -v` resolves the source path against
# the DAEMON's filesystem, not against the container issuing the request. When
# hived asks Docker to bind-mount /run/hive/agent.sock into an agent, Docker
# looks for that path on the host. If hived's socket directory is mounted
# somewhere else inside this container, the source resolves to a path that does
# not exist and Docker helpfully creates an empty DIRECTORY there instead —
# the agent then sees a directory where its socket should be, and the failure
# surfaces inside the harness rather than here.
#
# `images/agent/build.sh` already relies on this for the integration tests.
#
# # Build
#
#     docker build -f images/hived/Dockerfile -t hive-daemon:latest .
#
# # Run
#
#     docker run -d --name hived --restart unless-stopped \
#       -v /var/run/docker.sock:/var/run/docker.sock \
#       -v /run/hive:/run/hive \
#       -v hive-agents:/etc/hive/agents \
#       -v hive-secrets:/var/lib/hive \
#       hive-daemon:latest
#
# On macOS, /run/hive is a path in the Docker VM and /run is tmpfs — it does
# not survive a VM restart. Create it before starting this container, or the
# broker has nowhere to put sockets:
#
#     colima ssh -- sudo mkdir -p /run/hive && colima ssh -- sudo chmod 755 /run/hive

# Bookworm to match images/agent/Dockerfile. Building on a newer base links
# against a glibc the runtime stage does not have, and the binary fails at
# exec with a version error rather than at build time.
FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
# Only the two binaries a host needs. hive-headers ships in the AGENT image;
# buzz-backend-hive runs on the desktop.
RUN cargo build --release --locked -p hived --bin hived -p hive-cli --bin hive \
    && strip target/release/hived target/release/hive

FROM debian:bookworm-slim

# hive drives Docker through the CLI rather than the API, so the CLI is a hard
# runtime dependency. Copied from the official image rather than installed from
# apt: it is a mostly-static Go binary, and this pins the version instead of
# tracking whatever Debian currently ships.
#
# /usr/local/bin is the FIRST path DockerBackend::discover() checks.
COPY --from=docker:28-cli /usr/local/bin/docker /usr/local/bin/docker

COPY --from=builder /build/target/release/hived /usr/local/bin/hived
COPY --from=builder /build/target/release/hive  /usr/local/bin/hive

# 0700 on secrets is enforced by the broker at startup; creating it here with
# the right mode means a fresh container does not fail its first pass.
# 0755 on the socket dir because agent containers run as uid 1001 and must
# traverse it to reach their own socket.
RUN mkdir -p /etc/hive/agents /var/lib/hive/secrets /run/hive \
    && chmod 0700 /var/lib/hive/secrets \
    && chmod 0755 /run/hive

# Root, for the same reason packaging/hived.service runs as root: anything that
# can drive the Docker socket can escape most sandboxing, so dropping
# privileges here would be decoration rather than containment.
USER root

ENV RUST_LOG=hived=info,hive_core=info,hive_broker=info

# No HEALTHCHECK: `hive status` needs the control socket, and a failing
# healthcheck on a daemon whose job is to hold agents through transient Docker
# errors would restart it exactly when it should be waiting.
ENTRYPOINT ["/usr/local/bin/hived"]
