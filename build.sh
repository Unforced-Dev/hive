#!/usr/bin/env bash
# Build/test in a container against the Linux target, with no host toolchain.
#
# There is deliberately no local-toolchain path: hive targets Linux + Docker,
# and building on macOS would compile code that cannot run where it ships.
#
#   ./build.sh                     cargo test --workspace
#   ./build.sh --docker            also run the integration tests against a real
#                                  Docker daemon (creates and destroys containers)
#   ./build.sh <cmd...>            run an arbitrary cargo command
set -euo pipefail
HOST="${HIVE_BUILD_HOST:-root@uni}"
REMOTE="${HIVE_BUILD_DIR:-/root/hive}"

DOCKER_ARGS=()
CARGO_CMD=()

if [ "${1:-}" = "--docker" ]; then
    shift
    # The Docker CLI is a mostly-static Go binary, so mounting the host's copy
    # into a bookworm container works without dragging in a package. The socket
    # gives it a daemon to talk to — which means these tests create and destroy
    # real containers on $HOST.
    DOCKER_ARGS=(
        -v /var/run/docker.sock:/var/run/docker.sock
        -v /usr/bin/docker:/usr/bin/docker:ro
        -e HIVE_DOCKER_TESTS=1
    )
    CARGO_CMD=(cargo test --workspace)
fi

if [ $# -gt 0 ]; then
    CARGO_CMD=("$@")
elif [ ${#CARGO_CMD[@]} -eq 0 ]; then
    CARGO_CMD=(cargo test --workspace)
fi

ssh "$HOST" "mkdir -p $REMOTE"
rsync -a --delete --exclude target --exclude .git -e ssh ./ "$HOST:$REMOTE/"
ssh "$HOST" "cd $REMOTE && docker run --rm \
  -v $REMOTE:/w -w /w \
  -v hive-cargo:/usr/local/cargo/registry \
  -v hive-target:/w/target \
  ${DOCKER_ARGS[*]} \
  rust:1.95-bookworm ${CARGO_CMD[*]}"
