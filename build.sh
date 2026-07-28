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
# No default host: this repo builds on a remote Linux box with Docker, and
# guessing someone else's hostname is worse than asking.
HOST="${HIVE_BUILD_HOST:?set HIVE_BUILD_HOST, e.g. root@your-box}"
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
        # Same path inside and out. `docker run -v` resolves paths against the
        # HOST, not against this build container, so a socket created at
        # /run/hive here must be at /run/hive there too or the bind-mount
        # silently produces an empty directory in the agent container.
        -v /run/hive:/run/hive
        -e HIVE_DOCKER_TESTS=1
    )
    # --test-threads=1: these tests share ONE Docker daemon, and list() observes
    # global state — every hive-managed container on the box, including ones
    # other tests are mid-way through creating or destroying. Run in parallel it
    # fails intermittently and for reasons that have nothing to do with the code
    # under test, which is worse than being slow.
    CARGO_CMD=(cargo test --workspace -- --test-threads=1)
fi

if [ $# -gt 0 ]; then
    CARGO_CMD=("$@")
elif [ ${#CARGO_CMD[@]} -eq 0 ]; then
    # --test-threads=1: these tests share ONE Docker daemon, and list() observes
    # global state — every hive-managed container on the box, including ones
    # other tests are mid-way through creating or destroying. Run in parallel it
    # fails intermittently and for reasons that have nothing to do with the code
    # under test, which is worse than being slow.
    CARGO_CMD=(cargo test --workspace -- --test-threads=1)
fi

ssh "$HOST" "mkdir -p $REMOTE"
rsync -a --delete --exclude target --exclude .git -e ssh ./ "$HOST:$REMOTE/"
ssh "$HOST" "cd $REMOTE && docker run --rm \
  -v $REMOTE:/w -w /w \
  -v hive-cargo:/usr/local/cargo/registry \
  -v hive-target:/w/target \
  ${DOCKER_ARGS[*]:-} \
  rust:1.95-bookworm ${CARGO_CMD[*]}"
