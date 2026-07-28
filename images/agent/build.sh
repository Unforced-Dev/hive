#!/usr/bin/env bash
# Build the hive agent image on the remote Docker host.
#
# Two build contexts: this repo (main, for the entrypoint) and a buzz checkout
# (named `buzz`, for the buzz-acp + buzz binaries the image is built around).
#
# The image tag carries the buzz commit, because "which buzz is in there" is the
# question that actually gets asked when an agent misbehaves, and an image tagged
# `:latest` cannot answer it. `hive` moves faster than buzz, so the buzz commit is
# the stable coordinate.
set -euo pipefail

HOST="${HIVE_BUILD_HOST:?set HIVE_BUILD_HOST, e.g. root@your-box}"
REMOTE="${HIVE_BUILD_DIR:-/root/hive}"
BUZZ_TREE="${BUZZ_TREE:?set BUZZ_TREE to a buzz checkout on $HOST}"
IMAGE="${HIVE_IMAGE:-hive-agent}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ssh "$HOST" "test -d $BUZZ_TREE" || {
    echo "buzz checkout not found at $BUZZ_TREE on $HOST" >&2
    echo "set BUZZ_TREE=/path/to/buzz" >&2
    exit 1
}

BUZZ_COMMIT=$(ssh "$HOST" "cd $BUZZ_TREE && git rev-parse --short HEAD 2>/dev/null || echo unknown")
echo "buzz:  $BUZZ_COMMIT  ($BUZZ_TREE)"
echo "image: $IMAGE:$BUZZ_COMMIT"

ssh "$HOST" "mkdir -p $REMOTE"
rsync -a --delete --exclude target --exclude .git -e ssh "$REPO_ROOT/" "$HOST:$REMOTE/"

# NOTE: no --pull. The base images are pinned by tag and already present; pulling
# on every build would silently move node:24-bookworm-slim underneath a build
# whose whole point is reproducibility.
ssh "$HOST" "cd $REMOTE && docker build \
  -f images/agent/Dockerfile \
  --build-context buzz=$BUZZ_TREE \
  --build-arg BUZZ_COMMIT=$BUZZ_COMMIT \
  -t $IMAGE:$BUZZ_COMMIT \
  ."

# Only tag :latest once the build (and therefore the harness assertion) passed.
ssh "$HOST" "docker tag $IMAGE:$BUZZ_COMMIT $IMAGE:latest"

echo
echo "=== installed harnesses ==="
ssh "$HOST" "docker run --rm --entrypoint cat $IMAGE:$BUZZ_COMMIT /etc/hive/harnesses.json"
