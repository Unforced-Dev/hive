#!/usr/bin/env bash
# Build/test in a container against the Linux target, with no host toolchain.
#
# There is deliberately no local-toolchain path: hive targets Linux + Docker,
# and building on macOS would compile code that cannot run where it ships.
set -euo pipefail
HOST="${HIVE_BUILD_HOST:-root@uni}"
REMOTE="${HIVE_BUILD_DIR:-/root/hive}"
ssh "$HOST" "mkdir -p $REMOTE"
rsync -a --delete --exclude target --exclude .git -e ssh ./ "$HOST:$REMOTE/"
ssh "$HOST" "cd $REMOTE && docker run --rm \
  -v $REMOTE:/w -w /w \
  -v hive-cargo:/usr/local/cargo/registry \
  -v hive-target:/w/target \
  rust:1.95-bookworm ${*:-cargo test --workspace}"
