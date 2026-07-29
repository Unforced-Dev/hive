#!/bin/sh
# `hive` for a containerized daemon. Install as `hive` on your PATH.
#
# On Linux the CLI talks to hived directly over /run/hive/hived.sock and this
# wrapper is unnecessary — install the real binary instead.
#
# Where hived runs in a container (macOS and Windows; see images/hived/
# Dockerfile), that control socket lives inside the Docker VM. A native CLI
# cannot connect to it for exactly the reason the daemon is containerized in
# the first place: a unix socket does not survive the host/VM boundary. So the
# CLI has to run on the same side as the daemon, and typing
# `docker exec hived hive ...` for every command makes the container an
# interface detail the user has to remember. It should not be.
#
#   install -m 0755 packaging/hive-wrapper.sh ~/.local/bin/hive
#   hive status
#
# Override the container name with HIVE_CONTAINER if you run more than one.
set -eu

CONTAINER="${HIVE_CONTAINER:-hived}"

# -i always: `hive secret put` reads the credential from stdin, and without it
# the secret is silently truncated to nothing rather than failing.
# -t only when there is a real terminal on both ends — `docker exec -t` errors
# out when stdin is a pipe, which would break exactly the secret-put case.
if [ -t 0 ] && [ -t 1 ]; then
    exec docker exec -i -t "$CONTAINER" hive "$@"
else
    exec docker exec -i "$CONTAINER" hive "$@"
fi
