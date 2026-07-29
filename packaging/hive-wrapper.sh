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
#
# -t only when there is a real terminal on both ends AND this is not a command
# that reads stdin. Two separate reasons:
#
#   * `docker exec -t` errors outright when stdin is a pipe, which is the
#     `pbpaste | hive secret put ...` case.
#   * With a TTY allocated, Ctrl-D only signals EOF at the START of a line. A
#     pasted credential rarely ends in a newline, so one Ctrl-D flushes the
#     line and does not end input — the command appears to hang, or exits
#     having stored nothing. Reported as "not the most intuitive way of putting
#     a secret in", which is generous.
#
# So: no TTY for `secret put`, even interactively. Ctrl-D then behaves the way
# everyone expects.
needs_stdin=false
if [ "${1:-}" = "secret" ] && [ "${2:-}" = "put" ]; then
    needs_stdin=true
fi

if [ -t 0 ] && [ -t 1 ] && [ "$needs_stdin" = false ]; then
    exec docker exec -i -t "$CONTAINER" hive "$@"
else
    exec docker exec -i "$CONTAINER" hive "$@"
fi
