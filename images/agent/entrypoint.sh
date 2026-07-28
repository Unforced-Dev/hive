#!/bin/sh
# hive agent entrypoint.
#
# Exists for one reason: on a container's FIRST start the state volume is empty,
# so every per-harness directory under it is missing. Harnesses react to that
# badly and differently — some mkdir it, some write to a fallback path outside
# the volume (losing credentials on the next recreate), and any that hardcode
# $HOME/.<name> hit a dangling symlink, where `mkdir -p` fails with EEXIST
# rather than following through.
#
# So: create the directories, link the hardcoded paths, then get out of the way.
# Everything here is idempotent — it runs on every start, including restarts
# where the volume is already populated.
set -eu

STATE="${HIVE_STATE_DIR:-/home/agent/state}"

# Directories the env vars in the image point at.
for d in claude codex config config/goose data amp work; do
    mkdir -p "$STATE/$d"
done

# Harnesses that hardcode $HOME/.<name> and offer no env override. The link is
# created only when the path is absent or already the link we want, so a real
# directory placed there by a user (or by a harness that got there first) is
# never silently replaced.
link_state() {
    name="$1"; target="$STATE/$2"
    mkdir -p "$target"
    if [ -L "$HOME/$name" ] || [ ! -e "$HOME/$name" ]; then
        ln -sfn "$target" "$HOME/$name"
    fi
}
link_state .grok      grok       # grok login -> ~/.grok/auth.json (GROK_HOME is the install dir, not this)
link_state .kimi      kimi
link_state .cursor    cursor
link_state .opencode  opencode
link_state .omp       omp

# A harness that is selected but absent fails inside buzz-acp as "agent failed
# to spawn: No such file or directory", which surfaces on the desktop as "all N
# agents failed to start" — true, and useless. Say the actual thing instead.
if [ -n "${BUZZ_ACP_AGENT_COMMAND:-}" ]; then
    cmd="${BUZZ_ACP_AGENT_COMMAND%% *}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "hive: harness '$cmd' is not in this image." >&2
        echo "hive: available:" >&2
        for b in claude-agent-acp codex-acp goose grok opencode kimi amp-acp omp cursor-agent; do
            command -v "$b" >/dev/null 2>&1 && echo "hive:   $b" >&2
        done
        exit 127
    fi
fi

exec "$@"
