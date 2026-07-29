#!/bin/sh
# Speak ACP to every harness in the image and report which ones answer.
#
# WHY THIS EXISTS
#   The image build asserts that each harness binary is ON PATH. That is a much
#   weaker claim than it looks: `command -v` succeeds for a binary that cannot
#   execute on this architecture, and for one whose arguments the build never
#   tried. This caught `grok agent --no-auto-update` — a flag that reads
#   perfectly, is suggested in the wild, and does not exist, so the harness
#   refused to start and the image built green.
#
#   Run it after every image build. It is the difference between "the file is
#   there" and "the harness works".
#
# WHAT PASSING MEANS
#   The binary executes on this arch AND returns a JSON-RPC result to an ACP
#   `initialize`. It does NOT mean the harness is authenticated — initialize
#   precedes credentials, by design, for every harness here.
#
# Run inside the image, as the agent user, THROUGH the normal entrypoint:
#   docker run --rm -v .../smoke.sh:/smoke.sh:ro hive-agent:latest sh /smoke.sh
# Bypassing the entrypoint (--entrypoint sh) skips state-directory setup, and
# goose and opencode then fail on their own state dirs rather than on ACP.

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false}}}}'

fail=0

probe() {
    name="$1"; shift
    # Hold stdin OPEN after the request. A harness that reads to EOF may exit
    # cleanly before it ever answers — which looks identical to a crash, and is
    # not how a real ACP client behaves.
    out=$({ printf '%s\n' "$INIT"; sleep 12; } | timeout 20 "$@" 2>&1 | head -c 500)

    if printf '%s' "$out" | grep -q '"result"'; then
        printf '  %-10s PASS\n' "$name"
    else
        printf '  %-10s FAIL  %s\n' "$name" \
            "$(printf '%s' "$out" | tr '\n' ' ' | head -c 160)"
        fail=1
    fi
}

# --- persistence ------------------------------------------------------------
# Every path an agent writes to must resolve ONTO the state volume. A path left
# on the container's ephemeral layer looks perfect until the first recreate —
# which a spec edit triggers — and then the data is gone with no error anywhere.
#
# This exists because two of them were wrong at once: $GROK_HOME pointed at the
# read-only install, and /home/agent/work was a plain directory in the image, so
# an agent's working files were deleted on every recreate while its sessions and
# credentials survived. Both read fine in the Dockerfile.
STATE="${HIVE_STATE_DIR:-/home/agent/state}"

persists() {
    name="$1"; path="$2"
    real=$(readlink -f "$path" 2>/dev/null)
    case "$real" in
        "$STATE"|"$STATE"/*) printf '  %-10s PASS  %s\n' "$name" "$real" ;;
        "") printf '  %-10s FAIL  %s does not exist\n' "$name" "$path"; fail=1 ;;
        *)  printf '  %-10s FAIL  %s -> %s is NOT on the state volume\n' \
                "$name" "$path" "$real"; fail=1 ;;
    esac
}

echo "persistence:"
persists work     "$HOME/work"
persists grok     "${GROK_HOME:-$HOME/.grok}"
persists claude   "${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
persists codex    "${CODEX_HOME:-$HOME/.codex}"
persists kimi     "$HOME/.kimi"
persists cursor   "$HOME/.cursor"
persists opencode "$HOME/.opencode"
persists omp      "$HOME/.omp"
persists amp      "${AMP_HOME:-$HOME/.amp}"
echo
echo "acp:"

# The probe table. Kept in sync with hive-core's harness catalog by a test in
# crates/hive-core/src/lib.rs — edit the catalog, not just this list.
# HARNESS_TABLE_BEGIN
probe claude    claude-agent-acp
probe codex     codex-acp
probe goose     goose acp
probe grok      grok agent --always-approve stdio
probe opencode  opencode acp
probe kimi      kimi acp
probe amp       amp-acp
probe omp       omp acp
probe cursor    cursor-agent acp
# HARNESS_TABLE_END

if [ "$fail" -ne 0 ]; then
    echo
    echo "One or more harnesses did not answer ACP. This image should not ship." >&2
    exit 1
fi
echo
echo "all harnesses speak ACP"
