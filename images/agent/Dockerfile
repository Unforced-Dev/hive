# The hive agent image: every supported ACP harness in one layer.
#
# WHY ONE FAT IMAGE
#   Buzz's harness selector is independent of its "where to run" selector, so
#   any harness can be chosen for a remote agent. buzz-acp then literally spawns
#   BUZZ_ACP_AGENT_COMMAND, and a harness the image lacks fails with "agent
#   failed to spawn: No such file or directory" -> "all 1 agents failed to
#   start". Since BYOH (block/buzz#2773) the harness layer is data-driven and the
#   desktop can name eight presets plus arbitrary custom JSON, so a per-harness
#   image would mean a pull on every selector change. One image makes the
#   selector mean what it says. It also lets an agent shell out to a *second*
#   harness — a Claude agent invoking codex — which is a real workflow and is
#   impossible if each image holds one.
#
#   The cost is size (~2.2 GB). That is the trade, taken deliberately.
#
# EVERY VERSION HERE IS PINNED, and the harness set is asserted at the end of the
# build. See "THE ASSERTION" below — it is the most important thing in this file.

# ---------------------------------------------------------------------------
# Stage 1: buzz-acp (the harness bridge) + buzz (the CLI the agent replies with)
# ---------------------------------------------------------------------------
# The buzz source arrives as a NAMED build context, not the main one, so that
# this repo stays the build context and the image can copy its own entrypoint.
# Supply it with:  --build-context buzz=/path/to/buzz-checkout
FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY --from=buzz . .
# buzz-acp is the harness bridge; buzz is the CLI the agent shells out to in
# order to post replies. Without the CLI the agent thinks and reacts but never
# sends — it looks hung when it is actually working fine.
RUN cargo build --release --locked -p buzz-acp --bin buzz-acp -p buzz-cli --bin buzz \
    && strip target/release/buzz-acp target/release/buzz

# ---------------------------------------------------------------------------
# Stage 1b: hive-headers, the in-container MCP credentials helper
# ---------------------------------------------------------------------------
# Built from THIS repo (the main build context). Claude Code runs it once per
# MCP connection, on a 10-second budget, and reads auth headers from its stdout;
# it asks the broker over a per-agent socket so no secret is ever written into
# the container. Rust rather than a shell script because the image has no `nc`
# or `socat`, and rather than node because a helper on a 10s budget should not
# depend on a runtime a future base image might not carry.
FROM rust:1.95-bookworm AS hive-builder
WORKDIR /hive
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --release --locked -p hive-headers \
    && strip target/release/hive-headers

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim

# xz-utils for hermes-class tarballs; bzip2/libxcb1/libdbus-1-3 are goose's.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash git ca-certificates curl bzip2 xz-utils libxcb1 libdbus-1-3 jq \
    && rm -rf /var/lib/apt/lists/*

# --- THE npm LIFECYCLE-SCRIPT GATE ------------------------------------------
# node:24-bookworm-slim ships npm 11.16.0, which refuses to run dependency
# install scripts by default AND STILL EXITS 0 (`strict-allow-scripts` is
# false). A skipped postinstall is a silent, green failure.
#
# @ampcode/cli is genuinely broken by this: its postinstall only hardlinks the
# real binary out of the per-platform optional dep, so skipping it leaves an
# empty bin dir and no amp. grok survives the skip only because its launcher
# re-bootstraps a 127 MB binary into $HOME on first run — which costs latency
# and needs a writable HOME, so we allow it at build time and make it a no-op.
#
# Tested and RULED OUT: `--allow-scripts <pkg>` (npm mis-parses),
# allow-scripts=true, allow-scripts="*", allow-scripts=all,
# NPM_CONFIG_ALLOW_SCRIPTS=true. `allow-scripts` is an ARRAY of package names.
# The only working forms are the targeted `--allow-scripts=<name>` used below
# and the blanket `--dangerously-allow-all-scripts`.
#
# Pass the flag on EVERY global install, including ones that appear not to need
# it — a future release adding a postinstall would otherwise fail silently.

ARG CLAUDE_AGENT_ACP_VERSION=0.63.0
ARG CODEX_ACP_VERSION=1.1.7
ARG CLAUDE_CODE_VERSION=2.1.220
RUN npm install -g --no-fund --no-audit \
      --allow-scripts=@agentclientprotocol/claude-agent-acp \
      --allow-scripts=@agentclientprotocol/codex-acp \
      --allow-scripts=@anthropic-ai/claude-code \
      "@agentclientprotocol/claude-agent-acp@${CLAUDE_AGENT_ACP_VERSION}" \
      "@agentclientprotocol/codex-acp@${CODEX_ACP_VERSION}" \
      "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force

# codex ships bundled inside codex-acp but is not linked onto PATH, so an agent
# that shells out to `codex` cannot find it. The vendor path is ARCH-SPECIFIC
# (@openai/codex-linux-x64/vendor/x86_64-… vs -arm64/vendor/aarch64-…), so it is
# located rather than hardcoded — hardcoding x86_64 breaks the arm64 build
# silently, and arm64 is where this is headed.
RUN set -eux; \
    codex_bin="$(find /usr/local/lib/node_modules/@agentclientprotocol/codex-acp \
                   -type f -name codex -perm -u+x | head -1)"; \
    test -n "$codex_bin"; \
    ln -sf "$codex_bin" /usr/local/bin/codex

# --- goose ------------------------------------------------------------------
# block/goose now redirects to aaif-goose/goose (Linux Foundation / AAIF); both
# URLs resolve to the same release asset today. Pinned rather than `stable`
# because `stable` moves under a rebuilt image without any diff to show for it.
ARG GOOSE_VERSION=v1.44.0
RUN set -eux; \
    curl -fsSL "https://github.com/aaif-goose/goose/releases/download/${GOOSE_VERSION}/download_cli.sh" \
      -o /tmp/goose-install.sh; \
    CONFIGURE=false bash /tmp/goose-install.sh; \
    rm -f /tmp/goose-install.sh; \
    cp /root/.local/bin/goose /usr/local/bin/goose; \
    chmod 0755 /usr/local/bin/goose

# --- grok (Grok Build) — first-party xAI ------------------------------------
# GROK_HOME is the INSTALL location, not per-agent state. It must stay a shared
# read-only path: point it into the per-agent volume and every agent
# re-bootstraps its own 127 MB copy of the binary on first run.
ARG GROK_VERSION=0.2.112
ENV GROK_HOME=/opt/grok
RUN npm install -g --no-fund --no-audit \
      --allow-scripts=@xai-official/grok \
      "@xai-official/grok@${GROK_VERSION}" \
 && npm cache clean --force \
 && chmod -R a+rX /opt/grok 2>/dev/null || true

# --- opencode ---------------------------------------------------------------
ARG OPENCODE_VERSION=1.18.8
RUN npm install -g --no-fund --no-audit \
      --allow-scripts=opencode-ai \
      "opencode-ai@${OPENCODE_VERSION}" \
 && npm cache clean --force

# --- kimi (Kimi Code) — first-party Moonshot, MIT ---------------------------
ARG KIMI_VERSION=0.29.2
RUN npm install -g --no-fund --no-audit \
      --allow-scripts=@moonshot-ai/kimi-code \
      "@moonshot-ai/kimi-code@${KIMI_VERSION}" \
 && npm cache clean --force

# --- amp --------------------------------------------------------------------
# amp-acp is tao12345666333's third-party ACP adapter (which is what the Buzz
# preset points at), depending on @ampcode/cli. @sourcegraph/amp is deprecated
# in favour of @ampcode/cli. The --allow-scripts flag is LOAD-BEARING here.
ARG AMP_ACP_VERSION=0.8.1
RUN npm install -g --no-fund --no-audit \
      --allow-scripts=@ampcode/cli \
      --allow-scripts=amp-acp \
      "amp-acp@${AMP_ACP_VERSION}" \
 && npm cache clean --force \
 && amp_bin="$(find /usr/local/lib/node_modules/amp-acp/node_modules/@ampcode/cli/bin \
                 -name 'amp*' -type f | head -1)" \
 && test -n "$amp_bin" \
 && ln -sf "$amp_bin" /usr/local/bin/amp

# --- omp (Oh My Pi) ---------------------------------------------------------
# NAME COLLISION: the npm package named `oh-my-pi` is an unrelated project. The
# real one is can1357/oh-my-pi, npm @oh-my-pi/pi-coding-agent — and the npm path
# declares engines:{bun:">=1.3.14"}, dragging in a whole second runtime. The
# release binary is self-contained and needs neither Bun nor Node.
ARG OMP_VERSION=v17.1.7
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
      amd64) oa=x64 ;; arm64) oa=arm64 ;; \
      *) echo "unsupported arch for omp: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/can1357/oh-my-pi/releases/download/${OMP_VERSION}/omp-linux-${oa}" \
      -o /usr/local/bin/omp; \
    chmod +x /usr/local/bin/omp

# --- cursor -----------------------------------------------------------------
# The piped installer (https://cursor.com/install) is verified working but has no
# version flag — it serves whatever is current, so it cannot produce a
# reproducible image. The pinned tarball URL is confirmed to exist for both linux
# arches; its internal LAYOUT was inferred rather than verified, so the binary is
# located with `find` after extraction instead of assumed at a fixed depth. If
# the layout ever changes, this fails loudly here rather than shipping an image
# whose `cursor` harness is missing.
ARG CURSOR_AGENT_VERSION=2026.07.23-e383d2b
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
      amd64) ca=x64 ;; arm64) ca=arm64 ;; \
      *) echo "unsupported arch for cursor: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    mkdir -p /opt/cursor-agent; \
    curl -fsSL "https://downloads.cursor.com/lab/${CURSOR_AGENT_VERSION}/linux/${ca}/agent-cli-package.tar.gz" \
      | tar -xz -C /opt/cursor-agent; \
    cursor_bin="$(find /opt/cursor-agent -type f -name cursor-agent -perm -u+x | head -1)"; \
    test -n "$cursor_bin"; \
    ln -sf "$cursor_bin" /usr/local/bin/cursor-agent

# NOT INSTALLED, deliberately:
#   hermes   — 735 MB, and the installer tracks the default branch with no
#              version-pin flag, so the build is not reproducible. Its Buzz
#              preset also names `hermes-acp`, a binary the installer never
#              creates (the real entrypoint is `hermes acp`).
#   openclaw — 386 MB, and `openclaw acp` is a BRIDGE to a running OpenClaw
#              Gateway, not a self-contained agent. Shipping the binary alone
#              does not give a working harness; it needs a Gateway to talk to.

COPY --from=builder /build/target/release/buzz-acp /usr/local/bin/buzz-acp
COPY --from=builder /build/target/release/buzz /usr/local/bin/buzz
COPY --from=hive-builder /hive/target/release/hive-headers /usr/local/bin/hive-headers

# ---------------------------------------------------------------------------
# THE ASSERTION
# ---------------------------------------------------------------------------
# Every failure mode above is a QUIET one: npm skips a postinstall and exits 0, a
# tarball's layout shifts, an upstream package stops shipping a per-platform
# binary for one arch. Each ships a green image whose harness is missing, and the
# symptom surfaces much later as "all 1 agents failed to start" on someone's
# desktop, with no clue pointing back at the build.
#
# So the build asserts. Every harness hive's catalog claims must resolve on PATH
# here, or the image does not get built. This is the only defence against a class
# of bug that is otherwise invisible until deploy time.
RUN set -eux; \
    missing=""; \
    for b in buzz-acp buzz hive-headers \
             claude-agent-acp claude codex-acp codex goose \
             grok opencode kimi amp-acp amp omp cursor-agent; do \
      command -v "$b" >/dev/null 2>&1 || missing="$missing $b"; \
    done; \
    if [ -n "$missing" ]; then \
      echo "FATAL: harnesses missing from image:$missing" >&2; \
      echo "If this is an npm harness, suspect the allow-scripts gate first." >&2; \
      exit 1; \
    fi; \
    echo "all harnesses present"

# Machine-readable manifest of what actually resolved, for `hive doctor` to diff
# against its catalog. Recorded from the running image rather than from the ARGs
# above, so it reports what IS installed, not what was requested.
ARG BUZZ_COMMIT=unknown
RUN set -eux; \
    mkdir -p /etc/hive; \
    npm_ver() { npm ls -g --depth=0 --json 2>/dev/null \
                  | jq -r --arg p "$1" '.dependencies[$p].version // "absent"'; }; \
    jq -n \
      --arg buzz             "${BUZZ_COMMIT}" \
      --arg claude_agent_acp "$(npm_ver @agentclientprotocol/claude-agent-acp)" \
      --arg codex_acp        "$(npm_ver @agentclientprotocol/codex-acp)" \
      --arg claude_code      "$(npm_ver @anthropic-ai/claude-code)" \
      --arg grok             "$(npm_ver @xai-official/grok)" \
      --arg opencode         "$(npm_ver opencode-ai)" \
      --arg kimi             "$(npm_ver @moonshot-ai/kimi-code)" \
      --arg amp_acp          "$(npm_ver amp-acp)" \
      --arg goose            "$(goose --version 2>/dev/null | head -1 || echo absent)" \
      --arg omp              "$(omp --version 2>/dev/null | head -1 || echo unknown)" \
      --arg cursor           "${CURSOR_AGENT_VERSION}" \
      --arg arch             "$(dpkg --print-architecture)" \
      '$ARGS.named' > /etc/hive/harnesses.json; \
    cat /etc/hive/harnesses.json

# ---------------------------------------------------------------------------
# Runtime user and state
# ---------------------------------------------------------------------------
RUN useradd -m -u 1001 -s /bin/bash agent
COPY images/agent/entrypoint.sh /usr/local/bin/hive-entrypoint
RUN chmod 0755 /usr/local/bin/hive-entrypoint

USER agent
WORKDIR /home/agent
ENV HOME=/home/agent

# ONE state directory, mounted as the volume, with every harness pointed inside
# it. Getting this wrong is invisible until a REDEPLOY: config lands on the
# container filesystem, is destroyed on recreate, and the agent silently reverts
# to unauthenticated — working perfectly right up until it doesn't. An earlier
# version of this file had CODEX_HOME at /home/agent/.codex while only
# /home/agent/.claude was mounted, and that is exactly how it presented.
ENV CLAUDE_CONFIG_DIR=/home/agent/state/claude
ENV CODEX_HOME=/home/agent/state/codex
ENV XDG_CONFIG_HOME=/home/agent/state/config
ENV XDG_DATA_HOME=/home/agent/state/data
# Harnesses that hardcode $HOME/.<name> get a symlink instead of an env var; the
# entrypoint creates the targets, because on a FIRST run the volume is empty and
# a dangling symlink makes the harness's own `mkdir -p` fail with EEXIST.
ENV AMP_HOME=/home/agent/state/amp
# GROK_HOME is deliberately NOT redirected here — see the install step.

# Create the state root AS THE AGENT USER, before VOLUME.
#
# Docker creates a VOLUME's mountpoint itself if it does not exist, owned by
# root:root, regardless of the USER in effect — and a fresh named volume then
# inherits that ownership. The agent (uid 1001) cannot write to it, so the first
# thing every harness does is fail: goose panics on "Failed to create session
# database directory", opencode dies with EACCES on mkdir. Creating the
# directory here first means the volume inherits agent ownership instead.
RUN mkdir -p /home/agent/state /home/agent/work \
 && test -w /home/agent/state

VOLUME ["/home/agent/state"]

# ANTHROPIC_API_KEY is intentionally never set: it OUTRANKS CLAUDE_CODE_OAUTH_TOKEN
# and silently switches a subscription agent to metered API billing.
ENTRYPOINT ["/usr/local/bin/hive-entrypoint"]
CMD ["buzz-acp"]
