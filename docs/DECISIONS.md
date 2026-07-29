# Decisions and the reasoning behind them

Written 2026-07-28. `ARCHITECTURE.md` says what hive does; this says **why**, and
what was considered and rejected. Kept because the conclusions are cheap to write
down and expensive to re-derive.

---

## hive is a Buzz *backend provider*, not a custom harness

Buzz has two independent extension points and the UI calls both "runtime":

| | picks | how you add one |
|---|---|---|
| **harness** | *what* agent software runs | JSON in `custom_harnesses/` |
| **where to run** (backend) | *where* it runs | a `buzz-backend-*` executable on PATH or `~/.local/bin` |

hive is the second. It was seriously considered making it the first — a custom
harness would need no provider protocol and no spec files.

**It cannot work, and the reason is process topology.** `buzz-acp` — which holds
the relay connection *and* the agent's identity — is bundled as a Tauri sidecar
and runs wherever the desktop runs. A custom harness is spawned *by* buzz-acp, so
it is always downstream of it. A harness definition can change which binary is
spawned, never where buzz-acp lives.

```
provider:        laptop[desktop → shim, once] --ssh--> server[hived → container(buzz-acp → harness)]
                 laptop closed → agent still running ✓

custom harness:  laptop[desktop → buzz-acp → harness] → relay
                 laptop closed → agent gone ✗
```

An SSH-wrapper variant (`command: ssh`, `args: [host, docker, exec, -i, ...]`)
*mechanically* works — ACP is JSON-RPC over stdio and ssh is a stdio pipe; a full
`initialize` round-trip was verified. But it fails as an integration:

- `buzz-acp` injects auth and config into the child's environment
  (`cmd.env(...)`, `cmd.env("CODEX_CONFIG", merged)`). **None of it crosses ssh.**
- The desktop's config bridges (`config_bridge/{claude,codex,goose}.rs`) write
  harness config to *local* files the remote process never reads.
- `process_group(0)` + `kill_process_group` do not reach across ssh; idle-timeout
  respawns orphan remote processes.
- Laptop sleep drops TCP → SIGHUP → in-process ACP session state is gone.
- ACP's remote transport is still a draft RFD; stdio is the only stable one.

And the UX is a trap: the agent looks deployed and goes dark when the lid closes,
which users report as a hive bug.

**Left open:** the objections above are all about the *ssh boundary*. With a
**local** container they mostly dissolve — env can be forwarded into
`docker exec -e`, config bridges can be bind-mounted, and the router is a normal
child process so signals reach it. That is what `hive-acp` (below) would be.

## `hive-acp` — a routing ACP. Designed, not built

An ACP proxy that presents one agent upward to buzz-acp and routes to
containerized harnesses below. Registered as a custom harness, running locally.

The ACP surface it must carry, from `buzz-acp`'s own usage:

```
client→agent:  initialize, session/new, session/prompt, session/cancel,
               session/set_model, session/set_config_option
agent→client:  session/update (streaming), session/request_permission
vendor:        _goose/unstable/session/{steer,update}, _meta passthrough
```

Bidirectional — the agent calls *back* for permissions, so responses must route by
id. Not a pipe. Generic forwarding (intercept `initialize` and `session/new`, pass
everything else through by session id) makes it ~400–600 lines. The fiddly part is
`initialize`: capabilities must be advertised before a backend is chosen.

**What it unlocks that nothing else does:** switching between *different harnesses*
mid-conversation. Thread history lives on the relay, so a fresh backing session
isn't blind. Note `session/set_model` already exists — switching *models within* a
harness needs none of this.

**Cheaper 80%:** for containerized agents on one machine, add a **local mode to the
shim** (skip ssh, write the spec and store the secret directly, ~40 lines).
`hive-core` already drives Docker via `DOCKER_HOST`, unset for a local daemon. Do
that before building a router.

## Why the shim carries a catalog copy, and why it shouldn't

The shim maps the desktop's `agent_command`/`agent_args` back to a catalog id on
the *client*. That means every laptop carries a copy of the catalog and goes stale
when it changes.

**Planned:** move the lookup into `hived`, where the catalog already lives and
where the image that must contain the binary also lives. Then the shim is pure
translation and can be a dependency-free `python3` script — which removes the
rustup requirement for installing the provider. Do these in that order; the
python rewrite is only correct *after* the resolution moves.

## Credentials: three tiers, and why not one

| tier | used for | in container? | `docker inspect` sees it? |
|---|---|---|---|
| env | `CLAUDE_CODE_OAUTH_TOKEN`, `XAI_API_KEY`, nsec | yes | **yes** |
| file (`[[file]]`) | codex `auth.json` — no env form exists | yes | no |
| broker (`[[mcp]]`) | MCP tokens, **Claude Code only** | **no** | no |

The temptation is to claim "credentials never enter the container". That is true
only for MCP servers and only on Claude Code, because `headersHelper` is the only
per-connection hook that exists anywhere in the catalog. A harness authenticates
to its own model API and nothing can intercept that.

`harness.auth = broker | file | interactive` exists because requiring a
`harness/<id>` env credential unconditionally held agents forever waiting for a
credential that would never exist — and held them so hard you could not start a
container to log in interactively.

## Reconciler orderings that are load-bearing

- **A changed spec beats a crash loop.** The other order strands an agent whose
  crash the spec edit is trying to fix.
- **A crash loop beats merely being stopped.** Otherwise a failing agent restarts
  forever.
- **Build the new plan before removing the old container.** A failure to render
  config then leaves the old agent running.
- **Conflicts hold, they do not drop.** Dropping a spec makes its container look
  deleted; adding one bad file would tear down an agent that had been working. This
  was implemented the wrong way first and caught by testing on a real box.

## Subnet pool

Agent networks are allocated from `10.88.0.0/16`, one `/24` each, so firewall rules
are written **once**. Docker's arbitrary allocation meant per-agent rules, and an
agent missing them still reaches the public internet — so it looks alive and simply
never connects to the relay. Worst available failure mode, hit on the first agent.

## Relationship to Buzz, and why not upstream this

Buzz ships ~850 commits/month from a full-time team, and v0.5.0 was entirely
desktop UX. Hosting is out of scope **by design** — the docs say agents "can run on
your laptop, in the cloud, or at the edge". That is a stable boundary, not a gap
waiting to close.

`buzz-spawner` (server-hosted agents) is unmerged: 4 PRs, ~17k lines, from a
contributor with 0 merged PRs, 0 reviews, while staff PRs merge daily.

**What is worth upstreaming is small:** the HTTP variant for `buzz-acp`'s
`McpServer` (still `{name, command, args, env}` at v0.5.0, so HTTP MCP is
unreachable through ACP). Landing it would let hive **delete `mcp.rs`**. Also worth
reporting: Buzz's `hermes` preset invokes `hermes-acp`, a binary its installer
never creates.

Not worth upstreaming: hive itself. An agent host wants to outlive any one surface,
and the multi-relay case — one identity, several communities — is structurally
something a Buzz-internal runtime cannot own.

## On macOS, `hived` runs in a container — and it is not a workaround

`hived` **cannot run as a native macOS process.** The broker creates one unix
socket per agent and bind-mounts it into that agent's container. On macOS the
containers live inside a Linux VM, and a socket created on the host side and
shared in through virtiofs is *visible but not connectable* — `connect()`
returns `ENOTSUP`.

That failure mode is the dangerous kind. `hived` would start, reconcile, create
containers and report healthy, while every broker-delivered credential failed —
the one feature whose entire purpose is keeping secrets out of containers.

Running the daemon **inside a container** fixes it with no code change, because
the daemon is then on the same kernel as the agents and the sockets are ordinary
Linux sockets. Two mounts carry it:

```
-v /var/run/docker.sock:/var/run/docker.sock   # drive Docker
-v /run/hive:/run/hive                          # PATH-MATCHED, see below
```

The second must map to **the same path inside and out**. `docker run -v`
resolves the source against the *daemon's* filesystem, so when `hived` asks for
`/run/hive/agent.sock` to be mounted into an agent, Docker looks for that path
on the host. Mount the socket directory anywhere else inside the daemon
container and Docker finds nothing there — and silently creates an empty
*directory*, so the agent sees a directory where its socket should be and the
error surfaces inside the harness. `images/agent/build.sh` already depends on
this for the integration tests.

**Rejected: moving the broker to TCP.** It works mechanically — a container
reaches the macOS host on `host.docker.internal`. But the broker identifies its
caller *solely* by which socket the request arrived on, because every agent
container runs as uid 1001 and peer credentials cannot distinguish them. Over
TCP every agent can reach every port, so one agent could request another's
credentials. That replaces a working identity mechanism with none.

The same image runs on Linux, so this is a portable deployment mode rather than
a macOS special case — though on Linux `packaging/hived.service` remains simpler
and is still the recommendation.

**Consequence for the desktop shim:** with `hived` local there is no host to ssh
to, so `buzz-backend-hive` grew a `hived_container` config field and reaches the
daemon with `docker exec -i`. It still only ever does two things — store a
credential, write a spec — so the transport is the entire difference.

## Open

- **Retire or keep the Hetzner box (`uni`).** Undecided as of the wipe. Keeping it
  costs money and keeps hive's *remote* path exercised; retiring it makes the
  provider path vestigial and local mode urgent.
- **`/run/hive` is tmpfs inside a Docker VM** and does not survive a VM restart.
  Whatever starts the daemon container must create it first, or the broker has
  nowhere to put sockets. Not yet automated.
- **`cargo fmt --check` and `cargo clippy -D warnings` both fail on `main`.** The
  fmt diff is edition-2024 import ordering; clippy flags two things in
  `hive-core`. Neither is caused by this work, and both should be fixed
  separately so the diff is not buried in reformatting.
