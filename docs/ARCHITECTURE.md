# What hive is, and how it works

## In one paragraph

hive runs persistent [ACP](https://agentclientprotocol.com) agents in isolated
Docker containers on a single box you own. An agent is a TOML file; a daemon
makes reality match the files. Each agent gets its own container, its own network
and its own state; the credentials it needs at runtime are held by a broker
rather than baked into the image. It talks to [Buzz](https://github.com/block/buzz)
today because that is the surface it was built against, but the machinery
underneath is ACP-shaped rather than Buzz-shaped.

## The problem it solves

Buzz gives agents cryptographic identity and a place to talk. It deliberately
ships **no runtime** — its own docs say agents "can run on your laptop, in the
cloud, or at the edge". That is a reasonable scope decision, and it leaves a hole:
if you want an agent that is always on, that is not your laptop, and that cannot
reach your other machines, you have to build that yourself.

The obvious approach — `docker run` per agent with credentials in the environment
— works and is what most people do. It has three problems that only show up later:

1. **Every secret is readable** by anyone with Docker daemon access, via
   `docker inspect`, and by any process inside the container.
2. **Agents can reach each other and your network**, because a default bridge
   permits it and most firewall rules silently do not apply to container traffic.
3. **Nothing is reproducible.** Which harness version, which config, which
   credential — all of it lives in shell history.

hive is the small, auditable answer to those three.

## The shape

```
  hive (CLI) ─────┐
                  ├──►  hived  ──►  hive-core  ──►  Docker
  buzz-backend-   │       │        (never sees a secret)
    hive (SSH) ───┘       └──►  hive-broker  ──►  secret store
                                    │
                                    └── per-agent unix socket ──► hive-headers
                                                                  (in container)
```

Two front doors, one path. The Buzz desktop's provider picker writes a spec file
over SSH and stores a key; you can also just write the file. There is no third
code path that only the UI exercises, and an agent deployed either way is
byte-identical.

### The crates

| crate | responsibility | notes |
|---|---|---|
| `hive-spec` | spec types and validation | no I/O at all |
| `hive-core` | harness catalog, container backend, network policy, reconciler | never links the broker |
| `hive-broker` | the only component that sees secrets | |
| `hive-headers` | in-container MCP credentials helper | tiny, no runtime deps |
| `hived` | the daemon; composes core + broker | |
| `hive-cli` | `hive` | most subcommands work offline |
| `buzz-backend-hive` | Buzz desktop provider shim | runs on the desktop |

`hive-core` and `hive-broker` do not depend on each other. Core defines a
`CredentialSource` trait and the daemon wires the broker in as its implementation,
so a bug in reconciliation cannot read the credential store. That layering is
enforced by the dependency graph, not by convention.

## Reconciliation

`hived` polls the spec directory every 30 seconds, lists the containers it
manages, and computes a plan:

| situation | action |
|---|---|
| spec, no container | **Create** |
| spec hash differs from the container's label | **Replace** |
| container matches but is stopped | **Start** |
| container, no spec | **Remove** (container only — never the volume) |
| credentials missing | **Hold** |
| restarting ≥ 5 times | **Hold** |
| two specs, one identity, one relay | **Hold** both |

`plan(desired, observed) -> Vec<Action>` is a **pure function**. It does no I/O,
which means every destructive decision is unit-tested without a container runtime
present. Applying the plan is the only part that touches Docker.

Some ordering in there is load-bearing rather than stylistic:

- **A changed spec beats a crash loop**, so you can fix a crashing agent by
  editing its spec. The other order strands it.
- **A crash loop beats merely being stopped**, so a failing agent is held rather
  than restarted forever.
- **Build the new plan before removing the old container**, so a failure to
  render config leaves the old agent running.
- **Conflicts hold rather than drop.** Dropping a spec makes its container look
  deleted, so one bad new file would tear down an agent that had been working.

Containers carry a `dev.hive.managed` label and `list()` filters on it, so a
container hive did not create is invisible to reconciliation and can never be
adopted or deleted.

## Credentials

Three delivery tiers, and the difference between them is the point.

| tier | used for | in the container? | `docker inspect` sees it? |
|---|---|---|---|
| **env** | `CLAUDE_CODE_OAUTH_TOKEN`, `XAI_API_KEY`, `BUZZ_PRIVATE_KEY` | yes | **yes** |
| **file** (`[[file]]`) | codex `auth.json` — no env form exists | yes | no |
| **broker** (`[[mcp]]`) | MCP tokens, Claude Code only | **no** | no |

Specs contain credential *names*, never values. Validation refuses anything that
looks like a pasted secret, because specs are meant to be committed.

### How the broker tier works

Claude Code supports a `headersHelper`: a program it runs once per MCP connection
to obtain auth headers. hive points it at `hive-headers`, which connects to a unix
socket bind-mounted into that one container and asks the broker.

The contract was read out of the claude-code 2.1.220 binary rather than from
documentation: shell-invoked with no arguments, **10-second timeout**, must exit 0
*and* write to stdout, and receives `CLAUDE_CODE_MCP_SERVER_NAME` and
`CLAUDE_CODE_MCP_SERVER_URL` in its environment — so one helper serves every
server.

**Identity is the socket, never a claim.** Every agent container runs as uid 1001,
so `SO_PEERCRED` cannot distinguish them; one shared socket would let any agent
request any other agent's secrets. One listener per agent, bind-mounted
individually, makes mount topology the credential. The request type has no agent
field at all, and a test asserts that an extra one is ignored rather than honoured.

Grants are resolved **per request**, not captured at listener startup — a listener
outlives any particular version of a spec, and a deleted agent must be denied
rather than served from a stale snapshot.

### What is deliberately not promised

A harness authenticates to its own model API and there is no hook to intercept
that, so model credentials are injected and are readable by anyone with daemon
access. `headersHelper` is MCP-specific. hive offers a **smaller blast radius, not
zero**, and saying so plainly is more useful than a longer feature list.

Secrets are 0600 files, not encrypted. Encrypting them with a key stored on the
same disk protects against nothing an attacker who can read the files cannot also
do. The boundary is file permissions and root.

## Isolation

Each agent gets its **own Docker network**, created with
`com.docker.network.bridge.enable_icc=false`.

That flag is not belt-and-braces; on many hosts it is the *only* control that
works. Container-to-container traffic on a shared bridge traverses iptables only
when `br_netfilter` is loaded, and when it is absent no firewall rule can block it
— `/proc/sys/net/bridge` does not even exist. Disabling inter-container
communication at the bridge is what makes the isolation claim true.

Test it by probing a peer **by raw IP**. Probing by name only proves DNS is not
resolving and reports success on a wide-open network. hive's integration test runs
a peer that actually serves HTTP and asserts it is serving *before* checking that
it is unreachable, so a pass means something.

Containers also run with `--cap-drop=ALL` and `--security-opt no-new-privileges`.
A harness is a userspace process making HTTP calls; it needs no capabilities, and
this is a container running model-authored code by design.

Egress rules are **printed, not applied** — `hive firewall <agent>` emits iptables
rules with an explanation of each, and you run them. hive does not silently
rewrite your firewall.

## State

One volume per agent at `/home/agent/state`, with **every** harness state
directory inside it: `claude`, `codex`, `kimi`, `grok`, `amp`, `cursor`, `omp`,
`opencode`, plus `config`, `data`, `work`. Harnesses that hardcode `$HOME/.foo`
get a symlink into the volume, created by the entrypoint on first start (the
volume is empty then, and a dangling symlink makes the harness's own `mkdir -p`
fail with EEXIST).

So skills, credentials and history are per-agent by construction. Nothing is
shared unless you say so:

```toml
[[volume]]
name   = "uni-workspace"
target = "/home/agent/work"
```

Validation refuses a shared target inside `/home/agent/state` — mounting a shared
volume over private state would give every agent naming it the same `.claude`,
which is the precise failure per-agent volumes exist to prevent.

Removing a container never removes its volume. Not even on replace. That volume
holds credentials and any interactive OAuth session, and losing it to a spec edit
is a failure that surfaces hours later with no visible cause.

## The image

One image with nine ACP harnesses: claude, codex, goose, grok, opencode, kimi,
amp, omp, cursor. ~4 GB, every version pinned.

One image rather than one per harness because Buzz's harness selector is
independent of its "where to run" selector — any harness can be picked for a
remote agent, and a missing one fails as "agent failed to spawn: No such file or
directory". It also lets an agent shell out to a *second* harness, which is a real
workflow and impossible if each image holds one.

Two safeguards, both earned:

- **The build asserts.** Every harness the catalog claims must resolve on PATH or
  the image does not build. npm 11.16 refuses lifecycle scripts by default *and
  exits 0*, so a skipped postinstall is a silent green failure — amp is genuinely
  broken by it.
- **`images/agent/smoke.sh` speaks ACP to each harness.** Being on PATH is a much
  weaker claim than working: this caught `grok agent --no-auto-update`, a flag
  that reads perfectly, is suggested in the wild, and does not exist.

`hermes` and `openclaw` are in the catalog but deliberately not installed —
listed rather than hidden so selecting one gives a reason instead of a spawn
failure. hermes tracks a branch with no version pin (not reproducible); openclaw's
ACP mode is a bridge to a Gateway daemon rather than a self-contained agent.

## Identity across relays

`buzz-acp` takes a scalar `BUZZ_RELAY_URL`, so one agent in two communities is
genuinely two containers and two specs — but one identity. `identity.credential`
names the broker key explicitly so the private key exists in exactly one place:

```toml
# uni-other.toml
[identity]
pubkey     = "8f3c…"
relay_url  = "wss://other.example"
credential = "nsec/uni"
```

The same identity on the **same** relay is refused: two processes answer as one
agent, every mention gets two replies, both charged to the owner, and the turns
interleave — which reads as the model repeating itself rather than as a
deployment mistake. No single spec is wrong, so per-spec validation cannot see it;
`hived` checks across specs.

## Testing philosophy

Tests are named for the failure they prevent, not the function they cover:
`observer_defaults_on_because_remote_agents_are_otherwise_invisible`,
`published_ports_match_on_the_pre_dnat_destination_not_dport`,
`a_conflicting_spec_is_held_and_never_removes_a_running_container`.

Nearly every one is scar tissue from something that actually went wrong on a real
box. The unit tests verify what hive *decides*; the Docker integration tests
(`./build.sh --docker`) verify what Docker actually *does*, because that is where
the expensive bugs have been.
