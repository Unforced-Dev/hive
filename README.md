# hive

Run persistent [ACP](https://agentclientprotocol.com) agents in isolated
containers on a box you own.

One agent is one file. `hived` makes reality match the files. Each agent gets its
own container, its own network, and its own credentials — and the credentials it
needs at runtime are held by a broker rather than baked into the container.

Buzz-first, because that is the surface this was built against. ACP-shaped
underneath, because that is where the portability is.

```toml
# /etc/hive/agents/scribe.toml — commit this; it holds no secrets
[identity]
pubkey     = "8f3c…"
relay_url  = "wss://relay.example"
owner_pubkey = "a91b…"

[harness]
id = "claude"

[agent]
respond_to = "owner-only"

[[mcp]]
name       = "parachute"
transport  = "http"
url        = "https://vault.example/mcp"
credential = "mcp/parachute"     # a NAME, resolved by the broker
```

```console
$ hive secret put nsec/scribe   < agent.nsec
$ hive secret put harness/claude < oauth-token
$ hive secret put mcp/parachute < vault-token
$ hive status
```

---

## Why this exists

Buzz ships no runtime, deliberately — it provides identity and a surface, and
says agents "can run on your laptop, in the cloud, or at the edge". The runtime
is left to you. `BackendKind::Provider` is the seam for one, and upstream's own
issue text notes there is no open-source implementation of it.

The nearest prior art is Paradigm's Centaur: Kubernetes, per-*thread* rather than
per-agent, Slack-only. Everything else in the space is either an ephemeral code
sandbox (E2B, Modal, Cloudflare) or a vertically integrated product with no
reusable layer.

hive is the small version: **one box, no orchestrator.** If it needs a cluster,
it has failed.

## What you get

- **A container per agent**, with its own network. Agents cannot reach each
  other, your other Docker networks, or other hosts on your private network.
- **Nine ACP harnesses in one image** — claude, codex, goose, grok, opencode,
  kimi, amp, omp, cursor — all pinned, and all verified to answer an ACP
  `initialize` on the architecture the image was built for.
- **A credential broker.** MCP credentials are served per-connection over a
  per-agent unix socket and never enter the container.
- **Declarative specs.** An agent is a TOML file. Reconciliation is idempotent,
  and the plan is a pure function you can read.

## Install

```console
# on the host
git clone https://github.com/Unforced-Dev/hive && cd hive
./images/agent/build.sh              # builds the agent image (~4 GB)
cargo install --path crates/hived --path crates/hive-cli

sudo mkdir -p /etc/hive/agents /var/lib/hive/secrets /run/hive
sudo hived --once                    # one reconciliation pass, then exit
sudo cp packaging/hived.service /etc/systemd/system/ && sudo systemctl enable --now hived
```

`hive doctor` checks the things that are usually wrong.

## Getting inside a container

```console
$ hive shell <agent>              # exec into the running agent
$ hive shell --scratch <agent>    # side container on the agent's volumes
$ hive restart <agent>            # drop the container; hived recreates it
```

`--scratch` is the one for an interactive login (`codex login`,
`claude setup-token`). It starts a separate container from the same image with
the agent's state volume *and* its shared volumes mounted, on the agent's
network, with no relay connection — so the reconciler cannot replace the
container underneath you mid-flow, and it works when the agent is crash-looping
and `exec` would fail. Anything written under `/home/agent/state` persists;
`hive restart` makes the harness pick it up.

## State is per-agent, always

Each agent gets its own Docker volume at `/home/agent/state`, and **every**
harness state directory lives inside it — `claude`, `codex`, `kimi`, `grok`,
`amp`, `cursor`, `omp`, `opencode`, plus `config`, `data` and `work`. Harnesses
that hardcode `$HOME/.foo` get a symlink into the volume, made by the entrypoint.

So an agent's skills, credentials and history are its own. Nothing is shared by
default. The one shared path is `/opt/grok`, which is the grok *binary* —
root-owned, read-only to agents, and 127 MB you do not want copied per agent.

To share deliberately, name a volume:

```toml
[[volume]]
name   = "uni-workspace"
target = "/home/agent/work"
```

Two agents naming the same volume edit the same tree while keeping separate
skills and credentials. Validation refuses a target inside `/home/agent/state`,
because mounting a shared volume over private state is the exact failure this
design exists to prevent.

## Switching a model or harness

Edit the spec. hive replaces the container; the agent keeps its pubkey, its state
volume and its files, and thread history lives on the relay rather than in the
container — so the conversation survives. Both harnesses' state persists
side by side in the volume, so switching back and forth is free.

## How it hangs together

```
  hive (CLI) ─────┐
                  ├──►  hived  ──►  hive-core  ──►  Docker
  buzz-backend-   │       │         (no secrets)
    hive (SSH) ───┘       └──►  hive-broker  ──►  secrets
                                    │
                                    └── per-agent socket ──► hive-headers
                                                              (in container)
```

`hive-core` and `hive-broker` do not depend on each other. Core defines a
`CredentialSource` trait; the daemon wires the broker in. A bug in reconciliation
cannot read the credential store.

| crate | what it is |
|---|---|
| `hive-spec` | spec types and validation. No I/O. |
| `hive-core` | harness catalog, container backend, network policy, reconciler |
| `hive-broker` | the only component that sees secrets |
| `hive-headers` | tiny helper that runs *inside* the container |
| `hived` | the daemon |
| `hive-cli` | `hive` |
| `buzz-backend-hive` | Buzz desktop provider shim |

## What hive does *not* promise

Being straight about this is more useful than a longer feature list.

**Docker is not a security boundary against hostile code.** It is a namespace
boundary. hive is the right tool for "my own agents, which I do not want reaching
each other or my network" and the wrong tool for running code from someone who
wants in.

**"Credentials never enter the container" is only true for MCP servers, and only
on Claude Code.** A harness authenticates to its own model API and there is no
hook to intercept that, so model credentials are injected. `headersHelper` is
MCP-specific. What hive offers is a smaller blast radius, not zero. Three tiers,
worst to best:

| delivery | used for | `docker inspect` sees it? |
|---|---|---|
| env | `CLAUDE_CODE_OAUTH_TOKEN`, `XAI_API_KEY` | **yes** |
| file (`[[file]]`) | codex `auth.json` — no env form exists | no |
| broker (`[[mcp]]`) | MCP tokens, Claude only | never enters the container |

**Secrets are 0600 files, not encrypted.** Encrypting them with a key stored on
the same disk protects against nothing an attacker who can read the files cannot
also do. The boundary is file permissions and root. If that is not enough for
you, the answer is a KMS or a hardware token, not a local key file.

**Egress rules are printed, not applied.** `hive firewall <agent>` emits the
iptables rules with an explanation of each; you review and run them. hive does
not silently rewrite your firewall.

## Two things that will bite you, and are not hive's fault

**`br_netfilter`.** If it is absent — and it is on many hosts — container-to-
container traffic on a shared bridge never traverses iptables, and *no firewall
rule can block it*. hive gives each agent its own network with
`com.docker.network.bridge.enable_icc=false`, which is the only control that
works in that world. If you test isolation, probe a peer **by raw IP**: testing
by name only proves DNS is not resolving, and reports success on a wide-open
network.

**Docker publishes ports with DNAT, and it happens before the filter chains.** A
rule written against a published port matches nothing, while the service keeps
answering through some broader rule — so `iptables -L` looks correct and the
counter sits at zero. Read the packet counters, not the rules. `hive firewall`
emits `--ctorigdstport` with `--ctdir ORIGINAL` for that case, and plain
`--dport` for a host process, because the two are genuinely different.

## Development

```console
cargo test --workspace        # unit tests, no daemon needed
./build.sh                    # build + test in a pinned container
./build.sh --docker           # also run integration tests against a real daemon
```

The Docker integration tests create and destroy real containers. They exist
because the unit tests verify what hive *decides*, and most of the expensive bugs
here have been in what Docker actually *does*.

Tests are named after the failure they prevent, not the function they cover —
`observer_defaults_on_because_remote_agents_are_otherwise_invisible`,
`a_crash_looping_agent_is_held_not_recreated`. Almost every one of them is
scar tissue from something that went wrong on a real box.

## Status

Early. It runs, it is tested, and it has not been run by anyone but its authors.
Interfaces will move.

## License

Apache-2.0.
