# Testing hive against a real Buzz relay

A hands-on walkthrough that exercises everything hive does, in an order where each
step's failure mode is obvious. Roughly 45 minutes end to end.

Throughout, `$BOX` is the machine running Docker and `hived`.

> **Read this first.** If you already run agents on `$BOX` deployed some other way
> (a shell script, an older provider), do **not** give a hive agent the same
> identity on the same relay. Two processes would answer as one agent — every
> mention gets two replies, both charged to you, interleaved in the thread, which
> reads as the model repeating itself. hive refuses this between *its own* specs,
> but it cannot see containers it did not create. Use a fresh agent identity.

---

## 0. Prerequisites

```console
$ ssh $BOX
# hive doctor
```

Expected: docker ok, image present with a harness manifest, spec dir and secret
store ok. It will report the control socket missing until step 2 — that is fine,
and everything else still works without the daemon.

If the image is absent:

```console
$ export HIVE_BUILD_HOST=root@$BOX BUZZ_TREE=/path/to/buzz/checkout
$ ./images/agent/build.sh          # ~15 min cold, tags by buzz commit
$ ssh $BOX 'docker run --rm -v /tmp/smoke.sh:/smoke.sh:ro hive-agent:latest sh /smoke.sh'
```

The smoke test should print `PASS` for all nine harnesses. If any fails, stop —
the image is not shippable and everything downstream will be confusing.

## 1. Make an agent identity

The **Buzz desktop is the identity authority**: it generates the keypair and
publishes the agent's identity record to the relay. hive never generates keys.

In Buzz desktop → create an agent → give it a name (say `hivetest`) and pick a
harness. Do **not** deploy it anywhere yet.

You now need two things from it: its **pubkey** (visible in the agent's profile)
and its **nsec**. There are two ways to get the nsec to hive, and they are the two
real deployment paths:

**Path A — through the desktop (recommended, tests the most).** Install the shim
so the desktop hands hive the key itself; see §7. Do this after §2–§6 so you
understand what the shim is automating.

**Path B — by hand.** Copy the agent's nsec out of the desktop and store it
yourself. Use this while iterating; it is faster and involves no GUI.

## 2. Start the daemon

```console
# cp packaging/hived.service /etc/systemd/system/
# systemctl daemon-reload && systemctl enable --now hived
# journalctl -u hived -f
```

Or, to watch it work in the foreground:

```console
# hived --interval 10
```

## 3. Deploy your first agent

```console
# printf '%s' 'nsec1...' | hive secret put nsec/hivetest
# printf '%s' 'sk-ant-oat01-...' | hive secret put harness/claude   # from `claude setup-token`
```

```toml
# /etc/hive/agents/hivetest.toml   — THE FILE NAME IS THE AGENT NAME
[identity]
pubkey       = "<the agent's pubkey>"
relay_url    = "wss://your-relay.example"
owner_pubkey = "<your own pubkey>"

[harness]
id = "claude"

[agent]
respond_to = "owner-only"
observer   = true
```

Before deploying, check it:

```console
# hive validate /etc/hive/agents/hivetest.toml
```

This prints the harness it resolved, and **every credential the agent needs plus
how each is delivered** — including which ones `docker inspect` can read. Read
that list; it is the clearest summary of hive's credential model.

Within one interval:

```console
# hive ps
AGENT       RUNNING   RESTARTS  SPEC HASH          CONTAINER
hivetest    true      0         a3f1…              hive-hivetest
```

**Now talk to it in Buzz.** Add the agent to a channel and mention it. You should
see it typing and then replying. If it joins but never answers, `hive logs
hivetest` first.

## 4. Prove the failure modes are handled

These are the behaviours that matter when something goes wrong at 2am. Each takes
under a minute.

**a. Missing credentials hold, they do not half-start.**

```console
# hive secret rm harness/claude
# hive restart hivetest
# journalctl -u hived -n 20 | grep -i hold
```

Expect a `Hold` naming `harness/claude` and **no container**. An agent started
without its model credential would join the relay and answer wrongly — much harder
to attribute than a refusal. Put the credential back and it comes up again.

**b. A spec edit replaces cleanly, and state survives.**

```console
# hive shell hivetest -- sh -c 'echo marker > /home/agent/state/probe'
# sed -i 's/observer   = true/observer   = false/' /etc/hive/agents/hivetest.toml
# sleep 15 && hive ps            # spec hash has changed
# hive shell hivetest -- cat /home/agent/state/probe
marker
```

The container was replaced; the volume was not. Set `observer` back to `true`.

**c. Deleting a spec removes the container but keeps the volume.**

```console
# mv /etc/hive/agents/hivetest.toml /tmp/
# sleep 15 && hive ps                       # gone
# docker volume ls | grep hive-hivetest     # still there
# mv /tmp/hivetest.toml /etc/hive/agents/   # and it comes back with its state
```

**d. Agents cannot reach each other.** Deploy a second agent, then from inside one
probe the other **by raw IP** (by name only proves DNS is not resolving):

```console
# IP=$(docker inspect hive-agent2 -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
# hive shell hivetest -- curl -s -m 5 http://$IP:8080/ ; echo "exit=$?"
```

Expect a timeout.

## 5. Get inside a container, and do an interactive login

This is the answer to "codex needs me to log in".

```console
# hive shell hivetest                 # exec into the running agent
# hive shell --scratch hivetest       # side container on the same volumes
```

`--scratch` is the one for logins: a separate container from the same image, with
the agent's state volume and shared volumes mounted, on the agent's network, with
no relay connection. The reconciler cannot replace it underneath you, and it works
when the agent is crash-looping and `exec` would fail.

```console
# hive shell --scratch hivetest
agent@…:~$ codex login          # or: claude setup-token
agent@…:~$ exit
# hive restart hivetest         # so the harness picks it up
```

Anything written under `/home/agent/state` persists — `CLAUDE_CONFIG_DIR`,
`CODEX_HOME` and the `~/.grok`, `~/.kimi`, `~/.cursor` symlinks all point inside
it.

Prefer to inject a credential you already have? Use the file tier:

```console
# hive secret put codex/auth < ~/.codex/auth.json
```

```toml
[[file]]
credential = "codex/auth"
target     = "/home/agent/state/codex/auth.json"
mode       = "0600"
```

Unlike an env var, that is **not** visible to `docker inspect`.

## 6. The interesting parts

**a. An MCP server whose token never enters the container.**

```console
# hive secret put mcp/parachute < token.txt
```

```toml
[[mcp]]
name       = "parachute"
transport  = "http"
url        = "https://your-vault.example/mcp"
credential = "mcp/parachute"
```

After it redeploys, confirm the design holds:

```console
# hive shell hivetest -- cat /home/agent/state/claude/.claude.json
```

You should see `"headersHelper": "/usr/local/bin/hive-headers"` and **no token**.
Then check nothing leaked:

```console
# docker inspect hive-hivetest | grep -c "$(cat token.txt)"     # expect 0
```

And exercise the live path exactly as Claude Code does:

```console
# docker exec -e CLAUDE_CODE_MCP_SERVER_NAME=parachute hive-hivetest sh -c hive-headers
{"headers":{"Authorization":"Bearer …"}}

# tail -5 /var/lib/hive/secrets/audit.jsonl
```

Then ask the agent in Buzz to use one of the vault's tools. That is the whole
chain: relay → harness → helper → socket → broker.

**b. Two harnesses, one workspace.** The thing shared volumes are for.

```console
# docker volume create uni-workspace
```

Give two specs — say `uni-claude.toml` and `uni-codex.toml`, different harnesses —
the same block:

```toml
[[volume]]
name   = "uni-workspace"
target = "/home/agent/work"
```

Both edit one tree; skills and credentials stay separate. Verify:

```console
# hive shell uni-claude -- sh -c 'echo hello > /home/agent/work/shared.md'
# hive shell uni-codex  -- cat /home/agent/work/shared.md      # hello
# hive shell uni-codex  -- ls /home/agent/state/claude          # its OWN claude state
```

Note these are two Buzz identities. Thread history lives on the relay, so both see
the same conversation in a channel they share.

**c. Switching harness on one identity.** If you want *continuity* rather than two
agents, edit `harness.id` in a single spec. Same pubkey, same volume, same files;
both harnesses' state persists side by side, and the relay keeps the conversation.
A restart is the only cost.

**d. One identity, two relays.**

```toml
# uni-other.toml
[identity]
pubkey     = "<same pubkey>"
relay_url  = "wss://other-relay.example"
credential = "nsec/uni"      # ← the SAME key, stored once
```

Confirm hive catches the dangerous version: copy a spec, change nothing, and give
it the same relay. Both are held with a `Conflict`, and — importantly — **the
already-running agent is not torn down**. Delete the bad file and it recovers.

## 7. Deploy from the Buzz desktop

Now automate §1–§3 through the UI.

```console
$ cargo build --release -p buzz-backend-hive
$ cp target/release/buzz-backend-hive ~/.buzz/backends/     # discovery dir
```

Buzz discovers `buzz-backend-*` executables and shows the suffix in its picker, so
this appears as **hive**. Set the SSH host in its settings, then deploy an agent
to it.

The shim writes a spec over SSH and stores the nsec in the broker. It creates no
containers — `hived` reconciles it — so an agent deployed from the desktop is
byte-identical to one you wrote by hand. Confirm with `hive ps` and by reading the
generated `/etc/hive/agents/<name>.toml`; it should contain no secrets.

## 8. Teardown

```console
# rm /etc/hive/agents/hivetest.toml            # container goes, volume stays
# docker volume rm hive-hivetest-state         # explicit — credentials live here
# hive secret rm nsec/hivetest
```

---

## When something is wrong

| symptom | look here |
|---|---|
| agent never appears | `journalctl -u hived -n 50` — likely a `Hold` |
| agent joins but never replies | `hive logs <agent>` |
| "all N agents failed to start" | harness missing from the image — `hive harnesses` |
| MCP tool absent, no error | `.claude.json` in the state volume; `type` must be set |
| 401 on first tool call | run `hive-headers` by hand as in §6a |
| held forever | `hive validate` the spec; check `hive secret list` |
| worked, then stopped after redeploy | config written outside the state volume |

`hive doctor` covers most of the environmental causes, including whether
`br_netfilter` is present — which determines whether any firewall rule can affect
container-to-container traffic at all.
