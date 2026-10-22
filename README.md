# Tunnels

A [LazyRex](https://github.com/lazy-rex/LazyRex) plugin. Forward a local TCP port to a public URL with [opentunnel](https://github.com/anomalyco/opentunnel). `docs/opentunnel.md` has the research notes.

## Install

Check this repository out next to LazyRex, and add the plugin to the hub config:

```json
{"name": "tunnels", "path": "/path/to/Tunnels/tunnels.lua"}
```

Tunnels uses the LazyRex Plugin SDK (`lazyrex.json` `"sdk": "0"`; LazyRex `docs/plugin-sdk.md`). The hub
starts it through the SDK launcher, so it needs a hub with that launcher. The SDK does the
registration, the dispatch of agent and view calls, the caller checks and the error replies.
Tunnels keeps its own state and operation records in its SQL tables (`tunnels_store.lua`). Each write is
its own transaction, so a handler holds no transaction while it waits for Rex (`tx = false`,
`store = false`).

The plugin loads its other files from its own directory, so keep them together.

## Agent actions

The hub gives agents these actions (MCP tools):

- `tunnels.list`: the forwards (state, URL, session, creator, logs shown), the forwards with an
  unknown start result (`pending`), and the opentunnel services that are still stopping (`cleanups`:
  profile, phase, key, error, `legacy` and `releasable`).
- `tunnels.forward {key, source}` or `tunnels.forward {key, port, session_id?, block_id?}`: the
  form's Forward. The port becomes public: anyone with the URL can reach it, and the tunnel does not
  ask visitors to sign in. `source` is the `source` of a listener from `tunnels.ports` (its session,
  pane, port and address). `port` is the "Other port…" form: the target is `127.0.0.1:<port>`, the
  session defaults to the agent's session and the source pane to the agent's pane. An agent key has
  its own namespace, so it never meets a view key or another agent's key. A retry with the same key
  returns the first result, also after the listener exits.
- `tunnels.stop {forward, key}`: the panel's Stop. The user and any agent may stop any forward,
  also one that another caller started. A retry with the same key returns the first result.
- `tunnels.release {profile, attempt, accept_risk, key}`: the Release Reservation form (see
  "Release reservation"). A retry with the same key returns the first result.
- `tunnels.ports {session_id?}`: a new scan of the listening ports, as the form's Rescan. It
  changes only the scan that the form shows, so it takes no key.

Agents may forward and stop any port (decisions "Agents may act on anything" and "Agents use the
Tunnels plugin fully", 2026-10-19).

## Cleanup

When a forward ends, the plugin runs `opentunnel down` for its profile in a detached block of the
plugin session (`tunnels-down.sh`). Forward refuses the port while the cleanup record of its profile
exists. A `down` that runs would also stop a new `serve` of the profile.

- The script prints the receipt line `lazyrex-tunnel-down-exit <key> <code>` and then waits. So the
  plugin can prove the attempt with ps (label, key in argv, start time), also after a lost create
  reply or a lost write.
- The plugin saves the result, then closes the block. A failed close keeps the record and the block
  until a close succeeds or a Rex listing shows that the block is gone.

### Fenced attempts

Each attempt has a fence (decision "Cleanup attempt fence"). The catalog keeps the absolute path of
the fence directory, under `${XDG_STATE_HOME:-$HOME/.local/state}/lazyrex-tunnels/attempts/`. A new
attempt gets a random 128-bit key. The plugin makes the directory `<fence>/<key>` before it saves the
record (`fence_v = 1`, `attempt`), and it never uses an attempt directory again.

- The script and the plugin both try `ln -s <owner> <attempt>/claim`. Exactly one claim succeeds.
- A script claim runs `down` once and writes the exit code to `<attempt>/exit`.
- When the plugin cannot prove the create (for example after a lost create reply), it claims the
  attempt. A plugin claim means that the attempt never runs `down`: a late create finds the claim and
  exits. The plugin then starts a new attempt.
- A script claim without an exit file, or a block that is gone without a result, is retried only
  when ps shows that the attempt can never run `down` again: no wrapper with its key, and then, in
  a second ps read, no `down` of the profile.
- The port is released only after exit 0, and only when ps shows no `down` of the profile.
- A failed read, an unknown owner or invalid exit data keeps the reservation. The plugin starts no new
  attempt while Rex does not list the plugin session.

### Release reservation

A cleanup record of an older plugin version has no fence (`fence_v`). When its create result is
unknown (phase `sending`), its old script can still start and run `down`. Nothing proves that it
cannot, so the plugin never releases such a record. A missing plugin session is no proof either.

The user or an agent can release it, with an explicit risk acceptance:

- The panel row of the record has **Release reservation…**. It opens a form that names the profile
  and the attempt key and shows this warning: "The old stop command may still run. If it runs, it
  stops the next forward of this profile." The field "I accept this risk" is required: choose Yes.
- `tunnels.release {profile, attempt, accept_risk, key}` does the same for agents. `accept_risk` must
  be `true`. `attempt` is the `key` of a `tunnels.list` cleanup with `releasable = true`.

Both paths run one handler. It removes the record only when the record is still a legacy `sending`
record of the same attempt, also after a revision conflict. Otherwise it refuses with `conflict`. The
record removal and the operation result commit in one batch, and a retry with the same key returns
the first result. A release does not cancel the old stop command.

### Known leftovers

- A late create after a plugin claim leaves an exited block in the plugin session. The plugin does
  not close it.
- The plugin deletes no fence state: the attempt directories stay.

## Tests

Run the tests with `lazyrex-hub test` in this directory (LazyRex `docs/testing.md`). The command
starts its own lab Rex server and the real hub in test mode. Each lab has a private HOME, XDG and
TMPDIR. `lazyrex.json` sets the lab environment: the stand-in `tests/fake-opentunnel.sh` instead of
the real opentunnel, a fake state directory in the lab, and the `lazyrexlab-` profile prefix. No
test opens a public tunnel.

```sh
lazyrex-hub test
```

- `tests/*.lua`: the tests. Each file that forwards a port first runs `tests/lib/guard.lua`, which
  fails the file unless the lab forces the stand-in binary and private paths.
- `tests/lib/`: shared helpers (not test files). `tests/lib/sandbox.lua` loads the SDK from `sdk/lua` of the
  LazyRex checkout that runs the tests.
- `tests/parity_fixture.lua`: opens the Release Reservation form, which only a panel row opens, for
  the parity sweep (`lazyrex.json` `parity_routes`).
- `tests/fake-opentunnel.sh`: the stand-in for the opentunnel CLI.

The shared LazyRex renderer tests (view package) cover the generic keyboard, focus and screen
behavior of the forms and panels.

### Test writes

A test changes the state as another writer only through `T.edit` (`tests/lib/tunnels.lua`). It
writes a row only if the row is still as it read it, so it never overwrites a plugin commit that
came between its read and its write. If a test fails on a count, keep the lab
(`lazyrex-hub test -keep`) and record the helper error and the order of the `hub.sql` commits in
`hub.log` here.
