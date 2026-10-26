# Tunnels

A [LazyRex](https://github.com/lazy-rex/LazyRex) plugin. Share a local TCP port with a public URL
in two steps: choose a listening port from the palette, and Tunnels starts an
[opentunnel](https://github.com/anomalyco/opentunnel) forward for it. A panel shows each forward,
its URL and its logs, and stops it. `docs/opentunnel.md` has the research notes.

## Get it

LazyRex setup installs Tunnels with the other core plugins. To add it by hand, add an entry to the
`plugins` list of the hub config:

```json
{"source": "/path/to/Tunnels"}
```

The source is the plugin directory. Tunnels uses the LazyRex Plugin SDK (`"sdk": "0"` in
`lazyrex.json`). It needs LazyRex hub v0.4.0 or later (the SDK options `tx` and `store`).

Tunnels needs the `opentunnel` CLI. A Rex pane has no login `PATH`, so the plugin uses
`LAZYREX_TUNNELS_OPENTUNNEL` (an absolute path) if the hub environment sets it. Else it looks in
`/opt/homebrew/bin`, `/usr/local/bin`, `~/.cargo/bin` and `~/.local/bin`. Without it, a forward
fails with: "opentunnel is not installed. Install it with: brew install anomalyco/tap/opentunnel".

## Palette commands

- **LazyRex: Forward Port…** opens a form with the listening ports of the session. Choose a port,
  or **Other port…** for a port on `127.0.0.1`. **Rescan** scans the ports again.
- **LazyRex: Tunnels** opens a panel with the forwards. Each forward has **Show Logs** or
  **Hide Logs**, and **Stop**.

Each forward uses the opentunnel profile `lazyrex-<port>`.

## Settings

The plugin has no plugin args. It reads these environment variables of the hub:

- `LAZYREX_TUNNELS_OPENTUNNEL`: the `opentunnel` binary (see "Get it").
- `LAZYREX_TUNNELS_PROFILE_PREFIX` (default `lazyrex-`): for test labs only. Another prefix keeps
  lab profiles apart from real ones, and it allows only the test stand-in of opentunnel.

## Storage

Tunnels keeps its state and operation records in its own SQL tables (`tunnels_store.lua`):
`intents`, `forwards`, `stops`, `cleanups`, `ops` and `meta`. Each write is its own transaction,
so a handler holds no transaction while it waits for Rex (`tx = false`, `store = false`).

## Agent actions

The hub gives agents these actions (MCP tools):

- `tunnels.list`: the forwards (state, URL, session, creator, logs shown), the forwards with an
  unknown start result (`pending`), and the opentunnel services that are still stopping (`cleanups`:
  profile, phase, key and error).
- `tunnels.forward {key, source}` or `tunnels.forward {key, port, session_id?, block_id?}`: the
  form's Forward. The port becomes public: anyone with the URL can reach it, and the tunnel does not
  ask visitors to sign in. `source` is the `source` of a listener from `tunnels.ports` (its session,
  pane, port and address). `port` is the "Other port…" form: the target is `127.0.0.1:<port>`, the
  session defaults to the agent's session. The source pane defaults to the agent's pane when that
  pane is in the session. An agent key has its own namespace, so it never meets a view key or
  another agent's key. A retry with the same key and the same content returns the first result,
  also after the listener exits. The same key with other content gives `operation_conflict`. If
  the result of the first start is unknown, a retry gives `unresolved` until the plugin finds the
  tunnel block.
- `tunnels.stop {forward, key}`: the panel's Stop. The user and any agent may stop any forward,
  also one that another caller started. A retry with the same key returns the first result.
- `tunnels.ports {session_id?}`: a new scan of the listening ports, as the form's Rescan. It
  changes only the scan that the form shows, so it takes no key.

Agents may forward and stop any port.

## Cleanup

When a forward ends, or a pending start ends without a block, the plugin runs `opentunnel down` for its profile in a detached block of the
plugin session (`tunnels-down.sh`). Forward refuses the port while the cleanup record of its profile
exists. A `down` that runs would also stop a new `serve` of the profile.

- The script prints the receipt line `lazyrex-tunnel-down-exit <key> <code>` and then waits. So the
  plugin can prove the attempt with ps (label, key in argv, start time), also after a lost create
  reply or a lost write.
- The plugin saves the result, then closes the block. A failed close keeps the record and the block
  until a close succeeds or a Rex listing shows that the block is gone.

### Fenced attempts

Each attempt has a fence. The fence is the directory `<state>/lazyrex-tunnels/attempts/<random id>`.
`<state>` is `XDG_STATE_HOME` if it is an absolute path, else `$HOME/.local/state`. The catalog
keeps the absolute path of the fence. A new
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

### Known leftovers

- A late create after a plugin claim leaves an exited block in the plugin session. The plugin does
  not close it.
- The plugin deletes no fence state: the attempt directories stay.

## Tests

Run the tests with `lazyrex-hub test` in this directory (LazyRex
[docs/testing.md](https://github.com/lazy-rex/LazyRex/blob/main/docs/testing.md#run)).
`lazyrex-hub test` needs a LazyRex checkout: `-lazyrex <dir>`, `LAZYREX_DIR`, or `../LazyRex`
beside the plugin directory. The command
starts its own lab Rex server and the real hub in test mode. Each lab has a private HOME, XDG and
TMPDIR. `lazyrex.json` sets the lab environment: the stand-in `tests/fake-opentunnel.sh` instead of
the real opentunnel, a fake state directory in the lab, and the `lazyrexlab-` profile prefix. No
test opens a public tunnel.

With a lab profile prefix, the plugin runs only its own stand-in, `<plugin dir>/tests/fake-opentunnel.sh`.
`LAZYREX_TUNNELS_OPENTUNNEL` must still name an executable stand-in (an absolute path that ends in
`/tests/fake-opentunnel.sh`), but it can be the stand-in of another checkout. The plugin still runs its own stand-in.

```sh
lazyrex-hub test
```

- `tests/*.lua`: the tests. Each file that forwards a port first runs `tests/lib/guard.lua`, which
  fails the file unless the lab forces the stand-in binary and private paths.
- `tests/lib/`: shared helpers (not test files). `tests/lib/sandbox.lua` loads the SDK from `sdk/lua` of the
  LazyRex checkout that runs the tests.
- `tests/fake-opentunnel.sh`: the stand-in for the opentunnel CLI.

### Test writes

A test changes the state as another writer only through `T.edit` (`tests/lib/tunnels.lua`). It
writes a catalog row only if the row did not change after its read, so it never overwrites a
plugin commit that came between its read and its write. It writes the fence value without this
check. If a test fails on a count, run `lazyrex-hub test -keep` and read `hub.log` in the kept
lab.
