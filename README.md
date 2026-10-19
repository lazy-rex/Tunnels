# Tunnels

A [LazyRex](https://github.com/lazy-rex/LazyRex) plugin. Forward a local TCP port to a public URL with [opentunnel](https://github.com/anomalyco/opentunnel). `docs/opentunnel.md` has the research notes.

## Install

Check this repository out next to LazyRex, and add the plugin to the hub config:

```json
{"name": "tunnels", "path": "/path/to/Tunnels/tunnels.lua"}
```

The plugin loads its other files from its own directory, so keep them together.

## Agent actions

The hub gives agents these actions (MCP tools):

- `tunnels.list`: the forwards (state, URL, session, creator, logs shown), the forwards with an
  unknown start result (`pending`), and the opentunnel services that are still stopping (`cleanups`).
- `tunnels.forward {key, source}` or `tunnels.forward {key, port, session_id?, block_id?}`: the
  form's Forward. The port becomes public: anyone with the URL can reach it, and the tunnel does not
  ask visitors to sign in. `source` is the `source` of a listener from `tunnels.ports` (its session,
  pane, port and address). `port` is the "Other port…" form: the target is `127.0.0.1:<port>`, the
  session defaults to the agent's session and the source pane to the agent's pane. An agent key has
  its own namespace, so it never meets a view key or another agent's key. A retry with the same key
  returns the first result, also after the listener exits.
- `tunnels.stop {forward, key}`: the panel's Stop. The user and any agent may stop any forward,
  also one that another caller started. A retry with the same key returns the first result.
- `tunnels.ports {session_id?}`: a new scan of the listening ports, as the form's Rescan. It
  changes only the scan that the form shows, so it takes no key.

Agents may forward and stop any port (LazyRex `docs/decisions.md`, 7cf0851).

## Cleanup

When a forward ends, the plugin runs `opentunnel down` for its profile in a detached block of the
plugin session (`tunnels-down.sh`). Forward refuses the port until that cleanup ends with exit 0.

- The script prints the receipt line `lazyrex-tunnel-down-exit <key> <code>` and then waits. So the
  plugin can prove the attempt with ps (label, key in argv, start time), also after a lost create
  reply or a lost write.
- The plugin saves the result, then closes the block. A failed close keeps the record and the block
  until a close succeeds or a Rex listing shows that the block is gone.
- An attempt that ends without a receipt after the plugin adopted it runs again.
- An attempt that something else stops before the plugin adopts it cannot be proven. A block with only
  its label is no proof, because the original create can still arrive. Its profile stays reserved.
  No safe manual recovery exists yet: it must first prove that no original create can arrive and
  that no `down` of the profile remains. A check that no `down` runs now is not enough. This case
  needs investigation; until then, keep the reservation.

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
- `tests/lib/`: shared helpers (not test files).
- `tests/fake-opentunnel.sh`: the stand-in for the opentunnel CLI.

The shared LazyRex renderer tests (view package) cover the generic keyboard, focus and screen
behavior of the forms and panels.

### Known issue: one unexplained stop.lua failure

During the port, one run of `tests/stop.lua` failed once on a count check (the second count). The
cause is not known. That run kept no lab, so nobody could inspect it.

- Suspected cause (not proven): the old test helper turned a failed read into 0.
- Commit 3f76a4a makes the helper strict and adds helper tests. If the failure occurs again, the
  helper reports its cause.
- The failure did not occur again in more than 30 later runs (status at 7b65510).

If `tests/stop.lua` fails on a count, keep the lab (`lazyrex-hub test -keep`) and record the helper
error here.
