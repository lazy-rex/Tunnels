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
- `tunnels.stop {forward, key}`: the panel's Stop. The user may stop any forward. An agent may stop
  only a forward that an agent started. A retry with the same key returns the first result.
- `tunnels.ports {session_id?}`: a new scan of the listening ports, as the form's Rescan. It
  changes only the scan that the form shows, so it takes no key.

Forward Port… has no agent action yet: an agent that publishes a local port waits for a decision.

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

`tests/tunnels-lab.mjs` is the earlier Node lab test. It stays only for two renderer checks that no
LazyRex view test covers yet: the text of a closed select field on screen, and the first focused
control of a new panel. The Lua tests cover everything else it checks. Do not run it by hand: it
does not isolate HOME, and it can write opentunnel route files in your real configuration.
