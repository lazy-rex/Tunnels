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

The tests use `../LazyRex` (the client library in `lib/` and the lab harness in `lab/`).
Start an isolated lab server first, and never point tests at your own Rex server:

```sh
../LazyRex/lab/server.sh /tmp/rexlab
REX_SERVER=unix:///tmp/rexlab/rex.sock node tests/<name>.mjs
```

- tunnels-ports-unit.lua, tunnels-cleanup-contract.lua
- tunnels-lab.mjs, tunnels-ports-lab.mjs (lab; `fake-opentunnel.sh` stands in for the real CLI)
