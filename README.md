# Tunnels

A [LazyRex](https://github.com/lazy-rex/LazyRex) plugin. Forward a local TCP port to a public URL with [opentunnel](https://github.com/anomalyco/opentunnel). `docs/opentunnel.md` has the research notes.

## Install

Check this repository out next to LazyRex, and add the plugin to the hub config:

```json
{"name": "tunnels", "path": "/path/to/Tunnels/tunnels.lua"}
```

The plugin loads its other files from its own directory, so keep them together.

## Tests

The tests use `../LazyRex` (the client library in `lib/` and the lab harness in `lab/`).
Start an isolated lab server first, and never point tests at your own Rex server:

```sh
../LazyRex/lab/server.sh /tmp/rexlab
REX_SERVER=unix:///tmp/rexlab/rex.sock node tests/<name>.mjs
```

- tunnels-ports-unit.lua, tunnels-cleanup-contract.lua
- tunnels-lab.mjs, tunnels-ports-lab.mjs (lab; `fake-opentunnel.sh` stands in for the real CLI)
