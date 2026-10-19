# Handoff: Tunnels (2026-10-19)

## State

- `main` = 49a680f, pushed. The live hub runs the release clone at 49a680f.
- Branch `harness` = `main` plus this file. No other unpushed commits or branches.
- The reviewer approved the final tree (7b65510; 49a680f adds only a README note). The coordinator
  accepted it.

## Done

- The Node lab tests are ported to Lua tests that `lazyrex-hub test` runs (`tests/*.lua`). The
  Node tests are removed; `tests/fake-opentunnel.sh` stays (the lab uses it).
- Agent parity: `tunnels.list`, `tunnels.forward`, `tunnels.stop`, `tunnels.ports`. Per the user
  decision (LazyRex `docs/decisions.md`, 7cf0851), agents may forward and stop any port.
- Cleanup recovery: `tunnels-down.sh` stays provable until the plugin adopts it. The plugin saves
  the result (phase `closing`) before `block.close` (README, "Cleanup").
- Forward: a definite Rex refusal (only `bad_request`) keeps no intent. Every other create error
  stays an unknown result that needs process proof.

## Open

- Known issue (README, "Tests", "Known issue: one unexplained stop.lua failure"): one `stop.lua` run failed once on a `down` count. The cause
  is not explained. The suspect (a failed read counted as 0) is unproven. The helper is strict now
  (3f76a4a). If it fails again: keep the lab and record the helper error.
- Not solved: a cleanup attempt that something else stops before the plugin adopts it keeps its
  profile reserved. No safe manual recovery exists yet (README, "Cleanup"). It needs investigation.
- The user's decision: the real opentunnel config directory has about 10 old `lazyrexlab-*.toml`
  files from earlier Node lab runs. Nothing deleted them.

## Facts to keep

- Rex refuses a block label over 128 characters (`bad_request`). Agent operation IDs (`fwd/...`)
  use a digest label (`label_of`). The proof is the full ID in the process argv.
- The hub refuses a reused view operation key with different arguments before the plugin sees it.
  The plugin's own view fingerprint checks are tested in the sandbox (`tests/lib/sandbox.lua`).
- Tests never run the real opentunnel binary. `tests/lib/guard.lua` fails a file unless the lab
  forces the stand-in. Before and after a run, compare the real opentunnel directories, the
  LaunchAgents and the process list (read only).

## Next step

No work is required. A release of a later commit needs the user's approval through the
coordinator. Pushing `main` does not deploy.
