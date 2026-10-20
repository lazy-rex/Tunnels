#!/bin/sh
# Stops the opentunnel service of one profile, for the Tunnels plugin's cleanup. The plugin runs it in
# a detached Rex block, so Rex shows whether it still runs, also after a plugin restart.
# Usage: tunnels-down.sh <key> <opentunnel> <profile> [<attempt>]
#   key      the cleanup attempt. It is in argv: the plugin reads it with ps to prove that a block
#            with an unknown create result belongs to that attempt. This shell stays the parent of
#            opentunnel, and it stays alive after `down`, so that proof is possible until the plugin
#            adopts the block, even when the create reply was lost.
#   attempt  the attempt directory that the plugin made before the create (a fenced attempt). This
#            script never makes it. Without it (a create from an older plugin), the script runs down
#            as before.
# A fenced attempt first claims the attempt: one symlink, <attempt>/claim -> script. The plugin claims
# the same name (-> plugin) when it cannot prove the attempt. Exactly one claim succeeds, so a create
# that arrives late can never run down after the plugin gave the attempt up. Any failed claim (the
# plugin or another script owns it, or the directory is gone) prints the fenced line and runs no down.
# After `down`, the script writes the code to <attempt>/exit (a temp file, then mv), prints the receipt
# line "lazyrex-tunnel-down-exit <key> <code>" on a line of its own and waits. The plugin reads the
# exact receipt of its attempt, saves the result, and then closes the block, which ends the wait.
set -u
KEY=$1 OT=$2 PROFILE=$3
if [ $# -ge 4 ]; then
  ATTEMPT=$4
  if ! /bin/ln -s script "$ATTEMPT/claim" 2>/dev/null; then
    printf '\nlazyrex-tunnel-down-fenced %s\n' "$KEY"
    exit 0
  fi
  # LAB ONLY (decision "Cleanup attempt fence", C.b): the lab pauses a claimed wrapper before its
  # down. It applies only to the fake opentunnel of the tests and a lab profile, so a real cleanup
  # never waits here.
  case "$PROFILE:$OT" in
    lazyrexlab-*:*/tests/fake-opentunnel.sh)
      if [ -n "${FAKE_OT_DIR:-}" ]; then
        # touch, not a redirection: a failed redirection on : would end this shell.
        /usr/bin/touch "$FAKE_OT_DIR/down-gated-$KEY" 2>/dev/null
        while [ -e "$FAKE_OT_DIR/down-gate-$KEY" ]; do sleep 0.2; done
      fi ;;
  esac
fi
"$OT" --profile "$PROFILE" down
CODE=$?
if [ $# -ge 4 ]; then
  printf '%s\n' "$CODE" > "$ATTEMPT/exit.tmp" && /bin/mv "$ATTEMPT/exit.tmp" "$ATTEMPT/exit"
fi
printf '\nlazyrex-tunnel-down-exit %s %s\n' "$KEY" "$CODE"
trap 'exit 0' HUP INT TERM
while :; do sleep 3600; done
