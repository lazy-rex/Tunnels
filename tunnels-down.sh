#!/bin/sh
# Stops the opentunnel service of one profile, for the Tunnels plugin's cleanup. The plugin runs it in
# a detached Rex block, so Rex shows whether it still runs, also after a plugin restart.
# Usage: tunnels-down.sh <key> <opentunnel> <profile>
#   key  the cleanup attempt. It is only in argv: the plugin reads it with ps to prove that a block
#        with an unknown create result belongs to that attempt. This shell stays the parent of
#        opentunnel, and it stays alive after `down`, so that proof is possible until the plugin
#        adopts the block, even when the create reply was lost.
# After `down`, the script prints the receipt line "lazyrex-tunnel-down-exit <key> <code>" on a line
# of its own and waits. The plugin reads the exact receipt of its attempt, saves the result, and
# then closes the block, which ends the wait.
set -u
KEY=$1 OT=$2 PROFILE=$3
"$OT" --profile "$PROFILE" down
CODE=$?
printf '\nlazyrex-tunnel-down-exit %s %s\n' "$KEY" "$CODE"
trap 'exit 0' HUP INT TERM
while :; do sleep 3600; done
