#!/bin/sh
# Stops the opentunnel service of one profile, for the Tunnels plugin's cleanup. The plugin runs it in
# a detached Rex block, so Rex shows whether it still runs, also after a plugin restart.
# Usage: tunnels-down.sh <key> <opentunnel> <profile>
#   key  the cleanup attempt. It is only in argv: the plugin reads it with ps to prove that a block
#        with an unknown create result belongs to that attempt. This shell stays the parent of
#        opentunnel (the explicit exit keeps the last command from replacing it).
set -u
KEY=$1 OT=$2 PROFILE=$3
"$OT" --profile "$PROFILE" down
exit $?
