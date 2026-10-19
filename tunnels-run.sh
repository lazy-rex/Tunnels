#!/bin/sh
# Runs one Tunnels forward in its Rex block. The Tunnels plugin starts it in a detached block.
# Usage: tunnels-run.sh <op key> <opentunnel> <profile> <target>
#   op key      the Forward operation key. It is only in argv: the plugin reads it with ps to prove
#               that a block with an unknown create result belongs to that operation.
#   opentunnel  the opentunnel binary (the lab gives a stand-in)
#   profile     one profile per forward: one tunnel, one hostname (lazyrex-<port>)
#   target      the local address, for example 127.0.0.1:3000
# opentunnel 0.5.2 (source, not run here): only `up` and `route add` create a tunnel identity, and
# both also register a launchd service. `serve` runs in the foreground but waits for an identity.
# So a new profile gets `up` and then `down` (removes the launchd registration). The route file is
# written directly, because `route add` starts the service again. The block then runs `serve`, so
# the block owns the tunnel: closing the block or its session ends it. This shell stays the block's
# process (no exec), so its argv keeps the op key; it passes a hangup or stop on to `serve`. Stop
# never runs `delete`, so the profile keeps its hostname for the next forward of the same port.
set -eu
OP=$1 OT=$2 PROFILE=$3 TARGET=$4
CONF=${XDG_CONFIG_HOME:-$HOME/.config}/opentunnel
# A run that was killed between `up` and `down` left the launchd service. Remove it first. `down` is a
# no-op when nothing runs. The plugin also runs `down` after a forward ends (tunnels.lua, cleanups).
"$OT" --profile "$PROFILE" down || echo "lazyrex: down failed; the plugin retries it after this forward ends" >&2
if "$OT" --profile "$PROFILE" status 2>&1 | grep -q '^No tunnel exists'; then
  echo "lazyrex: creating the tunnel for profile $PROFILE"
  if ! "$OT" --profile "$PROFILE" up; then
    "$OT" --profile "$PROFILE" down || true
    echo "lazyrex: could not create the tunnel" >&2
    exit 1
  fi
  "$OT" --profile "$PROFILE" down
fi
mkdir -p "$CONF"
printf '# Written by the LazyRex Tunnels plugin.\n[routes]\n"@" = "%s"\n' "$TARGET" > "$CONF/$PROFILE.toml.new"
mv "$CONF/$PROFILE.toml.new" "$CONF/$PROFILE.toml"
HOST=$("$OT" --profile "$PROFILE" status 2>&1 | sed -n 's/^Hostname: //p' | head -n 1)
# The plugin reads the URL from this line.
echo "lazyrex-tunnel-url: https://$HOST"
echo "lazyrex: forwarding https://$HOST to $TARGET"
"$OT" --profile "$PROFILE" serve &
SERVE=$!
trap 'kill "$SERVE" 2>/dev/null' HUP INT TERM
wait "$SERVE" || CODE=$?
# A trap ends the first wait early; wait again for the exit status of serve.
wait "$SERVE" 2>/dev/null || CODE=${CODE:-$?}
exit "${CODE:-0}"
