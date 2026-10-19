#!/bin/sh
# LAB ONLY. A stand-in for opentunnel with the CLI shape that tunnels-run.sh uses. It opens no
# network connection. State: $FAKE_OT_DIR (default /tmp/fake-opentunnel). Each call is logged to
# $FAKE_OT_DIR/calls.log. FAKE_OT_SERVE_FAIL=1, or a file $FAKE_OT_DIR/fail-serve, makes `serve` exit
# with code 3. See `up` for fail-up and slow-up, and `down` for fail-down and slow-down.
set -eu
DIR=${FAKE_OT_DIR:-/tmp/fake-opentunnel}
mkdir -p "$DIR"
[ "$1" = --profile ] || { echo "fake-opentunnel: --profile is required" >&2; exit 2; }
PROFILE=$2 CMD=$3
echo "$PROFILE $CMD" >> "$DIR/calls.log"
case $CMD in
  status)
    if [ -f "$DIR/$PROFILE.id" ]; then echo "Tunnel ID: $(cat "$DIR/$PROFILE.id")"; echo "Hostname: $(cat "$DIR/$PROFILE.id").fake.invalid"
    else echo "No tunnel exists for this profile. Create one with: opentunnel up"; fi ;;
  up)
    # $DIR/<profile>.service stands for the launchd registration. fail-up: up registers, then fails.
    # slow-up: up registers, then waits 30 s (time to kill the block between up and down).
    [ -f "$DIR/$PROFILE.id" ] || echo "$PROFILE-$$" > "$DIR/$PROFILE.id"
    touch "$DIR/$PROFILE.service"
    [ -f "$DIR/fail-up" ] && { echo "fake-opentunnel: up failed" >&2; exit 1; }
    [ -f "$DIR/slow-up" ] && sleep 30
    echo "Connected https://$(cat "$DIR/$PROFILE.id").fake.invalid" ;;
  down)
    # fail-down: down fails and leaves the registration.
    [ -f "$DIR/fail-down" ] && { echo "fake-opentunnel: down failed" >&2; exit 1; }
    # slow-down: down waits 8 s first (time to try a Forward or a restart while it runs).
    [ -f "$DIR/slow-down" ] && sleep 8
    if [ -f "$DIR/$PROFILE.service" ]; then rm -f "$DIR/$PROFILE.service"; echo "Disconnected profile $PROFILE."; else echo "Profile $PROFILE is not connected."; fi ;;
  serve)
    { [ "${FAKE_OT_SERVE_FAIL:-}" = 1 ] || [ -f "$DIR/fail-serve" ]; } && { echo "fake-opentunnel: serve failed" >&2; exit 3; }
    echo "INFO starting tunnel hostname=$(cat "$DIR/$PROFILE.id").fake.invalid routes=1"
    echo 'INFO opentunnel::daemon: event={"type":"connecting","attempt":0}'
    echo 'INFO opentunnel::daemon: event={"type":"connected","routes":["@"]}'
    trap 'echo "fake-opentunnel: stopped"; exit 0' INT TERM HUP
    while :; do sleep 1; done ;;
  *) echo "fake-opentunnel: unsupported command $CMD" >&2; exit 2 ;;
esac
