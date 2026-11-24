#!/usr/bin/env bash
# handshake_flood (label: attack-like): N rapid connections, each closing right after the handshake
# (no application data). Defensive study of detectors only; target is our own server container.
# Hard caps: rate <= 20 connections/s, concurrency <= 4, N <= 1000, <= 600 s. These limits are constants
# in this script and cannot be raised from the environment.
set -uo pipefail
source "$(dirname "$0")/common.sh"
validate_caps
print_header handshake_flood
wait_for_server

RATE_CAP=20      # connections per second (maximum)
CONC_CAP=4       # simultaneous connections (maximum)
INTERVAL=0.05    # = 1 / RATE_CAP: minimum spacing between connection starts
tmp="$(mktemp -d)"

one() { # one INDEX : handshake, then stdin EOF -> s_client closes immediately
  timeout 60 "${SCLIENT[@]}" < /dev/null > /dev/null 2>&1
  echo $? > "$tmp/$1.rc"
}

started=0; truncated=0
for ((i = 1; i <= N; i++)); do
  if ! time_left; then truncated=$((N - i + 1)); echo "TIME CAP reached before connection $i"; break; fi
  while [ "$(jobs -rp | wc -l)" -ge "$CONC_CAP" ]; do wait -n; done
  one "$i" &
  started=$((started + 1))
  sleep "$INTERVAL"
done
wait

ok=0; failed=0
for ((i = 1; i <= started; i++)); do
  if [ "$(cat "$tmp/$i.rc" 2>/dev/null)" = 0 ]; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
done
echo "connections_started=$started rate_cap=${RATE_CAP}/s concurrency_cap=$CONC_CAP"
finish "$ok" "$failed" "$truncated"
