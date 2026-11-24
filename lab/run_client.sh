#!/usr/bin/env bash
# Lab client: one TLS 1.3 connection to the server, pinned to the same profile, then a PASS/FAIL line.
# Env: KEM, AUTH, CHAIN, SERVER (default server), PORT (default 4433), CERTS (default /certs).
set -uo pipefail
# shellcheck source=profiles.sh
source "$(dirname "$0")/profiles.sh"

: "${KEM:?set KEM}" "${AUTH:?set AUTH}" "${CHAIN:?set CHAIN}"
SERVER="${SERVER:-server}"; PORT="${PORT:-4433}"; CERTS="${CERTS:-/certs}"
GROUP="$(group_name "$KEM")"; SIGALG="$(sigalg_name "$AUTH")"; chain_len "$CHAIN" >/dev/null

for _ in $(seq 1 120); do [ -f "$CERTS/.done" ] && break; sleep 0.5; done
[ -f "$CERTS/.done" ] || { echo "client: certificates never appeared in $CERTS" >&2; exit 2; }

LOG="$(mktemp)"
for _ in $(seq 1 60); do   # wait for the server to listen
  # shellcheck disable=SC2046
  openssl s_client -connect "$SERVER:$PORT" -servername server -tls1_3 -groups "$GROUP" -sigalgs "$SIGALG" \
    $(client_trust_args "$AUTH" "$CHAIN" "$CERTS") -verify_return_error -verify_hostname server \
    < /dev/null > "$LOG" 2>&1 && break
  grep -q 'Connection refused' "$LOG" || break
  sleep 0.5
done
parse_client_log "$LOG"
reasons="$(judge "$KEM" "$AUTH" "$CHAIN" | paste -sd';' -)"
echo "client: group=$GRP sigalg=$SIG certs=$CERTS_SENT read=$RD written=$WR"
if [ -n "$reasons" ]; then echo "client: FAIL: $reasons"; tail -5 "$LOG"; exit 1; fi
echo "client: PASS"
