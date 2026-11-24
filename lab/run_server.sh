#!/usr/bin/env bash
# Lab server: `openssl s_server -WWW` (serves files from /srv/www) for one pinned profile.
# Env: KEM, AUTH, CHAIN (leaf|leaf_int), PORT (default 4433), CERTS (default /certs),
#      TICKETS (default 0 = session tickets disabled; set TICKETS=1 to enable them).
# Unknown names are errors; nothing falls back to a default.
set -euo pipefail
# shellcheck source=profiles.sh
source "$(dirname "$0")/profiles.sh"

: "${KEM:?set KEM (X25519 | mlkem768 | X25519MLKEM768)}" "${AUTH:?set AUTH}" "${CHAIN:?set CHAIN (leaf | leaf_int)}"
PORT="${PORT:-4433}"; CERTS="${CERTS:-/certs}"; TICKETS="${TICKETS:-0}"
GROUP="$(group_name "$KEM")"; SIGALG="$(sigalg_name "$AUTH")"; chain_len "$CHAIN" >/dev/null

# The first container to get here generates the private test PKI into the shared volume.
mkdir -p "$CERTS"
exec 9>"$CERTS/.gen.lock"
flock 9
[ -f "$CERTS/.done" ] || { /lab/gen_certs.sh "$CERTS" && touch "$CERTS/.done"; }
flock -u 9

# Document root: identical, incompressible files (AES-CTR keystream with a fixed key), same for every profile.
DOCROOT=/srv/www; mkdir -p "$DOCROOT"
for spec in 200b:200 1k:1024 2k:2048 5k:5120 10k:10240 100k:102400 500k:512000; do
  head -c "${spec#*:}" /dev/zero \
    | openssl enc -aes-128-ctr -nosalt -K 000102030405060708090a0b0c0d0e0f -iv 00000000000000000000000000000000 \
    > "$DOCROOT/${spec%%:*}.bin"
done

TICKET_ARGS="-no_ticket -num_tickets 0"
[ "$TICKETS" = 1 ] && TICKET_ARGS=""
echo "server: profile KEM=$KEM ($GROUP) AUTH=$AUTH ($SIGALG) CHAIN=$CHAIN port=$PORT tickets=$TICKETS"
cd "$DOCROOT"
# shellcheck disable=SC2046,SC2086
exec openssl s_server -WWW -accept "$PORT" $(server_cert_args "$AUTH" "$CHAIN" "$CERTS") \
  -tls1_3 -groups "$GROUP" -sigalgs "$SIGALG" $TICKET_ARGS
