#!/usr/bin/env bash
# Smoke test: for every KEM group x auth, start `openssl s_server -www` with that certificate and
# -groups/-sigalgs PINNED, connect with `openssl s_client` PINNED to the same, and check what was
# actually negotiated. Server and client run in this one container on 127.0.0.1.
#
# A profile PASSES only if the negotiated group, the peer signature type, TLS 1.3, certificate
# verification and the number of certificates sent all match. Anything else is FAIL, with the reason
# and the real OpenSSL error text. There is no fallback: if a pinned name is not supported the server
# or client refuses to start and the profile FAILS. Exit status is 1 if any profile fails.
#
# Env: CERTS (default /certs; generated if missing), CHAIN (leaf_int | leaf; default leaf_int),
#      LOGDIR (default /tmp/smoke_logs), TIMEOUT seconds per client (default 60),
#      SMOKE_ONLY="<kem>:<auth>" runs just that one profile (used by scripts/pcaps_to_flows.py for reference counts).
set -uo pipefail
# shellcheck source=profiles.sh
source "$(dirname "$0")/profiles.sh"

CERTS="${CERTS:-/certs}"; CHAIN="${CHAIN:-leaf_int}"; LOGDIR="${LOGDIR:-/tmp/smoke_logs}"
TIMEOUT="${TIMEOUT:-60}"; PORT=14433
mkdir -p "$LOGDIR"; rm -f "$LOGDIR"/*.log
chain_len "$CHAIN" >/dev/null || exit 2

if [ ! -f "$CERTS/ecdsa_p256/leaf.crt" ]; then
  echo "== no certificates in $CERTS; generating"; /lab/gen_certs.sh "$CERTS" > "$LOGDIR/gen_certs.out" 2>&1 \
    || { echo "gen_certs.sh failed; see $LOGDIR/gen_certs.out" >&2; exit 2; }
fi

echo "OpenSSL: $(openssl version)   chain: $CHAIN ($(chain_len "$CHAIN") certificate(s) on the wire)"
echo "TLS groups in this build:     $(openssl list -tls-groups)"
echo "TLS sigalgs in this build:    $(openssl list -tls-signature-algorithms)"
echo

first_error() { grep -m1 -iE 'error|failed|unknown|unsupported|refused' "$1" 2>/dev/null | cut -c1-150; }

run_profile() { # KEM AUTH -> sets RESULT, REASON ; globals from parse_client_log
  local kem="$1" auth="$2" tag="${1}_${2}" g s srv cli sp reasons
  g="$(group_name "$kem")"; s="$(sigalg_name "$auth")"
  srv="$LOGDIR/${tag}.server.log"; cli="$LOGDIR/${tag}.client.log"
  GRP="-"; SIG="-"; CERTS_SENT="-"; RD="-"; WR="-"; VERIFY_OK="-"; PROTO="-"
  # shellcheck disable=SC2046
  openssl s_server -www -accept "127.0.0.1:$PORT" $(server_cert_args "$auth" "$CHAIN" "$CERTS") \
    -tls1_3 -groups "$g" -sigalgs "$s" > "$srv" 2>&1 &
  sp=$!
  for _ in $(seq 1 50); do grep -q '^ACCEPT' "$srv" && break; kill -0 "$sp" 2>/dev/null || break; sleep 0.1; done
  if ! grep -q '^ACCEPT' "$srv"; then
    wait "$sp" 2>/dev/null
    RESULT=FAIL; REASON="server did not start: $(first_error "$srv")"; return
  fi
  # shellcheck disable=SC2046
  timeout "$TIMEOUT" openssl s_client -connect "127.0.0.1:$PORT" -servername server -tls1_3 \
    -groups "$g" -sigalgs "$s" $(client_trust_args "$auth" "$CHAIN" "$CERTS") \
    -verify_return_error -verify_hostname server < /dev/null > "$cli" 2>&1
  local rc=$?
  kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
  parse_client_log "$cli"
  reasons="$(judge "$kem" "$auth" "$CHAIN" | paste -sd';' -)"
  if [ "$rc" -ne 0 ] || [ -n "$reasons" ]; then
    RESULT=FAIL; REASON="client exit $rc; ${reasons:+$reasons; }$(first_error "$cli")"
  else
    RESULT=PASS; REASON=""
  fi
}

printf '%-12s %-16s | %-16s %-24s %5s %12s | %s\n' auth kem "negotiated group" "peer sigalg" certs "rd/wr bytes" result
printf '%s\n' "-----------------------------------------------------------------------------------------------------------"
FAILED=(); RAN=0
for auth in "${AUTHS[@]}"; do
  for kem in "${KEMS[@]}"; do
    [ -z "${SMOKE_ONLY:-}" ] || [ "$SMOKE_ONLY" = "$kem:$auth" ] || continue
    RAN=$((RAN + 1))
    run_profile "$kem" "$auth"
    printf '%-12s %-16s | %-16s %-24s %5s %12s | %s\n' "$auth" "$kem" "$GRP" "$SIG" "$CERTS_SENT" "$RD/$WR" "$RESULT"
    [ "$RESULT" = PASS ] || FAILED+=("$auth + $kem: $REASON")
  done
done

echo
[ "$RAN" -gt 0 ] || { echo "no profile matched SMOKE_ONLY='${SMOKE_ONLY:-}'" >&2; exit 2; }
if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "ALL PROFILES PASSED"; exit 0
fi
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!! ${#FAILED[@]} PROFILE(S) FAILED !!!!!!!!!!!!!!!!!!!!!!!!!!!!"
printf '  FAIL  %s\n' "${FAILED[@]}"
echo "Unsupported profiles are dropped, never faked or silently replaced by a default. Logs: $LOGDIR"
exit 1
