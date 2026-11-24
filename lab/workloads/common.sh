#!/usr/bin/env bash
# Shared code for the lab workloads. Source this file; do not execute it.
#
# Workloads are IDENTICAL for every crypto profile: same scripts, same request sequence for a given
# SEED and N. The profile (KEM/AUTH/CHAIN) only selects the pinned TLS group/sigalg and trust anchors.
# They talk ONLY to the lab server container on the internal Docker network (lab/README.md rules 1-3).
#
# Env (set by run_matrix.sh): KEM, AUTH, CHAIN, N (sessions), SEED, SERVER (default server),
# PORT (default 4433), CERTS (default /certs), MAX_SECONDS (duration cap, can only be lowered).

# shellcheck source=../profiles.sh
source "$(dirname "${BASH_SOURCE[0]}")/../profiles.sh"

# Hard caps. Environment values may lower them but never raise them.
HARD_MAX_SESSIONS=1000
HARD_MAX_SECONDS=600

: "${KEM:?set KEM}" "${AUTH:?set AUTH}" "${CHAIN:?set CHAIN}" "${N:?set N (number of sessions)}" "${SEED:?set SEED}"
SERVER="${SERVER:-server}"; PORT="${PORT:-4433}"; CERTS="${CERTS:-/certs}"
MAX_SECONDS="${MAX_SECONDS:-$HARD_MAX_SECONDS}"
WORKLOAD_START=$SECONDS

# Client-side NIC offloads off (logged; a failure is recorded by run_matrix.sh, not hidden).
/lab/offload_off.sh client eth0 || true

validate_caps() {
  [[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] || { echo "N must be a positive integer" >&2; exit 2; }
  [[ "$SEED" =~ ^[0-9]+$ ]] || { echo "SEED must be a non-negative integer" >&2; exit 2; }
  if [ "$N" -gt "$HARD_MAX_SESSIONS" ]; then echo "N=$N exceeds hard cap $HARD_MAX_SESSIONS" >&2; exit 2; fi
  [ "$MAX_SECONDS" -le "$HARD_MAX_SECONDS" ] || MAX_SECONDS=$HARD_MAX_SECONDS
}

time_left() { [ $((SECONDS - WORKLOAD_START)) -lt "$MAX_SECONDS" ]; }

GROUP="$(group_name "$KEM")"; SIGALG="$(sigalg_name "$AUTH")"; chain_len "$CHAIN" >/dev/null

# Wait for the PKI only. We deliberately do NOT probe the server's TCP port: a probe connection would show up in
# the capture as a stray flow. lab/run_matrix.sh starts the workload only after the server has logged ACCEPT.
wait_for_server() {
  local i
  for i in $(seq 1 120); do [ -f "$CERTS/.done" ] && return 0; sleep 0.5; done
  echo "certificates never appeared in $CERTS" >&2; exit 2
}

# Pinned s_client arguments, computed once (the leaf-only trust bundle is written here, not per connection).
TRUST_ARGS="$(client_trust_args "$AUTH" "$CHAIN" "$CERTS" "/tmp/trust_${AUTH}.pem")"
# shellcheck disable=SC2206
SCLIENT=(openssl s_client -connect "$SERVER:$PORT" -servername server -tls1_3 -groups "$GROUP"
         -sigalgs "$SIGALG" $TRUST_ARGS -verify_return_error -verify_hostname server)

# Expected response size (bytes of file) by name.
file_bytes() { case "$1" in 200b.bin) echo 200 ;; 1k.bin) echo 1024 ;; 2k.bin) echo 2048 ;; 5k.bin) echo 5120 ;; 10k.bin) echo 10240 ;; 100k.bin) echo 102400 ;; 500k.bin) echo 512000 ;; esac; }

print_header() { # WORKLOAD
  echo "workload=$1 kem=$KEM auth=$AUTH chain=$CHAIN n=$N seed=$SEED max_seconds=$MAX_SECONDS openssl=\"$(openssl version)\""
}

# print_summary OK FAILED TRUNCATED  -> exit 1 unless every session succeeded in time
finish() {
  echo "SUMMARY ok=$1 failed=$2 truncated=$3 elapsed_s=$((SECONDS - WORKLOAD_START))"
  if [ "$2" -ne 0 ] || [ "$3" -ne 0 ]; then echo "WORKLOAD INCOMPLETE" >&2; exit 1; fi
  exit 0
}
