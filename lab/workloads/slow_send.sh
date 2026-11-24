#!/usr/bin/env bash
# slow_send (label: attack-like, slowloris style): N sequential sessions; each opens a TLS 1.3 session and
# sends one HTTP request ONE BYTE AT A TIME with a fixed delay, then reads the response. Target is our own
# server container only. Hard caps: N <= 1000 sessions, <= 600 s, one connection at a time.
set -uo pipefail
source "$(dirname "$0")/common.sh"
validate_caps
print_header slow_send
wait_for_server

DELAY=0.1                                  # seconds between bytes (fixed, identical for every profile)
REQUEST=$'GET /1k.bin HTTP/1.0\r\n\r\n'    # 24 bytes -> 24 TLS application-data records of 1 byte each

send_slowly() {
  local i
  for ((i = 0; i < ${#REQUEST}; i++)); do printf '%s' "${REQUEST:i:1}"; sleep "$DELAY"; done
}

ok=0; failed=0; truncated=0
out="$(mktemp)"
for ((i = 1; i <= N; i++)); do
  if ! time_left; then truncated=$((N - i + 1)); echo "TIME CAP reached before session $i"; break; fi
  send_slowly | timeout 60 "${SCLIENT[@]}" -quiet -ign_eof > "$out" 2>/dev/null
  rc=${PIPESTATUS[1]}
  got=$(wc -c < "$out")
  if [ "$rc" -eq 0 ] && [ "$got" -ge 1024 ]; then status=ok; ok=$((ok + 1)); else status=FAIL; failed=$((failed + 1)); fi
  echo "session=$i request_bytes=${#REQUEST} delay_s=$DELAY status=$status rc=$rc bytes_received=$got"
done
finish "$ok" "$failed" "$truncated"
