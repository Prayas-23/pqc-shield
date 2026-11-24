#!/usr/bin/env bash
# benign_api (label: benign): N sequential sessions of small API-style requests. Each session is one TLS 1.3
# connection that requests one small file (200 B, 1 KB, 2 KB or 5 KB), then pauses a random 0-200 ms before the
# next session. File choice and pause both come from bash's PRNG seeded with SEED, so the sequence is identical
# for every crypto profile. Hard caps: N <= 1000 sessions, <= 600 s; one connection at a time.
set -uo pipefail
source "$(dirname "$0")/common.sh"
validate_caps
print_header benign_api
wait_for_server

FILES=(200b.bin 1k.bin 2k.bin 5k.bin)
RANDOM=$SEED
ok=0; failed=0; truncated=0
out="$(mktemp)"
for ((i = 1; i <= N; i++)); do
  if ! time_left; then truncated=$((N - i + 1)); echo "TIME CAP reached before session $i"; break; fi
  f="${FILES[$((RANDOM % 4))]}"
  pause_ms=$((RANDOM % 201))                 # 0..200 ms
  printf 'GET /%s HTTP/1.0\r\n\r\n' "$f" | timeout 60 "${SCLIENT[@]}" -quiet -ign_eof > "$out" 2>/dev/null
  rc=$?
  got=$(wc -c < "$out"); want=$(file_bytes "$f")
  if [ "$rc" -eq 0 ] && [ "$got" -ge "$want" ]; then status=ok; ok=$((ok + 1)); else status=FAIL; failed=$((failed + 1)); fi
  echo "session=$i file=$f status=$status rc=$rc bytes_received=$got pause_ms=$pause_ms"
  sleep "0.$(printf '%03d' "$pause_ms")"
done
finish "$ok" "$failed" "$truncated"
