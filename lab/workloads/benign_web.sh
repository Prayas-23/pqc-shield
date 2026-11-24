#!/usr/bin/env bash
# benign_web (label: benign): N sequential sessions, each one TLS 1.3 connection that requests one file
# from the server (1 KB, 10 KB, 100 KB or 500 KB). The file sequence comes from bash's PRNG seeded with
# SEED, so it is identical for every crypto profile. Hard caps: N <= 1000 sessions, <= 600 s.
set -uo pipefail
source "$(dirname "$0")/common.sh"
validate_caps
print_header benign_web
wait_for_server

FILES=(1k.bin 10k.bin 100k.bin 500k.bin)
RANDOM=$SEED
ok=0; failed=0; truncated=0
out="$(mktemp)"
for ((i = 1; i <= N; i++)); do
  if ! time_left; then truncated=$((N - i + 1)); echo "TIME CAP reached before session $i"; break; fi
  f="${FILES[$((RANDOM % 4))]}"
  printf 'GET /%s HTTP/1.0\r\n\r\n' "$f" | timeout 60 "${SCLIENT[@]}" -quiet -ign_eof > "$out" 2>/dev/null
  rc=$?
  got=$(wc -c < "$out"); want=$(file_bytes "$f")
  if [ "$rc" -eq 0 ] && [ "$got" -ge "$want" ]; then status=ok; ok=$((ok + 1)); else status=FAIL; failed=$((failed + 1)); fi
  echo "session=$i file=$f status=$status rc=$rc bytes_received=$got"
done
finish "$ok" "$failed" "$truncated"
