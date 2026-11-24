#!/usr/bin/env bash
# Capture matrix driver (runs on the HOST, drives docker compose). One pcap per
# (kem, auth, chain, workload): <dir>/<kem>_<auth>_<chain>_<workload>.pcap, plus a row in <dir>/manifest.csv.
#
#   lab/run_matrix.sh --mini            one profile (mlkem768 + mldsa65, leaf_int), N=20 per workload -> data/pcaps_mini/
#   lab/run_matrix.sh --full            the full matrix -> data/pcaps/
#   lab/run_matrix.sh --rep             replicate captures (4 profiles x 3 replicates x 4 workloads = 48) in a random
#                                       order -> data/pcaps_rep/ ; replicate r uses seed (--seed + r) for every profile,
#                                       so seeds differ between replicates but not between profiles (as in the main run)
# Options: --n N (override sessions per pcap for every workload), --seed S (default 1234),
#          --order-seed S (random capture order for --rep; default 20261124, recorded in the manifest),
#          --plan (print the job list and exit; touches nothing).
#
# Full matrix: KEM {X25519, mlkem768, X25519MLKEM768} x AUTH {ecdsa_p256, mldsa44, mldsa65, mldsa87} with chain
# leaf_int FIRST (12 profiles), then chain leaf for ecdsa_p256 and mldsa65 only (6 profiles); 4 workloads each.
# Sessions: benign_web 300, benign_api 300, handshake_flood 200, slow_send 50.
#
# Guarantees: resumable (a pcap with a manifest row is skipped); a pcap is only accepted if tcpdump dropped 0
# packets, the workload completed, the parser counts exactly the intended number of connections, and the pcap is
# non-empty. A failed pcap is retried at most twice, then the run STOPS loudly. Refuses to run with < 20 GB free.
# One run at a time (lock directory lab/.run.lock). All traffic stays on the internal Docker network.
set -uo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: do not rewrite /lab/... paths

cd "$(dirname "$0")/.."
# shellcheck source=profiles.sh
source lab/profiles.sh

MODE=""; N_OVERRIDE=""; SEED=1234; ORDER_SEED=20261124; PLAN=""; MIN_FREE_GB=20; MAX_ATTEMPTS=3; MAX_OFFLOAD_PAYLOAD=1460
while [ $# -gt 0 ]; do
  case "$1" in
    --mini) MODE=mini ;; --full) MODE=full ;; --rep) MODE=rep ;; --plan) PLAN=1 ;;
    --n) N_OVERRIDE="$2"; shift ;; --seed) SEED="$2"; shift ;; --order-seed) ORDER_SEED="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$MODE" ] || { echo "choose --mini, --full or --rep" >&2; exit 2; }

utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "$(utc) $*"; }

# The version of the code that produced a capture: `git rev-parse HEAD`, with "-dirty" appended when there are
# uncommitted changes (tracked or untracked, ignoring .gitignore'd files). "unknown" if this is not a git repo or
# has no commit yet. Evaluated at the start of every pcap, so a change made mid-run is visible in the manifest.
code_version() {
  local sha
  sha="$(git rev-parse HEAD 2>/dev/null)" || { echo unknown; return; }
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then echo "${sha}-dirty"; else echo "$sha"; fi
}

if ! command -v docker >/dev/null 2>&1; then
  for d in "$LOCALAPPDATA/Programs/DockerDesktop/resources/bin" "/c/Program Files/Docker/Docker/resources/bin"; do
    if [ -x "$d/docker.exe" ] || [ -x "$d/docker" ]; then PATH="$PATH:$d"; break; fi
  done
fi
command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 2; }
PY=.venv/Scripts/python; [ -x "$PY" ] || PY=.venv/bin/python
[ -x "$PY" ] || { echo "python venv not found (run make setup)" >&2; exit 2; }

# ---- job list: one flat list for every mode -------------------------------------------------
WORKLOADS=(benign_web benign_api handshake_flood slow_send)
workload_label() { case "$1" in benign_web|benign_api) echo benign ;; handshake_flood|slow_send) echo attack ;; *) echo "unknown workload $1" >&2; return 1 ;; esac; }
n_for() { # WORKLOAD -> sessions (--rep uses the same counts as the main run)
  if [ -n "$N_OVERRIDE" ]; then echo "$N_OVERRIDE"; return; fi
  if [ "$MODE" = mini ]; then echo 20; return; fi
  case "$1" in benign_web|benign_api) echo 300 ;; handshake_flood) echo 200 ;; slow_send) echo 50 ;; esac
}

JOBS=()   # "run_order kem auth chain replicate workload"; replicate is "-" outside --rep
if [ "$MODE" = rep ]; then
  while read -r ro kem auth chain r wl; do JOBS+=("$ro $kem $auth $chain $r $wl"); done \
    < <("$PY" scripts/capture_order.py --seed "$ORDER_SEED")
else
  PROFILES=()   # "kem auth chain"
  if [ "$MODE" = mini ]; then
    PROFILES+=("mlkem768 mldsa65 leaf_int")
  else
    for kem in "${KEMS[@]}"; do for auth in "${AUTHS[@]}"; do PROFILES+=("$kem $auth leaf_int"); done; done
    for kem in "${KEMS[@]}"; do for auth in ecdsa_p256 mldsa65; do PROFILES+=("$kem $auth leaf"); done; done
  fi
  k=0
  for p in "${PROFILES[@]}"; do
    read -r kem auth chain <<< "$p"
    for wl in "${WORKLOADS[@]}"; do k=$((k + 1)); JOBS+=("$k $kem $auth $chain - $wl"); done
  done
fi
if [ -n "$PLAN" ]; then
  echo "mode=$MODE seed=$SEED order_seed=$ORDER_SEED jobs=${#JOBS[@]}"
  printf '%s\n' "${JOBS[@]}"
  exit 0
fi

capture_name() { # KEM AUTH CHAIN WORKLOAD REPLICATE
  local name="$1_$2_$3_$4"; [ "$5" != "-" ] && name="${name}_r$5"; echo "$name"
}

case "$MODE" in mini) PCAPS=data/pcaps_mini ;; rep) PCAPS=data/pcaps_rep ;; *) PCAPS=data/pcaps ;; esac
MANIFEST=$PCAPS/manifest.csv
HEADER="kem,auth,chain,workload,label,intended_sessions,observed_connections,seed,openssl_version,start_utc,end_utc,pcap_file,pcap_bytes,tcpdump_dropped,capture_offload_ok,max_tcp_payload,code_commit"
[ "$MODE" = rep ] && HEADER="$HEADER,replicate_id,run_order,order_seed"
mkdir -p "$PCAPS"

# ---- single-instance lock ---------------------------------------------------------------------
LOCK=lab/.run.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  old="$(cat "$LOCK/pid" 2>/dev/null || true)"
  if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then echo "already running (pid $old); not starting a second run" >&2; exit 9; fi
  log "removing stale lock (pid ${old:-unknown} is not running)"; rm -rf "$LOCK"; mkdir "$LOCK" || exit 9
fi
echo $$ > "$LOCK/pid"

cleanup() { docker compose down -v >/dev/null 2>&1 || true; }
on_exit() { cleanup; rm -rf "$LOCK"; }
trap on_exit EXIT

# ---- disk check ------------------------------------------------------------------------------
free_gb=$(( $(df -Pk "$PCAPS" | awk 'NR==2 {print $4}') / 1024 / 1024 ))
log "free disk on the pcap drive: ${free_gb} GB (minimum ${MIN_FREE_GB} GB)"
[ "$free_gb" -ge "$MIN_FREE_GB" ] || { echo "REFUSING TO RUN: less than ${MIN_FREE_GB} GB free" >&2; exit 3; }

OPENSSL_VERSION="$(docker run --rm pqdl-lab:openssl-3.5.9 openssl version | awk '{print $2}')"
[ -n "$OPENSSL_VERSION" ] || { echo "could not get the OpenSSL version" >&2; exit 2; }
if [ -f "$MANIFEST" ]; then
  [ "$(head -1 "$MANIFEST")" = "$HEADER" ] || { echo "$MANIFEST has a different header; move it away first" >&2; exit 2; }
else
  echo "$HEADER" > "$MANIFEST"
fi

wait_for_log() { # SERVICE PATTERN WHAT : poll a container's own log (generates no network traffic)
  for _ in $(seq 1 120); do
    docker compose logs --no-color "$1" 2>/dev/null | grep -q "$2" && return 0
    sleep 0.5
  done
  echo "$3 never became ready" >&2; return 1
}

has_row() { grep -q ",$1.pcap," "$MANIFEST"; }

_run_one() { # KEM AUTH CHAIN WORKLOAD REPLICATE RUN_ORDER ; non-zero on any problem (caller cleans up and may retry)
  local kem="$1" auth="$2" chain="$3" wl="$4" rep="$5" run_order="$6" n label name pcap part start end rc=0 dropped code_commit seed extra=""
  n="$(n_for "$wl")"; label="$(workload_label "$wl")" || return 1
  code_commit="$(code_version)"
  seed="$SEED"; [ "$rep" != "-" ] && { seed=$((SEED + rep)); extra=",$rep,$run_order,$ORDER_SEED"; }
  name="$(capture_name "$kem" "$auth" "$chain" "$wl" "$rep")"; pcap="$PCAPS/$name.pcap"; part="$pcap.part"
  export KEM="$kem" AUTH="$auth" CHAIN="$chain" PCAP_NAME="$name.pcap"
  start="$(utc)"
  # Server first; wait for its own log line (no probe connection), THEN start the capture, then the workload.
  docker compose up -d server >/dev/null 2>&1 || { echo "server failed to start" >&2; return 1; }
  wait_for_log server 'ACCEPT$' "s_server" || return 1
  docker compose up -d capture >/dev/null 2>&1 || { echo "capture failed to start" >&2; return 1; }
  wait_for_log capture 'listening on' "tcpdump" || return 1
  docker compose run --rm -T -e N="$n" -e SEED="$seed" client "/lab/workloads/$wl.sh" \
    > "$PCAPS/$name.workload.log" 2>&1 || rc=$?
  sleep 1                                          # let the last packets reach the capture
  docker compose stop -t 20 capture >/dev/null 2>&1   # SIGTERM: tcpdump flushes its file and prints its statistics
  end="$(utc)"
  docker compose logs --no-color capture > "$PCAPS/$name.capture.log" 2>&1
  dropped="$(grep -oE '[0-9]+ packets dropped by kernel' "$PCAPS/$name.capture.log" | awk '{print $1}' | tail -1)"
  rm -f "$part"; docker compose cp "capture:/tmp/$name.pcap" "$part" >/dev/null 2>&1
  [ "$rc" -eq 0 ] || { echo "workload $wl exited $rc: $(tail -2 "$PCAPS/$name.workload.log" | tr '\n' ' ')" >&2; return 1; }
  [ "${dropped:-unknown}" = 0 ] || { echo "tcpdump reported '${dropped:-no statistics}' dropped packets" >&2; return 1; }
  [ -s "$part" ] && [ "$(stat -c %s "$part")" -gt 24 ] || { echo "pcap missing or empty" >&2; return 1; }
  local obs maxpl bytes ok_server ok_client offload_ok
  read -r obs maxpl < <("$PY" scripts/pcap_check.py "$part" 2>/dev/null | sed -E 's/observed_connections=([0-9]+) max_payload=([0-9]+)/\1 \2/')
  [ "${obs:-x}" = "$n" ] || { echo "intended $n sessions but the parser found '${obs:-nothing}' connections" >&2; return 1; }
  grep -q 'OFFLOAD server eth0: ok' "$PCAPS/$name.capture.log" && ok_server=1 || ok_server=0
  grep -q 'OFFLOAD client eth0: ok' "$PCAPS/$name.workload.log" && ok_client=1 || ok_client=0
  if [ "$ok_server" = 1 ] && [ "$ok_client" = 1 ] && [ "$maxpl" -le "$MAX_OFFLOAD_PAYLOAD" ]; then offload_ok=true; else offload_ok=false; fi
  bytes="$(stat -c %s "$part")"
  grep -v ",$name.pcap," "$MANIFEST" > "$MANIFEST.tmp" || true; mv "$MANIFEST.tmp" "$MANIFEST"   # idempotent row
  echo "$kem,$auth,$chain,$wl,$label,$n,$obs,$seed,$OPENSSL_VERSION,$start,$end,$name.pcap,$bytes,$dropped,$offload_ok,$maxpl,$code_commit$extra" >> "$MANIFEST"
  mv "$part" "$pcap"
  log "done   $name  conns=$obs/$n  bytes=$bytes  max_payload=$maxpl  offload_ok=$offload_ok  $(tail -1 "$PCAPS/$name.workload.log")"
}

run_one() { local rc=0; _run_one "$@" || rc=$?; cleanup; return "$rc"; }

TOTAL=${#JOBS[@]}; K=0; T0=$SECONDS
log "mode=$MODE seed=$SEED order_seed=$ORDER_SEED openssl=$OPENSSL_VERSION -> $TOTAL pcaps in $PCAPS"
for job in "${JOBS[@]}"; do
  read -r run_order kem auth chain rep wl <<< "$job"
  K=$((K + 1)); name="$(capture_name "$kem" "$auth" "$chain" "$wl" "$rep")"
  if [ -e "$PCAPS/$name.pcap" ]; then
    if has_row "$name"; then log "[$K/$TOTAL] skip   $name (already captured)"; continue; fi
    log "[$K/$TOTAL] $name exists without a manifest row (interrupted); recapturing"; rm -f "$PCAPS/$name.pcap"
  fi
  attempt=1
  while true; do
    log "[$K/$TOTAL] run    $name  (attempt $attempt/$MAX_ATTEMPTS, N=$(n_for "$wl"), elapsed $((SECONDS - T0)) s)"
    if run_one "$kem" "$auth" "$chain" "$wl" "$rep" "$run_order"; then break; fi
    log "[$K/$TOTAL] FAILED attempt $attempt for $name (see $PCAPS/$name.workload.log and $name.capture.log)"
    attempt=$((attempt + 1))
    if [ "$attempt" -gt "$MAX_ATTEMPTS" ]; then
      log "STOPPING: $name failed $MAX_ATTEMPTS times. Fix the cause, then run the same command again to resume."
      exit 1
    fi
  done
done
log "FINISHED all $TOTAL pcaps in $((SECONDS - T0)) s; manifest rows: $(( $(wc -l < "$MANIFEST") - 1 ))"
