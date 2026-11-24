#!/usr/bin/env bash
# Shared profile definitions and checks for gen_certs.sh, smoke_test.sh, run_server.sh, run_client.sh.
# Source this file; do not execute it.
#
# A profile is (KEM group, auth, chain). Nothing here has a default: an unknown name is an error,
# so a profile can never silently fall back to a different group or signature algorithm.

AUTHS=(ecdsa_p256 mldsa44 mldsa65 mldsa87)
KEMS=(X25519 mlkem768 X25519MLKEM768)
CHAINS=(leaf leaf_int)   # leaf = 1 certificate on the wire, leaf_int = leaf + intermediate (2)

# KEM name used by this lab -> OpenSSL group name for -groups.
group_name() {
  case "$1" in
    X25519) echo "X25519" ;;
    mlkem768) echo "MLKEM768" ;;
    X25519MLKEM768) echo "X25519MLKEM768" ;;
    *) echo "unknown KEM '$1'" >&2; return 1 ;;
  esac
}

# Auth name -> arguments for `openssl genpkey`.
keygen_args() {
  case "$1" in
    ecdsa_p256) echo "-algorithm EC -pkeyopt ec_paramgen_curve:P-256" ;;
    mldsa44) echo "-algorithm ML-DSA-44" ;;
    mldsa65) echo "-algorithm ML-DSA-65" ;;
    mldsa87) echo "-algorithm ML-DSA-87" ;;
    *) echo "unknown auth '$1'" >&2; return 1 ;;
  esac
}

# Auth name -> TLS signature algorithm name for -sigalgs.
# SLH-DSA is not in the matrix: OpenSSL 3.5.9 has no TLS 1.3 sigalg for it (docs/lab_findings.md).
sigalg_name() {
  case "$1" in
    ecdsa_p256) echo "ecdsa_secp256r1_sha256" ;;
    mldsa44) echo "mldsa44" ;;
    mldsa65) echo "mldsa65" ;;
    mldsa87) echo "mldsa87" ;;
    *) echo "unknown auth '$1'" >&2; return 1 ;;
  esac
}

# Number of certificates the server sends for a chain choice.
chain_len() {
  case "$1" in
    leaf) echo 1 ;;
    leaf_int) echo 2 ;;
    *) echo "unknown chain '$1'" >&2; return 1 ;;
  esac
}

# s_server certificate arguments. NOTE: `-cert` loads only the first certificate of a PEM file, so the
# intermediate must be given with -cert_chain.
server_cert_args() { # AUTH CHAIN [CERTS_DIR]
  local d="${3:-/certs}/$1"
  case "$2" in
    leaf) echo "-cert $d/leaf.crt -key $d/leaf.key" ;;
    leaf_int) echo "-cert $d/leaf.crt -cert_chain $d/int.crt -key $d/leaf.key" ;;
    *) echo "unknown chain '$2'" >&2; return 1 ;;
  esac
}

# s_client trust arguments. With leaf-only chains the client must trust the intermediate directly.
client_trust_args() { # AUTH CHAIN [CERTS_DIR] [BUNDLE_PATH]
  local d="${3:-/certs}/$1" bundle="${4:-/tmp/trust_$1.pem}"
  case "$2" in
    leaf_int) echo "-CAfile $d/ca.crt" ;;
    leaf) cat "$d/ca.crt" "$d/int.crt" > "$bundle"; echo "-CAfile $bundle -partial_chain" ;;
    *) echo "unknown chain '$2'" >&2; return 1 ;;
  esac
}

# Parse an s_client log into globals: GRP SIG VERIFY_OK CERTS_SENT RD WR PROTO.
parse_client_log() { # LOGFILE
  local f="$1"
  GRP="$(sed -n 's/^Negotiated TLS1.3 group: *//p' "$f" | head -1)"
  [ -n "$GRP" ] || GRP="$(sed -n 's/^Peer Temp Key: *\([^,]*\).*/\1/p' "$f" | head -1)"   # plain X25519
  [ -n "$GRP" ] || GRP="(none)"
  SIG="$(sed -n 's/^Peer signature type: *//p' "$f" | head -1)"; [ -n "$SIG" ] || SIG="(none)"
  if grep -q '^Verify return code: 0 (ok)' "$f"; then VERIFY_OK=yes; else VERIFY_OK=no; fi
  CERTS_SENT="$(grep -cE '^ [0-9]+ s:' "$f" || true)"
  read -r RD WR < <(sed -n 's/^SSL handshake has read \([0-9]*\) bytes and written \([0-9]*\) bytes.*/\1 \2/p' "$f" | head -1)
  RD="${RD:--}"; WR="${WR:--}"
  PROTO="$(sed -n 's/^Protocol: *//p' "$f" | head -1)"; [ -n "$PROTO" ] || PROTO="(none)"
}

# After parse_client_log: print one reason per mismatch (empty output = PASS).
judge() { # KEM AUTH CHAIN
  local g s n
  g="$(group_name "$1")"; s="$(sigalg_name "$2")"; n="$(chain_len "$3")"
  [ "$GRP" = "$g" ] || echo "negotiated group '$GRP' != pinned '$g'"
  [ "$SIG" = "$s" ] || echo "peer signature '$SIG' != pinned '$s'"
  [ "$PROTO" = "TLSv1.3" ] || echo "protocol '$PROTO' != TLSv1.3"
  [ "$VERIFY_OK" = yes ] || echo "certificate verification failed"
  [ "$CERTS_SENT" = "$n" ] || echo "server sent $CERTS_SENT certificates, expected $n"
}
