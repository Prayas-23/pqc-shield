#!/usr/bin/env bash
# Generate the lab's private test PKI with OpenSSL 3.5 (native ML-DSA / SLH-DSA).
#
# For each auth: its own private root CA -> intermediate CA -> server leaf, all using the SAME
# algorithm, so chain sizes reflect that algorithm only. Two chain files per auth:
#   chain_leaf.pem      leaf only                (n_certs = 1 on the wire)
#   chain_leaf_int.pem  leaf + intermediate      (n_certs = 2 on the wire)
# The root is never sent. Throwaway PKI: never add these certificates to any trust store.
#
# Usage: gen_certs.sh [OUT_DIR]      (default /certs)
set -euo pipefail

OUT="${1:-/certs}"
CNF="${OPENSSL_CONF:-/lab/openssl-lab.cnf}"
DAYS=30
# shellcheck source=profiles.sh
source "$(dirname "$0")/profiles.sh"

genkey() { # genkey AUTH FILE
  # shellcheck disable=SC2046
  openssl genpkey $(keygen_args "$1") -out "$2"
  chmod 600 "$2"
}

der_size() { openssl x509 -in "$1" -outform DER | wc -c; }

make_chain() { # make_chain AUTH
  local auth="$1" d="$OUT/$1"
  mkdir -p "$d"
  cd "$d"
  local subj="/O=PQ-DRIFTLAB lab (test only)"

  genkey "$auth" ca.key
  openssl req -x509 -new -key ca.key -subj "$subj/CN=Lab Root CA $auth" -days "$DAYS" \
    -config "$CNF" -extensions v3_ca -out ca.crt

  genkey "$auth" int.key
  openssl req -new -key int.key -subj "$subj/CN=Lab Intermediate CA $auth" -out int.csr
  openssl x509 -req -in int.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days "$DAYS" \
    -extfile "$CNF" -extensions v3_int -out int.crt

  genkey "$auth" leaf.key
  openssl req -new -key leaf.key -subj "$subj/CN=server" -out leaf.csr
  openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -days "$DAYS" \
    -extfile "$CNF" -extensions v3_leaf -out leaf.crt

  cat leaf.crt > chain_leaf.pem
  cat leaf.crt int.crt > chain_leaf_int.pem
  rm -f leaf.csr int.csr
  # Fail loudly if the chain does not verify (leaf+intermediate against the root).
  openssl verify -CAfile ca.crt -untrusted int.crt leaf.crt >/dev/null
  cd - >/dev/null
}

print_sizes() {
  printf '\n%-12s %-20s %12s %12s\n' "auth" "file" "file bytes" "DER bytes"
  printf '%-12s %-20s %12s %12s\n' "----" "----" "----------" "---------"
  local auth f der
  for auth in "${AUTHS[@]}"; do
    for f in ca.key ca.crt int.key int.crt leaf.key leaf.crt chain_leaf.pem chain_leaf_int.pem; do
      der="-"
      case "$f" in
        *.crt) der="$(der_size "$OUT/$auth/$f")" ;;
        chain_leaf.pem) der="$(der_size "$OUT/$auth/leaf.crt")" ;;
        chain_leaf_int.pem) der="$(( $(der_size "$OUT/$auth/leaf.crt") + $(der_size "$OUT/$auth/int.crt") ))" ;;
      esac
      printf '%-12s %-20s %12s %12s\n' "$auth" "$f" "$(stat -c %s "$OUT/$auth/$f")" "$der"
    done
  done
}

echo "OpenSSL: $(openssl version)"
mkdir -p "$OUT"
for a in "${AUTHS[@]}"; do
  echo "== generating chain for $a"
  make_chain "$a"
done
print_sizes
echo "(DER bytes for a chain file = the bytes of certificates the server sends in Certificate.)"
