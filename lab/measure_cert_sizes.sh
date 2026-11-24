#!/usr/bin/env bash
# Print DER sizes of the lab's leaf and intermediate certificates for every auth, from a FRESH throwaway PKI made by
# gen_certs.sh inside the container. Output lines: auth,leaf_der,int_der. Used by scripts/measure_cert_overhead.py.
set -euo pipefail
OUT="$(mktemp -d)"
/lab/gen_certs.sh "$OUT" >/dev/null 2>&1
source /lab/profiles.sh
for auth in "${AUTHS[@]}"; do
  leaf="$(openssl x509 -in "$OUT/$auth/leaf.crt" -outform DER | wc -c)"
  int="$(openssl x509 -in "$OUT/$auth/int.crt" -outform DER | wc -c)"
  echo "$auth,$leaf,$int"
done
