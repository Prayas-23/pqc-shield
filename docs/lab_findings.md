# Lab findings

## SLH-DSA cannot be negotiated in TLS 1.3 with OpenSSL 3.5.9

**OpenSSL 3.5.9: no TLS 1.3 sigalg for SLH-DSA; certificates can be created but not negotiated.**

Observed on the lab image (`pqdl-lab:openssl-3.5.9`, OpenSSL 3.5.9 built from the official tarball):

- The library knows SLH-DSA (`openssl list -signature-algorithms` lists `SLH-DSA-SHA2-128s` and
  others) and `gen_certs.sh` produced a full SLH-DSA-SHA2-128s root, intermediate and leaf that verify.
- `openssl list -tls-signature-algorithms` lists `mldsa44`, `mldsa65` and `mldsa87` but **no SLH-DSA
  entry** (0 matches for "slh").
- Pinning a signature algorithm name, on `s_server` and on `s_client` alike, fails immediately:

  ```
  Call to SSL_CONF_cmd(-sigalgs, slhdsa128s) failed
  ```

- Without pinning, `s_server` refuses to load the SLH-DSA certificate as a server certificate:

  ```
  error setting certificate
  80BB306592710000:error:0A0000F7:SSL routines:ssl_set_cert:unknown certificate type:ssl/ssl_rsa.c:270:
  ```

Consequence: the `slhdsa128s` profiles FAIL in the smoke test (3 of 12 profiles then) and are **dropped
from the capture matrix**, not faked or replaced by another algorithm. They would need a TLS stack with an
SLH-DSA TLS signature scheme (none was looked for).

## Matrix after the change

KEMs: X25519, mlkem768, X25519MLKEM768. Auths: ecdsa_p256, mldsa44, mldsa65, mldsa87 (`mldsa87` added: the
dataset also uses it and the build supports it). 3 x 4 = 12 profiles, chain `leaf_int` (2 certificates).
Chain `leaf` (1 certificate) is captured for ecdsa_p256 and mldsa65 only, as a direct test of the chain-length
parameter. Total: 12 + 6 = 18 profile/chain configurations.
