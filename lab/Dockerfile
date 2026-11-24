# PQ-DRIFTLAB lab image: OpenSSL built from the official source tarball.
#
# Targets:
#   lab      OpenSSL 3.5.x (own build under /opt/openssl) + our scripts. No system OpenSSL/libssl.
#   capture  tcpdump only. Debian's tcpdump depends on libssl3, so it lives in its own image and
#            never runs TLS; it is kept out of the `lab` image on purpose.
#
# Build:  docker build --target lab -t pqdl-lab:openssl-3.5.9 lab/
# See lab/README.md for the safety rules.

ARG DEBIAN_TAG=bookworm-slim

# ---------------------------------------------------------------- build stage
FROM debian:${DEBIAN_TAG} AS build
ARG OPENSSL_VERSION=3.5.9
# Expected SHA-256 of openssl-3.5.9.tar.gz, as published by the OpenSSL project in
#   https://www.openssl.org/source/openssl-3.5.9.tar.gz.sha256
# and (identical) in the GitHub release asset
#   https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz.sha256
# The build below also re-downloads the published .sha256 and requires all three values to agree.
ARG OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

# Build tools only (curl here links the system OpenSSL, but this stage is discarded).
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential perl curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN set -eu; \
    base="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"; \
    curl -fsSL -o openssl.tar.gz "$base"; \
    curl -fsSL -o openssl.tar.gz.sha256 "$base.sha256"; \
    published="$(cut -d' ' -f1 openssl.tar.gz.sha256)"; \
    computed="$(sha256sum openssl.tar.gz | cut -d' ' -f1)"; \
    echo "SHA-256 pinned in this Dockerfile : ${OPENSSL_SHA256}"; \
    echo "SHA-256 published by OpenSSL      : ${published}   (${base}.sha256)"; \
    echo "SHA-256 computed from the download: ${computed}"; \
    if [ "${OPENSSL_SHA256}" != "${published}" ] || [ "${published}" != "${computed}" ]; then \
        echo "CHECKSUM MISMATCH: refusing to build" >&2; exit 1; \
    fi; \
    echo "CHECKSUM OK"; \
    tar xzf openssl.tar.gz --strip-components=1

# rpath so the binary uses only /opt/openssl/lib, never a system libssl.
RUN set -eu; \
    ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl/ssl --libdir=lib \
        -Wl,-rpath,/opt/openssl/lib; \
    make -j"$(nproc)"; \
    make install_sw install_ssldirs

# ---------------------------------------------------------------- lab image
FROM debian:${DEBIAN_TAG} AS lab
COPY --from=build /opt/openssl /opt/openssl
ENV PATH=/opt/openssl/bin:$PATH
# ethtool links only libc/libmnl (no OpenSSL); the check below still fails the build if any libssl/openssl package is installed.
RUN apt-get update && apt-get install -y --no-install-recommends ethtool && rm -rf /var/lib/apt/lists/*
COPY openssl-lab.cnf profiles.sh gen_certs.sh smoke_test.sh run_server.sh run_client.sh offload_off.sh /lab/
COPY workloads /lab/workloads
RUN chmod +x /lab/*.sh /lab/workloads/*.sh \
 # Fail the build if any system OpenSSL/libssl is installed, or the binary links anything but ours.
 && if dpkg -l | grep -Eq '^ii +(libssl|openssl)'; then echo "system OpenSSL present" >&2; exit 1; fi \
 && ldd /opt/openssl/bin/openssl | tee /dev/stderr | grep -E 'libssl|libcrypto' | grep -vq '/opt/openssl/lib' && exit 1 || true \
 && openssl version -a
WORKDIR /lab
ENV OPENSSL_CONF=/lab/openssl-lab.cnf

# ---------------------------------------------------------------- capture image
FROM debian:${DEBIAN_TAG} AS capture
RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump ethtool \
 && rm -rf /var/lib/apt/lists/*
# ethtool here changes the SERVER's NIC offloads: this container shares the server's network namespace.
COPY offload_off.sh /lab/offload_off.sh
RUN chmod +x /lab/offload_off.sh
