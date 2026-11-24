"""Handshake profile definitions.

A Profile names one handshake configuration (key exchange, authentication
algorithm, transport). All byte sizes live in the single SIZES table below so they
can be audited against the standards in one place.
"""

from __future__ import annotations

from dataclasses import dataclass

# Byte sizes, all in bytes.
# Sources: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), RFC 8446 (TLS 1.3).
# VERIFY: every number below must be checked against the standards by a human.
#   "kem":  name -> (client_share, server_share)
#   "auth": name -> (public_key, signature)   (ECDSA-P256 uses raw 64-byte encodings)
SIZES: dict[str, dict[str, tuple[int, int]]] = {
    "kem": {
        "X25519": (32, 32),  # VERIFY
        "X25519MLKEM768": (1216, 1120),  # VERIFY
        "MLKEM768": (1184, 1088),  # VERIFY
        "MLKEM1024": (1568, 1568),  # VERIFY (FIPS 203: encapsulation key 1568, ciphertext 1568)
    },
    "auth": {
        "ECDSA-P256": (64, 64),  # VERIFY (raw)
        "ECDSA-P384": (96, 96),  # VERIFY (raw r||s and x||y; not DER)
        "MLDSA44": (1312, 2420),  # VERIFY
        "MLDSA65": (1952, 3309),  # VERIFY
        "MLDSA87": (2592, 4627),  # VERIFY (FIPS 204)
        "RSA3072": (384, 384),  # VERIFY (modulus-sized key and signature; RFC 8446 RSA-PSS)
        "SLHDSA128s": (32, 7856),  # VERIFY
    },
}

TRANSPORTS: tuple[str, ...] = ("TCP", "QUIC")


@dataclass(frozen=True)
class Overheads:
    """Fixed per-message overheads in bytes. All configurable; VERIFY against RFC 8446."""

    l_ee: int = 30  # EncryptedExtensions
    o_cert: int = 40  # per-certificate framing overhead
    o_cv: int = 8  # CertificateVerify framing overhead
    l_fin: int = 36  # Finished (both directions)
    sh_base: int = 90  # ServerHello = sh_base + server key share
    ch_base: int = 250  # ClientHello = ch_base + client key share


@dataclass(frozen=True)
class Profile:
    """One handshake configuration."""

    kem: str
    auth: str
    transport: str
    n_certs: int = 2

    def __post_init__(self) -> None:
        if self.kem not in SIZES["kem"]:
            raise ValueError(f"unknown kem {self.kem!r}; known: {sorted(SIZES['kem'])}")
        if self.auth not in SIZES["auth"]:
            raise ValueError(f"unknown auth {self.auth!r}; known: {sorted(SIZES['auth'])}")
        if self.transport not in TRANSPORTS:
            raise ValueError(f"unknown transport {self.transport!r}; known: {TRANSPORTS}")
        if self.n_certs < 0:
            raise ValueError("n_certs must be >= 0")


def kem_sizes(profile: Profile) -> tuple[int, int]:
    """Return (client_share, server_share) in bytes for the profile's KEM."""
    return SIZES["kem"][profile.kem]


def auth_sizes(profile: Profile) -> tuple[int, int]:
    """Return (public_key, signature) in bytes for the profile's auth algorithm."""
    return SIZES["auth"][profile.auth]
