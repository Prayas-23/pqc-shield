"""Plan for the replicate captures (data/pcaps_rep): which captures, and in what random order.

Purpose: test whether timing differences between profiles are a crypto effect or pcap-to-pcap noise. Four chosen
profiles (all chain leaf_int), 3 replicates each, 4 workloads each = 48 captures. The order of all 48 is a random
permutation from a recorded seed, so that position in the run (laptop load, thermal state, time of day) is not
confounded with the profile or the replicate. Nothing here touches the lab; it only produces the list.
"""

from __future__ import annotations

import numpy as np

REPLICATE_CHAIN = "leaf_int"
REPLICATE_PROFILES: tuple[tuple[str, str], ...] = (
    ("X25519", "ecdsa_p256"),            # the reference profile of the main run
    ("mlkem768", "mldsa65"),
    ("X25519MLKEM768", "mldsa65"),
    ("X25519MLKEM768", "mldsa87"),
)
REPLICATES: tuple[int, ...] = (1, 2, 3)
REPLICATE_WORKLOADS: tuple[str, ...] = ("benign_web", "benign_api", "handshake_flood", "slow_send")

# One entry per capture: (run_order, kem, auth, chain, replicate, workload); run_order runs 1..48.
Capture = tuple[int, str, str, str, int, str]


def replicate_order(seed: int) -> list[Capture]:
    """All (profile, replicate, workload) captures in a random order fixed by `seed` (numpy default_rng permutation)."""
    jobs = [(kem, auth, REPLICATE_CHAIN, rep, wl)
            for kem, auth in REPLICATE_PROFILES for rep in REPLICATES for wl in REPLICATE_WORKLOADS]
    order = np.random.default_rng(seed).permutation(len(jobs))
    return [(position + 1, *jobs[int(index)]) for position, index in enumerate(order)]
