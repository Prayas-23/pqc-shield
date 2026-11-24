from pqdl.labplan import (
    REPLICATE_PROFILES,
    REPLICATE_WORKLOADS,
    REPLICATES,
    replicate_order,
)


def test_plan_has_every_capture_exactly_once() -> None:
    plan = replicate_order(seed=1)
    assert len(plan) == len(REPLICATE_PROFILES) * len(REPLICATES) * len(REPLICATE_WORKLOADS) == 48
    assert sorted(p[0] for p in plan) == list(range(1, 49))                     # run_order 1..48, no gaps
    keys = {(kem, auth, chain, rep, wl) for _, kem, auth, chain, rep, wl in plan}
    assert len(keys) == 48                                                       # no capture repeated
    assert {(k, a) for k, a, *_ in keys} == set(REPLICATE_PROFILES)
    assert {r for *_, r, _ in keys} == set(REPLICATES) and {w for *_, w in keys} == set(REPLICATE_WORKLOADS)
    assert {c for _, _, c, _, _ in keys} == {"leaf_int"}


def test_order_is_reproducible_from_the_seed_and_depends_on_it() -> None:
    assert replicate_order(7) == replicate_order(7)
    assert [p[1:] for p in replicate_order(7)] != [p[1:] for p in replicate_order(8)]


def test_order_is_not_the_sorted_nested_loop_order() -> None:
    plan = replicate_order(20261124)
    nested = [p[1:] for p in sorted(plan, key=lambda p: (REPLICATE_PROFILES.index((p[1], p[2])), p[4],
                                                         REPLICATE_WORKLOADS.index(p[5])))]
    assert [p[1:] for p in plan] != nested
