"""Tests for pqdl.drift. All data here is SYNTHETIC (pqdl.synth) or hand-built; no real data."""

from __future__ import annotations

import math
import warnings

import numpy as np
import pandas as pd
import pytest

from pqdl.drift import (
    MAX_CATEGORIES,
    PQC_DESIGN_CELLS,
    PSI_EPS,
    drift_table,
    eta_squared,
    mmd2_rbf,
    pqc_contrast_table,
    psi,
    psi_mode,
    two_way_effects,
)
from pqdl.loaders import MixedSourceError
from pqdl.synth import SYNTHETIC_SOURCE, synthetic_groups, synthetic_pqc_cells


def synth_frame(**columns: object) -> pd.DataFrame:
    return pd.DataFrame({**columns, "source": SYNTHETIC_SOURCE})


# ------------------------------------------------------------------------------------- PSI
def test_psi_identical_samples_is_zero_both_paths() -> None:
    rng = np.random.default_rng(0)
    quantile_sample = rng.normal(size=500)  # > 20 distinct -> quantile path
    categorical_sample = rng.integers(0, 5, size=500)  # 5 distinct -> categorical path
    assert psi_mode(quantile_sample, quantile_sample) == "quantile"
    assert psi_mode(categorical_sample, categorical_sample) == "categorical"
    assert psi(quantile_sample, quantile_sample) == 0.0
    assert psi(categorical_sample, categorical_sample) == 0.0


@pytest.mark.parametrize(("n_distinct", "expected"), [(MAX_CATEGORIES, "categorical"), (MAX_CATEGORIES + 1, "quantile")])
def test_psi_mode_boundary(n_distinct: int, expected: str) -> None:
    values = np.arange(n_distinct)
    assert psi_mode(values, values) == expected


def test_psi_categorical_hand_computed() -> None:
    # ref 50/50, new 80/20: (0.5-0.8)ln(0.5/0.8) + (0.5-0.2)ln(0.5/0.2) = 0.141001 + 0.274887
    ref = np.array([0] * 50 + [1] * 50)
    new = np.array([0] * 80 + [1] * 20)
    assert psi(ref, new) == pytest.approx(0.415888, abs=1e-5)


def test_psi_categorical_unseen_category_is_finite_and_large() -> None:
    value = psi(np.array([0, 1] * 50), np.array([2] * 100))
    assert math.isfinite(value) and value > 1.0


def test_psi_quantile_path_matches_hand_built_bins() -> None:
    # ref = 0..999: decile edges give 10 bins of exactly 100. new = 900..999 -> all in the last bin.
    ref = np.arange(1000.0)
    new = np.arange(900.0, 1000.0)
    assert psi_mode(ref, new) == "quantile"
    q = np.array([PSI_EPS] * 9 + [1.0])
    q /= q.sum()
    p = np.full(10, 0.1)
    assert psi(ref, new) == pytest.approx(float(np.sum((p - q) * np.log(p / q))))


@pytest.mark.parametrize("outside", [-5000.0, 5000.0])
def test_psi_values_outside_reference_range_land_in_tail_bins(outside: float) -> None:
    ref = np.arange(1000.0)
    new = np.full(100, outside)  # many repeats, but still > 20 distinct values overall
    q = np.array([PSI_EPS] * 10)
    q[0 if outside < 0 else -1] = 1.0
    q /= q.sum()
    p = np.full(10, 0.1)
    assert psi(ref, new) == pytest.approx(float(np.sum((p - q) * np.log(p / q))))


def test_psi_grows_with_shift_and_ignores_nan() -> None:
    rng = np.random.default_rng(1)
    ref = rng.normal(size=2000)
    values = [psi(ref, rng.normal(shift, 1.0, 2000)) for shift in (0.0, 0.5, 1.0)]
    assert values[0] < values[1] < values[2]
    assert psi(np.append(ref, np.nan), ref) == psi(ref, ref) == 0.0


def test_psi_errors() -> None:
    with pytest.raises(ValueError):
        psi([], [1.0])
    with pytest.raises(ValueError):
        psi([1.0, 2.0], [1.0], bins=1)


# ------------------------------------------------------------------------------------- MMD
def test_mmd2_hand_computed_tiny_case() -> None:
    # X = Y = {0, 2}, gamma = 1, no standardisation: unbiased MMD^2 = exp(-4) - 1.
    x = np.array([[0.0], [2.0]])
    res = mmd2_rbf(x, x.copy(), gamma=1.0, standardise=False, n_perm=0)
    assert res.mmd2 == pytest.approx(math.exp(-4) - 1.0)
    assert math.isnan(res.p_value)


def test_mmd2_same_distribution_near_zero() -> None:
    rng = np.random.default_rng(0)
    x, y = rng.normal(size=(400, 3)), rng.normal(size=(400, 3))
    res = mmd2_rbf(x, y, n_perm=99, seed=1)
    assert abs(res.mmd2) < 0.01
    assert res.p_value > 0.05


def test_mmd2_shifted_distribution_large_and_significant() -> None:
    rng = np.random.default_rng(0)
    x, y = rng.normal(size=(400, 3)), rng.normal(loc=2.0, size=(400, 3))
    res = mmd2_rbf(x, y, n_perm=99, seed=1)
    assert res.mmd2 > 0.1
    assert res.p_value == pytest.approx(1 / 100)  # no permutation reaches the observed value


def test_mmd2_standardisation_removes_column_scale() -> None:
    rng = np.random.default_rng(2)
    x, y = rng.normal(size=(200, 2)), rng.normal(loc=1.0, size=(200, 2))
    scale = np.array([1.0, 1e6])
    plain = mmd2_rbf(x, y, n_perm=0)
    scaled = mmd2_rbf(x * scale, y * scale, n_perm=0)
    assert scaled.mmd2 == pytest.approx(plain.mmd2, rel=1e-9)


def test_mmd2_median_zero_falls_back_to_mean_of_nonzero_distances() -> None:
    # 90% zeros, 10% ones in each sample: the median pairwise distance is 0, every nonzero
    # distance is 1, so the fallback sigma is 1 and gamma = 1 / (2 * 1^2) = 0.5.
    sample = np.array([[0.0]] * 90 + [[1.0]] * 10)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        res = mmd2_rbf(sample, sample.copy(), standardise=False, n_perm=0)
    assert res.gamma == pytest.approx(0.5)


def test_mmd2_all_points_identical_returns_zero_with_warning() -> None:
    zeros = np.zeros((20, 2))
    with pytest.warns(UserWarning, match="all pairwise distances are 0"):
        res = mmd2_rbf(zeros, zeros.copy(), n_perm=10)
    assert res.mmd2 == 0.0 and res.p_value == 1.0 and "undefined" in res.note


def test_mmd2_subsampling_is_capped_and_deterministic() -> None:
    rng = np.random.default_rng(3)
    x, y = rng.normal(size=(300, 2)), rng.normal(size=(300, 2))
    a = mmd2_rbf(x, y, max_n=50, n_perm=20, seed=7)
    b = mmd2_rbf(x, y, max_n=50, n_perm=20, seed=7)
    assert (a.n_x, a.n_y) == (50, 50)
    assert a == b


def test_mmd2_drops_nan_rows_and_validates_size() -> None:
    x = np.array([[0.0, 0.0], [np.nan, 1.0], [1.0, 1.0], [2.0, 0.5]])
    assert mmd2_rbf(x, x.copy(), n_perm=0).n_x == 3
    with pytest.raises(ValueError):
        mmd2_rbf(x[:1], x, n_perm=0)


# ------------------------------------------------------------------------- eta squared
def test_eta_squared_hand_computed() -> None:
    # groups [1, 2] and [3, 4]: SS_between = 4, SS_total = 5 -> 0.8
    df = synth_frame(y=[1.0, 2.0, 3.0, 4.0], g=["a", "a", "b", "b"])
    assert eta_squared(df, "y", "g") == pytest.approx(0.8)


def test_eta_squared_pure_function_of_factor_is_one() -> None:
    df = synth_frame(g=np.repeat(["a", "b", "c"], 50))
    df["y"] = df["g"].map({"a": 1.0, "b": 5.0, "c": 9.0})
    assert eta_squared(df, "y", "g") == pytest.approx(1.0)


def test_eta_squared_pure_noise_near_zero() -> None:
    rng = np.random.default_rng(0)
    df = synth_frame(y=rng.normal(size=3000), g=rng.choice(["a", "b", "c"], 3000))
    assert eta_squared(df, "y", "g") < 0.01


def test_eta_squared_constant_feature_is_nan_and_nan_rows_dropped() -> None:
    assert math.isnan(eta_squared(synth_frame(y=[2.0, 2.0, 2.0], g=["a", "b", "b"]), "y", "g"))
    df = synth_frame(y=[1.0, 2.0, 3.0, 4.0, np.nan], g=["a", "a", "b", "b", "b"])
    assert eta_squared(df, "y", "g") == pytest.approx(0.8)


def test_single_source_guard_on_frame_functions() -> None:
    df = pd.DataFrame({"y": [1.0, 2.0], "g": ["a", "b"], "source": ["x", "y"]})
    with pytest.raises(MixedSourceError):
        eta_squared(df, "y", "g")
    with pytest.raises(MixedSourceError):
        two_way_effects(df, "y", "g", "g")
    with pytest.raises(MixedSourceError):
        drift_table(df, "g", "a", ["y"])


# ------------------------------------------------------------------------- two-way effects
def crossed_frame(effect_a: float, effect_b: float, interaction: float, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for a in (0, 1):
        for b in (0, 1):
            y = effect_a * a + effect_b * b + interaction * a * b + rng.normal(0, 1, 200)
            rows.append(pd.DataFrame({"y": y, "A": f"a{a}", "B": f"b{b}"}))
    return pd.concat(rows, ignore_index=True).assign(source=SYNTHETIC_SOURCE)


def test_two_way_main_effect_of_a_only() -> None:
    res = two_way_effects(crossed_frame(4.0, 0.0, 0.0), "y", "A", "B")
    assert res.design == "two_way" and res.effect_kind == "partial_eta2"
    assert res.effects["A"] > 0.5
    assert res.effects["B"] < 0.02 and res.effects["A:B"] < 0.02
    assert set(res.cell_sizes.values()) == {200}


def test_two_way_pure_interaction() -> None:
    # y = 4 * a * b has an interaction but (balanced) main effects that are also nonzero; the
    # interaction partial eta^2 must be the largest of the three.
    res = two_way_effects(crossed_frame(0.0, 0.0, 4.0), "y", "A", "B")
    assert res.effects["A:B"] > res.effects["A"] and res.effects["A:B"] > res.effects["B"]
    assert res.effects["A:B"] > 0.3


def test_two_way_exact_function_of_one_factor_has_no_roundoff_effects() -> None:
    # Feature is exactly 1184 / 1568 depending on A only (like a key-share size fixed by the kem).
    # SS for B and A:B are 0 up to float round-off; they must come out as exactly 0, not as
    # ratios of round-off noise.
    df = pd.DataFrame({"A": np.repeat(["a0", "a1"], 600), "B": np.tile(np.repeat(["b0", "b1", "b2"], 200), 2)})
    df["y"] = df["A"].map({"a0": 1184.0, "a1": 1568.0})
    res = two_way_effects(df.assign(source=SYNTHETIC_SOURCE), "y", "A", "B")
    assert res.design == "two_way"
    assert res.effects["B"] == 0.0 and res.effects["A:B"] == 0.0
    assert res.effects["A"] == pytest.approx(1.0)


def test_two_way_constant_feature_is_nan() -> None:
    df = crossed_frame(0.0, 0.0, 0.0).assign(y=5.0)
    assert all(math.isnan(v) for v in two_way_effects(df, "y", "A", "B").effects.values())


def test_two_way_falls_back_to_one_way_when_not_crossed() -> None:
    df = crossed_frame(4.0, 0.0, 0.0)
    df = df[~((df["A"] == "a1") & (df["B"] == "b1"))]  # remove one cell
    res = two_way_effects(df, "y", "A", "B")
    assert res.design == "one_way_only" and res.effect_kind == "eta2"
    assert "empty cells" in res.reason and "a1+b1" in res.reason
    assert set(res.effects) == {"A", "B"}


def test_two_way_falls_back_when_cells_too_small() -> None:
    df = pd.DataFrame({"y": [1.0, 2.0, 3.0, 4.0], "A": ["a0", "a0", "a1", "a1"], "B": ["b0", "b1", "b0", "b1"],
                       "source": SYNTHETIC_SOURCE})
    assert "fewer than 2" in two_way_effects(df, "y", "A", "B").reason


# --------------------------------------------------------------------------- drift_table
def test_drift_table_shape_and_content() -> None:
    df = synthetic_groups({"ref": [0.0, 0.0], "shifted": [3.0, 0.0], "same": [0.0, 0.0]}, n_per_group=300, seed=4)
    out = drift_table(df, "group", "ref", ["f0", "f1"], n_perm=19)
    assert len(out) == 4  # 2 compared groups x 2 features
    shifted = out[out["compared_group"] == "shifted"].set_index("feature")
    same = out[out["compared_group"] == "same"].set_index("feature")
    assert shifted.loc["f0", "psi"] > 10 * shifted.loc["f1", "psi"]
    assert shifted.loc["f0", "eta2"] > 0.5 > shifted.loc["f1", "eta2"]
    assert shifted["mmd2"].nunique() == 1  # multivariate MMD computed once per compared group
    assert shifted["mmd2"].iloc[0] > same["mmd2"].iloc[0]
    assert set(out["n_ref"]) == {300}
    assert out["eta2_all_groups"].notna().all()


def test_drift_table_compare_groups_and_errors() -> None:
    df = synthetic_groups({"a": [0.0], "b": [1.0], "c": [2.0]}, n_per_group=50)
    assert set(drift_table(df, "group", "a", ["f0"], compare_groups=["c"], n_perm=0)["compared_group"]) == {"c"}
    with pytest.raises(ValueError):
        drift_table(df, "group", "zzz", ["f0"])
    with pytest.raises(ValueError):
        drift_table(df, "group", "a", ["f0"], compare_groups=["zzz"])


# --------------------------------------------------------------------- PQC contrast table
KEM_EFFECT = {"X25519": 0.0, "mlkem768": 3.0, "mlkem1024": 6.0}
AUTH_EFFECT = {"rsa": 0.0, "mldsa65": 3.0, "mldsa87": 6.0, "ecdsa_p256": 1.0, "ecdsa_p384": 1.0, "rsa3072": 1.0}


@pytest.fixture(scope="module")
def contrasts() -> pd.DataFrame:
    cells = synthetic_pqc_cells(PQC_DESIGN_CELLS, KEM_EFFECT, AUTH_EFFECT, n_per_cell=40, seed=5)
    return pqc_contrast_table(cells, features=["f0", "f1"], n_perm=9, max_n=100, seed=0)


def test_contrast_table_layout(contrasts: pd.DataFrame) -> None:
    assert list(contrasts.columns)[:3] == ["eta2", "eta2_all_groups", "partial_eta2"]  # effect sizes first
    assert set(contrasts["source"]) == {SYNTHETIC_SOURCE}
    assert contrasts["contrast"].notna().all() and (contrasts["contrast"] != "").all()
    assert (contrasts["cell_sizes"] != "").all() and contrasts["cell_sizes"].notna().all()
    by_kind = contrasts.groupby("contrast_kind").size().to_dict()
    # 2 features: kem@rsa 3 pairs, auth@2 kems 3 pairs each, two-way 3 terms, pooled 9 cells
    assert by_kind == {"kem_at_fixed_auth": 6, "auth_at_fixed_kem": 12, "two_way_crossed": 6,
                       "pooled_confounded": 18}


def test_contrast_cell_sizes_are_reported(contrasts: pd.DataFrame) -> None:
    kem = contrasts[contrasts["contrast_kind"] == "kem_at_fixed_auth"]["cell_sizes"].iloc[0]
    assert kem == "X25519=40;mlkem1024=40;mlkem768=40"
    block = contrasts[contrasts["contrast_kind"] == "two_way_crossed"]["cell_sizes"].iloc[0]
    assert block.count("=40") == 6


def test_pooled_rows_never_called_kem_or_auth_effects(contrasts: pd.DataFrame) -> None:
    pooled = contrasts[contrasts["contrast_kind"] == "pooled_confounded"]
    assert pooled["contrast"].str.startswith("pooled, confounded").all()
    assert (pooled["factor"] == "kem+auth (confounded)").all()
    assert not pooled["contrast"].str.contains("kem comparison|auth comparison").any()
    assert set(pooled["ref_group"]) == {"X25519+ecdsa_p256"}
    assert len(set(pooled["compared_group"])) == 9


def test_contrast_effects_point_at_the_right_factor(contrasts: pd.DataFrame) -> None:
    kem = contrasts[contrasts["contrast_kind"] == "kem_at_fixed_auth"].groupby("feature")["eta2_all_groups"].first()
    auth = contrasts[contrasts["contrast_kind"] == "auth_at_fixed_kem"].groupby("feature")["eta2_all_groups"].mean()
    assert kem["f0"] > 0.5 > kem["f1"]  # kem shifts f0 only
    assert auth["f1"] > 0.5 > auth["f0"]  # auth shifts f1 only
    two = contrasts[contrasts["contrast_kind"] == "two_way_crossed"].set_index(["feature", "term"])["partial_eta2"]
    assert two[("f0", "kem_scenario")] > 0.5 > two[("f0", "auth_scenario")]
    assert two[("f1", "auth_scenario")] > 0.5 > two[("f1", "kem_scenario")]


def test_contrast_table_requires_normal_rows_and_all_cells() -> None:
    cells = synthetic_pqc_cells(PQC_DESIGN_CELLS, KEM_EFFECT, AUTH_EFFECT, n_per_cell=10)
    with pytest.raises(ValueError, match="design cells missing"):
        pqc_contrast_table(cells.iloc[10:], features=["f0"], n_perm=0)
    with pytest.raises(ValueError, match="Normal rows only"):
        pqc_contrast_table(cells.assign(label_raw="Anomaly"), features=["f0"], n_perm=0)


# ======================================================================================
# noise floors, invariance table, two-way table (SYNTHETIC data)
# ======================================================================================
from pqdl.drift import (  # noqa: E402
    eta2_from_codes,
    eta2_noise_floor,
    invariance_table,
    max_psi_vs_reference,
    psi_noise_floor,
    summarise_invariance,
    two_way_table,
)


def test_eta2_from_codes_matches_hand_value_and_eta_squared() -> None:
    y, codes = np.array([1.0, 2.0, 3.0, 4.0]), np.array([0, 0, 1, 1])
    assert eta2_from_codes(y, codes, 2) == pytest.approx(0.8)          # SS_between 4 / SS_total 5
    df = synth_frame(y=y, g=["a", "a", "b", "b"])
    assert eta2_from_codes(y, codes, 2) == pytest.approx(eta_squared(df, "y", "g"))
    assert math.isnan(eta2_from_codes(np.array([2.0, 2.0, 2.0]), np.array([0, 1, 1]), 2))   # constant


def test_eta2_noise_floor_is_small_for_noise_and_deterministic() -> None:
    rng = np.random.default_rng(0)
    y, codes = rng.normal(size=600), np.repeat(np.arange(6), 100)
    floor = eta2_noise_floor(y, codes, 6, n_perm=200, seed=1)
    assert 0.0 < floor < 0.02                 # chance level for 6 groups of 100 is about (6-1)/600 = 0.008
    assert floor == eta2_noise_floor(y, codes, 6, n_perm=200, seed=1)
    structured = y + codes * 1.0              # strong group effect
    assert eta2_from_codes(structured, codes, 6) > 10 * floor


def test_max_psi_vs_reference_picks_the_most_shifted_group() -> None:
    rng = np.random.default_rng(2)
    values = np.concatenate([rng.normal(0, 1, 300), rng.normal(0, 1, 300), rng.normal(2, 1, 300)])
    codes = np.repeat([0, 1, 2], 300)
    expected = psi(values[codes == 0], values[codes == 2])
    assert max_psi_vs_reference(values, codes, ref=0, k=3) == pytest.approx(expected)
    assert expected > psi(values[codes == 0], values[codes == 1])


def test_psi_noise_floor_positive_and_below_a_real_shift() -> None:
    rng = np.random.default_rng(3)
    values = rng.normal(size=1200)
    codes = np.repeat(np.arange(4), 300)
    floor = psi_noise_floor(values, codes, ref=0, k=4, n_perm=100, seed=1)
    assert 0.0 < floor < 0.25
    shifted = values + (codes == 3) * 1.5
    assert max_psi_vs_reference(shifted, codes, 0, 4) > floor


def test_invariance_table_flags_only_the_shifted_feature() -> None:
    # 5 profiles x 200 flows. f0 is shifted in profile g4 (+1.5); f1 is the same for everyone.
    df = synthetic_groups({"g0": [0.0, 0.0], "g1": [0.0, 0.0], "g2": [0.0, 0.0], "g3": [0.0, 0.0], "g4": [1.5, 0.0]},
                          n_per_group=200, seed=7, group_col="profile")
    table = invariance_table(df, "profile", "g0", ["f0", "f1"], n_noise=100, seed=1)
    assert len(table) == 8                      # 4 compared profiles x 2 features
    summary = summarise_invariance(table).set_index("feature")
    assert bool(summary.loc["f0", "not_invariant"]) and bool(summary.loc["f0", "eta2_above_noise"])
    assert summary.loc["f0", "eta2_all_groups"] > 5 * summary.loc["f1", "eta2_all_groups"]
    assert not bool(summary.loc["f1", "not_invariant"])
    assert summary.loc["f0", "max_mmd2"] > 0.05


def test_two_way_table_deterministic_flag_and_effects() -> None:
    cells = [(k, a) for k in ("X25519", "mlkem768", "mlkem1024") for a in ("ecdsa", "mldsa44", "mldsa65", "mldsa87")]
    df = synthetic_pqc_cells(cells, {"X25519": 0.0, "mlkem768": 3.0, "mlkem1024": 6.0},
                             {"ecdsa": 0.0, "mldsa44": 1.0, "mldsa65": 2.0, "mldsa87": 3.0}, n_per_cell=30, seed=4)
    # det = exact function of both factors (additive): deterministic, so every partial eta^2 is trivially 0 or 1
    kem_code = df["kem_scenario"].map({"X25519": 0, "mlkem768": 1, "mlkem1024": 2})
    auth_code = df["auth_scenario"].map({"ecdsa": 0, "mldsa44": 1, "mldsa65": 2, "mldsa87": 3})
    df["det"] = 1000.0 * kem_code + 10.0 * auth_code
    out = two_way_table(df, ["f0", "f1", "det"], "kem_scenario", "auth_scenario")
    eff = out.set_index(["feature", "term"])["partial_eta2"]
    det = out[out["feature"] == "det"]
    assert det["deterministic"].all() and not out[out["feature"] == "f0"]["deterministic"].any()
    assert eff[("det", "kem_scenario")] == 1.0 and eff[("det", "auth_scenario")] == 1.0
    assert eff[("det", "kem_scenario:auth_scenario")] == 0.0       # additive: no interaction
    assert eff[("f0", "kem_scenario")] > 0.5 > eff[("f0", "auth_scenario")]   # kem shifts f0 only
    assert eff[("f1", "auth_scenario")] > 0.5 > eff[("f1", "kem_scenario")]   # auth shifts f1 only
