# Drift notes: read this before using `results/pqc_drift.csv`

Produced by `scripts/pqc_drift.py` (fixed seed 0) from the real CIC-PQC_OAV **normal** rows only, using
`pqdl.drift.pqc_contrast_table` and the 8 features in `pqdl.features.PQC_DRIFT_FEATURES`.
This file lists caveats only; it contains no results. Every number is in the CSV (`source = cic_pqc_oav`).

## What the data can and cannot show

1. **Synthetic testbed.** CIC-PQC_OAV was generated between local containers. Large effects on size
   features mostly show that bigger keys and signatures make bigger records, which the size model
   already says. Treat the size results as validation of the drift code and of the size model, not as a
   finding about real networks. (They have not yet been compared against `handshake.py` predictions.)
2. **Only 8 features** (4 size, 2 timing, 2 entropy). The 21 constant and 3 kem one-hot features are
   excluded on purpose. The dataset has **no application-phase features**, so it says nothing about
   whether drift continues after the handshake. That question needs the lab captures.
3. **Kem and auth are confounded outside the contrasts.** The kem x auth design is not crossed (8 of 18
   cells are empty). Only these comparisons are valid:
   - kem effect: at fixed `auth = rsa` (X25519 vs mlkem768 vs mlkem1024);
   - auth effect: at fixed kem (`mlkem768` and `mlkem1024` separately; rsa vs mldsa65 vs mldsa87);
   - two-way (kem x auth, interaction): only on the crossed 2 x 3 block {mlkem768, mlkem1024} x {mldsa65, mldsa87, rsa}.
4. **"pooled, confounded" rows** (`contrast_kind = pooled_confounded`, reference X25519+ecdsa_p256) change
   kem and auth together. They must never be reported as a kem effect or an auth effect.
5. The auth name `rsa` is taken from the scenario id as-is. It is assumed to be the same certificate under
   every kem; this has not been verified. `rsa3072`, `ecdsa_p384` and `mldsa87` have no entry in `SIZES`.

## Reading the columns

- **Effect sizes come first**: `eta2` (reference vs that one group), `eta2_all_groups` (all groups in the
  contrast), `partial_eta2` (two-way rows), `psi`, `mmd2`. `mmd2_p_value` is secondary.
- **p-values:** permutation p-values use `n_perm = 200`, so the smallest possible value is 1/201. With
  3,500 rows per cell nearly everything is "significant"; use effect sizes. No multiple-comparison
  correction is applied.
- **`mmd2`** is multivariate (all 8 standardised features at once, computed once per compared group and
  repeated on that group's feature rows). Each side is subsampled to `max_n = 2000` rows with seed 0. It
  is the unbiased estimator, so it can be slightly negative. Because several size features are exact
  functions of the cell, they dominate it; it is not a per-feature measure.
- **`psi`** has two paths, recorded in `psi_mode`: one bin per distinct value when the two samples
  together have at most 20 distinct values, otherwise 10 bins from the reference quantiles. The two
  paths are not comparable with each other, and the path can differ between contrasts for the same
  feature. Proportions are floored at 1e-4, so completely disjoint distributions saturate at about 18.4.
- **`eta2` / `partial_eta2` saturate at 1.0** when a feature is an exact (or nearly exact) function of
  the factor, so 1.0 means "determined by the factor", not "same size as another 1.0". Use the cell means
  to compare magnitudes.
- **NaN effects** mean the feature is exactly constant inside that comparison (for example the client key
  share within a single kem), so the effect is undefined. In the two-way fit, a sum of squares below 1e-12
  of the total is treated as exactly 0 so round-off is not reported as an effect.
- **`cell_sizes`** on every row gives the rows in each cell of that contrast; `n_ref` / `n_group` give the
  two cells being compared.

## Not investigated

- Where PSI and eta-squared disagree (for example a timing feature with a large PSI but a near-zero
  eta-squared between two kems) the distribution shape changed without a mean shift. No explanation was
  looked for.
- No dedicated test of the `e5_entropy_c` and `e6_time_char` dependence on auth beyond the effect sizes.
