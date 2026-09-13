"""check_leakage.py

Data leakage audit for the XIDS train/test split.

Checks how many rows in the held-out 20% test set are near-duplicates of rows
in the 80% training set, broken down by label class.

Two detection methods
---------------------
1. ROUNDED-EXACT  : Round every feature to 3 decimal places, hash each row.
                    A test row is flagged if its rounded hash exists in the
                    training set. Catches precision-rounding duplicates.
                    (True exact duplicates were already removed by preprocessing
                    BEFORE splitting, so this catches rows that only differ
                    below 3 decimal places.)

2. COSINE-PROXY   : L2-normalise each row, then round to 3 decimal places,
                    then hash. Two rows that match in this space have cosine
                    similarity >= ~0.998. This catches near-parallel feature
                    vectors regardless of scale differences.

Results are reported per label (BENIGN vs each attack class) and as a
combined BENIGN vs attacks summary.

Usage (from project root)
--------------------------
    .\\venv\\Scripts\\python.exe check_leakage.py
"""

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# -- stdout UTF-8 for safe printing on Windows cp1252 consoles ---------------
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# -- Constants (must match training pipeline exactly) -------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_PATH    = PROJECT_ROOT / "data" / "CICIDS2017_Combined.csv"
LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"
TEST_SIZE    = 0.20
RANDOM_STATE = 42
ROUND_DP     = 3          # decimal places for rounding

DIVIDER  = "=" * 80
DIVIDER2 = "-" * 80


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def elapsed(t0: float) -> str:
    s = int(time.time() - t0)
    return f"{s // 60}m {s % 60}s"


def hash_frame(df: pd.DataFrame) -> pd.Series:
    """Vectorised per-row hash using pandas built-in (returns uint64 Series)."""
    return pd.util.hash_pandas_object(df, index=False)


def round_df(df: pd.DataFrame, decimals: int) -> pd.DataFrame:
    """Round all columns to *decimals* decimal places."""
    return df.round(decimals)


def normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    """Row-wise L2 normalisation. Zero-norm rows are left as zero vectors."""
    arr   = df.values.astype(np.float64)
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0          # avoid division by zero
    return pd.DataFrame(arr / norms, columns=df.columns, index=df.index)


def check_leakage(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test_labels: pd.Series,
    method_name: str,
    round_fn,
) -> pd.DataFrame:
    """
    Generic near-duplicate detector.

    Transforms both train and test feature matrices with *round_fn*, hashes
    each row, then checks which test-row hashes exist in the training hash set.

    Args:
        X_train, X_test : Numeric feature DataFrames (clean, aligned columns).
        y_test_labels   : String class labels for each test row.
        method_name     : Short name for progress messages.
        round_fn        : Callable(pd.DataFrame) -> pd.DataFrame applied before
                          hashing (defines what "similarity" means).

    Returns:
        pd.DataFrame with columns: label | total | leakage_count | leakage_pct
    """
    print(f"\n  [{method_name}] Transforming and hashing training rows ...", flush=True)
    t0 = time.time()

    train_hash_series = hash_frame(round_fn(X_train))
    train_hash_set    = set(train_hash_series.values.tolist())
    print(f"    Done in {elapsed(t0)}  ({len(train_hash_set):,} unique signatures "
          f"from {len(X_train):,} rows)")

    print(f"  [{method_name}] Hashing test rows and checking membership ...", flush=True)
    test_hash_series = hash_frame(round_fn(X_test))
    is_leak = test_hash_series.map(lambda h: h in train_hash_set)
    is_leak.index = y_test_labels.index    # ensure index alignment

    print(f"    Done in {elapsed(t0)}")

    # -- Per-label breakdown -------------------------------------------------
    rows      = []
    all_labels = sorted(y_test_labels.unique())

    # BENIGN first, then attack classes alphabetically
    ordered = [BENIGN_LABEL] + [lb for lb in all_labels if lb != BENIGN_LABEL]
    for label in ordered:
        mask  = y_test_labels == label
        total = int(mask.sum())
        if total == 0:
            continue
        leaks = int(is_leak[mask].sum())
        rows.append({
            "label":         label,
            "total":         total,
            "leakage_count": leaks,
            "leakage_pct":   round(100.0 * leaks / total, 4),
        })

    # Overall summary row
    total_all = len(y_test_labels)
    leaks_all = int(is_leak.sum())
    rows.append({
        "label":         "ALL",
        "total":         total_all,
        "leakage_count": leaks_all,
        "leakage_pct":   round(100.0 * leaks_all / total_all, 4),
    })

    return pd.DataFrame(rows)


def print_report(title: str, df: pd.DataFrame) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)
    print(f"  {'Label':<35}  {'Test rows':>10}  {'Leaks':>8}  {'Leak %':>8}")
    print(f"  {DIVIDER2}")
    for _, row in df.iterrows():
        if row["label"] == BENIGN_LABEL:
            marker = "  <-- BENIGN"
        elif row["label"] == "ALL":
            marker = "  <-- TOTAL"
        else:
            marker = ""
        print(
            f"  {str(row['label']):<35}  "
            f"{int(row['total']):>10,}  "
            f"{int(row['leakage_count']):>8,}  "
            f"{row['leakage_pct']:>7.4f}%"
            f"{marker}"
        )
    print(DIVIDER)


def print_benign_vs_attacks(df_exact: pd.DataFrame, df_cosine: pd.DataFrame) -> None:
    print(f"\n{DIVIDER}")
    print("  SUMMARY: BENIGN vs ATTACK CLASSES")
    print(DIVIDER)

    for method_label, df_res in [
        ("Rounded-Exact  (3dp hash match)         ", df_exact),
        ("Cosine-Proxy   (L2-norm + 3dp hash match)", df_cosine),
    ]:
        benign_row  = df_res[df_res["label"] == BENIGN_LABEL]
        attack_rows = df_res[
            (df_res["label"] != BENIGN_LABEL) & (df_res["label"] != "ALL")
        ]
        total_row   = df_res[df_res["label"] == "ALL"]

        b_pct = float(benign_row["leakage_pct"].iloc[0])   if len(benign_row) else 0.0
        b_cnt = int(benign_row["leakage_count"].iloc[0])   if len(benign_row) else 0
        b_tot = int(benign_row["total"].iloc[0])           if len(benign_row) else 0

        a_cnt = int(attack_rows["leakage_count"].sum())
        a_tot = int(attack_rows["total"].sum())
        a_pct = 100.0 * a_cnt / a_tot if a_tot > 0 else 0.0

        t_pct = float(total_row["leakage_pct"].iloc[0])    if len(total_row) else 0.0
        t_cnt = int(total_row["leakage_count"].iloc[0])    if len(total_row) else 0
        t_tot = int(total_row["total"].iloc[0])            if len(total_row) else 0

        print(f"\n  [{method_label}]")
        print(f"    BENIGN   : {b_cnt:>8,} / {b_tot:>8,}  leak rate = {b_pct:.4f}%")
        print(f"    ATTACKS  : {a_cnt:>8,} / {a_tot:>8,}  leak rate = {a_pct:.4f}%")
        print(f"    OVERALL  : {t_cnt:>8,} / {t_tot:>8,}  leak rate = {t_pct:.4f}%")

    print(f"\n{DIVIDER}")
    print("  Interpretation guide")
    print(DIVIDER2)
    print("  Rounded-Exact  0.000%  => Expected: preprocessing already removed exact dupes")
    print("  Rounded-Exact  > 0%    => Near-identical rows exist below the 3dp threshold")
    print("  Cosine-Proxy   0.000%  => No flows share the same directional fingerprint")
    print("  Cosine-Proxy   > 0%    => Some flows are near-parallel (scale-invariant match)")
    print("  High BENIGN rate       => Benign traffic is highly repetitive/stereotyped")
    print("  High ATTACK rate       => Attack traffic pattern is stereotyped in the dataset")
    print(DIVIDER)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(DIVIDER)
    print("  XIDS DATA LEAKAGE AUDIT")
    print(f"  Source     : {DATA_PATH.name}")
    print(f"  Split      : {int((1 - TEST_SIZE) * 100)}% train / {int(TEST_SIZE * 100)}% test  "
          f"(random_state={RANDOM_STATE})")
    print(f"  Rounding   : {ROUND_DP} decimal places")
    print(DIVIDER)

    # -----------------------------------------------------------------------
    # Step 1: Load raw CSV
    # -----------------------------------------------------------------------
    print(f"\n[1/5] Reading {DATA_PATH.name} ...", flush=True)
    t_total = time.time()

    # Detect actual (possibly space-padded) Label column name in CSV header
    header_df     = pd.read_csv(DATA_PATH, nrows=0, low_memory=False)
    raw_label_col = next(
        (c for c in header_df.columns if c.strip() == LABEL_COLUMN), None
    )
    if raw_label_col is None:
        raise ValueError(
            f"Column '{LABEL_COLUMN}' not found in CSV. "
            f"Available (stripped): {[c.strip() for c in header_df.columns]}"
        )

    df = pd.read_csv(DATA_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    df[LABEL_COLUMN] = df[LABEL_COLUMN].astype(str).str.strip()
    print(f"  Loaded {len(df):,} rows x {df.shape[1]} columns in {elapsed(t_total)}")

    # -----------------------------------------------------------------------
    # Step 2: Clean (mirror train.py / preprocessing.py pipeline exactly)
    # -----------------------------------------------------------------------
    print(f"\n[2/5] Cleaning (inf -> NaN -> drop -> dedup) ...", flush=True)
    t_clean = time.time()

    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)

    n_before   = len(df)
    df         = df.dropna().reset_index(drop=True)
    n_after_na = len(df)
    df         = df.drop_duplicates().reset_index(drop=True)
    n_final    = len(df)

    print(f"  Rows removed (NaN/Inf)   : {n_before - n_after_na:,}")
    print(f"  Rows removed (exact dup) : {n_after_na - n_final:,}")
    print(f"  Clean rows               : {n_final:,}  ({elapsed(t_clean)})")

    # -----------------------------------------------------------------------
    # Step 3: Stratified 80/20 split (identical params to train.py)
    # -----------------------------------------------------------------------
    print(f"\n[3/5] Reconstructing stratified {int((1-TEST_SIZE)*100)}/{int(TEST_SIZE*100)} "
          f"split ...", flush=True)

    le  = LabelEncoder()
    y   = le.fit_transform(df[LABEL_COLUMN])
    idx = np.arange(len(df))

    idx_train, idx_test = train_test_split(
        idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    feature_cols = [c for c in df.columns if c != LABEL_COLUMN]

    X_train    = df.iloc[idx_train][feature_cols].reset_index(drop=True)
    X_test     = df.iloc[idx_test][feature_cols].reset_index(drop=True)
    y_test_lbl = df.iloc[idx_test][LABEL_COLUMN].reset_index(drop=True)

    print(f"  Train : {len(X_train):,} rows | Test : {len(X_test):,} rows")
    print(f"\n  Test class distribution:")
    counts = y_test_lbl.value_counts()
    # BENIGN first
    for cls in ([BENIGN_LABEL] + sorted(c for c in counts.index if c != BENIGN_LABEL)):
        if cls not in counts:
            continue
        cnt = counts[cls]
        pct = 100.0 * cnt / len(y_test_lbl)
        print(f"    {str(cls):<35}  {cnt:>8,}  ({pct:.3f}%)")

    # -----------------------------------------------------------------------
    # Step 4: Method 1 — Rounded-exact
    # -----------------------------------------------------------------------
    print(f"\n[4/5] Method 1: Rounded-exact leakage check ...", flush=True)

    df_exact = check_leakage(
        X_train, X_test, y_test_lbl,
        method_name="Rounded-Exact",
        round_fn=lambda df_in: round_df(df_in, ROUND_DP),
    )

    # -----------------------------------------------------------------------
    # Step 5: Method 2 — Cosine-proxy
    # -----------------------------------------------------------------------
    print(f"\n[5/5] Method 2: Cosine-proxy leakage check ...", flush=True)

    df_cosine = check_leakage(
        X_train, X_test, y_test_lbl,
        method_name="Cosine-Proxy",
        round_fn=lambda df_in: round_df(normalize_df(df_in), ROUND_DP),
    )

    # -----------------------------------------------------------------------
    # Reports
    # -----------------------------------------------------------------------
    print_report(
        "METHOD 1: Rounded-Exact  "
        "(all features rounded to 3dp, row hash matched against training set)",
        df_exact,
    )
    print_report(
        "METHOD 2: Cosine-Proxy   "
        "(L2-normalised + rounded to 3dp, row hash matched; catches cosine sim >= ~0.998)",
        df_cosine,
    )
    print_benign_vs_attacks(df_exact, df_cosine)

    print(f"\n  Total wall-clock time: {elapsed(t_total)}")


if __name__ == "__main__":
    if not DATA_PATH.exists():
        print(f"[FATAL] Data file not found: {DATA_PATH}")
        sys.exit(1)
    main()
