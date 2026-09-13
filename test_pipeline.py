"""End-to-end integration test for the XIDS predict_and_explain() pipeline.

Tests the full pipeline (predict.py + explain.py) against the held-out 20% test set,
without re-running training or modifying any source modules.

Usage (from the project root):
    .\\venv\\Scripts\\python.exe test_pipeline.py

Requirements:
    - models/best_model.pkl          (run model_selection.py first)
    - models/label_encoder.pkl
    - models/feature_columns.json
    - data/CICIDS2017_Combined.csv   (raw dataset)
"""

import json
import logging
import random
import sys
import traceback
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# -- Force UTF-8 output so non-ASCII class names (e.g. Web Attack → XSS) print
# cleanly on Windows consoles that default to cp1252.
import io
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# -- Project root on sys.path so relative imports work -----------------------
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# -- Suppress noisy INFO logs from preprocessing / models during the test ----
logging.basicConfig(level=logging.WARNING,
                    format="%(levelname)s - %(name)s - %(message)s")

from explainability.explain import predict_and_explain  # noqa: E402
from models.predict import load_prediction_artifacts    # noqa: E402

# -- Constants -- must match training settings exactly -----------------------
DATA_PATH    = PROJECT_ROOT / "data" / "CICIDS2017_Combined.csv"
MODELS_DIR   = PROJECT_ROOT / "models"
LABEL_COLUMN = "Label"
TEST_SIZE    = 0.20
RANDOM_STATE = 42
SAMPLE_SEED  = 7          # separate seed so sample selection is reproducible
BENIGN_LABEL = "BENIGN"
N_BENIGN     = 2
N_ATTACK     = 3
TOP_K_SHAP   = 5

DIVIDER  = "=" * 80
DIVIDER2 = "-" * 80


# ---------------------------------------------------------------------------
# Section 1 -- Helpers
# ---------------------------------------------------------------------------

def load_test_set_raw() -> pd.DataFrame:
    """
    Reconstruct the held-out 20% test set from the raw CSV without running
    the full preprocessing pipeline (which takes several minutes on 2.8M rows).

    Strategy:
        1. Read the full CSV but keep only the Label column to determine the
           stratified split indices (very cheap -- no numeric parsing).
        2. Perform the identical stratified train_test_split (same test_size,
           random_state, stratify) used in train.py.
        3. Re-read the full CSV for the test-set rows only.

    Returns:
        pd.DataFrame: Raw (un-encoded) test-set rows, column names stripped.
    """
    print(f"\n[1/4] Loading test-set label index from {DATA_PATH.name} ...")

    # Step A: Read header row only to find the actual (possibly space-padded)
    # column name for 'Label'. usecols= validates against the raw header, so
    # we must use the original name (before stripping).
    header_df = pd.read_csv(DATA_PATH, nrows=0, low_memory=False)
    raw_label_col = next(
        (c for c in header_df.columns if c.strip() == LABEL_COLUMN), None
    )
    if raw_label_col is None:
        raise ValueError(
            f"Column '{LABEL_COLUMN}' not found in CSV header. "
            f"Available columns (stripped): {[c.strip() for c in header_df.columns]}"
        )

    # Step B: Read only the Label column (fast — one narrow scan of the file)
    label_df = pd.read_csv(DATA_PATH, usecols=[raw_label_col], low_memory=False)
    label_df.columns = label_df.columns.str.strip()
    label_df[LABEL_COLUMN] = label_df[LABEL_COLUMN].astype(str).str.strip()

    valid_mask = label_df[LABEL_COLUMN].notna() & (label_df[LABEL_COLUMN] != "nan")
    label_s = label_df.loc[valid_mask, LABEL_COLUMN].reset_index(drop=True)

    tmp_enc = LabelEncoder()
    label_enc = tmp_enc.fit_transform(label_s)
    idx_all = np.arange(len(label_s))

    _, idx_test = train_test_split(
        idx_all,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=label_enc,
    )

    print(f"    Test split: {len(idx_test):,} rows  "
          f"({100*len(idx_test)/len(idx_all):.1f}% of {len(idx_all):,} cleaned rows)")

    # Step C: Map split indices back to original CSV data-row positions
    # (valid_positions[i] = 0-indexed data row in the full CSV for clean row i)
    valid_positions = np.where(valid_mask.values)[0]
    original_rows   = valid_positions[idx_test]

    # Step D: Re-read the full CSV keeping ONLY test-set rows.
    # Use a callable skiprows to avoid building a 2.3M-element list.
    # File line 0 = header (never skip); file line k = data row k-1.
    # We keep a row if (k-1) is in the test set.
    test_line_nums = set(int(r) + 1 for r in original_rows)  # file line numbers
    print(f"    Reading full feature data for {len(test_line_nums):,} test rows ...")

    df_test = pd.read_csv(
        DATA_PATH,
        skiprows=lambda x: x != 0 and x not in test_line_nums,
        low_memory=False,
    )
    df_test.columns = df_test.columns.str.strip()
    df_test[LABEL_COLUMN] = df_test[LABEL_COLUMN].astype(str).str.strip()

    print(f"    Test DataFrame shape: {df_test.shape}")
    return df_test


def sample_flows(df_test: pd.DataFrame,
                 feature_columns: List[str]) -> List[Dict]:
    """
    Sample N_BENIGN benign flows + N_ATTACK flows from distinct attack classes,
    then shuffle. Returns list of dicts: {flow_dict, true_label, sample_index}.
    """
    rng = random.Random(SAMPLE_SEED)

    available_cols = [c for c in feature_columns if c in df_test.columns]
    df_clean = df_test.dropna(subset=available_cols + [LABEL_COLUMN]).copy()
    inf_mask = np.isinf(df_clean[available_cols].select_dtypes(include=[np.number]).values).any(axis=1)
    df_clean = df_clean[~inf_mask]

    # Benign samples
    benign_rows = df_clean[df_clean[LABEL_COLUMN] == BENIGN_LABEL]
    if len(benign_rows) < N_BENIGN:
        raise RuntimeError(
            f"Not enough BENIGN rows in test set (found {len(benign_rows)}, need {N_BENIGN})."
        )
    benign_sample = benign_rows.sample(n=N_BENIGN, random_state=SAMPLE_SEED)

    # Attack samples -- one per distinct attack class
    attack_rows = df_clean[df_clean[LABEL_COLUMN] != BENIGN_LABEL]
    attack_classes = [c for c in attack_rows[LABEL_COLUMN].unique()
                      if c.strip() and c != BENIGN_LABEL]
    rng.shuffle(attack_classes)

    attack_sample_list = []
    for atk_class in attack_classes:
        if len(attack_sample_list) >= N_ATTACK:
            break
        class_rows = attack_rows[attack_rows[LABEL_COLUMN] == atk_class]
        if len(class_rows) > 0:
            attack_sample_list.append(class_rows.sample(n=1, random_state=SAMPLE_SEED))

    if len(attack_sample_list) < N_ATTACK:
        raise RuntimeError(
            f"Could not find {N_ATTACK} distinct attack classes. "
            f"Found only {len(attack_sample_list)}."
        )

    attack_sample = pd.concat(attack_sample_list, ignore_index=True)
    combined = pd.concat([benign_sample, attack_sample], ignore_index=True)
    combined = combined.sample(frac=1, random_state=SAMPLE_SEED).reset_index(drop=True)

    samples = []
    for i, row in combined.iterrows():
        true_label = row[LABEL_COLUMN]
        flow_dict  = row.drop(labels=[LABEL_COLUMN]).to_dict()
        samples.append({"flow_dict": flow_dict, "true_label": true_label, "sample_index": int(i)})

    return samples


def print_sample_header(n: int, true_label: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  SAMPLE #{n}  |  True Label: '{true_label}'")
    print(DIVIDER)


def print_shap_features(top_features: List[Dict]) -> None:
    print(f"\n  Top {len(top_features)} SHAP Features:")
    print(f"  {'Feature':<32}  {'Value':>12}  {'SHAP':>10}  Direction")
    print(f"  {DIVIDER2}")
    for feat in top_features:
        print(
            f"  {feat['feature']:<32}  "
            f"{feat['feature_value']:>12.4f}  "
            f"{feat['shap_value']:>+10.4f}  "
            f"{feat['direction']}"
        )


def print_summary_table(results: List[Dict]) -> None:
    print(f"\n{DIVIDER}")
    print("  END-TO-END TEST SUMMARY")
    print(DIVIDER)
    header = f"  {'#':<4}  {'True Label':<28}  {'Predicted':<28}  {'Conf':>6}  Match"
    print(header)
    print(f"  {DIVIDER2}")

    all_pass = True
    for r in results:
        match  = r["true_label"] == r["predicted_class"]
        symbol = "Y" if match else "N"
        if not match:
            all_pass = False
        print(
            f"  {r['n']:<4}  "
            f"{r['true_label']:<28}  "
            f"{r['predicted_class']:<28}  "
            f"{r['confidence']:>6.4f}  "
            f"{symbol}"
        )

    n_pass  = sum(1 for r in results if r["true_label"] == r["predicted_class"])
    n_total = len(results)
    print(DIVIDER2)
    print(f"  Result: {n_pass}/{n_total} correct  "
          f"({'ALL PASS' if all_pass else str(n_total - n_pass) + ' MISMATCH(ES)'})")
    print(DIVIDER)


# ---------------------------------------------------------------------------
# Section 2 -- Main test runner
# ---------------------------------------------------------------------------

def run_pipeline_tests() -> None:
    print(DIVIDER)
    print("  XIDS PIPELINE INTEGRATION TEST")
    print(f"  Models dir : {MODELS_DIR}")
    print(f"  Data file  : {DATA_PATH.name}")
    print(DIVIDER)

    # Load artifacts once (cached for all samples)
    print("\n[2/4] Loading model artifacts ...")
    model, label_encoder, feature_columns = load_prediction_artifacts(
        model_path=MODELS_DIR / "best_model.pkl",
        encoder_path=MODELS_DIR / "label_encoder.pkl",
        features_path=MODELS_DIR / "feature_columns.json",
        use_cache=True,
    )
    print(f"    Model    : {type(model).__name__}")
    # Sanitize class names for safe console printing (label encoder may
    # contain non-ASCII chars like the arrow in 'Web Attack → XSS')
    safe_classes = [c.encode('utf-8', 'replace').decode('utf-8') for c in label_encoder.classes_]
    print(f"    Classes  : {safe_classes}")
    print(f"    Features : {len(feature_columns)}")

    # Reconstruct test set
    df_test = load_test_set_raw()

    # Sample flows with required class mix
    print("\n[3/4] Sampling flows ...")
    samples = sample_flows(df_test, feature_columns)

    classes_in_sample = [s["true_label"] for s in samples]
    benign_count      = sum(1 for c in classes_in_sample if c == BENIGN_LABEL)
    attack_count      = len(samples) - benign_count
    distinct_attacks  = len(set(c for c in classes_in_sample if c != BENIGN_LABEL))
    print(f"    {len(samples)} flows: {benign_count} BENIGN, {attack_count} attack "
          f"({distinct_attacks} distinct attack classes)")
    print(f"    Labels: {classes_in_sample}")

    # Run predict_and_explain for each sample
    print("\n[4/4] Running predict_and_explain() for each sampled flow ...")
    summary_rows: List[Dict] = []

    for n, sample in enumerate(samples, start=1):
        true_label = sample["true_label"]
        flow_dict  = sample["flow_dict"]

        print_sample_header(n, true_label)

        # Full traceback on failure -- do NOT catch silently
        result = predict_and_explain(
            flow_data=flow_dict,
            models_dir=MODELS_DIR,
            top_k=TOP_K_SHAP,
            model=model,
            label_encoder=label_encoder,
            feature_columns=feature_columns,
        )

        predicted_class = result["predicted_class"]
        confidence      = result["confidence"]
        top_features    = result["top_features"]

        match = (predicted_class == true_label)
        print(f"\n  Predicted Class : {predicted_class}")
        print(f"  Confidence      : {confidence:.4f}")
        print(f"  Match           : {'YES' if match else 'NO  <-- MISMATCH'}")

        print_shap_features(top_features)

        summary_rows.append({
            "n":               n,
            "true_label":      true_label,
            "predicted_class": predicted_class,
            "confidence":      confidence,
            "match":           match,
        })

    print_summary_table(summary_rows)


# ---------------------------------------------------------------------------
# Section 3 -- Edge case: missing column must raise ValueError, not silently fail
# ---------------------------------------------------------------------------

def run_edge_case_missing_column() -> None:
    """
    Take a real flow, drop one feature column, and confirm predict_and_explain()
    raises a clear ValueError instead of silently producing a wrong prediction.

    Per the requirement: DO NOT catch and hide the error -- full traceback
    surfaces for any unexpected exception type.
    """
    print(f"\n{DIVIDER}")
    print("  EDGE CASE: Missing Column Must Raise ValueError")
    print(DIVIDER)

    print("\n  Loading one real flow for edge-case test ...")
    df_sample = pd.read_csv(DATA_PATH, nrows=20, low_memory=False)
    df_sample.columns = df_sample.columns.str.strip()

    model, label_encoder, feature_columns = load_prediction_artifacts(
        model_path=MODELS_DIR / "best_model.pkl",
        encoder_path=MODELS_DIR / "label_encoder.pkl",
        features_path=MODELS_DIR / "feature_columns.json",
        use_cache=True,
    )

    row       = df_sample.iloc[0]
    flow_dict = row.drop(labels=[LABEL_COLUMN]).to_dict()

    dropped_col = feature_columns[0]
    del flow_dict[dropped_col]
    print(f"  Dropped feature column: '{dropped_col}'")
    print(f"  Expecting  : ValueError from predict_and_explain()\n")

    raised_correctly = False
    caught_exc       = None

    try:
        predict_and_explain(
            flow_data=flow_dict,
            models_dir=MODELS_DIR,
            top_k=TOP_K_SHAP,
            model=model,
            label_encoder=label_encoder,
            feature_columns=feature_columns,
        )
    except ValueError as exc:
        raised_correctly = True
        caught_exc       = exc
    except Exception:
        # Unexpected type -- show full traceback, nothing hidden
        print("  UNEXPECTED exception type. Full traceback:")
        traceback.print_exc()

    if raised_correctly:
        print(f"  PASS -- ValueError raised correctly:")
        print(f"    --> {caught_exc}")
        print("\n  Pipeline correctly rejected an incomplete flow.")
    else:
        print(
            f"\n  FAIL: predict_and_explain() did NOT raise ValueError when "
            f"'{dropped_col}' was missing. "
            f"Pipeline may silently produce wrong predictions!"
        )

    print(DIVIDER)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Validate required artifacts before doing anything
    missing = []
    for artifact in [
        MODELS_DIR / "best_model.pkl",
        MODELS_DIR / "label_encoder.pkl",
        MODELS_DIR / "feature_columns.json",
        DATA_PATH,
    ]:
        if not artifact.exists():
            missing.append(str(artifact))

    if missing:
        print("\n[FATAL] Required artifacts not found:")
        for m in missing:
            print(f"        {m}")
        print("        Run model_selection.py (or the full training pipeline) first.")
        sys.exit(1)

    run_pipeline_tests()
    run_edge_case_missing_column()
