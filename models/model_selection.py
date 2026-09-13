"""Model selection module for XIDS.

Per WORKFLOW.md Section 7:
- Evaluates saved model metrics using Recall and F1-Score as primary criteria
  (avoiding Accuracy due to class imbalance)
- Outputs selection justification
- Persists winning model to models/best_model.pkl
- Persists fitted label encoder to models/label_encoder.pkl
- Persists training feature columns list to models/feature_columns.json
- Reuses already-trained models without retraining
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def select_and_persist_best_model(
    report_path: Path | str = "models/saved_models/evaluation_report.json",
    saved_models_dir: Path | str = "models/saved_models",
    output_dir: Path | str = "models",
) -> Tuple[str, Any, Path]:
    """Select best model using Recall and F1-score metrics and persist required artifacts.

    Args:
        report_path: Path to evaluation_report.json.
        saved_models_dir: Directory containing trained .joblib model files.
        output_dir: Output directory for best_model.pkl, label_encoder.pkl, feature_columns.json.

    Returns:
        Tuple[str, Any, Path]: (best_model_name, best_model_instance, best_model_path)
    """
    report_path = Path(report_path)
    saved_models_dir = Path(saved_models_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not report_path.exists():
        raise FileNotFoundError(f"Evaluation report not found at {report_path}")

    logger.info(f"Loading evaluation report from {report_path}...")
    with open(report_path, "r", encoding="utf-8") as f:
        metrics_report: Dict[str, Dict[str, Any]] = json.load(f)

    if not metrics_report:
        raise ValueError("Evaluation report is empty.")

    best_name = None
    best_score = -1.0
    winning_metrics = None

    # Calculate selection score prioritizing Recall (60%) and F1-Score (40%)
    for model_name, metrics in metrics_report.items():
        recall_w = metrics.get("recall_weighted", 0.0)
        f1_w = metrics.get("f1_weighted", 0.0)
        recall_m = metrics.get("recall_macro", 0.0)
        f1_m = metrics.get("f1_macro", 0.0)

        # Composite score weighting Recall higher than F1, combining weighted & macro
        score = 0.40 * recall_w + 0.30 * f1_w + 0.20 * recall_m + 0.10 * f1_m

        logger.info(
            f"Evaluating '{model_name}': Recall(W)={recall_w:.4f}, F1(W)={f1_w:.4f}, "
            f"Recall(M)={recall_m:.4f}, F1(M)={f1_m:.4f} -> Selection Score = {score:.4f}"
        )

        if score > best_score:
            best_score = score
            best_name = model_name
            winning_metrics = metrics

    # Generate short justification text
    justification = (
        f"Selected '{best_name}' as the winning model with a composite selection score of {best_score:.4f}.\n"
        f"Justification: In class-imbalanced Intrusion Detection Systems (IDS), Recall is prioritized over Accuracy\n"
        f"to minimize missed attacks (false negatives). '{best_name}' achieved a Weighted Recall of "
        f"{winning_metrics.get('recall_weighted', 0):.4f}, Macro Recall of {winning_metrics.get('recall_macro', 0):.4f}, "
        f"and Weighted F1-Score of {winning_metrics.get('f1_weighted', 0):.4f}."
    )
    print("\n" + "=" * 80)
    print("MODEL SELECTION RESULT & JUSTIFICATION")
    print("=" * 80)
    print(justification)
    print("=" * 80 + "\n")

    # Locate saved model artifact matching winning model
    file_slug = best_name.lower().replace(" ", "_")
    model_filename = f"{file_slug}.joblib"
    model_file_path = saved_models_dir / model_filename

    if not model_file_path.exists():
        # Fall back to best_model.joblib if specific model file doesn't exist
        model_file_path = saved_models_dir / "best_model.joblib"

    if not model_file_path.exists():
        raise FileNotFoundError(f"Model file not found for '{best_name}' at {model_file_path}")

    logger.info(f"Loading winning model instance from {model_file_path}...")
    best_model = joblib.load(model_file_path)

    # 1. Persist best_model.pkl in output_dir
    best_model_pkl_path = output_dir / "best_model.pkl"
    logger.info(f"Saving winning model to {best_model_pkl_path}...")
    joblib.dump(best_model, best_model_pkl_path)

    # 2. Persist label_encoder.pkl
    label_encoder = None
    encoder_src_path = saved_models_dir / "label_encoder.joblib"
    encoder_dst_path = output_dir / "label_encoder.pkl"

    if encoder_src_path.exists():
        logger.info(f"Loading label encoder from {encoder_src_path}...")
        label_encoder = joblib.load(encoder_src_path)
        logger.info(f"Saving label encoder to {encoder_dst_path}...")
        joblib.dump(label_encoder, encoder_dst_path)

    # 3. Extract and persist feature_columns.json
    feature_columns: List[str] = []
    if hasattr(best_model, "feature_names_in_"):
        feature_columns = list(best_model.feature_names_in_)
    elif hasattr(best_model, "get_booster"):
        try:
            feature_columns = list(best_model.get_booster().feature_names)
        except Exception:
            pass

    if not feature_columns:
        logger.warning("Could not extract feature_names_in_ directly from model object.")

    feature_cols_path = output_dir / "feature_columns.json"
    logger.info(f"Saving {len(feature_columns)} feature column names to {feature_cols_path}...")
    with open(feature_cols_path, "w", encoding="utf-8") as f:
        json.dump(feature_columns, f, indent=2)

    logger.info("Model selection and artifact persistence complete.")
    return best_name, best_model, best_model_pkl_path


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    select_and_persist_best_model(
        report_path=project_root / "models" / "saved_models" / "evaluation_report.json",
        saved_models_dir=project_root / "models" / "saved_models",
        output_dir=project_root / "models",
    )
