"""Model evaluation and reporting module for XIDS.

Per section 6 of WORKFLOW.md:
- Evaluates trained models (Random Forest and XGBoost)
- Computes Accuracy, Precision, Recall, F1-Score, Confusion Matrix, and ROC-AUC
- Generates structured JSON and Markdown evaluation reports highlighting Recall for IDS priority
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from models.train import prepare_features_and_split
from preprocessing.preprocessing import preprocess_pipeline

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def compute_metrics(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    model_name: str,
    target_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Compute full suite of classification evaluation metrics for a model.

    Args:
        model: Trained classifier model.
        X_test: Test features.
        y_test: Test target vector.
        model_name: Descriptive name of the model.
        target_names: Optional string names of target classes.

    Returns:
        Dict[str, Any]: Structured evaluation metrics.
    """
    logger.info(f"Computing evaluation metrics for model: '{model_name}'...")
    y_pred = model.predict(X_test)

    y_proba = None
    if hasattr(model, "predict_proba"):
        try:
            y_proba = model.predict_proba(X_test)
        except Exception as e:
            logger.warning(f"Could not calculate probabilities for {model_name}: {e}")

    # Standard classification metrics
    accuracy = float(accuracy_score(y_test, y_pred))

    precision_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    recall_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    precision_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    recall_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

    cm = confusion_matrix(y_test, y_pred)

    # ROC-AUC computation
    roc_auc = None
    if y_proba is not None:
        try:
            classes_present = np.unique(y_test)
            if len(classes_present) == 2:
                # Binary classification
                roc_auc = float(roc_auc_score(y_test, y_proba[:, 1]))
            elif len(classes_present) > 2:
                # Multi-class OvR
                roc_auc = float(roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted"))
        except Exception as e:
            logger.warning(f"ROC-AUC calculation skipped for {model_name}: {e}")

    report_dict = classification_report(
        y_test,
        y_pred,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )
    report_text = classification_report(
        y_test,
        y_pred,
        target_names=target_names,
        zero_division=0,
    )

    metrics = {
        "model_name": model_name,
        "sample_count": len(y_test),
        "accuracy": accuracy,
        "precision_weighted": precision_weighted,
        "recall_weighted": recall_weighted,
        "f1_weighted": f1_weighted,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "f1_macro": f1_macro,
        "roc_auc": roc_auc,
        "confusion_matrix": cm.tolist(),
        "classification_report_dict": report_dict,
        "classification_report_text": report_text,
    }

    return metrics


def generate_markdown_report(
    evaluations: Dict[str, Dict[str, Any]],
    target_names: Optional[List[str]] = None,
) -> str:
    """Generate a clean Markdown summary report comparing models.

    Args:
        evaluations: Dictionary mapping model names to evaluation metric dicts.
        target_names: Class labels list.

    Returns:
        str: Formatted Markdown text.
    """
    md = []
    md.append("# XIDS Model Evaluation Report")
    md.append("")
    md.append("Per **WORKFLOW.md Section 6**, models are evaluated across Accuracy, Precision, Recall, F1-Score, Confusion Matrix, and ROC-AUC.")
    md.append("> **Note for IDS Workflows:** Recall is prioritized to minimize costly false negatives (missed intrusion attacks).")
    md.append("")

    md.append("## Model Comparison Summary")
    md.append("")
    md.append("| Model | Accuracy | Recall (Weighted) | Precision (Weighted) | F1-Score (Weighted) | ROC-AUC |")
    md.append("|---|---|---|---|---|---|")

    for name, metrics in evaluations.items():
        roc_str = f"{metrics['roc_auc']:.4f}" if metrics["roc_auc"] is not None else "N/A"
        md.append(
            f"| **{name}** | {metrics['accuracy']:.4f} | **{metrics['recall_weighted']:.4f}** | "
            f"{metrics['precision_weighted']:.4f} | {metrics['f1_weighted']:.4f} | {roc_str} |"
        )

    md.append("")
    md.append("## Detailed Performance Breakdowns")
    md.append("")

    for name, metrics in evaluations.items():
        md.append(f"### {name}")
        md.append("")
        md.append("```text")
        md.append(metrics["classification_report_text"])
        md.append("```")
        md.append("")
        md.append("**Confusion Matrix:**")
        md.append("```json")
        md.append(json.dumps(metrics["confusion_matrix"]))
        md.append("```")
        md.append("")

    return "\n".join(md)


def evaluate_and_report(
    data_path: Union[str, Path] = "data",
    models_dir: Union[str, Path] = "models/saved_models",
    output_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Load saved models, evaluate on test set, and write evaluation reports to disk.

    Args:
        data_path: Dataset path or directory.
        models_dir: Directory containing saved model artifacts.
        output_dir: Output directory for report files.

    Returns:
        Dict[str, Dict[str, Any]]: Dictionary of model evaluations.
    """
    models_dir = Path(models_dir)
    output_dir = Path(output_dir) if output_dir else models_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load data & prep train/test split
    logger.info("Loading preprocessed dataset for evaluation...")
    df_encoded, encoder = preprocess_pipeline(data_path=data_path, save_processed=False)
    _, X_test, _, y_test = prepare_features_and_split(df_encoded, target_column="Label", test_size=0.20)

    class_names = [str(c) for c in encoder.classes_] if encoder else None

    # 2. Discover saved models
    logger.info(f"Searching for saved models in {models_dir}...")
    model_files = list(models_dir.glob("*.joblib"))
    if not model_files:
        raise FileNotFoundError(f"No saved .joblib models found in {models_dir}")

    evaluations = {}
    for model_path in model_files:
        if model_path.stem in ["label_encoder", "best_model"]:
            continue  # Skip utility files during comparative evaluation

        model_name = model_path.stem.replace("_", " ").title()
        logger.info(f"Loading model '{model_name}' from {model_path}...")
        model = joblib.load(model_path)
        evaluations[model_name] = compute_metrics(model, X_test, y_test, model_name=model_name, target_names=class_names)

    # 3. Save JSON Report
    json_path = output_dir / "evaluation_report.json"
    logger.info(f"Writing evaluation JSON report to {json_path}...")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(evaluations, f, indent=2)

    # 4. Save Markdown Report
    md_content = generate_markdown_report(evaluations, target_names=class_names)
    md_path = output_dir / "evaluation_report.md"
    logger.info(f"Writing evaluation Markdown report to {md_path}...")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    logger.info("Model evaluation and reporting completed successfully.")
    return evaluations


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data"
    saved_models_dir = project_root / "models" / "saved_models"

    if (data_dir / "CICIDS2017_Combined.csv").exists():
        target_data = data_dir / "CICIDS2017_Combined.csv"
    else:
        target_data = data_dir

    evaluate_and_report(
        data_path=target_data,
        models_dir=saved_models_dir,
        output_dir=saved_models_dir,
    )
