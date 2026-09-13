"""Model training and evaluation module for XIDS.

Per sections 3, 4, 5, 6, 7 of WORKFLOW.md:
- Feature Preparation: Separate feature matrix X and target y
- 80/20 Train/Test Split: Stratified split on target y
- Model Training: Train RandomForestClassifier and XGBClassifier
- Model Evaluation: Compute Accuracy, Precision, Recall, F1-Score, Confusion Matrix, and ROC-AUC
- Model Selection & Saving: Select the best model (prioritizing Recall/F1) and save model artifacts
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from preprocessing.preprocessing import preprocess_pipeline

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def prepare_features_and_split(
    df: pd.DataFrame,
    target_column: str = "Label",
    test_size: float = 0.20,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Separate features (X) and target (y) and perform an 80/20 stratified split.

    Args:
        df: Preprocessed DataFrame.
        target_column: Name of target column (default: 'Label').
        test_size: Proportion of test split (default: 0.20).
        random_state: Random state seed.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]: X_train, X_test, y_train, y_test
    """
    if target_column not in df.columns:
        raise KeyError(f"Target column '{target_column}' not found in DataFrame.")

    X = df.drop(columns=[target_column])
    y = df[target_column]

    logger.info(f"Feature matrix shape: {X.shape}, Target vector shape: {y.shape}")

    # Verify class distribution for stratification
    unique_classes, counts = np.unique(y, return_counts=True)
    logger.info(f"Class distribution before split: {dict(zip(unique_classes, counts))}")

    # Perform stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y if len(unique_classes) > 1 else None,
    )

    logger.info(
        f"Train/Test split complete (test_size={test_size}). "
        f"X_train: {X_train.shape}, X_test: {X_test.shape}"
    )

    return X_train, X_test, y_train, y_test


def evaluate_model(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    model_name: str = "Model",
) -> Dict[str, Any]:
    """Evaluate trained classifier with standard evaluation metrics per section 6 of WORKFLOW.md.

    Args:
        model: Trained classifier model.
        X_test: Test feature matrix.
        y_test: Test true labels.
        model_name: Name of the model for logging.

    Returns:
        Dict[str, Any]: Evaluation metrics dictionary.
    """
    logger.info(f"Evaluating {model_name}...")
    y_pred = model.predict(X_test)

    # Probabilities for ROC-AUC
    y_proba = None
    if hasattr(model, "predict_proba"):
        try:
            y_proba = model.predict_proba(X_test)
        except Exception as e:
            logger.warning(f"Could not compute predict_proba for {model_name}: {e}")

    # Metrics calculation
    accuracy = accuracy_score(y_test, y_pred)
    precision_w = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall_w = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1_w = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    precision_m = precision_score(y_test, y_pred, average="macro", zero_division=0)
    recall_m = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1_m = f1_score(y_test, y_pred, average="macro", zero_division=0)

    cm = confusion_matrix(y_test, y_pred)

    roc_auc = None
    if y_proba is not None:
        try:
            num_classes = len(np.unique(y_test))
            if num_classes == 2:
                roc_auc = roc_auc_score(y_test, y_proba[:, 1])
            elif num_classes > 2:
                roc_auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted")
        except Exception as e:
            logger.warning(f"ROC-AUC calculation skipped due to error: {e}")

    metrics = {
        "model_name": model_name,
        "accuracy": float(accuracy),
        "precision_weighted": float(precision_w),
        "recall_weighted": float(recall_w),
        "f1_weighted": float(f1_w),
        "precision_macro": float(precision_m),
        "recall_macro": float(recall_m),
        "f1_macro": float(f1_m),
        "roc_auc": float(roc_auc) if roc_auc is not None else None,
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(y_test, y_pred, zero_division=0),
    }

    logger.info(f"--- {model_name} Performance ---")
    logger.info(f"Accuracy:        {accuracy:.4f}")
    logger.info(f"Recall (W):      {recall_w:.4f}  (IDS priority)")
    logger.info(f"Precision (W):   {precision_w:.4f}")
    logger.info(f"F1-Score (W):    {f1_w:.4f}")
    if roc_auc is not None:
        logger.info(f"ROC-AUC:         {roc_auc:.4f}")

    return metrics


def train_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train RandomForest and XGBoost classifiers in parallel.

    Args:
        X_train: Training features.
        y_train: Training labels.
        random_state: Random state seed.

    Returns:
        Dict[str, Any]: Dictionary of trained models.
    """
    models = {}

    # 1. Random Forest Classifier
    logger.info("Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=random_state,
        n_jobs=-1,
    )
    rf_model.fit(X_train, y_train)
    models["Random Forest"] = rf_model
    logger.info("Random Forest training complete.")

    # 2. XGBoost Classifier
    logger.info("Training XGBoost Classifier...")
    num_classes = len(np.unique(y_train))
    objective = "binary:logistic" if num_classes <= 2 else "multi:softprob"

    xgb_model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective=objective,
        random_state=random_state,
        n_jobs=-1,
        eval_metric="logloss" if num_classes <= 2 else "mlogloss",
    )
    xgb_model.fit(X_train, y_train)
    models["XGBoost"] = xgb_model
    logger.info("XGBoost training complete.")

    return models


def select_and_save_best_model(
    models: Dict[str, Any],
    evaluations: Dict[str, Dict[str, Any]],
    output_dir: Union[str, Path] = "models/saved_models",
    label_encoder: Any = None,
) -> Tuple[str, Any, Path]:
    """Select the best model based on Recall and F1-score and save model artifacts to disk.

    Args:
        models: Dictionary of trained model objects.
        evaluations: Dictionary of model metrics.
        output_dir: Directory where models should be saved.
        label_encoder: Optional fitted LabelEncoder to save alongside model artifacts.

    Returns:
        Tuple[str, Any, Path]: Best model name, best model instance, path to saved best model.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Compare models prioritizing Recall and F1
    best_name = None
    best_score = -1.0
    best_model = None

    for name, metrics in evaluations.items():
        # Score combining weighted recall (60% weight) and weighted F1 (40% weight) for IDS priority
        score = 0.6 * metrics["recall_weighted"] + 0.4 * metrics["f1_weighted"]
        logger.info(f"Model Selection Score for {name}: {score:.4f}")

        # Save individual model
        model_filename = name.lower().replace(" ", "_") + ".joblib"
        joblib.dump(models[name], output_dir / model_filename)

        if score > best_score:
            best_score = score
            best_name = name
            best_model = models[name]

    logger.info(f"Best model selected: '{best_name}' (Score: {best_score:.4f})")

    # Save best model separately as best_model.joblib
    best_model_path = output_dir / "best_model.joblib"
    joblib.dump(best_model, best_model_path)
    logger.info(f"Saved best model to {best_model_path}")

    # Save label encoder if provided
    if label_encoder is not None:
        encoder_path = output_dir / "label_encoder.joblib"
        joblib.dump(label_encoder, encoder_path)
        logger.info(f"Saved label encoder to {encoder_path}")

    return best_name, best_model, best_model_path


def run_training_pipeline(
    data_path: Union[str, Path] = "data",
    output_dir: Union[str, Path] = "models/saved_models",
) -> Tuple[Dict[str, Any], Dict[str, Any], str, Any]:
    """Execute full model training, evaluation, and selection pipeline.

    Args:
        data_path: Path to dataset or directory.
        output_dir: Directory to save trained model artifacts.

    Returns:
        Tuple[Dict[str, Any], Dict[str, Any], str, Any]: Models, Evaluation results, Best model name, Best model instance.
    """
    logger.info("--- STAGE 2: Preprocessing Pipeline ---")
    df_encoded, encoder = preprocess_pipeline(data_path=data_path, save_processed=False)

    logger.info("--- STAGE 3 & 4: Feature Preparation & 80/20 Stratified Split ---")
    X_train, X_test, y_train, y_test = prepare_features_and_split(df_encoded, target_column="Label")

    logger.info("--- STAGE 5: Training Random Forest & XGBoost Models ---")
    models = train_models(X_train, y_train)

    logger.info("--- STAGE 6: Model Evaluation ---")
    evaluations = {}
    for name, model in models.items():
        evaluations[name] = evaluate_model(model, X_test, y_test, model_name=name)

    logger.info("--- STAGE 7: Best Model Selection & Artifact Preservation ---")
    best_name, best_model, _ = select_and_save_best_model(
        models=models,
        evaluations=evaluations,
        output_dir=output_dir,
        label_encoder=encoder,
    )

    return models, evaluations, best_name, best_model


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data"

    if (data_dir / "CICIDS2017_Combined.csv").exists():
        target_data = data_dir / "CICIDS2017_Combined.csv"
    else:
        target_data = data_dir

    models, evals, best_name, best_model = run_training_pipeline(
        data_path=target_data,
        output_dir=project_root / "models" / "saved_models",
    )
    logger.info(f"Training pipeline complete. Winner: {best_name}")
