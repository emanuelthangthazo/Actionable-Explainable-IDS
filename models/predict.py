"""Inference prediction module for XIDS.

Per section 8 of WORKFLOW.md:
- Loads best_model.pkl, label_encoder.pkl, and feature_columns.json
- Accepts a single network flow (as a dictionary or one-row DataFrame)
- Validates and reorders columns to match feature_columns.json exactly
- Returns predicted attack class string and prediction confidence score as a dictionary
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Global artifact cache for fast re-use across calls
_ARTIFACT_CACHE: Dict[str, Any] = {}


def load_prediction_artifacts(
    model_path: Union[str, Path] = "models/best_model.pkl",
    encoder_path: Union[str, Path] = "models/label_encoder.pkl",
    features_path: Union[str, Path] = "models/feature_columns.json",
    use_cache: bool = True,
) -> Tuple[Any, LabelEncoder, List[str]]:
    """Load model, label encoder, and feature columns artifacts from disk.

    Args:
        model_path: Path to best_model.pkl (or best_model.joblib).
        encoder_path: Path to label_encoder.pkl (or label_encoder.joblib).
        features_path: Path to feature_columns.json.
        use_cache: Whether to use cached artifacts if already loaded.

    Returns:
        Tuple[Any, LabelEncoder, List[str]]: (model, label_encoder, feature_columns)
    """
    global _ARTIFACT_CACHE

    if use_cache and _ARTIFACT_CACHE:
        return (
            _ARTIFACT_CACHE["model"],
            _ARTIFACT_CACHE["label_encoder"],
            _ARTIFACT_CACHE["feature_columns"],
        )

    model_path = Path(model_path)
    encoder_path = Path(encoder_path)
    features_path = Path(features_path)

    # Fallback checks if paths in models/ saved_models/ are passed
    if not model_path.exists() and (model_path.parent / "saved_models" / "best_model.joblib").exists():
        model_path = model_path.parent / "saved_models" / "best_model.joblib"

    if not encoder_path.exists() and (encoder_path.parent / "saved_models" / "label_encoder.joblib").exists():
        encoder_path = encoder_path.parent / "saved_models" / "label_encoder.joblib"

    if not model_path.exists():
        raise FileNotFoundError(f"Model artifact not found at {model_path}")
    if not encoder_path.exists():
        raise FileNotFoundError(f"Label encoder artifact not found at {encoder_path}")
    if not features_path.exists():
        raise FileNotFoundError(f"Feature columns artifact not found at {features_path}")

    logger.info(f"Loading model from {model_path}...")
    model = joblib.load(model_path)

    logger.info(f"Loading label encoder from {encoder_path}...")
    label_encoder = joblib.load(encoder_path)

    logger.info(f"Loading feature column order from {features_path}...")
    with open(features_path, "r", encoding="utf-8") as f:
        feature_columns: List[str] = json.load(f)

    if use_cache:
        _ARTIFACT_CACHE["model"] = model
        _ARTIFACT_CACHE["label_encoder"] = label_encoder
        _ARTIFACT_CACHE["feature_columns"] = feature_columns

    return model, label_encoder, feature_columns


def predict_flow(
    flow_data: Union[Dict[str, Any], pd.DataFrame],
    model: Optional[Any] = None,
    label_encoder: Optional[LabelEncoder] = None,
    feature_columns: Optional[List[str]] = None,
    models_dir: Union[str, Path] = "models",
) -> Dict[str, Any]:
    """Predict attack class and confidence for a single network flow.

    Args:
        flow_data: Single flow as a dictionary or 1-row DataFrame.
        model: Pre-loaded model instance (loaded automatically if None).
        label_encoder: Pre-loaded LabelEncoder instance (loaded automatically if None).
        feature_columns: Pre-loaded feature columns list (loaded automatically if None).
        models_dir: Base directory containing model artifacts if auto-loading.

    Returns:
        Dict[str, Any]: {"predicted_class": str, "confidence": float}
    """
    models_dir = Path(models_dir)

    # 1. Auto-load artifacts if not provided
    if model is None or label_encoder is None or feature_columns is None:
        loaded_model, loaded_encoder, loaded_features = load_prediction_artifacts(
            model_path=models_dir / "best_model.pkl",
            encoder_path=models_dir / "label_encoder.pkl",
            features_path=models_dir / "feature_columns.json",
        )
        model = model or loaded_model
        label_encoder = label_encoder or loaded_encoder
        feature_columns = feature_columns or loaded_features

    # 2. Input validation and conversion to DataFrame
    if isinstance(flow_data, dict):
        df = pd.DataFrame([flow_data])
    elif isinstance(flow_data, pd.DataFrame):
        df = flow_data.copy()
        if len(df) == 0:
            raise ValueError("Input DataFrame is empty.")
    else:
        raise TypeError(f"flow_data must be a dict or pd.DataFrame, got {type(flow_data)}")

    # Clean leading/trailing spaces from input column names
    df.columns = df.columns.str.strip()

    # 3. Validate feature presence
    missing_cols = [col for col in feature_columns if col not in df.columns]
    if missing_cols:
        raise ValueError(
            f"Input flow data is missing {len(missing_cols)} required feature column(s): {missing_cols[:5]}..."
            if len(missing_cols) > 5 else f"Input flow data is missing required feature column(s): {missing_cols}"
        )

    # 4. Reorder columns to match training feature order exactly
    df_ordered = df[feature_columns].copy()

    # Convert features to numeric (coerce errors if string representations exist)
    for col in feature_columns:
        df_ordered[col] = pd.to_numeric(df_ordered[col], errors="coerce")

    # 5. Predict probabilities
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(df_ordered)[0]
        predicted_idx = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_idx])
    else:
        # Fallback if model doesn't support predict_proba
        predicted_idx = int(model.predict(df_ordered)[0])
        confidence = 1.0

    # 6. Decode integer class index back to string label
    predicted_class_str = str(label_encoder.inverse_transform([predicted_idx])[0])

    result = {
        "predicted_class": predicted_class_str,
        "confidence": round(confidence, 4),
    }

    return result


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    models_path = project_root / "models"

    print("Checking prediction pipeline initialization...")
    try:
        model, encoder, features = load_prediction_artifacts(
            model_path=models_path / "best_model.pkl",
            encoder_path=models_path / "label_encoder.pkl",
            features_path=models_path / "feature_columns.json",
        )
        print(f"Artifacts loaded successfully! Model: {type(model).__name__}, Classes: {len(encoder.classes_)}, Features: {len(features)}")
    except Exception as e:
        print(f"Artifact loading error (run model_selection.py first): {e}")
