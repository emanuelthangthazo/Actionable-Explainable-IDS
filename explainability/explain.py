"""SHAP Explainability module for XIDS predictions.

Per sections 9 & 10 of WORKFLOW.md:
- Builds a shap.TreeExplainer on the best trained model (XGBoost / Random Forest)
- Computes per-prediction SHAP feature attributions for a single network flow
- Handles multi-class output by extracting attributions for the PREDICTED class
- Identifies top contributing features sorted by absolute impact with feature values and direction (TOWARD / AWAY)
- Combines prediction with SHAP explanations into predict_and_explain()
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import shap
from sklearn.preprocessing import LabelEncoder

from models.predict import load_prediction_artifacts, predict_flow

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Global cache for TreeExplainer instance to avoid re-initializing on every call
_EXPLAINER_CACHE: Dict[str, Any] = {}


def get_tree_explainer(
    model: Any,
    use_cache: bool = True,
) -> shap.TreeExplainer:
    """Initialize or retrieve a cached shap.TreeExplainer for the given tree-based model.

    Args:
        model: Trained tree-based model (RandomForestClassifier or XGBClassifier).
        use_cache: Whether to reuse a cached explainer.

    Returns:
        shap.TreeExplainer: Initialized SHAP tree explainer.
    """
    global _EXPLAINER_CACHE

    model_id = id(model)
    if use_cache and model_id in _EXPLAINER_CACHE:
        return _EXPLAINER_CACHE[model_id]

    logger.info(f"Initializing shap.TreeExplainer for model: {type(model).__name__}...")
    try:
        explainer = shap.TreeExplainer(model)
    except Exception as e:
        logger.error(f"Failed to create TreeExplainer: {e}")
        raise ValueError(f"Model {type(model).__name__} is not supported by TreeExplainer: {e}")

    if use_cache:
        _EXPLAINER_CACHE[model_id] = explainer

    return explainer


def extract_shap_values_for_class(
    explainer: shap.TreeExplainer,
    df_input: pd.DataFrame,
    predicted_idx: int,
) -> np.ndarray:
    """Extract a 1D numpy array of SHAP values corresponding specifically to the PREDICTED class.

    Args:
        explainer: Initialized TreeExplainer.
        df_input: Preprocessed 1-row DataFrame matching training feature order.
        predicted_idx: Index of predicted class.

    Returns:
        np.ndarray: 1D array of SHAP values for each feature.
    """
    # Try Explanation object API first (SHAP modern interface)
    try:
        explanation = explainer(df_input)
        values = explanation.values
        if values.ndim == 3:
            # Shape: (1, n_features, n_classes) -> extract predicted_idx slice
            return values[0, :, predicted_idx]
        elif values.ndim == 2:
            # Shape: (1, n_features) for binary
            return values[0, :]
    except Exception as e:
        logger.debug(f"Explanation API fallback due to: {e}")

    # Legacy fallback: explainer.shap_values()
    raw_sv = explainer.shap_values(df_input)
    if isinstance(raw_sv, list):
        # List of arrays, one array per class
        return raw_sv[predicted_idx][0]
    elif isinstance(raw_sv, np.ndarray):
        if raw_sv.ndim == 3:
            return raw_sv[0, :, predicted_idx]
        elif raw_sv.ndim == 2:
            return raw_sv[0, :]

    raise ValueError("Unable to extract 1D SHAP values array for predicted class.")


def explain_prediction(
    flow_data: Union[Dict[str, Any], pd.DataFrame],
    predicted_class: str,
    model: Any,
    label_encoder: LabelEncoder,
    feature_columns: List[str],
    top_k: int = 5,
    explainer: Optional[shap.TreeExplainer] = None,
) -> List[Dict[str, Any]]:
    """Compute SHAP feature attributions for a single flow prediction and extract top contributors.

    Args:
        flow_data: Input flow (dict or 1-row DataFrame).
        predicted_class: Predicted class label string.
        model: Trained model instance.
        label_encoder: Fitted LabelEncoder.
        feature_columns: Ordered list of feature names.
        top_k: Number of top features to return (default: 5).
        explainer: Optional pre-initialized TreeExplainer.

    Returns:
        List[Dict[str, Any]]: Sorted list of top feature attribution dictionaries.
    """
    # 1. Format input DataFrame matching feature_columns
    if isinstance(flow_data, dict):
        df = pd.DataFrame([flow_data])
    else:
        df = flow_data.copy()

    df.columns = df.columns.str.strip()
    df_input = df[feature_columns].copy()
    for col in feature_columns:
        df_input[col] = pd.to_numeric(df_input[col], errors="coerce")

    # 2. Map predicted class name back to integer index
    try:
        predicted_idx = int(label_encoder.transform([predicted_class])[0])
    except Exception:
        # Fallback if predicted_class string isn't in encoder classes directly
        classes_list = list(label_encoder.classes_)
        predicted_idx = classes_list.index(predicted_class) if predicted_class in classes_list else 0

    # 3. Get Explainer & extract SHAP values array for the predicted class
    if explainer is None:
        explainer = get_tree_explainer(model)

    shap_array = extract_shap_values_for_class(explainer, df_input, predicted_idx)

    # 4. Construct feature attribution records
    features_info = []
    for i, feature_name in enumerate(feature_columns):
        s_val = float(shap_array[i])
        f_val = float(df_input.iloc[0, i])
        direction = "TOWARD" if s_val >= 0 else "AWAY"

        features_info.append({
            "feature": feature_name,
            "shap_value": round(s_val, 4),
            "feature_value": round(f_val, 4),
            "direction": direction,
            "abs_impact": abs(s_val),
        })

    # 5. Sort by absolute SHAP impact descending and take top_k
    features_info.sort(key=lambda x: x["abs_impact"], reverse=True)

    top_features = []
    for item in features_info[:top_k]:
        top_features.append({
            "feature": item["feature"],
            "shap_value": item["shap_value"],
            "feature_value": item["feature_value"],
            "direction": item["direction"],
        })

    return top_features


def predict_and_explain(
    flow_data: Union[Dict[str, Any], pd.DataFrame],
    models_dir: Union[str, Path] = "models",
    top_k: int = 5,
    model: Optional[Any] = None,
    label_encoder: Optional[LabelEncoder] = None,
    feature_columns: Optional[List[str]] = None,
    explainer: Optional[shap.TreeExplainer] = None,
) -> Dict[str, Any]:
    """Combined prediction and SHAP explainability pipeline for a single network flow.

    Args:
        flow_data: Single network flow as a dict or 1-row DataFrame.
        models_dir: Directory containing best_model.pkl, label_encoder.pkl, feature_columns.json.
        top_k: Number of top SHAP features to return (default: 5).
        model: Pre-loaded model (optional).
        label_encoder: Pre-loaded LabelEncoder (optional).
        feature_columns: Pre-loaded feature columns list (optional).
        explainer: Pre-loaded TreeExplainer (optional).

    Returns:
        Dict[str, Any]: {
            "predicted_class": str,
            "confidence": float,
            "top_features": List[Dict[str, Any]]
        }
    """
    models_dir = Path(models_dir)

    # 1. Load artifacts if missing
    if model is None or label_encoder is None or feature_columns is None:
        loaded_model, loaded_encoder, loaded_features = load_prediction_artifacts(
            model_path=models_dir / "best_model.pkl",
            encoder_path=models_dir / "label_encoder.pkl",
            features_path=models_dir / "feature_columns.json",
        )
        model = model or loaded_model
        label_encoder = label_encoder or loaded_encoder
        feature_columns = feature_columns or loaded_features

    # 2. Obtain prediction result
    pred_result = predict_flow(
        flow_data=flow_data,
        model=model,
        label_encoder=label_encoder,
        feature_columns=feature_columns,
    )

    # 3. Generate SHAP explanation for the predicted class
    top_features = explain_prediction(
        flow_data=flow_data,
        predicted_class=pred_result["predicted_class"],
        model=model,
        label_encoder=label_encoder,
        feature_columns=feature_columns,
        top_k=top_k,
        explainer=explainer,
    )

    return {
        "predicted_class": pred_result["predicted_class"],
        "confidence": pred_result["confidence"],
        "top_features": top_features,
    }


if __name__ == "__main__":
    # Test script using sample flows from CIC-IDS2017 dataset
    project_root = Path(__file__).resolve().parent.parent
    data_file = project_root / "data" / "CICIDS2017_Combined.csv"
    models_dir = project_root / "models"

    print("Loading test samples from CIC-IDS2017 dataset...")
    df_raw = pd.read_csv(data_file, nrows=1000)
    df_raw.columns = df_raw.columns.str.strip()

    # Find sample flows of different attack classes
    sample_indices = [0]
    for target in ["DDoS", "DoS Hulk", "PortScan", "BENIGN"]:
        matches = df_raw[df_raw["Label"].str.strip() == target].index
        if len(matches) > 0 and matches[0] not in sample_indices:
            sample_indices.append(matches[0])

    print(f"Testing predict_and_explain on {len(sample_indices[:3])} sample flows...\n")

    for idx in sample_indices[:3]:
        true_label = df_raw.iloc[idx]["Label"].strip()
        flow_dict = df_raw.iloc[idx].drop("Label").to_dict()

        result = predict_and_explain(flow_dict, models_dir=models_dir, top_k=5)

        print("=" * 80)
        print(f"Sample Index: {idx} | Ground Truth Label: '{true_label}'")
        print(f"Predicted Class: '{result['predicted_class']}' (Confidence: {result['confidence']:.4f})")
        print("Top 5 Contributing SHAP Features:")
        for feat in result["top_features"]:
            print(
                f"  - {feat['feature']:<30} | Value: {feat['feature_value']:<10} | "
                f"SHAP: {feat['shap_value']:>+8.4f} | Direction: {feat['direction']}"
            )
        print("=" * 80 + "\n")
