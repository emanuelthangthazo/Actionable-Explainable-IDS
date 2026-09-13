"""Explainability package for model interpretation and SHAP analysis."""

from .explain import (
    get_tree_explainer,
    explain_prediction,
    predict_and_explain,
)

__all__ = [
    "get_tree_explainer",
    "explain_prediction",
    "predict_and_explain",
]
