"""Actionable Alert Builder combining ML predictions, SHAP attributions, RAG context, and LLM synthesis."""

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from explainability.explain import predict_and_explain
from llm.config import (
    BACKOFF_FACTOR,
    DEFAULT_MODEL,
    FALLBACK_EXPLANATION,
    FALLBACK_RECOMMENDATION,
    MAX_RETRIES,
)
from llm.ollama_client import OllamaClient, OllamaError
from llm.prompts import format_explanation_prompt, format_recommendation_prompt
from rag.retriever import KnowledgeRetriever, RetrievalResult, retrieve

logger = logging.getLogger(__name__)


def _call_with_retries(
    client: OllamaClient,
    prompt: str,
    system: str,
    expected_key: str,
    fallback_text: str,
    max_retries: int = MAX_RETRIES,
    backoff_factor: float = BACKOFF_FACTOR,
) -> Tuple[str, str]:
    """Call Ollama with retry and exponential backoff, falling back gracefully on failure."""
    last_error: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            res = client.generate(prompt=prompt, system=system, format_json=True)
            if isinstance(res, dict) and expected_key in res and isinstance(res[expected_key], str) and res[expected_key].strip():
                return res[expected_key].strip(), "success"
            elif isinstance(res, dict) and len(res) > 0:
                # Handle alternative key names if model deviated slightly
                first_val = next(iter(res.values()))
                if isinstance(first_val, str) and first_val.strip():
                    return first_val.strip(), "success"
            
            raise ValueError(f"Expected key '{expected_key}' missing or empty in JSON: {res}")

        except Exception as err:
            last_error = err
            if attempt < max_retries:
                sleep_time = backoff_factor * (2 ** attempt)
                logger.warning(
                    "LLM generation attempt %d failed (%s). Retrying in %.1fs...",
                    attempt + 1,
                    err,
                    sleep_time,
                )
                time.sleep(sleep_time)
            else:
                logger.error(
                    "LLM generation failed after %d retries. Error: %s. Using fallback.",
                    max_retries,
                    err,
                )

    return fallback_text, f"failed: {last_error}"


def build_alert(
    prediction_result: Dict[str, Any],
    retrieval_result: Union[RetrievalResult, Dict[str, Any]],
    llm_client: Optional[OllamaClient] = None,
    include_llm: bool = True,
) -> Dict[str, Any]:
    """Assemble a complete, structured Actionable Alert JSON dictionary.

    Args:
        prediction_result: Output dict from `predict_and_explain()`.
        retrieval_result: `RetrievalResult` instance or dict from `retrieve()`.
        llm_client: Optional OllamaClient instance.
        include_llm: If False, skips LLM generation and uses standard fallbacks.

    Returns:
        Dict[str, Any]: Standardized Actionable Alert JSON dictionary.
    """
    predicted_class = prediction_result.get("predicted_class", "UNKNOWN")
    confidence = float(prediction_result.get("confidence", 0.0))
    top_features = prediction_result.get("top_features", [])
    is_attack = (predicted_class.upper() != "BENIGN")

    # Normalize retrieval result
    if isinstance(retrieval_result, dict):
        severity = retrieval_result.get("severity")
        actions = retrieval_result.get("actions", [])
        sources = retrieval_result.get("sources", [])
        kb_files = retrieval_result.get("kb_files", [])
        match_type = retrieval_result.get("match_type", "none")
        profile_chunk = retrieval_result.get("profile")
        mitigation_chunk = retrieval_result.get("mitigation")
        feature_chunks = retrieval_result.get("features", [])
        profile_text = profile_chunk.get("text") if isinstance(profile_chunk, dict) else None
        mitigation_text = mitigation_chunk.get("text") if isinstance(mitigation_chunk, dict) else None
        feature_glossary_texts = [
            f.get("text") for f in feature_chunks if isinstance(f, dict) and f.get("text")
        ]
    else:
        severity = retrieval_result.severity
        actions = list(retrieval_result.actions)
        sources = list(retrieval_result.sources)
        kb_files = list(retrieval_result.kb_files)
        match_type = retrieval_result.match_type
        profile_text = retrieval_result.profile.text if retrieval_result.profile else None
        mitigation_text = retrieval_result.mitigation.text if retrieval_result.mitigation else None
        feature_glossary_texts = [f.text for f in retrieval_result.features if f.text]

    explanation_text = FALLBACK_EXPLANATION
    recommendation_text = FALLBACK_RECOMMENDATION
    generation_status = "skipped"

    if include_llm:
        client = llm_client or OllamaClient()

        # Pass 1: Explanation
        exp_prompt, exp_system = format_explanation_prompt(
            attack_class=predicted_class,
            confidence=confidence,
            top_features=top_features,
            profile_text=profile_text,
            feature_glossary_texts=feature_glossary_texts,
        )
        explanation_text, exp_status = _call_with_retries(
            client=client,
            prompt=exp_prompt,
            system=exp_system,
            expected_key="explanation",
            fallback_text=FALLBACK_EXPLANATION,
        )

        # Pass 2: Recommendation (Omit SHAP features for strict mitigation grounding)
        rec_prompt, rec_system = format_recommendation_prompt(
            attack_class=predicted_class,
            severity=severity,
            mitigation_text=mitigation_text,
            actions=actions,
        )
        recommendation_text, rec_status = _call_with_retries(
            client=client,
            prompt=rec_prompt,
            system=rec_system,
            expected_key="recommendation",
            fallback_text=FALLBACK_RECOMMENDATION,
        )

        if exp_status == "success" and rec_status == "success":
            generation_status = "success"
        else:
            generation_status = f"partial (explanation: {exp_status}, recommendation: {rec_status})"

    # Structure final JSON schema
    alert_json: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prediction": {
            "attack_class": predicted_class,
            "confidence": round(confidence, 4),
            "is_attack": is_attack,
        },
        "explainability": {
            "top_features": top_features,
        },
        "retrieval_context": {
            "match_type": match_type,
            "kb_files": kb_files,
        },
        "alert": {
            "severity": severity,
            "explanation": explanation_text,
            "recommendation": recommendation_text,
            "mitigation_playbook": {
                "actions": actions,
            },
            "sources": sources,
        },
        "metadata": {
            "model": "XGBoost",
            "llm": (llm_client.model if llm_client else DEFAULT_MODEL) if include_llm else "none",
            "generation_status": generation_status,
        },
    }

    return alert_json


def process_flow_to_alert(
    flow_data: Union[Dict[str, Any], pd.DataFrame],
    models_dir: str = "models",
    kb_dir: Optional[str] = None,
    db_dir: Optional[str] = None,
    llm_client: Optional[OllamaClient] = None,
    top_k: int = 5,
) -> Dict[str, Any]:
    """Complete end-to-end pipeline: Predict -> Explain -> Retrieve -> LLM Synthesize -> Alert.

    Args:
        flow_data: Single flow record as dict or 1-row DataFrame.
        models_dir: Directory containing trained model artifacts.
        kb_dir: Optional custom KB directory.
        db_dir: Optional custom ChromaDB directory.
        llm_client: Optional custom OllamaClient instance.
        top_k: Number of top SHAP features to compute.

    Returns:
        Dict[str, Any]: Complete Actionable Alert JSON dictionary.
    """
    # 1. Quantitative prediction + SHAP
    pred_res = predict_and_explain(flow_data=flow_data, models_dir=models_dir, top_k=top_k)

    # 2. Extract feature names for retrieval
    feature_names = [f["feature"] for f in pred_res.get("top_features", [])]

    # 3. Retrieve relevant Knowledge Base chunks
    retriever_kwargs = {}
    if kb_dir:
        retriever_kwargs["kb_dir"] = kb_dir
    if db_dir:
        retriever_kwargs["db_dir"] = db_dir

    retriever = KnowledgeRetriever(**retriever_kwargs) if retriever_kwargs else None
    retrieval_res = retriever.retrieve(
        attack_class=pred_res["predicted_class"],
        top_features=feature_names,
    ) if retriever else retrieve(
        attack_class=pred_res["predicted_class"],
        top_features=feature_names,
    )

    # 4. Generate qualitative explanation + recommendation & build alert
    return build_alert(
        prediction_result=pred_res,
        retrieval_result=retrieval_res,
        llm_client=llm_client,
        include_llm=True,
    )
