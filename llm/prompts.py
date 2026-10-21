"""Prompt template definitions and formatting utilities for two-pass LLM generation."""

from typing import Any, Dict, List, Optional, Tuple


EXPLANATION_SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst assistant for AXIDS (Actionable Explainable Intrusion Detection System).
Your task is to explain why a specific network flow was classified as the predicted class.
You must ground your explanation strictly on the provided flow metrics, SHAP feature attributions, and Knowledge Base profile context.

Strict Grounding Rules:
1. Do not invent feature importance rankings or unlisted metrics — only describe the features and directions given to you.
2. Feature Direction Semantics:
   - 'TOWARD' means the feature pushed towards the predicted class, increasing model suspicion/confidence for this classification.
   - 'AWAY' means the feature pushed away from the predicted class, reducing model confidence or opposing this classification.
3. Explicit Prohibition: NEVER claim, describe, or imply that an 'AWAY' feature 'supports', 'confirms', 'justifies', or 'indicates' the predicted class. If citing an 'AWAY' feature, explicitly state that it counterbalanced, reduced confidence, or acted as counter-evidence against the classification.
4. For BENIGN classifications: explain how TOWARD features align with normal baseline behavior, while correctly identifying that any AWAY features showed atypical characteristics that reduced confidence in the benign label.
5. Keep your explanation concise, professional, and directly useful for a SOC analyst (2-4 sentences).
6. Output MUST be a valid JSON object matching this exact schema: {"explanation": "<your explanation text>"}"""



RECOMMENDATION_SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst assistant for AXIDS (Actionable Explainable Intrusion Detection System).
Your task is to synthesize actionable containment and mitigation advice for a security alert.

Strict Grounding Rules:
1. Base your recommendation strictly on the provided Knowledge Base Mitigation Playbook.
2. If mitigation KB content is missing, unavailable, or for BENIGN normal traffic, state clearly that no mitigation action is required. Do not invent security advice.
3. Keep your recommendation concise, prioritized, and actionable (2-4 sentences).
4. Output MUST be a valid JSON object matching this exact schema: {"recommendation": "<your recommendation text>"}"""


def format_explanation_prompt(
    attack_class: str,
    confidence: float,
    top_features: List[Dict[str, Any]],
    profile_text: Optional[str] = None,
    feature_glossary_texts: Optional[List[str]] = None,
) -> Tuple[str, str]:
    """Format prompt and system message for Pass 1 (Explanation generation).

    Args:
        attack_class: Predicted attack class name.
        confidence: Prediction probability (0.0 to 1.0).
        top_features: List of top SHAP feature attribution dicts.
        profile_text: Attack profile text retrieved from KB.
        feature_glossary_texts: Optional list of feature descriptions from KB.

    Returns:
        Tuple[str, str]: (user_prompt, system_prompt)
    """
    formatted_features = []
    for f in top_features:
        name = f.get("feature", "Unknown")
        val = f.get("feature_value", 0.0)
        shap_val = f.get("shap_value", 0.0)
        direction = f.get("direction", "TOWARD")
        formatted_features.append(
            f"  - {name}: Value = {val}, SHAP Impact = {shap_val:+.4f} (Direction: {direction})"
        )
    features_str = "\n".join(formatted_features) if formatted_features else "  - (No top features provided)"

    profile_context = profile_text.strip() if profile_text else "No attack profile documentation found in Knowledge Base."

    glossary_context = ""
    if feature_glossary_texts:
        glossary_context = "\n\nRelevant Feature Definitions:\n" + "\n".join(
            f"  * {g.strip()}" for g in feature_glossary_texts if g
        )

    user_prompt = (
        f"Analyze this network flow detection:\n\n"
        f"- Predicted Class: {attack_class} (Confidence: {confidence:.2%})\n"
        f"- Top Contributing Flow Features (SHAP Attributions):\n{features_str}\n\n"
        f"- Knowledge Base Profile Context:\n{profile_context}"
        f"{glossary_context}\n\n"
        f"Provide a concise, grounded explanation for why this flow was flagged as {attack_class}."
    )

    return user_prompt, EXPLANATION_SYSTEM_PROMPT


def format_recommendation_prompt(
    attack_class: str,
    severity: Optional[str] = None,
    mitigation_text: Optional[str] = None,
    actions: Optional[List[str]] = None,
) -> Tuple[str, str]:
    """Format prompt and system message for Pass 2 (Recommendation generation).

    Note: SHAP features are deliberately omitted to prevent speculative remediation.

    Args:
        attack_class: Predicted attack class name.
        severity: Severity level string (e.g. 'high', 'critical', or None).
        mitigation_text: Mitigation playbook text retrieved from KB.
        actions: List of parsed mitigation action bullets from KB.

    Returns:
        Tuple[str, str]: (user_prompt, system_prompt)
    """
    sev_str = severity.upper() if severity else "NOT SPECIFIED"
    
    if mitigation_text:
        mitigation_context = mitigation_text.strip()
    elif actions:
        mitigation_context = "Actions:\n" + "\n".join(f"  * {a}" for a in actions)
    else:
        mitigation_context = "No specific mitigation playbook available for this class."

    user_prompt = (
        f"Synthesize an actionable incident response recommendation for this detection:\n\n"
        f"- Attack Class: {attack_class}\n"
        f"- Severity Level: {sev_str}\n"
        f"- Knowledge Base Mitigation Playbook:\n{mitigation_context}\n\n"
        f"Synthesize prioritized, concise mitigation steps strictly from the playbook above."
    )

    return user_prompt, RECOMMENDATION_SYSTEM_PROMPT
