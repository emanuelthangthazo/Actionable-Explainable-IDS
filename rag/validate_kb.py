"""Knowledge Base validator for AXIDS RAG module."""

import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

import joblib

from rag.config import (
    FEATURE_COLUMNS_PATH,
    KB_DIR,
    KB_FILES,
    LABEL_ENCODER_PATH,
    REQUIRED_FIELDS,
    SEVERITY_LEVELS,
)
from rag.kb_parser import normalize_key, parse_kb_file

logger = logging.getLogger(__name__)


def validate_kb(
    kb_dir: Path = KB_DIR,
    encoder_path: Path = LABEL_ENCODER_PATH,
    features_path: Path = FEATURE_COLUMNS_PATH,
) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
    """Validate all Knowledge Base files against required schema and model artifacts.

    Args:
        kb_dir: Directory containing the KB markdown files.
        encoder_path: Path to label_encoder.pkl.
        features_path: Path to feature_columns.json.

    Returns:
        Tuple[bool, List[str], List[str], Dict[str, Any]]:
            - is_valid: True if zero errors encountered.
            - errors: List of error messages.
            - warnings: List of warning messages.
            - stats: Summary statistics dictionary.
    """
    kb_dir = Path(kb_dir)
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, Any] = {
        "section_counts": {},
        "word_counts": {},
        "not_verified_count": 0,
    }

    # 1. Check existence of model artifacts
    if not Path(encoder_path).exists():
        errors.append(f"Model label encoder artifact not found: {encoder_path}")
        return False, errors, warnings, stats

    if not Path(features_path).exists():
        errors.append(f"Feature columns artifact not found: {features_path}")
        return False, errors, warnings, stats

    label_encoder = joblib.load(encoder_path)
    model_classes = [str(c) for c in label_encoder.classes_]

    with open(features_path, "r", encoding="utf-8") as f:
        model_features: List[str] = json.load(f)

    # 2. Check existence of KB files
    for doc_type, filename in KB_FILES.items():
        file_path = kb_dir / filename
        if not file_path.exists():
            errors.append(f"KB file missing: {file_path}")

    if errors:
        return False, errors, warnings, stats

    # 3. Parse and validate each file
    parsed_kb: Dict[str, List[Any]] = {}
    normalized_keys_per_doc: Dict[str, Set[str]] = {}
    not_verified_count = 0

    for doc_type, filename in KB_FILES.items():
        file_path = kb_dir / filename
        sections = parse_kb_file(file_path, doc_type=doc_type, include_mitre=True)
        parsed_kb[doc_type] = sections
        stats["section_counts"][doc_type] = len(sections)

        seen_keys: Set[str] = set()
        normalized_keys_per_doc[doc_type] = set()

        for sec in sections:
            # Check duplicate normalized headings inside one file
            if sec.key_norm in seen_keys:
                errors.append(
                    f"[{doc_type}] Duplicate normalized heading found: '{sec.key}' (norm: '{sec.key_norm}')"
                )
            seen_keys.add(sec.key_norm)
            normalized_keys_per_doc[doc_type].add(sec.key_norm)

            # Check required fields
            req_fields = REQUIRED_FIELDS.get(doc_type, ())
            for req in req_fields:
                if req not in sec.fields or not sec.fields[req].strip():
                    errors.append(
                        f"[{doc_type}] Section '{sec.key}' is missing required field: '{req}'"
                    )

            # Check Source field has at least one valid URL
            if not sec.urls:
                errors.append(
                    f"[{doc_type}] Section '{sec.key}' has zero valid URLs in Source field"
                )

            # Check mitigations specifics: valid Severity and at least 1 action bullet
            if doc_type == "mitigations":
                if sec.severity not in SEVERITY_LEVELS:
                    errors.append(
                        f"[mitigations] Section '{sec.key}' has invalid severity: '{sec.severity}' "
                        f"(allowed: {SEVERITY_LEVELS})"
                    )
                if not sec.actions:
                    errors.append(
                        f"[mitigations] Section '{sec.key}' has zero action items in Actions field"
                    )

            # Check word count warning (> 250 words)
            word_count = len(sec.text.split())
            if word_count > 250:
                warnings.append(
                    f"[{doc_type}] Section '{sec.key}' has {word_count} words (exceeds 250 words)"
                )

            # Count 'not verified' occurrences
            if "not verified" in sec.text.lower():
                not_verified_count += 1

    stats["not_verified_count"] = not_verified_count

    # 4. Cross-check with Model Artifacts
    # a. Every model class must be in attack_profiles
    profile_keys = normalized_keys_per_doc.get("attack_profiles", set())
    for cls_name in model_classes:
        norm_c = normalize_key(cls_name)
        if norm_c not in profile_keys:
            errors.append(
                f"Model class '{cls_name}' (norm: '{norm_c}') is missing from attack_profiles.md"
            )

    # b. Every model class other than BENIGN must be in mitigations
    mitigation_keys = normalized_keys_per_doc.get("mitigations", set())
    for cls_name in model_classes:
        norm_c = normalize_key(cls_name)
        if norm_c == "benign":
            continue
        if norm_c not in mitigation_keys:
            errors.append(
                f"Attack class '{cls_name}' (norm: '{norm_c}') is missing from mitigations.md"
            )

    # c. Every model feature must be in feature_glossary
    glossary_keys = normalized_keys_per_doc.get("feature_glossary", set())
    for feat_name in model_features:
        norm_f = normalize_key(feat_name)
        if norm_f not in glossary_keys:
            errors.append(
                f"Model feature '{feat_name}' (norm: '{norm_f}') is missing from feature_glossary.md"
            )

    # 5. Warnings for extra KB headings that do not map to model artifacts
    model_classes_norm = {normalize_key(c) for c in model_classes}
    model_features_norm = {normalize_key(f) for f in model_features}

    for p_norm in profile_keys:
        if p_norm not in model_classes_norm:
            warnings.append(
                f"[attack_profiles] Heading '{p_norm}' matches no class in label_encoder.pkl"
            )

    for m_norm in mitigation_keys:
        if m_norm not in model_classes_norm:
            warnings.append(
                f"[mitigations] Heading '{m_norm}' matches no class in label_encoder.pkl"
            )

    for g_norm in glossary_keys:
        if g_norm not in model_features_norm:
            warnings.append(
                f"[feature_glossary] Heading '{g_norm}' matches no feature in feature_columns.json"
            )

    is_valid = (len(errors) == 0)
    return is_valid, errors, warnings, stats


def main() -> int:
    """CLI entry point for python -m rag.validate_kb."""
    # Configure console for clean UTF-8
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    print("=" * 80)
    print("  AXIDS KNOWLEDGE BASE VALIDATOR")
    print(f"  KB Directory   : {KB_DIR}")
    print(f"  Model Encoder  : {LABEL_ENCODER_PATH}")
    print(f"  Feature Columns: {FEATURE_COLUMNS_PATH}")
    print("=" * 80)

    is_valid, errors, warnings, stats = validate_kb()

    print("\n[Parsed Section Counts]")
    total_sections = 0
    for doc_type, count in stats["section_counts"].items():
        print(f"  - {doc_type:<20}: {count} sections")
        total_sections += count
    print(f"  Total KB Chunks     : {total_sections}")
    print(f"  'Not verified' count: {stats['not_verified_count']} sections")

    if warnings:
        print(f"\n[Warnings ({len(warnings)})]")
        for w in warnings:
            print(f"  [WARN] {w}")

    if errors:
        print(f"\n[Errors ({len(errors)})]")
        for e in errors:
            print(f"  [ERROR] {e}")
        print("\n" + "=" * 80)
        print("  VALIDATION FAILED: Errors found in Knowledge Base or model alignment.")
        print("=" * 80)
        return 1

    print("\n" + "=" * 80)
    print("  VALIDATION PASSED: Knowledge Base is valid and aligned with model artifacts.")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
