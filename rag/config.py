"""Configuration constants and paths for the AXIDS RAG module."""

import os
from pathlib import Path
from typing import Dict, Tuple

# Project root directory
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]

# Knowledge base directory
KB_DIR: Path = PROJECT_ROOT / "rag" / "kb"

# Vector database directory and manifest
DB_DIR: Path = PROJECT_ROOT / "rag" / "chroma_db"
MANIFEST_PATH: Path = DB_DIR / "index_manifest.json"
KB_MANIFEST_PATH: Path = PROJECT_ROOT / "rag" / "kb_manifest.json"

# Collection name for ChromaDB
COLLECTION_NAME: str = "axids_kb"

# Canonical KB filenames
KB_FILES: Dict[str, str] = {
    "attack_profiles": "attack_profiles.md",
    "mitigations": "mitigations.md",
    "feature_glossary": "feature_glossary.md",
}

# Expected required fields per doc_type
REQUIRED_FIELDS: Dict[str, Tuple[str, ...]] = {
    "attack_profiles": (
        "Summary",
        "Flow-level signature",
        "Typical impact",
        "Tools/dataset context",
        "MITRE ATT&CK",
        "Source",
    ),
    "mitigations": (
        "Severity",
        "Actions",
        "Monitoring",
        "Source",
    ),
    "feature_glossary": (
        "Measures",
        "High values",
        "Low values",
        "Relevant attacks",
        "Source",
    ),
}

# Config flags
INCLUDE_MITRE: bool = True
SEMANTIC_FALLBACK_N: int = 2

# Distance threshold for semantic fallback (calibrated empirically in Phase 3):
# - Security near-matches ('Slowloris'->0.5107, 'slow http attack'->0.4042, 'ssh brute force'->0.4032,
#   'sql injection'->0.3652, 'port scanning'->0.3147, 'ftp brute force'->0.3281) have distance <= 0.52.
# - Irrelevant/nonsense queries ('banana smoothie'->0.9401, 'quarterly sales'->0.9345, 'quantum physics'->0.9221,
#   'weather in tokyo'->0.9304) have distance >= 0.70.
# Threshold of 0.55 provides robust separation margin.
MAX_DISTANCE: float = 0.55

# Allowed severity levels in mitigations
SEVERITY_LEVELS: Tuple[str, ...] = ("low", "medium", "high", "critical")

# Default model artifact paths
MODEL_PATH: Path = PROJECT_ROOT / "models" / "best_model.pkl"
LABEL_ENCODER_PATH: Path = PROJECT_ROOT / "models" / "label_encoder.pkl"
FEATURE_COLUMNS_PATH: Path = PROJECT_ROOT / "models" / "feature_columns.json"
