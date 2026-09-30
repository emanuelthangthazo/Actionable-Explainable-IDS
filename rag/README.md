# AXIDS RAG Module (`rag/`)

The `rag/` module provides knowledge retrieval for the Actionable Explainable Intrusion Detection System (AXIDS). It maps predicted attack classes and top SHAP feature attributions to curated security knowledge base (KB) entries, mitigations, and feature explanations stored in a local ChromaDB vector store.

---

## Architecture & Components

```
Knowledge Base (.md files in rag/kb/)
      │
      ▼
rag/kb_parser.py       — Normalizes keys, extracts URLs, parses Markdown sections
      │
      ▼
rag/validate_kb.py     — Validates schema and alignment with model artifacts
      │
      ▼
rag/build_index.py     — Builds local ChromaDB collection (`axids_kb`), writes manifest
      │
      ▼
rag/retriever.py       — Exact lookup + guarded semantic fallback (`MAX_DISTANCE = 0.55`)
```

### Key Files

- **`kb/`**: Source markdown knowledge base files:
  - `attack_profiles.md` (15 entries, including `BENIGN`)
  - `mitigations.md` (14 attack mitigation playbooks)
  - `feature_glossary.md` (78 flow feature descriptions)
- **`config.py`**: Centralized configuration paths, constants (`MAX_DISTANCE = 0.55`, `INCLUDE_MITRE = True`).
- **`kb_parser.py`**: Normalizes headings and feature names via `normalize_key()`, robust URL parsing via `extract_urls()`.
- **`validate_kb.py`**: Pre-indexing validator ensuring all model classes and features are present and well-formed.
- **`build_index.py`**: Embeds 107 chunks using `all-MiniLM-L6-v2` ONNX offline model into ChromaDB with cosine distance.
- **`retriever.py`**: `KnowledgeRetriever` class and `retrieve()` function returning structured, JSON-serializable `RetrievalResult`.
- **`kb_manifest.json`**: Records SHA-256 hashes of KB files and chunk counts for automatic staleness detection.

---

## How to Rebuild the Index

To validate the KB and rebuild the ChromaDB index:

```bash
# 1. Validate KB integrity and model alignment
python -m rag.validate_kb

# 2. Build or recreate the ChromaDB vector index
python -m rag.build_index
```

The build is idempotent and runs fully offline after the first run.

---

## How to Query (CLI Demo)

You can test retrieval directly from the terminal:

```bash
# Formatted console output
python -m rag.retriever --attack-class "DDoS" --features "Flow Duration" "Bwd Packet Length Std"

# JSON output
python -m rag.retriever --attack-class "DDoS" --features "Flow Duration" "Bwd Packet Length Std" --json
```

---

## Configuration

In `rag/config.py`:
- **`INCLUDE_MITRE`**: Set to `True` (default) to include MITRE ATT&CK technique IDs in chunk text; set to `False` to omit them.
- **`MAX_DISTANCE`**: Set to `0.55` (calibrated cosine distance threshold for semantic fallback).
