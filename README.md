# AXIDS — Actionable Explainable Intrusion Detection System

AXIDS is a machine learning pipeline that detects network intrusions from
flow-level traffic data, explains *why* a flow was flagged using SHAP feature
attributions, and (in progress) generates plain-English analyst alerts via a
locally-hosted LLM. It is designed for Security Operations Centre (SOC)
workflows where understanding and acting on alerts quickly matters as much as
detecting them accurately.

---

## Pipeline Architecture

```
CIC-IDS2017 Raw Flows
        │
        ▼
Data Preprocessing          preprocessing/preprocessing.py
        │
        ▼
Feature Preparation (X, y)
        │
        ▼
80/20 Stratified Split
        │
   ┌────┴────┐
   ▼         ▼
Random    XGBoost            models/train.py
Forest
   └────┬────┘
        ▼
Model Evaluation             models/evaluate.py
        │
        ▼
Best Model Selection         models/model_selection.py
        │
        ▼
Prediction                   models/predict.py
(attack class + confidence)
        │
        ▼
SHAP Explainability          explainability/explain.py
(per-prediction feature
 attributions)
        │
        ▼
Top Contributing Features
        │
        ▼
RAG Knowledge Retrieval      rag/           [complete]
        │
        │  kb_parser.py → validate_kb.py → build_index.py → retriever.py
        │  ChromaDB  ·  107 chunks  ·  all-MiniLM-L6-v2 (offline)
        │
        ▼
LLM — Llama 3.2 / Ollama     llm/           [complete]
        │
        │  ollama_client.py → prompts.py → alert_builder.py
        │  Two-pass grounded prompting · Localhost only
        │
   ┌────┴────┐
   ▼         ▼
Explanation  Recommendation
   └────┬────┘
        ▼
  Actionable Alert JSON
```

See [`WORKFLOW.md`](WORKFLOW.md) for detailed design rationale for each stage.

---

## Dataset

This project uses the **CIC-IDS-2017** dataset (Canadian Institute for
Cybersecurity). The raw CSV is **not included** in this repository (921 MB).

See [`data/README.md`](data/README.md) for download instructions and dataset
statistics. After downloading, place the combined file at
`data/CICIDS2017_Combined.csv`.

---

## Setup

### Prerequisites

- Python 3.10+
- (For the LLM stage) [Ollama](https://ollama.com) with `llama3.2` pulled locally

### Install

```bash
# 1. Clone the repository
git clone <repo-url>
cd axids

# 2. Create and activate a virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the pipeline & tests

```bash
# Step 1 — Train models (requires data/CICIDS2017_Combined.csv)
python -m models.train

# Step 2 — Evaluate and select best model
python -m models.evaluate
python -m models.model_selection

# Step 3 — Run the ML + SHAP integration test
python test_pipeline.py

# Step 4 — Run the data leakage audit
python check_leakage.py

# Step 5 — Run the full test suite (33 tests across RAG and LLM)
python -m unittest discover tests
```

> **Note:** Steps 1–2 take ~10–15 minutes on a modern CPU. Steps 3–4 each take
> ~2 minutes (they re-read the CSV to reconstruct the test split without
> retraining). Pre-trained model artifacts are included in `models/` so you
> can run Step 3 immediately after cloning (no retraining needed).

---

## Project Status

### ✅ Built and tested

| Component | File(s) | Notes |
|---|---|---|
| Data preprocessing | `preprocessing/preprocessing.py` | Strip → clean inf/nan → dedup → label-encode |
| Model training | `models/train.py` | Random Forest + XGBoost, stratified 80/20 split |
| Model evaluation | `models/evaluate.py` | Accuracy, Precision, Recall, F1, ROC-AUC, confusion matrix |
| Best model selection | `models/model_selection.py` | Weighted recall (60%) + F1 (40%) composite score |
| Inference | `models/predict.py` | Validates feature columns, returns class + confidence |
| SHAP explainability | `explainability/explain.py` | TreeExplainer, top-k features with direction |
| Combined pipeline | `explainability/explain.py` | `predict_and_explain()` end-to-end function |
| Integration test | `test_pipeline.py` | 5-sample mix from held-out test set, pass/fail table, edge-case check |
| Leakage audit | `check_leakage.py` | Rounded-exact + cosine-proxy duplicate detection, per-class breakdown |
| KB parser | `rag/kb_parser.py` | Parses 3 Markdown KB files into 107 normalized chunks |
| KB validator | `rag/validate_kb.py` | Validates KB schema + alignment with trained model artifacts |
| RAG index builder | `rag/build_index.py` | Embeds 107 chunks into ChromaDB (`axids_kb`), cosine distance, idempotent, manifest writer |
| RAG retriever | `rag/retriever.py` | Exact lookup + guarded semantic fallback (`MAX_DISTANCE=0.55`), staleness detection, CLI demo |
| RAG test suite | `tests/test_rag.py` | 22 tests: parser, validator, index, retriever, end-to-end pipeline — all passing |
| Ollama client | `llm/ollama_client.py` | Robust localhost-guarded HTTP client with timeout/connection error hierarchy |
| Grounded prompt templates | `llm/prompts.py` | Two-pass prompt formatters: Pass 1 (SHAP explanation), Pass 2 (KB-grounded mitigation) |
| Actionable alert builder | `llm/alert_builder.py` | `build_alert()` + `process_flow_to_alert()` assembling structured SOC JSON alerts |
| LLM test suite | `tests/test_llm.py` | 11 unit, mock, and live Llama 3.2 end-to-end tests — all passing |

**Model performance** (XGBoost, held-out 20% test set):
- Accuracy: ~99.9%  |  Weighted Recall: ~99.9%  |  Weighted F1: ~99.9%
- See `models/saved_models/evaluation_report.md` for full per-class breakdown

**Leakage audit findings:**
- Rounded-exact leakage: 1.4% overall (sub-3dp precision noise, not true leakage)
- Cosine-proxy similarity: 64.8% overall (reflects inherent repetitiveness of network traffic, not a data pipeline issue)

**RAG details:**
- 107 chunks: 15 attack profiles, 14 mitigations, 78 feature glossary entries
- Embedding model: `all-MiniLM-L6-v2` ONNX (~90 MB, cached at `~/.cache/chroma/`, 100% offline after first run)
- All 15 attack classes retrieve via exact match; semantic fallback guards against hallucination (`MAX_DISTANCE=0.55`)

**LLM details:**
- Model: `llama3.2` running via local Ollama instance on `localhost:11434`
- Structured two-pass JSON synthesis with automatic retry + exponential backoff

---

## Tech Stack

| Layer | Technology | Status |
|---|---|---|
| Dataset | CIC-IDS-2017 (Canadian Institute for Cybersecurity) | ✅ |
| ML models | Random Forest, XGBoost (scikit-learn / xgboost) | ✅ |
| Explainability | SHAP (`TreeExplainer`) | ✅ |
| Retrieval | ChromaDB · 107 chunks · `all-MiniLM-L6-v2` ONNX (offline) | ✅ |
| LLM | Llama 3.2 via Ollama (local) | ✅ |

---

## Repository Structure

```
axids/
├── data/
│   └── README.md               # Download instructions for CIC-IDS2017
├── explainability/
│   └── explain.py              # SHAP TreeExplainer + predict_and_explain()
├── llm/                        # [pending] LLM prompt + generation + alert assembly
├── models/
│   ├── train.py                # Training pipeline
│   ├── evaluate.py             # Evaluation metrics + reports
│   ├── model_selection.py      # Best model selection + artifact persistence
│   ├── predict.py              # Inference: predict_flow()
│   ├── best_model.pkl          # Trained XGBoost model (2.6 MB)
│   ├── label_encoder.pkl       # Fitted LabelEncoder
│   ├── feature_columns.json    # Ordered feature column list
│   └── saved_models/           # Full model comparison artefacts
├── notebooks/                  # Exploratory notebooks (gitignored *.ipynb)
├── preprocessing/
│   └── preprocessing.py        # Load → clean → encode pipeline
├── rag/
│   ├── kb_parser.py            # Markdown KB parser, normalize_key, extract_urls
│   ├── validate_kb.py          # Schema + model artifact alignment validator
│   ├── build_index.py          # ChromaDB index builder + manifest writer
│   ├── retriever.py            # KnowledgeRetriever: exact lookup + semantic fallback
│   ├── config.py               # Shared paths and constants (MAX_DISTANCE, etc.)
│   ├── chroma_db/              # ChromaDB persistence dir (gitignored)
│   ├── kb_manifest.json        # KB file hashes + chunk counts for staleness detection
│   └── knowledge_base/         # Markdown KB source files
│       ├── attack_profiles.md
│       ├── mitigations.md
│       └── feature_glossary.md
├── tests/
│   └── test_rag.py              # 22 unit, integration, and end-to-end RAG tests
├── check_leakage.py            # Data leakage audit script
├── test_pipeline.py            # End-to-end integration test (models + SHAP)
├── requirements.txt
└── WORKFLOW.md                 # Detailed pipeline design document
```
