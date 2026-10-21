# AGENTS.md — Project Memory for AXIDS

> Auto-loaded by Antigravity (and compatible tools) at the start of every
> session in this workspace. Keep this in sync with reality as you build.
> Design rationale per stage lives in `WORKFLOW.md`; repo layout and current
> build status live in `README.md`. This file is the reconciled, current
> source of truth — if `WORKFLOW.md`'s TODOs and this file disagree, this
> file wins (WORKFLOW.md was written earlier and hasn't been updated).

## Project

**AXIDS — Actionable Explainable Intrusion Detection System.**

Flow-level intrusion detection on CIC-IDS2017 → SHAP explains *why* a flow
was flagged → RAG + local LLM turns that into a plain-English SOC alert with
a recommendation. Two-stage design: quantitative (RF/XGBoost → SHAP, accurate
but opaque) → qualitative (RAG → LLM, translates that into something an
analyst can act on).

## Pipeline (source of truth — matches actual file layout)

```
CIC-IDS2017 Raw Flows
  → preprocessing/preprocessing.py   (strip → clean inf/nan → dedup → label-encode)
  → Feature prep (X, y)
  → 80/20 stratified split            [DECIDED: stratified on y — done]
  → models/train.py                  (Random Forest + XGBoost)
  → models/evaluate.py                (accuracy, precision, recall, F1, ROC-AUC, confusion matrix)
  → models/model_selection.py         (weighted recall 60% + F1 40% composite → best model)
                                       [DECIDED: recall weighted higher — missed attacks cost more than false alarms]
  → models/predict.py                 (attack class + confidence)
  → explainability/explain.py         (SHAP TreeExplainer → top-k features w/ direction, predict_and_explain())
  → rag/                              [DONE] KB parser → validator → ChromaDB index → KnowledgeRetriever
  → llm/                              [DONE] Llama 3.2 via Ollama → explanation + recommendation
  → Actionable Alert (JSON schema defined & live)
  → tools/triage_cli.py               [DONE] Interactive SOC triage dashboard (Rich UI)
```

## Current status — check here before assuming anything is undone

### ✅ Built and tested
- `preprocessing/preprocessing.py` — full clean pipeline
- `models/train.py`, `models/evaluate.py`, `models/model_selection.py`, `models/predict.py`
- `explainability/explain.py` — TreeExplainer + `predict_and_explain()`
- `test_pipeline.py` — 5-sample integration test against held-out test set
- `check_leakage.py` — leakage audit (rounded-exact + cosine-proxy)
- `rag/kb_parser.py` — Markdown KB parser with normalization & URL extraction
- `rag/validate_kb.py` — Pre-indexing schema and model artifact alignment validator
- `rag/build_index.py` — ChromaDB vector index builder with cosine distance and manifest generator
- `rag/retriever.py` — KnowledgeRetriever with exact/semantic fallback, staleness check, and CLI demo
- `tests/test_rag.py` — 22 unit, integration, and end-to-end tests covering parser, validator, index builder, retriever, and pipeline integration
- `llm/config.py` — host, model name, timeout, retry policy, fallback strings
- `llm/ollama_client.py` — local HTTP wrapper around `POST /api/generate` with 3 distinct exception types (`OllamaConnectionError`, `OllamaTimeoutError`, `OllamaResponseError`)
- `llm/prompts.py` — two grounded prompt formatters (Pass 1: Explanation with SHAP attributions, Pass 2: Recommendation grounded strictly in KB mitigations)
- `llm/alert_builder.py` — `build_alert()` and `process_flow_to_alert()` assembles structured Actionable Alert JSON dictionary
- `tests/test_llm.py` — 11 unit, integration, and live Llama 3.2 end-to-end tests
- `tools/triage_cli.py` — interactive CLI triage tool using Rich for terminal UI, SHAP horizontal bar charts, and live flow inspection
- `tests/test_triage_cli.py` — 4 unit and rendering tests (total 37 tests across full test suite)

**RAG Index, Model Cache & Retriever:**
- All 107 chunks indexed into ChromaDB collection `axids_kb` (`rag/chroma_db/`).
- Manifest generated at `rag/kb_manifest.json` and `rag/chroma_db/index_manifest.json`.
- `MAX_DISTANCE` calibrated to `0.55` (valid near-matches <= 0.52 vs irrelevant queries >= 0.70).
- All 15 model attack classes verified to retrieve cleanly via exact match.
- The `all-MiniLM-L6-v2` ONNX embedding model (~90MB) is cached locally and runs 100% offline.

**LLM Generation & Actionable Alerts:**
- Local Llama 3.2 via Ollama (`http://localhost:11434`), strictly localhost guarded (no cloud fallbacks).
- Two-pass prompting: Pass 1 generates plain-English explanation of SHAP attributions; Pass 2 synthesizes mitigation recommendations strictly from KB mitigations.
- Structured JSON alert schema output with timestamp, prediction, explainability, retrieval context, actionable alert, and metadata.

**Trained artifacts already exist** in `models/` (`best_model.pkl` = XGBoost,
`label_encoder.pkl`, `feature_columns.json`, `saved_models/`). Do not retrain
from scratch unless explicitly asked — `test_pipeline.py` runs against the
existing artifacts in ~2 minutes.

**Model performance** (XGBoost, held-out 20%): ~99.9% accuracy, ~99.9%
weighted recall, ~99.9% weighted F1. Full per-class breakdown in
`models/saved_models/evaluation_report.md`.

**Leakage audit result:** rounded-exact leakage ~1.4% (sub-3dp float
precision noise, not true leakage); cosine-proxy similarity ~64.8% (inherent
repetitiveness of network flow data, not a pipeline bug). Already
investigated — don't re-run this from scratch, only extend it if new
evidence suggests the conclusion was wrong.

### 🔲 Pipeline Complete — Optional Next Extensions
- End-to-end demo CLI or Web UI for live flow inspection and interactive SOC alert triage.
- Export / streaming pipeline for real-time PCAP or live flow ingestion.

## Decisions already made (don't reopen without new evidence)

- **Stratified 80/20 split** on `y` — settled, due to class imbalance.
- **Model selection metric**: weighted recall (60%) + F1 (40%), not raw
  accuracy — because missed attacks (false negatives) are costlier than
  false alarms in an IDS context. Resulting best model: XGBoost.
- **Explainability tool**: SHAP `TreeExplainer` — exact and fast for tree
  models, no need for a model-agnostic explainer.
- **Class imbalance handling**: resolved implicitly via the recall-weighted
  selection metric and stratified split.
- **RAG vector store**: ChromaDB with cosine distance — confirmed and live.
  107 chunks indexed, `axids_kb` collection, `all-MiniLM-L6-v2` ONNX
  embeddings (~90 MB, cached offline). Do not swap to FAISS or another store.
- **RAG retrieval strategy**: exact lookup first (deterministic ChromaDB ID),
  semantic fallback only on miss, `MAX_DISTANCE=0.55` guardrail — calibrated
  empirically; don't lower it without re-running calibration queries.
- **LLM runtime**: Llama 3.2 via Ollama (local, no API key needed) — confirmed.
- **Prompting architecture**: Two-pass prompting (Explanation + Recommendation separate calls).
  SHAP features are omitted from Pass 2 to prevent speculative mitigation.
- **Alert JSON schema**: Defined with standard fields: `timestamp`, `prediction`,
  `explainability`, `retrieval_context`, `alert` (`severity`, `explanation`,
  `recommendation`, `mitigation_playbook`, `sources`), and `metadata`.

## Open decisions (ask before assuming)

- End-to-end integration or UI layer format (CLI interactive tool vs Web Dashboard vs REST API endpoint).
- Real-time streaming integration / PCAP packet flow capture listener.

## Conventions already established in this repo

- Modules run via `python -m <package>.<module>` (e.g. `python -m models.train`, `python -m rag.retriever`, `python -m unittest discover tests`) — follow this pattern for all modules.
- venv at `venv/`, dependencies pinned in `requirements.txt`.
- Dataset lives at `data/CICIDS2017_Combined.csv` (921MB, gitignored) — assume it's already present locally.
- Model artifacts persisted as `.pkl` + a separate `feature_columns.json` to guarantee column order at inference.
- New modules must include an integration test suite (`tests/test_rag.py`, `tests/test_llm.py`).

## What NOT to re-explain or redo

- Preprocessing, training, evaluation, model selection, SHAP explainability, RAG index/retrieval, and LLM prompt/alert pipeline are all DONE and tested.
- Don't re-run training or leakage audits unless requested.

## Next task by default

All core phases (1 to 4) of AXIDS are complete:
- Quantitative Stage: XGBoost + TreeExplainer SHAP
- Retrieval Stage: ChromaDB + 107-chunk KB + KnowledgeRetriever
- Qualitative Stage: Local Llama 3.2 via Ollama + two-pass grounded prompts + Actionable Alert JSON

Next options:
1. Build an interactive SOC CLI triage demo or Web UI dashboard for inspecting flows and alerts in real-time.
2. Build an end-to-end batch evaluation or benchmark runner across large slices of the CIC-IDS2017 dataset.
