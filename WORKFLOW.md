# Actionable Explainable Intrusion Detection System (XIDS)

A machine learning pipeline that not only detects network intrusions but explains *why* a flow was flagged and *what to do about it*, using SHAP for model interpretability and a local LLM (via RAG) for human-readable, actionable alerts.

---

## Architecture Overview

```
CIC-IDS2017 Raw Flows
        │
        ▼
Data Preprocessing
        │
        ▼
Feature Preparation (X, y)
        │
        ▼
80/20 Train/Test Split
        │
   ┌────┴────┐
   ▼         ▼
Random    XGBoost
Forest
   └────┬────┘
        ▼
Model Evaluation
        │
        ▼
Best Model Selection
        │
        ▼
Prediction (Attack Class + Probability)
        │
        ▼
SHAP (Feature Attribution)
        │
        ▼
Top Contributing Features
        │
        ▼
RAG (Knowledge Retrieval)
        │
        ▼
LLM (Llama 3.2 via Ollama)
        │
   ┌────┴────┐
   ▼         ▼
Explanation  Recommendation
   └────┬────┘
        ▼
  Actionable Alert
```

---

## Pipeline Stages & Status

### 1. Data Source — CIC-IDS2017 `[COMPLETE]`
Labeled network traffic dataset containing benign and attack flows (DoS, DDoS, port scans, brute force, botnet, infiltration, etc.), each represented as a row of ~80 statistical flow features (packet lengths, flow duration, byte rates, flag counts, etc.).

### 2. Data Preprocessing (`preprocessing/preprocessing.py`) `[COMPLETE]`
Raw flow data cleanup:
- Stripped space-padded column names
- Cleaned NaN, null, and Inf values
- Deduplication of flow rows
- Label encoding of attack classes (15 classes, including `BENIGN`)

### 3. Feature Preparation (`X`, `y`) `[COMPLETE]`
- `X` = network flow features (numeric tabular data, 78 features)
- `y` = attack label (encoded)

### 4. 80/20 Stratified Split `[COMPLETE]`
- Settled on **stratified split on `y`** to preserve class distribution across imbalanced attack classes.

### 5. Model Training (`models/train.py`) `[COMPLETE]`
Two models trained in parallel for comparison:
- **Random Forest**: Bagged decision trees
- **XGBoost**: Gradient-boosted decision trees

### 6. Model Evaluation (`models/evaluate.py`) `[COMPLETE]`
Evaluation on held-out 20% test set:
- Accuracy, Precision, Recall, F1-score, Confusion Matrix, ROC-AUC.
- Full per-class evaluation saved to `models/saved_models/evaluation_report.md`.

### 7. Best Model Selection (`models/model_selection.py`) `[COMPLETE]`
- Evaluated with composite metric: **60% Weighted Recall + 40% Weighted F1** (prioritizing recall as missed attacks are costlier than false alarms).
- **Best Model Selected**: XGBoost (~99.9% weighted recall, ~99.9% weighted F1).

### 8. Prediction (`models/predict.py`) `[COMPLETE]`
- Validates input features against `feature_columns.json`.
- Outputs predicted attack class + confidence probability.

### 9. SHAP Explainability Layer (`explainability/explain.py`) `[COMPLETE]`
- Exact `TreeExplainer` computed per prediction.
- Identifies features pushing toward or away from the predicted class.

### 10. Top Contributing Features `[COMPLETE]`
- Computes top-$k$ (default 5) features with their magnitude and direction (`TOWARD` vs `AWAY`).
- Encapsulated in `predict_and_explain()`.

### 11. RAG Knowledge Retrieval (`rag/`) `[COMPLETE]`
- **Knowledge Base**: 107 Markdown chunks (15 attack profiles, 14 mitigations, 78 feature glossaries).
- **Index**: ChromaDB vector store (`axids_kb`), cosine distance, `all-MiniLM-L6-v2` ONNX embeddings (100% offline).
- **Retriever (`rag/retriever.py`)**: Exact deterministic ID lookup with guarded semantic fallback (`MAX_DISTANCE=0.55`) and manifest staleness detection.

### 12. LLM — Llama 3.2 via Ollama (`llm/`) `[COMPLETE]`
- **Localhost Guarded Client (`llm/ollama_client.py`)**: Local HTTP wrapper around `http://localhost:11434/api/generate` with distinct `OllamaConnectionError`, `OllamaTimeoutError`, and `OllamaResponseError`.
- **Two-Pass Prompting Architecture (`llm/prompts.py`)**:
  - **Pass 1 (Explanation)**: Receives predicted class, confidence, top SHAP features (values & directions), and KB attack profile.
  - **Pass 2 (Recommendation)**: Receives predicted class, severity, and KB mitigation playbook (SHAP features omitted to strictly ground mitigations in KB facts).

### 13. Actionable Alert JSON (`llm/alert_builder.py`) `[COMPLETE]`
- `build_alert()` and `process_flow_to_alert()` synthesize ML predictions, SHAP attributions, RAG retrieval context, and LLM text into a standardized JSON SOC alert schema.

---

## Design Rationale

This is a **two-stage pipeline**:

1. **Quantitative stage** (XGBoost $\rightarrow$ SHAP) — accurate, high-speed, auditable
2. **Qualitative stage** (RAG $\rightarrow$ Llama 3.2) — translates numerical attributions into human-actionable language

This makes the system an end-to-end classification + interpretability + action system suitable for SOC workflows.

---

## Tech Stack & Current Status

| Layer | Technology | Status |
|---|---|---|
| **Dataset** | CIC-IDS2017 (Canadian Institute for Cybersecurity) | ✅ Complete |
| **ML Models** | Random Forest, XGBoost (scikit-learn / xgboost) | ✅ Complete |
| **Explainability** | SHAP (`TreeExplainer`) | ✅ Complete |
| **Retrieval** | ChromaDB · 107 chunks · `all-MiniLM-L6-v2` ONNX (offline) | ✅ Complete |
| **LLM** | Llama 3.2 via Ollama (localhost only, two-pass grounded prompts) | ✅ Complete |
| **Alert Builder** | Standardized JSON Actionable Alert Schema | ✅ Complete |
| **Tests** | 33 comprehensive unit, integration, and live E2E tests | ✅ 100% Pass |

---

## Milestone Status

- [x] Preprocessing pipeline & data leakage audit (`check_leakage.py`)
- [x] Stratified 80/20 train/test split & model training
- [x] Evaluation & weighted recall model selection (XGBoost selected)
- [x] SHAP TreeExplainer & `predict_and_explain()`
- [x] Knowledge Base curation, validation (`validate_kb.py`), and ChromaDB index builder (`build_index.py`)
- [x] KnowledgeRetriever with exact/semantic fallback and staleness detection
- [x] Phase 4 LLM client (`llm/ollama_client.py`), two-pass prompts (`llm/prompts.py`), and alert builder (`llm/alert_builder.py`)
- [x] Live Llama 3.2 integration test suite (`tests/test_llm.py` & `tests/test_rag.py`)

