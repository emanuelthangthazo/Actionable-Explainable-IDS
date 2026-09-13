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

## Pipeline Stages

### 1. Data Source — CIC-IDS2017
Labeled network traffic dataset containing benign and attack flows (DoS, DDoS, port scans, brute force, botnet, infiltration, etc.), each represented as a row of ~80 statistical flow features (packet lengths, flow duration, byte rates, flag counts, etc.).

### 2. Data Preprocessing
Raw flow data requires cleanup before modeling:
- Remove NaN/null rows (common due to malformed flows)
- Remove Inf/-Inf values (division-based features like `Flow Bytes/s` can blow up when duration = 0)
- Remove duplicate rows (known duplication issue in CIC-IDS2017 — important to fix to avoid train/test leakage)
- Encode labels (attack type strings → integers)

### 3. Feature Preparation
- `X` = network flow features (numeric)
- `y` = attack label (encoded)

### 4. 80/20 Train/Test Split
Standard split for evaluating generalization. Recommend **stratifying on `y`** since CIC-IDS2017 is heavily class-imbalanced (benign traffic dominates).

### 5. Model Training
Two models trained in parallel for comparison:

| Model | Notes |
|---|---|
| **Random Forest** | Bagged decision trees, robust baseline, less prone to overfitting |
| **XGBoost** | Gradient-boosted trees, typically stronger on imbalanced tabular data, integrates efficiently with SHAP's `TreeExplainer` |

### 6. Model Evaluation
Metrics computed for both models:
- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- ROC-AUC

> **Note:** For IDS use cases, prioritize **Recall** — missed attacks (false negatives) are more costly than false alarms.

### 7. Best Model Selection
Select the stronger model based on evaluation criteria above, with justification (e.g., best F1/Recall tradeoff, or best SHAP compatibility).

### 8. Prediction
Selected model outputs, for a new/unseen flow:
- Predicted attack class
- Prediction probability/confidence

### 9. SHAP (Explainability Layer)
Computes per-prediction feature attributions — which features pushed this specific flow toward its predicted class, and by how much. Converts the black-box prediction into an auditable decision.

### 10. Top Contributing Features
Extract the highest-magnitude SHAP values for the prediction (e.g., `Flow Duration`, `Fwd Packet Length Mean`, `SYN Flag Count`) — the human-readable "why."

### 11. RAG (Retrieval-Augmented Generation)
Given the predicted class + top SHAP features, retrieve relevant domain knowledge from a knowledge base (attack definitions, feature significance, standard mitigations). Grounds the LLM's output in real security knowledge instead of letting it hallucinate.

### 12. LLM — Llama 3.2 via Ollama
Retrieved context + SHAP features + prediction are passed as a prompt to a locally-hosted LLM, generating:
- **Explanation** — plain-English reasoning for the alert
- **Recommendation** — actionable mitigation steps (e.g., block source IP, rate-limit SYN packets)

### 13. Actionable Alert
Final output combining:
- Predicted class
- Confidence score
- SHAP-based reasoning
- LLM-generated explanation + recommendation

---

## Design Rationale

This is a **two-stage pipeline**:

1. **Quantitative stage** (RF/XGBoost → SHAP) — accurate, but opaque
2. **Qualitative stage** (RAG → LLM) — translates opaque numbers into human-actionable language

This makes the system more than a classifier — it's classification + interpretability + action, suitable for real SOC (Security Operations Center) workflows where analysts need to understand and act on alerts quickly.

---

## Tech Stack

- **Dataset:** CIC-IDS2017
- **ML Models:** Random Forest, XGBoost (scikit-learn / xgboost)
- **Explainability:** SHAP
- **Retrieval:** RAG (vector store + retriever, e.g., FAISS/Chroma)
- **LLM:** Llama 3.2 (served locally via Ollama)

---

## Open Questions / TODOs

- [ ] Finalize class imbalance strategy (SMOTE, class weights, undersampling?)
- [ ] Decide on stratification strategy for train/test split
- [ ] Build/curate the RAG knowledge base (attack types, mitigations, MITRE ATT&CK mapping?)
- [ ] Define prompt template for the LLM explanation/recommendation stage
- [ ] Define alert output schema (JSON format for downstream SOC integration)
