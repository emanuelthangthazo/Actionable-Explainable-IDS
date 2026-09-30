# AXIDS LLM Module (`llm/`)

The `llm/` module provides qualitative explanation and actionable recommendation synthesis for the Actionable Explainable Intrusion Detection System (AXIDS). It transforms numerical SHAP feature attributions and retrieved Knowledge Base context into human-readable SOC alerts using a locally-hosted Llama 3.2 model via Ollama.

---

## Architecture & Components

```
RetrievalResult + PredictResult (SHAP top-k features)
                     │
                     ▼
  Pass 1: Explanation Prompt (llm/prompts.py)
  - Predicted class & confidence
  - Top SHAP features (values & TOWARD/AWAY directions)
  - KB attack profile context
                     │
                     ▼
  OllamaClient (llm/ollama_client.py)
  - Localhost only (http://localhost:11434)
  - Enforced JSON format output
                     │
                     ▼
  Pass 2: Recommendation Prompt (llm/prompts.py)
  - Predicted class & severity
  - KB mitigation playbook
  - (SHAP features omitted for strict mitigation grounding)
                     │
                     ▼
  Alert Builder (llm/alert_builder.py)
  - Assembles Actionable Alert JSON dictionary
```

---

## Key Files

- **`config.py`**: Constants (`DEFAULT_OLLAMA_HOST = "http://localhost:11434"`, `DEFAULT_MODEL = "llama3.2"`, timeout, retry policy, fallback strings).
- **`ollama_client.py`**: Lightweight HTTP wrapper with strict localhost safety and structured error hierarchy:
  - `OllamaConnectionError`: Ollama server unreachable (service not running).
  - `OllamaTimeoutError`: Generation exceeded configured timeout.
  - `OllamaResponseError`: HTTP error or malformed payload.
- **`prompts.py`**: Two-pass grounded prompt templates and formatters:
  - `format_explanation_prompt()`: Explanation grounded in SHAP attributions and attack profile.
  - `format_recommendation_prompt()`: Recommendation strictly grounded in KB mitigation playbooks.
- **`alert_builder.py`**:
  - `build_alert()`: Assembles the structured JSON SOC alert schema.
  - `process_flow_to_alert()`: Complete pipeline from single raw flow to JSON alert.

---

## Output Alert JSON Schema

```json
{
  "timestamp": "2026-09-30T05:03:42.944Z",
  "prediction": {
    "attack_class": "DDoS",
    "confidence": 0.9999,
    "is_attack": true
  },
  "explainability": {
    "top_features": [
      {"feature": "Fwd Packet Length Max", "feature_value": 11680.0, "shap_value": 1.4821, "direction": "TOWARD"}
    ]
  },
  "retrieval_context": {
    "match_type": "exact",
    "kb_files": ["attack_profiles.md", "mitigations.md"]
  },
  "alert": {
    "severity": "high",
    "explanation": "...",
    "recommendation": "...",
    "mitigation_playbook": {
      "actions": ["..."]
    },
    "sources": ["https://attack.mitre.org/techniques/T1498/"]
  },
  "metadata": {
    "model": "XGBoost",
    "llm": "llama3.2",
    "generation_status": "success"
  }
}
```

---

## Running Tests

```bash
# Run LLM unit and live integration tests
python -m unittest tests.test_llm -v

# Run the complete test suite (RAG + LLM)
python -m unittest discover tests
```
