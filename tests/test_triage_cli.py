"""Tests for the AXIDS Interactive Triage CLI tool (tools/triage_cli.py)."""

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd
from rich.table import Table
from rich.text import Text

from llm.alert_builder import process_flow_to_alert
from test_pipeline import DATA_PATH, load_test_set_raw
from tools.triage_cli import (
    display_detail_view,
    display_flow_alert,
    display_raw_json,
    render_severity_badge,
    render_shap_bar_chart,
    sample_triage_flows,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestTriageCLI(unittest.TestCase):
    """Test suite for UI rendering, sampling, and flow processing in triage_cli."""

    def setUp(self):
        self.sample_features = [
            {"feature": "Fwd Packet Length Max", "feature_value": 11680.0, "shap_value": 1.4821, "direction": "TOWARD"},
            {"feature": "Total Length of Fwd Packets", "feature_value": 11680.0, "shap_value": 1.1204, "direction": "TOWARD"},
            {"feature": "Average Packet Size", "feature_value": 1460.0, "shap_value": -0.9321, "direction": "AWAY"},
        ]
        self.sample_alert = {
            "timestamp": "2026-09-30T10:00:00Z",
            "prediction": {
                "attack_class": "DDoS",
                "confidence": 0.9999,
                "is_attack": True,
            },
            "explainability": {
                "top_features": self.sample_features,
            },
            "retrieval_context": {
                "match_type": "exact",
                "kb_files": ["attack_profiles.md", "mitigations.md"],
            },
            "alert": {
                "severity": "high",
                "explanation": "Flow exhibits high volume packets consistent with DDoS.",
                "recommendation": "Apply edge ACLs and rate limiting.",
                "mitigation_playbook": {
                    "actions": ["Apply edge ACLs", "Enable scrubbing"],
                },
                "sources": ["https://attack.mitre.org/techniques/T1498/"],
            },
            "metadata": {
                "model": "XGBoost",
                "llm": "llama3.2",
                "generation_status": "success",
            },
        }

    def test_render_shap_bar_chart(self):
        """Verify SHAP bar chart creates a Rich Table with relative bars and colors."""
        table = render_shap_bar_chart(self.sample_features)
        self.assertIsInstance(table, Table)
        self.assertEqual(len(table.rows), 3)

        # Empty features handling
        empty_table = render_shap_bar_chart([])
        self.assertIsInstance(empty_table, Table)
        self.assertEqual(len(empty_table.rows), 1)

    def test_render_severity_badge(self):
        """Verify severity badge produces styled text for different levels."""
        badge_crit = render_severity_badge("critical", is_attack=True)
        self.assertIsInstance(badge_crit, Text)
        self.assertIn("CRITICAL", badge_crit.plain)

        badge_high = render_severity_badge("high", is_attack=True)
        self.assertIn("HIGH", badge_high.plain)

        badge_med = render_severity_badge("medium", is_attack=True)
        self.assertIn("MEDIUM", badge_med.plain)

        badge_benign = render_severity_badge(None, is_attack=False)
        self.assertIn("BENIGN", badge_benign.plain)

    def test_display_flow_alert_rendering(self):
        """Verify alert display functions execute cleanly without exceptions."""
        # 1. Normal alert
        display_flow_alert(1, 5, "DDoS", self.sample_alert)
        # 2. Degraded alert
        degraded_alert = dict(self.sample_alert)
        degraded_alert["metadata"] = {"generation_status": "failed", "model": "XGBoost", "llm": "none"}
        display_flow_alert(1, 5, "DDoS", degraded_alert)
        # 3. Detail view & Raw JSON
        display_detail_view(self.sample_alert)
        display_raw_json(self.sample_alert)

    def test_sample_triage_flows_mix(self):
        """Verify sampling produces balanced benign and attack flows."""
        # Create a synthetic DataFrame mimicking CIC-IDS2017 structure
        data = {
            "Destination Port": [80, 443, 22, 21, 8080, 80],
            "Flow Duration": [1000, 2000, 3000, 4000, 5000, 6000],
            "Label": ["BENIGN", "BENIGN", "DDoS", "PortScan", "Bot", "FTP-Patator"],
        }
        df_test = pd.DataFrame(data)
        feature_cols = ["Destination Port", "Flow Duration"]

        samples = sample_triage_flows(df_test, feature_columns=feature_cols, count=4, seed=42)
        self.assertEqual(len(samples), 4)
        for s in samples:
            self.assertIn("flow_dict", s)
            self.assertIn("true_label", s)
            self.assertIn("Destination Port", s["flow_dict"])
            self.assertNotIn("Label", s["flow_dict"])

        labels = [s["true_label"] for s in samples]
        self.assertTrue(any(l == "BENIGN" for l in labels))
        self.assertTrue(any(l != "BENIGN" for l in labels))

    # -------------------------------------------------------------------------
    # End-to-End Integration Test (Requires Dataset, Model Artifacts & Ollama)
    # -------------------------------------------------------------------------
    def test_end_to_end_flow_to_alert(self):
        """Integration test: sample real flows using sample_triage_flows() and run full pipeline.

        NOTE: This is a full end-to-end integration test that requires:
          1. Raw CIC-IDS2017 test dataset at data/CICIDS2017_Combined.csv
          2. Trained model artifacts in models/
          3. Local Ollama running with Llama 3.2 (or graceful fallback)
        This test executes the actual ML -> SHAP -> RAG -> LLM pipeline with no mocks.
        """
        if not DATA_PATH.exists():
            self.skipTest(f"Dataset not found at {DATA_PATH}")

        models_dir = PROJECT_ROOT / "models"
        features_path = models_dir / "feature_columns.json"
        if not features_path.exists():
            self.skipTest(f"Feature columns artifact missing at {features_path}")

        with open(features_path, "r", encoding="utf-8") as f:
            feature_columns = json.load(f)

        # 1. Load real test flows using the CLI tool's own sample_triage_flows()
        df_test = load_test_set_raw()
        samples = sample_triage_flows(df_test, feature_columns=feature_columns, count=2, seed=7)
        self.assertEqual(len(samples), 2)

        # 2. Actually call process_flow_to_alert() on each flow through the real pipeline
        for idx, sample in enumerate(samples, start=1):
            flow_data = sample["flow_dict"]
            true_label = sample["true_label"]

            alert = process_flow_to_alert(
                flow_data=flow_data,
                models_dir=str(models_dir),
                top_k=5,
            )

            # 3. Assert the returned alert dict has expected top-level keys and valid structure
            self.assertIsInstance(alert, dict)
            for expected_key in ["timestamp", "prediction", "explainability", "retrieval_context", "alert", "metadata"]:
                self.assertIn(expected_key, alert)

            # Check prediction block
            pred = alert["prediction"]
            self.assertIn("attack_class", pred)
            self.assertIn("confidence", pred)
            self.assertIn("is_attack", pred)
            self.assertIsInstance(pred["confidence"], float)

            # Check explainability block
            exp = alert["explainability"]
            self.assertIn("top_features", exp)
            self.assertIsInstance(exp["top_features"], list)
            self.assertTrue(len(exp["top_features"]) > 0)

            # Check alert body
            alert_body = alert["alert"]
            self.assertIn("explanation", alert_body)
            self.assertIn("recommendation", alert_body)
            self.assertIn("severity", alert_body)
            self.assertIn("mitigation_playbook", alert_body)
            self.assertIn("sources", alert_body)

            # Check metadata block
            meta = alert["metadata"]
            self.assertIn("model", meta)
            self.assertIn("generation_status", meta)


if __name__ == "__main__":
    unittest.main()

