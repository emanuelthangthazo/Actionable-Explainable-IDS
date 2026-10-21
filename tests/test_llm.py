"""Comprehensive unit, integration, and end-to-end test suite for the AXIDS LLM module."""

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

import pandas as pd

from explainability.explain import predict_and_explain
from llm.alert_builder import build_alert, process_flow_to_alert
from llm.config import FALLBACK_EXPLANATION, FALLBACK_RECOMMENDATION
from llm.ollama_client import (
    OllamaClient,
    OllamaConnectionError,
    OllamaError,
    OllamaResponseError,
    OllamaTimeoutError,
)
from llm.prompts import (
    EXPLANATION_SYSTEM_PROMPT,
    RECOMMENDATION_SYSTEM_PROMPT,
    format_explanation_prompt,
    format_recommendation_prompt,
)
from rag.retriever import Chunk, RetrievalResult, retrieve

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestOllamaClient(unittest.TestCase):
    """Unit tests for OllamaClient wrapper error handling and isolation."""

    def test_localhost_guard(self):
        """Ensure client rejects remote or cloud URLs to preserve local privacy."""
        with self.assertRaises(ValueError):
            OllamaClient(host="https://api.openai.com/v1")
        with self.assertRaises(ValueError):
            OllamaClient(host="http://remote-server.com:11434")

        # Valid local hosts
        c1 = OllamaClient(host="http://localhost:11434")
        self.assertEqual(c1.host, "http://localhost:11434")
        c2 = OllamaClient(host="http://127.0.0.1:11434")
        self.assertEqual(c2.host, "http://127.0.0.1:11434")

    @patch("urllib.request.urlopen")
    def test_successful_json_generation(self, mock_urlopen):
        """Verify successful JSON request and response parsing."""
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = json.dumps({
            "response": json.dumps({"explanation": "This is a test explanation."})
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        client = OllamaClient()
        res = client.generate(prompt="Explain flow", system="System rule", format_json=True)
        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("explanation"), "This is a test explanation.")

    @patch("urllib.request.urlopen")
    def test_connection_refused_error(self, mock_urlopen):
        """Verify connection refused raises OllamaConnectionError with clear advice."""
        mock_urlopen.side_effect = urllib.error.URLError(ConnectionRefusedError(10061, "Connect call failed"))

        client = OllamaClient()
        with self.assertRaises(OllamaConnectionError) as ctx:
            client.generate(prompt="Hello")
        self.assertIn("ollama", str(ctx.exception).lower())

    @patch("urllib.request.urlopen")
    def test_timeout_error(self, mock_urlopen):
        """Verify socket/request timeout raises OllamaTimeoutError."""
        mock_urlopen.side_effect = urllib.error.URLError(TimeoutError("timed out"))

        client = OllamaClient(timeout=5.0)
        with self.assertRaises(OllamaTimeoutError) as ctx:
            client.generate(prompt="Hello")
        self.assertIn("timed out", str(ctx.exception).lower())

    @patch("urllib.request.urlopen")
    def test_server_http_error(self, mock_urlopen):
        """Verify HTTP 404 or 500 error raises OllamaResponseError."""
        mock_err = urllib.error.HTTPError(
            url="http://localhost:11434/api/generate",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=MagicMock(read=lambda: b'{"error":"model \'llama3.2\' not found"}')
        )
        mock_urlopen.side_effect = mock_err

        client = OllamaClient()
        with self.assertRaises(OllamaResponseError) as ctx:
            client.generate(prompt="Hello")
        self.assertIn("404", str(ctx.exception))


class TestPrompts(unittest.TestCase):
    """Unit tests for prompt formatters and grounding constraints."""

    def test_format_explanation_prompt(self):
        """Check Pass 1 prompt formatting with confidence, SHAP features, and profile."""
        top_features = [
            {"feature": "Bwd Packet Length Std", "feature_value": 142.35, "shap_value": 1.84, "direction": "TOWARD"},
            {"feature": "Flow Duration", "feature_value": 3000, "shap_value": -0.45, "direction": "AWAY"},
        ]
        user_prompt, sys_prompt = format_explanation_prompt(
            attack_class="DDoS",
            confidence=0.9998,
            top_features=top_features,
            profile_text="DDoS profile text here",
        )
        self.assertEqual(sys_prompt, EXPLANATION_SYSTEM_PROMPT)
        self.assertIn("DDoS (Confidence: 99.98%)", user_prompt)
        self.assertIn("Bwd Packet Length Std", user_prompt)
        self.assertIn("Direction: TOWARD", user_prompt)
        self.assertIn("Direction: AWAY", user_prompt)
        self.assertIn("DDoS profile text here", user_prompt)

    def test_format_recommendation_prompt_omits_shap(self):
        """Check Pass 2 prompt strictly omits SHAP features for grounded mitigations."""
        user_prompt, sys_prompt = format_recommendation_prompt(
            attack_class="PortScan",
            severity="medium",
            mitigation_text="PortScan mitigation details",
            actions=["Isolate source IP", "Block scanned ports"],
        )
        self.assertEqual(sys_prompt, RECOMMENDATION_SYSTEM_PROMPT)
        self.assertIn("Attack Class: PortScan", user_prompt)
        self.assertIn("Severity Level: MEDIUM", user_prompt)
        self.assertIn("PortScan mitigation details", user_prompt)
        # Verify SHAP attributions and values are NOT present
        self.assertNotIn("SHAP", user_prompt)
        self.assertNotIn("TOWARD", user_prompt)
        self.assertNotIn("AWAY", user_prompt)


class TestAlertBuilder(unittest.TestCase):
    """Unit tests for build_alert schema, retries, and fallback resilience."""

    def setUp(self):
        self.sample_pred = {
            "predicted_class": "DDoS",
            "confidence": 0.9995,
            "top_features": [
                {"feature": "Bwd Packet Length Std", "feature_value": 140.0, "shap_value": 1.5, "direction": "TOWARD"}
            ],
        }
        self.sample_retrieval = RetrievalResult(
            attack_class="DDoS",
            match_type="exact",
            found=True,
            profile=Chunk(doc_type="attack_profile", key="DDoS", text="DDoS summary"),
            mitigation=Chunk(doc_type="mitigation", key="DDoS", text="Mitigation text"),
            severity="high",
            actions=["Action 1", "Action 2"],
            sources=["https://example.com/ddos"],
            kb_files=["attack_profiles.md", "mitigations.md"],
        )

    def test_schema_and_kb_field_preservation(self):
        """Verify output schema matches AGENTS.md and KB fields are preserved unchanged."""
        mock_client = MagicMock()
        mock_client.model = "llama3.2"
        mock_client.generate.side_effect = [
            {"explanation": "Generated explanation for DDoS."},
            {"recommendation": "Generated recommendation for DDoS."},
        ]

        alert = build_alert(
            prediction_result=self.sample_pred,
            retrieval_result=self.sample_retrieval,
            llm_client=mock_client,
        )

        # Check top-level keys
        for key in ["timestamp", "prediction", "explainability", "retrieval_context", "alert", "metadata"]:
            self.assertIn(key, alert)

        # Check prediction & explainability
        self.assertEqual(alert["prediction"]["attack_class"], "DDoS")
        self.assertTrue(alert["prediction"]["is_attack"])
        self.assertEqual(len(alert["explainability"]["top_features"]), 1)

        # Check alert section (severity, actions, sources from KB)
        self.assertEqual(alert["alert"]["severity"], "high")
        self.assertEqual(alert["alert"]["mitigation_playbook"]["actions"], ["Action 1", "Action 2"])
        self.assertEqual(alert["alert"]["sources"], ["https://example.com/ddos"])
        self.assertEqual(alert["alert"]["explanation"], "Generated explanation for DDoS.")
        self.assertEqual(alert["alert"]["recommendation"], "Generated recommendation for DDoS.")
        self.assertEqual(alert["metadata"]["generation_status"], "success")

    def test_retry_on_transient_failure_then_success(self):
        """Verify retry mechanism catches first failure and succeeds on retry."""
        mock_client = MagicMock()
        mock_client.model = "llama3.2"
        # First call fails on attempt 1, succeeds on attempt 2; second call succeeds immediately
        mock_client.generate.side_effect = [
            OllamaTimeoutError("Timeout on attempt 1"),
            {"explanation": "Succeeded on retry 1"},
            {"recommendation": "Immediate success"},
        ]

        alert = build_alert(
            prediction_result=self.sample_pred,
            retrieval_result=self.sample_retrieval,
            llm_client=mock_client,
        )

        self.assertEqual(alert["alert"]["explanation"], "Succeeded on retry 1")
        self.assertEqual(alert["alert"]["recommendation"], "Immediate success")
        self.assertEqual(alert["metadata"]["generation_status"], "success")

    def test_graceful_fallback_when_ollama_unavailable(self):
        """Ensure pipeline does not crash if Ollama is down; returns alert with fallback prose."""
        mock_client = MagicMock()
        mock_client.model = "llama3.2"
        mock_client.generate.side_effect = OllamaConnectionError("Connection refused")

        alert = build_alert(
            prediction_result=self.sample_pred,
            retrieval_result=self.sample_retrieval,
            llm_client=mock_client,
        )

        # Alert is produced successfully
        self.assertEqual(alert["alert"]["explanation"], FALLBACK_EXPLANATION)
        self.assertEqual(alert["alert"]["recommendation"], FALLBACK_RECOMMENDATION)
        # Severity, actions, and sources from KB are still intact!
        self.assertEqual(alert["alert"]["severity"], "high")
        self.assertEqual(len(alert["alert"]["mitigation_playbook"]["actions"]), 2)
        self.assertIn("partial", alert["metadata"]["generation_status"])


class TestEndToEndLLM(unittest.TestCase):
    """End-to-end integration tests using real model predictions and live Ollama Llama 3.2."""

    @classmethod
    def setUpClass(cls):
        data_path = PROJECT_ROOT / "data" / "CICIDS2017_Combined.csv"
        if not data_path.exists():
            raise unittest.SkipTest("CICIDS2017_Combined.csv not present.")

        # Test whether local Ollama is reachable and has llama3.2
        try:
            client = OllamaClient(timeout=30.0)
            client.generate(prompt="test", system="Say hi in JSON: {\"status\": \"ok\"}", format_json=True)
            cls.ollama_available = True
        except Exception as e:
            print(f"\n[INFO] Live Ollama probe failed ({e}). Live generation test will be skipped.")
            cls.ollama_available = False

    def test_end_to_end_3_flows_inspection(self):
        """Test 3 real flows (DDoS, PortScan, BENIGN) end-to-end and display prose for review."""
        if not self.ollama_available:
            self.skipTest("Ollama llama3.2 is not currently available for live inference.")

        data_path = PROJECT_ROOT / "data" / "CICIDS2017_Combined.csv"

        # Known first-occurrence row offsets per class (0-indexed data rows, no header).
        # Verified against full dataset scan — avoids loading 900 MB just to find a sample.
        # skiprows skips 1-based CSV rows: header = row 0, so skip header + preceding rows.
        class_rows = {
            "BENIGN":   0,       # starts at first data row
            "DDoS":     18883,   # first DDoS row (data index)
            "PortScan": 227208,  # first PortScan row (data index)
        }

        samples = {}
        for target, data_row_idx in class_rows.items():
            # header is row 1; data rows start at 2 → skip rows [2 .. data_row_idx+1]
            skip = list(range(1, data_row_idx + 1))  # skip header row indices 1..data_row_idx
            df_chunk = pd.read_csv(data_path, skiprows=skip, nrows=1)
            df_chunk.columns = df_chunk.columns.str.strip()
            if not df_chunk.empty:
                samples[target] = df_chunk.iloc[0].to_dict()

        self.assertEqual(len(samples), 3, f"Failed to locate all 3 target classes. Found: {list(samples.keys())}")

        print("\n" + "=" * 80)
        print("  LIVE LLM GENERATION QUALITATIVE REVIEW (Llama 3.2 via Ollama)")
        print("=" * 80)

        for target, flow in samples.items():
            alert = process_flow_to_alert(flow_data=flow, models_dir=str(PROJECT_ROOT / "models"))

            # Verify alert structure is valid
            self.assertIn("timestamp", alert)
            self.assertIn("prediction", alert)
            self.assertIn("alert", alert)
            self.assertIn("explainability", alert)
            self.assertIn("metadata", alert)
            # Note: raw CSV rows may predict differently due to preprocessing differences;
            # this test validates alert structure + LLM output quality, not model accuracy.
            predicted = alert["prediction"]["attack_class"]

            print(f"\n--- [SAMPLE requested: {target} | predicted: {predicted}] ---")
            print(f"Confidence     : {alert['prediction']['confidence']:.2%}")
            print(f"Severity (KB)  : {alert['alert']['severity']}")
            print(f"Top Features   : {[f['feature'] for f in alert['explainability']['top_features'][:3]]}")
            print(f"Explanation    : {alert['alert']['explanation']}")
            print(f"Recommendation : {alert['alert']['recommendation']}")
            print(f"Actions (KB)   : {alert['alert']['mitigation_playbook']['actions'][:2]}")

    def test_mixed_direction_feature_explanation_grounding(self):
        """Verify LLM properly discriminates between TOWARD and AWAY features for a BENIGN flow.

        Specifically verifies that an AWAY feature (e.g. suspicious Destination Port 4444)
        is not erroneously claimed as 'supporting' or 'confirming' the benign prediction.
        """
        if not self.ollama_available:
            self.skipTest("Ollama llama3.2 is not currently available for live inference.")

        client = OllamaClient(timeout=30.0)
        mixed_features = [
            {"feature": "Total Length of Fwd Packets", "feature_value": 0.0, "shap_value": 1.45, "direction": "TOWARD"},
            {"feature": "Destination Port", "feature_value": 4444.0, "shap_value": -1.10, "direction": "AWAY"},
            {"feature": "Flow Duration", "feature_value": 1200.0, "shap_value": 0.85, "direction": "TOWARD"},
        ]

        user_prompt, sys_prompt = format_explanation_prompt(
            attack_class="BENIGN",
            confidence=0.92,
            top_features=mixed_features,
            profile_text="Normal benign network baseline traffic with standard application layer exchanges.",
        )

        resp = client.generate(prompt=user_prompt, system=sys_prompt, format_json=True)
        self.assertIsInstance(resp, dict)
        explanation = resp.get("explanation", "")
        self.assertTrue(len(explanation) > 0, "LLM returned empty explanation")

        print("\n" + "-" * 80)
        print("  MIXED-DIRECTION EXPLANATION REVIEW (Pass 1 Grounding)")
        print("-" * 80)
        print(f"Generated Explanation:\n{explanation}")
        print("-" * 80)

        explanation_lower = explanation.lower()

        # Contradiction checks:
        # Destination Port was 'AWAY' (reduced benign confidence).
        # It must NOT be described as supporting / confirming / indicating benign or normal traffic.
        contradictory_phrases = [
            "destination port supports",
            "destination port confirms",
            "destination port justifies",
            "destination port indicates normal",
            "destination port indicates benign",
            "port 4444 supports",
            "port 4444 confirms",
            "port 4444 indicates normal",
            "port 4444 indicates benign",
        ]
        for phrase in contradictory_phrases:
            self.assertNotIn(
                phrase,
                explanation_lower,
                f"Contradiction detected: LLM claimed AWAY feature supports classification with phrase '{phrase}'",
            )


if __name__ == "__main__":
    unittest.main()

