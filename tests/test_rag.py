"""Comprehensive tests for the AXIDS RAG module."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag.config import (
    FEATURE_COLUMNS_PATH,
    KB_DIR,
    KB_FILES,
    LABEL_ENCODER_PATH,
)
from rag.kb_parser import extract_urls, normalize_key, parse_kb_file
from rag.validate_kb import validate_kb


class TestNormalizeKey(unittest.TestCase):
    """Unit tests for normalize_key."""

    def test_dash_variants_and_replacement_char(self):
        # Three variants: en dash (U+2013), plain hyphen, replacement char (U+FFFD)
        en_dash = "Web Attack \u2013 Brute Force"
        hyphen = "Web Attack - Brute Force"
        replacement = "web  attack \ufffd brute force"
        em_dash = "Web Attack \u2014 Brute Force"

        k_en = normalize_key(en_dash)
        k_hy = normalize_key(hyphen)
        k_rep = normalize_key(replacement)
        k_em = normalize_key(em_dash)

        self.assertEqual(k_en, "web attack - brute force")
        self.assertEqual(k_en, k_hy)
        self.assertEqual(k_en, k_rep)
        self.assertEqual(k_en, k_em)

    def test_distinct_features_preserved(self):
        k1 = normalize_key("Fwd Header Length")
        k2 = normalize_key("Fwd Header Length.1")
        self.assertNotEqual(k1, k2)
        self.assertEqual(k1, "fwd header length")
        self.assertEqual(k2, "fwd header length.1")

    def test_punctuation_preserved(self):
        # ., /, _ must not be stripped or modified
        text = "Flow_IAT.Min / Max_val"
        norm = normalize_key(text)
        self.assertEqual(norm, "flow_iat.min / max_val")


class TestExtractUrls(unittest.TestCase):
    """Unit tests for extract_urls."""

    def test_url_with_parentheses(self):
        # URL containing parentheses must remain intact
        url_with_parens = (
            "https://owasp.org/www-community/attacks/A7_2017-Cross-Site_Scripting_(XSS)"
        )
        text = f"Check this source: {url_with_parens} for more details."
        extracted = extract_urls(text)
        self.assertEqual(extracted, [url_with_parens])

    def test_url_trailing_punctuation(self):
        text = "Sources: https://example.com/doc., https://example.org/path; and https://test.org/end:"
        extracted = extract_urls(text)
        self.assertEqual(
            extracted,
            [
                "https://example.com/doc",
                "https://example.org/path",
                "https://test.org/end",
            ],
        )

    def test_url_deduplication_preserves_order(self):
        text = "https://a.com https://b.com https://a.com https://c.com"
        extracted = extract_urls(text)
        self.assertEqual(extracted, ["https://a.com", "https://b.com", "https://c.com"])


class TestKBParser(unittest.TestCase):
    """Unit tests for parse_kb_file."""

    def test_real_kb_section_counts(self):
        profiles = parse_kb_file(KB_DIR / KB_FILES["attack_profiles"], doc_type="attack_profiles")
        mitigations = parse_kb_file(KB_DIR / KB_FILES["mitigations"], doc_type="mitigations")
        glossary = parse_kb_file(KB_DIR / KB_FILES["feature_glossary"], doc_type="feature_glossary")

        self.assertEqual(len(profiles), 15)
        self.assertEqual(len(mitigations), 14)
        self.assertEqual(len(glossary), 78)

    def test_en_dash_preserved_in_heading(self):
        profiles = parse_kb_file(KB_DIR / KB_FILES["attack_profiles"], doc_type="attack_profiles")
        web_attacks = [p for p in profiles if "Web Attack" in p.key]
        self.assertEqual(len(web_attacks), 3)
        for p in web_attacks:
            self.assertIn("\u2013", p.key, f"Heading '{p.key}' should contain en-dash U+2013")

    def test_crlf_and_bom_handling(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / "test_crlf.md"
            sample_content = (
                "\ufeff# Test Title\r\n\r\n"
                "## Test Class\r\n"
                "**Summary:** Test summary\r\n"
                "**Flow-level signature:** Test sig\r\n"
                "**Typical impact:** Test impact\r\n"
                "**Tools/dataset context:** Test context\r\n"
                "**MITRE ATT&CK:** None\r\n"
                "**Source:** https://example.com\r\n"
            )
            tmp_path.write_bytes(sample_content.encode("utf-8-sig"))

            sections = parse_kb_file(tmp_path, doc_type="attack_profiles")
            self.assertEqual(len(sections), 1)
            sec = sections[0]
            self.assertEqual(sec.key, "Test Class")
            self.assertEqual(sec.fields["Summary"], "Test summary")
            self.assertEqual(sec.urls, ["https://example.com"])

    def test_mitigation_parsing_details(self):
        mitigations = parse_kb_file(KB_DIR / KB_FILES["mitigations"], doc_type="mitigations")
        hulk = next((m for m in mitigations if m.key == "DoS Hulk"), None)
        self.assertIsNotNone(hulk)
        self.assertEqual(hulk.severity, "high")
        self.assertGreater(len(hulk.actions), 0)
        self.assertTrue(all(isinstance(a, str) and len(a) > 0 for a in hulk.actions))
        self.assertGreater(len(hulk.urls), 0)

    def test_include_mitre_flag(self):
        profile_path = KB_DIR / KB_FILES["attack_profiles"]
        sec_with = parse_kb_file(profile_path, doc_type="attack_profiles", include_mitre=True)
        sec_without = parse_kb_file(profile_path, doc_type="attack_profiles", include_mitre=False)

        goldeneye_with = next(s for s in sec_with if s.key == "DoS GoldenEye")
        goldeneye_without = next(s for s in sec_without if s.key == "DoS GoldenEye")

        self.assertIn("MITRE ATT&CK", goldeneye_with.fields)
        self.assertIn("**MITRE ATT&CK:**", goldeneye_with.text)

        self.assertNotIn("MITRE ATT&CK", goldeneye_without.fields)
        self.assertNotIn("**MITRE ATT&CK:**", goldeneye_without.text)


class TestKBValidator(unittest.TestCase):
    """Unit tests for validate_kb."""

    def test_real_kb_passes_validation(self):
        is_valid, errors, warnings, stats = validate_kb()
        self.assertTrue(is_valid, f"Validation failed with errors: {errors}")
        self.assertEqual(len(errors), 0)
        self.assertEqual(stats["section_counts"]["attack_profiles"], 15)
        self.assertEqual(stats["section_counts"]["mitigations"], 14)
        self.assertEqual(stats["section_counts"]["feature_glossary"], 78)

    def test_validator_detects_broken_kb(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_kb = Path(tmpdir)
            # Copy valid KB files first
            for fname in KB_FILES.values():
                shutil.copy2(KB_DIR / fname, tmp_kb / fname)

            # 1. Test missing field
            broken_profile = (tmp_kb / KB_FILES["attack_profiles"]).read_text(encoding="utf-8-sig")
            broken_profile_missing_field = broken_profile.replace("**Summary:**", "**WrongField:**", 1)
            (tmp_kb / KB_FILES["attack_profiles"]).write_text(broken_profile_missing_field, encoding="utf-8-sig")

            is_valid, errors, _, _ = validate_kb(kb_dir=tmp_kb)
            self.assertFalse(is_valid)
            self.assertTrue(any("missing required field" in e for e in errors))

            # 2. Test duplicate heading
            dup_profile = broken_profile + "\n\n## BENIGN\n**Summary:** dup\n**Flow-level signature:** sig\n**Typical impact:** imp\n**Tools/dataset context:** ctx\n**MITRE ATT&CK:** None\n**Source:** https://example.com\n"
            (tmp_kb / KB_FILES["attack_profiles"]).write_text(dup_profile, encoding="utf-8-sig")

            is_valid, errors, _, _ = validate_kb(kb_dir=tmp_kb)
            self.assertFalse(is_valid)
            self.assertTrue(any("Duplicate normalized heading" in e for e in errors))

            # 3. Test invalid severity
            shutil.copy2(KB_DIR / KB_FILES["attack_profiles"], tmp_kb / KB_FILES["attack_profiles"])
            mitigation_text = (tmp_kb / KB_FILES["mitigations"]).read_text(encoding="utf-8-sig")
            bad_sev_text = mitigation_text.replace("**Severity:** high", "**Severity:** extreme", 1)
            (tmp_kb / KB_FILES["mitigations"]).write_text(bad_sev_text, encoding="utf-8-sig")

            is_valid, errors, _, _ = validate_kb(kb_dir=tmp_kb)
            self.assertFalse(is_valid)
            self.assertTrue(any("invalid severity" in e for e in errors))


class TestBuildIndex(unittest.TestCase):
    """Integration tests for build_index with ChromaDB."""

    def test_build_index_temp_dir_counts_and_manifest(self):
        import gc
        from rag.build_index import build_index, compute_kb_hash

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_db = Path(tmpdir) / "chroma_db"
            manifest = build_index(kb_dir=KB_DIR, db_dir=tmp_db)

            # Check chunk count and breakdown
            self.assertEqual(manifest["n_chunks"], 107)
            self.assertEqual(manifest["chunk_count"], 107)
            self.assertEqual(manifest["doc_type_counts"]["attack_profiles"], 15)
            self.assertEqual(manifest["doc_type_counts"]["mitigations"], 14)
            self.assertEqual(manifest["doc_type_counts"]["feature_glossary"], 78)
            self.assertIn("file_hashes", manifest)
            self.assertEqual(len(manifest["file_hashes"]), 3)

            # Check manifest file on disk
            manifest_file = tmp_db / "index_manifest.json"
            self.assertTrue(manifest_file.exists())

            with open(manifest_file, "r", encoding="utf-8") as f:
                disk_manifest = json.load(f)

            self.assertEqual(disk_manifest["n_chunks"], 107)
            self.assertEqual(disk_manifest["chunk_count"], 107)
            self.assertEqual(disk_manifest["kb_hash"], compute_kb_hash())
            self.assertEqual(disk_manifest["embedding_model"], "all-MiniLM-L6-v2")

            # Check idempotency: second build produces identical results and exactly 107 chunks
            manifest2 = build_index(kb_dir=KB_DIR, db_dir=tmp_db)
            self.assertEqual(manifest2["n_chunks"], 107)
            self.assertEqual(manifest2["kb_hash"], manifest["kb_hash"])

            # Verify collection contents and metadata fields directly
            import chromadb
            from chromadb.config import Settings
            from rag.config import COLLECTION_NAME

            client = chromadb.PersistentClient(
                path=str(tmp_db),
                settings=Settings(anonymized_telemetry=False),
            )
            col = client.get_collection(name=COLLECTION_NAME)
            self.assertEqual(col.count(), 107)

            # Test retrieving a sample chunk and inspecting metadata
            sample = col.get(ids=["attack_profiles::dos hulk"])
            self.assertEqual(len(sample["ids"]), 1)
            meta = sample["metadatas"][0]
            self.assertEqual(meta["chunk_type"], "attack_profiles")
            self.assertEqual(meta["normalized_key"], "dos hulk")
            self.assertEqual(meta["source_file"], "attack_profiles.md")

            # Test cosine distance properties via query with identical text
            doc_text = sample["documents"][0]
            query_res = col.query(query_texts=[doc_text], n_results=1)
            top_dist = query_res["distances"][0][0]
            # Cosine distance for identical text should be virtually 0 (< 1e-4)
            self.assertLess(top_dist, 0.001)

            # Properly release ChromaDB references and system cache on Windows
            del col
            del client
            try:
                chromadb.api.client.SharedSystemClient.clear_system_cache()
            except Exception:
                pass
            gc.collect()

    def test_build_index_aborts_on_invalid_kb(self):
        from rag.build_index import build_index

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_kb = Path(tmpdir) / "kb"
            tmp_kb.mkdir()
            tmp_db = Path(tmpdir) / "chroma_db"

            # Create an invalid attack_profiles missing required fields
            broken_file = tmp_kb / "attack_profiles.md"
            broken_file.write_text("## Incomplete Attack\n**Summary:** only summary\n", encoding="utf-8-sig")

            # Copy other files
            shutil.copy2(KB_DIR / KB_FILES["mitigations"], tmp_kb / KB_FILES["mitigations"])
            shutil.copy2(KB_DIR / KB_FILES["feature_glossary"], tmp_kb / KB_FILES["feature_glossary"])

            with self.assertRaises(ValueError) as ctx:
                build_index(kb_dir=tmp_kb, db_dir=tmp_db)

            self.assertIn("validation failed", str(ctx.exception).lower())


class TestRetriever(unittest.TestCase):
    """Integration tests for KnowledgeRetriever and retrieve()."""

    def test_all_15_model_classes_exact_retrieval(self):
        import joblib
        from rag.retriever import retrieve

        encoder = joblib.load(LABEL_ENCODER_PATH)
        classes = [str(c) for c in encoder.classes_]
        self.assertEqual(len(classes), 15)

        sample_features = ["Flow Duration", "Bwd Packet Length Std", "Average Packet Size"]

        for cls_name in classes:
            res = retrieve(attack_class=cls_name, top_features=sample_features)
            self.assertTrue(res.found, f"Class '{cls_name}' was not found")
            self.assertEqual(res.match_type, "exact", f"Class '{cls_name}' did not match exactly")
            self.assertIsNotNone(res.profile, f"Class '{cls_name}' missing profile")
            self.assertEqual(len(res.features), len(sample_features))

            if cls_name == "BENIGN":
                self.assertIsNone(res.mitigation, "BENIGN should not have a mitigation chunk")
            else:
                self.assertIsNotNone(res.mitigation, f"Attack '{cls_name}' missing mitigation")
                self.assertGreater(len(res.actions), 0, f"Attack '{cls_name}' has no actions")
                self.assertGreater(len(res.sources), 0, f"Attack '{cls_name}' has no sources")

    def test_dash_variations_match_exact(self):
        from rag.retriever import retrieve

        # Test plain hyphen
        res_hyphen = retrieve(attack_class="Web Attack - Brute Force")
        self.assertTrue(res_hyphen.found)
        self.assertEqual(res_hyphen.match_type, "exact")
        self.assertEqual(res_hyphen.profile.key, "Web Attack \u2013 Brute Force")

        # Test replacement character
        res_rep = retrieve(attack_class="Web Attack \ufffd XSS")
        self.assertTrue(res_rep.found)
        self.assertEqual(res_rep.match_type, "exact")
        self.assertEqual(res_rep.profile.key, "Web Attack \u2013 XSS")

    def test_feature_ordering_dedup_and_missing(self):
        from rag.retriever import retrieve

        test_features = [
            "Flow Duration",
            "Flow Duration",  # duplicate
            "Bwd Packet Length Std",
            "NonExistentFeature_XYZ",  # missing
        ]

        res = retrieve(attack_class="DDoS", top_features=test_features)
        self.assertEqual(len(res.features), 2)
        self.assertEqual(res.features[0].key, "Flow Duration")
        self.assertEqual(res.features[1].key, "Bwd Packet Length Std")
        self.assertEqual(res.missing_features, ["NonExistentFeature_XYZ"])

    def test_semantic_fallback_and_guardrail(self):
        from rag.retriever import retrieve

        # 1. Near-match should trigger semantic fallback and resolve correctly
        res_near = retrieve(attack_class="Slowloris")
        self.assertTrue(res_near.found)
        self.assertEqual(res_near.match_type, "semantic")
        self.assertEqual(res_near.profile.key, "DoS slowloris")
        self.assertTrue(any("Resolved to" in w for w in res_near.warnings))

        # 2. Nonsense / irrelevant query must exceed MAX_DISTANCE and return found=False
        res_nonsense = retrieve(attack_class="banana smoothie recipe")
        self.assertFalse(res_nonsense.found)
        self.assertEqual(res_nonsense.match_type, "none")
        self.assertIsNone(res_nonsense.profile)
        self.assertTrue(any("exceeded threshold" in w or "No relevant" in w for w in res_nonsense.warnings))

    def test_staleness_detection_missing_and_modified_manifest(self):
        import gc
        from rag.build_index import build_index
        from rag.retriever import IndexMissingError, IndexStaleError, KnowledgeRetriever

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_kb = Path(tmpdir) / "kb"
            tmp_kb.mkdir()
            tmp_db = Path(tmpdir) / "chroma_db"

            for fname in KB_FILES.values():
                shutil.copy2(KB_DIR / fname, tmp_kb / fname)

            # Build index in temp dir
            build_index(kb_dir=tmp_kb, db_dir=tmp_db)

            # 1. Valid retriever init passes
            retriever = KnowledgeRetriever(kb_dir=tmp_kb, db_dir=tmp_db, check_staleness=True)
            res = retriever.retrieve(attack_class="DDoS")
            self.assertTrue(res.found)
            retriever.close()
            del retriever
            gc.collect()

            # 2. Modify a KB file -> raises IndexStaleError
            (tmp_kb / KB_FILES["mitigations"]).write_text("## Modified\n", encoding="utf-8-sig")
            with self.assertRaises(IndexStaleError):
                KnowledgeRetriever(kb_dir=tmp_kb, db_dir=tmp_db, check_staleness=True)

            # 3. Missing manifest -> raises IndexMissingError
            (tmp_db / "index_manifest.json").unlink()
            with self.assertRaises(IndexMissingError):
                KnowledgeRetriever(kb_dir=tmp_kb, db_dir=tmp_db, check_staleness=True)

            try:
                chromadb.api.client.SharedSystemClient.clear_system_cache()
            except Exception:
                pass
            gc.collect()

    def test_json_serialization(self):
        from rag.retriever import retrieve

        res = retrieve(attack_class="DoS Hulk", top_features=["Flow Duration", "Bwd Packet Length Std"])
        d = res.to_dict()
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)

        parsed = json.loads(json_str)
        self.assertEqual(parsed["attack_class"], "DoS Hulk")
        self.assertEqual(parsed["match_type"], "exact")
        self.assertTrue(parsed["found"])
        self.assertEqual(parsed["severity"], "high")
        self.assertIsInstance(parsed["actions"], list)
        self.assertIsInstance(parsed["sources"], list)
        self.assertEqual(len(parsed["features"]), 2)

    def test_end_to_end_pipeline_with_sample_flow(self):
        from explainability.explain import predict_and_explain
        import pandas as pd
        from rag.retriever import retrieve

        data_path = PROJECT_ROOT / "data" / "CICIDS2017_Combined.csv"
        if not data_path.exists():
            self.skipTest("CIC-IDS2017 dataset CSV not found for end-to-end flow test.")

        # Read small sample to avoid loading 921MB file into memory
        df_sample = pd.read_csv(data_path, nrows=50)
        df_sample.columns = df_sample.columns.str.strip()

        row = df_sample.iloc[0].drop("Label", errors="ignore").to_dict()
        expl_result = predict_and_explain(row, top_k=5)

        pred_class = expl_result["predicted_class"]
        top_feature_names = [f["feature"] for f in expl_result["top_features"]]

        rag_result = retrieve(attack_class=pred_class, top_features=top_feature_names)
        self.assertTrue(rag_result.found)
        self.assertEqual(rag_result.match_type, "exact")
        self.assertIsNotNone(rag_result.profile)
        self.assertEqual(len(rag_result.features), len(top_feature_names))
        self.assertEqual(len(rag_result.missing_features), 0)


def run_rag_tests() -> bool:
    """Run all RAG unit and integration tests with formatted output."""
    print("=" * 80)
    print("  RUNNING AXIDS RAG UNIT & INTEGRATION TESTS")
    print("=" * 80)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestNormalizeKey))
    suite.addTests(loader.loadTestsFromTestCase(TestExtractUrls))
    suite.addTests(loader.loadTestsFromTestCase(TestKBParser))
    suite.addTests(loader.loadTestsFromTestCase(TestKBValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestBuildIndex))
    suite.addTests(loader.loadTestsFromTestCase(TestRetriever))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_rag_tests()
    sys.exit(0 if success else 1)

