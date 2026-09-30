"""Knowledge Base Retriever for AXIDS RAG module."""

import argparse
from dataclasses import asdict, dataclass, field
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Union

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

from rag.build_index import compute_kb_hash
from rag.config import (
    COLLECTION_NAME,
    DB_DIR,
    KB_DIR,
    KB_FILES,
    KB_MANIFEST_PATH,
    MANIFEST_PATH,
    MAX_DISTANCE,
    SEMANTIC_FALLBACK_N,
    SEVERITY_LEVELS,
)
from rag.kb_parser import extract_urls, normalize_key

logger = logging.getLogger(__name__)

# Regex to match bold field labels: **Label:** value
_FIELD_RE = re.compile(r"^\*\*([^*]+?):\*\*\s*(.*)$")


class IndexMissingError(FileNotFoundError):
    """Raised when the vector database or its manifest cannot be found."""
    pass


class IndexStaleError(RuntimeError):
    """Raised when the Knowledge Base on disk has changed since index build."""
    pass


@dataclass
class Chunk:
    """Represents an individual retrieved Knowledge Base chunk."""
    doc_type: str
    key: str
    text: str
    fields: Dict[str, str] = field(default_factory=dict)
    urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert chunk into JSON-serializable dictionary."""
        return {
            "doc_type": self.doc_type,
            "key": self.key,
            "text": self.text,
            "fields": self.fields,
            "urls": self.urls,
        }


@dataclass
class RetrievalResult:
    """Structured, JSON-serializable result returned by retrieve()."""
    attack_class: str
    match_type: str  # "exact", "semantic", or "none"
    found: bool
    profile: Optional[Chunk] = None
    mitigation: Optional[Chunk] = None
    features: List[Chunk] = field(default_factory=list)
    missing_features: List[str] = field(default_factory=list)
    severity: Optional[str] = None
    actions: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    kb_files: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert retrieval result into a clean, JSON-serializable dictionary."""
        return {
            "attack_class": self.attack_class,
            "match_type": self.match_type,
            "found": self.found,
            "profile": self.profile.to_dict() if self.profile else None,
            "mitigation": self.mitigation.to_dict() if self.mitigation else None,
            "features": [f.to_dict() for f in self.features],
            "missing_features": list(self.missing_features),
            "severity": self.severity,
            "actions": list(self.actions),
            "sources": list(self.sources),
            "kb_files": list(self.kb_files),
            "warnings": list(self.warnings),
        }


def _parse_chunk(
    doc_type: str,
    key: str,
    text: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Chunk:
    """Parse raw chunk text and metadata into a structured Chunk object."""
    fields: Dict[str, str] = {}
    current_field: Optional[str] = None
    current_field_lines: List[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("## "):
            continue

        field_match = _FIELD_RE.match(stripped)
        if field_match:
            if current_field:
                fields[current_field] = "\n".join(current_field_lines).strip()
            current_field = field_match.group(1).strip()
            initial_val = field_match.group(2).strip()
            current_field_lines = [initial_val] if initial_val else []
        else:
            if current_field:
                current_field_lines.append(stripped)

    if current_field:
        fields[current_field] = "\n".join(current_field_lines).strip()

    # Extract URLs from metadata or fields
    urls: List[str] = []
    if metadata and "urls_json" in metadata and metadata["urls_json"]:
        try:
            urls = json.loads(metadata["urls_json"])
        except Exception:
            urls = extract_urls(fields.get("Source", ""))
    else:
        urls = extract_urls(fields.get("Source", ""))

    return Chunk(
        doc_type=doc_type,
        key=key,
        text=text,
        fields=fields,
        urls=urls,
    )


def _extract_actions(mitigation_chunk: Optional[Chunk]) -> List[str]:
    """Extract action item bullets from a mitigation chunk."""
    if not mitigation_chunk or "Actions" not in mitigation_chunk.fields:
        return []

    actions: List[str] = []
    for line in mitigation_chunk.fields["Actions"].splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            actions.append(stripped[2:].strip())
        elif stripped.startswith("* "):
            actions.append(stripped[2:].strip())
    return actions


def _extract_severity(mitigation_chunk: Optional[Chunk]) -> Optional[str]:
    """Extract and validate severity from a mitigation chunk."""
    if not mitigation_chunk or "Severity" not in mitigation_chunk.fields:
        return None

    raw_sev = mitigation_chunk.fields["Severity"].strip()
    first_word = raw_sev.split()[0].lower() if raw_sev else ""
    if first_word in SEVERITY_LEVELS:
        return first_word
    return first_word or None


class KnowledgeRetriever:
    """Retriever for AXIDS RAG knowledge base using ChromaDB."""

    def __init__(
        self,
        kb_dir: Union[str, Path] = KB_DIR,
        db_dir: Union[str, Path] = DB_DIR,
        collection_name: str = COLLECTION_NAME,
        max_distance: float = MAX_DISTANCE,
        check_staleness: bool = True,
    ) -> None:
        """Initialize the retriever with staleness validation.

        Args:
            kb_dir: Directory containing Knowledge Base markdown files.
            db_dir: Directory containing persisted ChromaDB vector database.
            collection_name: Name of ChromaDB collection.
            max_distance: Distance threshold for semantic fallback.
            check_staleness: Whether to verify KB hash against index manifest.
        """
        self.kb_dir = Path(kb_dir)
        self.db_dir = Path(db_dir)
        self.collection_name = collection_name
        self.max_distance = max_distance

        # 1. Staleness Gate: Check manifest existence
        manifest_path = self.db_dir / "index_manifest.json"
        if not manifest_path.exists() and self.db_dir == DB_DIR and KB_MANIFEST_PATH.exists():
            manifest_path = KB_MANIFEST_PATH

        if not manifest_path.exists():
            raise IndexMissingError(
                f"Vector index manifest missing at {manifest_path}. Run: python -m rag.build_index"
            )

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # 2. Staleness Gate: Compare KB hash
        if check_staleness:
            include_mitre = manifest.get("include_mitre", True)
            current_kb_hash = compute_kb_hash(kb_dir=self.kb_dir, include_mitre=include_mitre)
            if current_kb_hash != manifest.get("kb_hash"):
                raise IndexStaleError(
                    f"Knowledge Base on disk changed since index was built.\n"
                    f"  Current hash : {current_kb_hash}\n"
                    f"  Manifest hash: {manifest.get('kb_hash')}\n"
                    f"Run: python -m rag.build_index"
                )

        # 3. Initialize ChromaDB client and collection
        self.client = chromadb.PersistentClient(
            path=str(self.db_dir),
            settings=Settings(anonymized_telemetry=False),
        )
        self.embedding_func = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_collection(
            name=self.collection_name,
            embedding_function=self.embedding_func,
        )

    def close(self) -> None:
        """Explicitly close ChromaDB client and release file handles."""
        if hasattr(self, "client"):
            if hasattr(self.client, "close"):
                try:
                    self.client.close()
                except Exception:
                    pass
        try:
            chromadb.api.client.SharedSystemClient.clear_system_cache()
        except Exception:
            pass

    def retrieve(
        self,
        attack_class: str,
        top_features: Sequence[str] = (),
    ) -> RetrievalResult:
        """Retrieve relevant KB chunks for a given attack class and top SHAP features.

        Args:
            attack_class: Predicted attack class name (e.g. 'DDoS', 'DoS Hulk', 'BENIGN').
            top_features: Sequence of top SHAP feature names.

        Returns:
            RetrievalResult: Complete structured retrieval result.
        """
        warnings: List[str] = []
        kb_files_used: List[str] = []

        class_norm = normalize_key(attack_class)

        profile: Optional[Chunk] = None
        mitigation: Optional[Chunk] = None
        match_type: str = "none"

        # 1. Exact lookup for attack profile
        profile_id = f"attack_profiles::{class_norm}"
        try:
            profile_res = self.collection.get(ids=[profile_id])
            if profile_res and profile_res["ids"]:
                key = profile_res["metadatas"][0]["key"]
                doc_text = profile_res["documents"][0]
                meta = profile_res["metadatas"][0]
                profile = _parse_chunk("attack_profiles", key, doc_text, meta)
                kb_files_used.append(KB_FILES["attack_profiles"])
                match_type = "exact"
        except Exception as e:
            logger.warning(f"Error during exact profile lookup for '{attack_class}': {e}")

        # 2. Exact lookup for mitigation (legitimately absent for BENIGN)
        mitigation_id = f"mitigations::{class_norm}"
        try:
            mit_res = self.collection.get(ids=[mitigation_id])
            if mit_res and mit_res["ids"]:
                key = mit_res["metadatas"][0]["key"]
                doc_text = mit_res["documents"][0]
                meta = mit_res["metadatas"][0]
                mitigation = _parse_chunk("mitigations", key, doc_text, meta)
                kb_files_used.append(KB_FILES["mitigations"])
                if match_type == "none":
                    match_type = "exact"
        except Exception as e:
            logger.warning(f"Error during exact mitigation lookup for '{attack_class}': {e}")

        # 3. Guarded Semantic Fallback if profile not found
        if profile is None and class_norm != "benign":
            feature_str = ", ".join(top_features) if top_features else "none"
            query_text = f"{attack_class}. Features: {feature_str}"

            try:
                sem_res = self.collection.query(
                    query_texts=[query_text],
                    n_results=SEMANTIC_FALLBACK_N,
                    where={"doc_type": {"$in": ["attack_profiles", "mitigations"]}},
                )

                if sem_res and sem_res["ids"] and len(sem_res["ids"][0]) > 0:
                    top_dist = sem_res["distances"][0][0]
                    top_id = sem_res["ids"][0][0]
                    top_meta = sem_res["metadatas"][0][0]
                    top_text = sem_res["documents"][0][0]

                    if top_dist <= self.max_distance:
                        match_type = "semantic"
                        dt = top_meta["doc_type"]
                        key = top_meta["key"]
                        matched_chunk = _parse_chunk(dt, key, top_text, top_meta)

                        if dt == "attack_profiles" and profile is None:
                            profile = matched_chunk
                            kb_files_used.append(KB_FILES["attack_profiles"])
                            # Also attempt to grab the matching mitigation for the resolved class
                            resolved_norm = top_meta["key_norm"]
                            mit_id = f"mitigations::{resolved_norm}"
                            m_res = self.collection.get(ids=[mit_id])
                            if m_res and m_res["ids"] and mitigation is None:
                                m_key = m_res["metadatas"][0]["key"]
                                mitigation = _parse_chunk("mitigations", m_key, m_res["documents"][0], m_res["metadatas"][0])
                                kb_files_used.append(KB_FILES["mitigations"])
                        elif dt == "mitigations" and mitigation is None:
                            mitigation = matched_chunk
                            kb_files_used.append(KB_FILES["mitigations"])

                        warnings.append(
                            f"Exact profile for '{attack_class}' not found. Resolved to '{key}' "
                            f"via semantic search (distance {top_dist:.4f} <= {self.max_distance})."
                        )
                    else:
                        warnings.append(
                            f"No relevant knowledge base entry found for attack class '{attack_class}' "
                            f"(nearest match '{top_meta['key']}' distance {top_dist:.4f} exceeded threshold {self.max_distance})."
                        )
                else:
                    warnings.append(f"No semantic match found for attack class '{attack_class}'.")
            except Exception as e:
                logger.warning(f"Error during semantic fallback query for '{attack_class}': {e}")
                warnings.append(f"Semantic search failed: {e}")

        # 4. Feature glossary lookups (exact match only, never substitute a different feature)
        features: List[Chunk] = []
        missing_features: List[str] = []

        seen_features = set()
        for feat in top_features:
            if feat in seen_features:
                continue
            seen_features.add(feat)

            feat_norm = normalize_key(feat)
            feat_id = f"feature_glossary::{feat_norm}"
            try:
                feat_res = self.collection.get(ids=[feat_id])
                if feat_res and feat_res["ids"]:
                    f_key = feat_res["metadatas"][0]["key"]
                    f_text = feat_res["documents"][0]
                    f_meta = feat_res["metadatas"][0]
                    features.append(_parse_chunk("feature_glossary", f_key, f_text, f_meta))
                    if KB_FILES["feature_glossary"] not in kb_files_used:
                        kb_files_used.append(KB_FILES["feature_glossary"])
                else:
                    missing_features.append(feat)
            except Exception as e:
                logger.warning(f"Error looking up feature '{feat}': {e}")
                missing_features.append(feat)

        # 5. Extract structured fields, severity, actions, and sources
        actions = _extract_actions(mitigation)
        severity = _extract_severity(mitigation)

        # Build de-duplicated sources (mitigation first, then profile, then features)
        sources: List[str] = []
        if mitigation:
            sources.extend(mitigation.urls)
        if profile:
            sources.extend(profile.urls)
        for f in features:
            sources.extend(f.urls)
        sources = list(dict.fromkeys(sources))

        found = (profile is not None) or (mitigation is not None)

        return RetrievalResult(
            attack_class=attack_class,
            match_type=match_type,
            found=found,
            profile=profile,
            mitigation=mitigation,
            features=features,
            missing_features=missing_features,
            severity=severity,
            actions=actions,
            sources=sources,
            kb_files=list(dict.fromkeys(kb_files_used)),
            warnings=warnings,
        )


# Shared cached retriever instance
_SHARED_RETRIEVER: Optional[KnowledgeRetriever] = None


def get_default_retriever() -> KnowledgeRetriever:
    """Get or create the shared KnowledgeRetriever instance."""
    global _SHARED_RETRIEVER
    if _SHARED_RETRIEVER is None:
        _SHARED_RETRIEVER = KnowledgeRetriever()
    return _SHARED_RETRIEVER


def retrieve(
    attack_class: str,
    top_features: Sequence[str] = (),
) -> RetrievalResult:
    """Retrieve KB chunks using the shared KnowledgeRetriever instance.

    Args:
        attack_class: Predicted attack class name.
        top_features: Sequence of top SHAP feature names.

    Returns:
        RetrievalResult: Structured retrieval result.
    """
    return get_default_retriever().retrieve(
        attack_class=attack_class,
        top_features=top_features,
    )


def main() -> int:
    """CLI demo entry point for python -m rag.retriever."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="AXIDS Knowledge Base Retriever CLI Demo")
    parser.add_argument(
        "--attack-class",
        type=str,
        required=True,
        help="Predicted attack class name (e.g. 'DDoS', 'DoS Hulk', 'BENIGN')",
    )
    parser.add_argument(
        "--features",
        nargs="*",
        default=[],
        help="List of top SHAP feature names",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as raw formatted JSON",
    )

    args = parser.parse_args()

    try:
        result = retrieve(attack_class=args.attack_class, top_features=args.features)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
            return 0

        print("=" * 80)
        print("  AXIDS RAG RETRIEVAL RESULT")
        print("=" * 80)
        print(f"  Query Attack Class : {result.attack_class}")
        print(f"  Match Type         : {result.match_type.upper()}")
        print(f"  Found              : {result.found}")
        print(f"  Severity           : {result.severity or 'N/A'}")
        print(f"  KB Files Used      : {', '.join(result.kb_files) if result.kb_files else 'None'}")

        if result.profile:
            print("\n[Attack Profile]")
            print(f"  Heading: {result.profile.key}")
            for k, v in result.profile.fields.items():
                val_single = v.replace("\n", " ")
                if len(val_single) > 100:
                    val_single = val_single[:97] + "..."
                print(f"  - {k:<22}: {val_single}")

        if result.mitigation:
            print("\n[Mitigation Playbook]")
            print(f"  Heading: {result.mitigation.key}")
            print(f"  Severity: {result.severity}")
            if result.actions:
                print("  Actions:")
                for a in result.actions:
                    print(f"    * {a}")

        print(f"\n[Feature Glossary ({len(result.features)} matched, {len(result.missing_features)} missing)]")
        for f in result.features:
            print(f"  - {f.key}: {f.fields.get('Measures', '')}")
        if result.missing_features:
            print(f"  - MISSING FEATURES: {', '.join(result.missing_features)}")

        if result.sources:
            print("\n[Sources]")
            for s in result.sources:
                print(f"  - {s}")

        if result.warnings:
            print("\n[Warnings]")
            for w in result.warnings:
                print(f"  ! {w}")

        print("\n" + "=" * 80)
        return 0
    except Exception as e:
        print(f"\n[ERROR] Retrieval failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
