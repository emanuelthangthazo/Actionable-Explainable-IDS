"""Index builder module for AXIDS RAG using ChromaDB."""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

from rag.config import (
    COLLECTION_NAME,
    DB_DIR,
    INCLUDE_MITRE,
    KB_DIR,
    KB_FILES,
    KB_MANIFEST_PATH,
    MANIFEST_PATH,
)
from rag.kb_parser import Section, parse_kb_file
from rag.validate_kb import validate_kb

logger = logging.getLogger(__name__)


def compute_file_hashes(kb_dir: Union[str, Path] = KB_DIR) -> Dict[str, str]:
    """Compute individual SHA-256 hashes for all KB files.

    Args:
        kb_dir: Directory containing KB markdown files.

    Returns:
        Dict[str, str]: Map of filename to hex SHA-256 hash.
    """
    kb_dir = Path(kb_dir)
    file_hashes: Dict[str, str] = {}
    for doc_type in ["attack_profiles", "mitigations", "feature_glossary"]:
        filename = KB_FILES[doc_type]
        file_path = kb_dir / filename
        if file_path.exists():
            file_hashes[filename] = hashlib.sha256(file_path.read_bytes()).hexdigest()
        else:
            file_hashes[filename] = "__MISSING__"
    return file_hashes


def compute_kb_hash(
    kb_dir: Union[str, Path] = KB_DIR,
    include_mitre: bool = INCLUDE_MITRE,
) -> str:
    """Compute deterministic SHA-256 hash of all Knowledge Base files and settings.

    Args:
        kb_dir: Directory containing KB markdown files.
        include_mitre: Whether MITRE ATT&CK lines are included.

    Returns:
        str: Hexadecimal SHA-256 hash.
    """
    kb_dir = Path(kb_dir)
    hasher = hashlib.sha256()
    # Fixed canonical file ordering
    for doc_type in ["attack_profiles", "mitigations", "feature_glossary"]:
        filename = KB_FILES[doc_type]
        file_path = kb_dir / filename
        hasher.update(filename.encode("utf-8"))
        if file_path.exists():
            hasher.update(file_path.read_bytes())
        else:
            hasher.update(b"__MISSING__")

    hasher.update(f"include_mitre={include_mitre}".encode("utf-8"))
    return hasher.hexdigest()


def build_index(
    kb_dir: Union[str, Path] = KB_DIR,
    db_dir: Union[str, Path] = DB_DIR,
    include_mitre: bool = INCLUDE_MITRE,
    client: Optional[Any] = None,
) -> Dict[str, Any]:
    """Build and persist the ChromaDB vector index from Knowledge Base files.

    Args:
        kb_dir: Directory containing the KB files.
        db_dir: Directory where ChromaDB SQLite and index files are persisted.
        include_mitre: Whether to include MITRE ATT&CK lines.
        client: Optional pre-existing ChromaDB client instance.

    Returns:
        Dict[str, Any]: Manifest dictionary describing the built index.
    """
    kb_dir = Path(kb_dir)
    db_dir = Path(db_dir)
    manifest_path = db_dir / "index_manifest.json"

    # 1. Run KB validation first
    is_valid, errors, _, _ = validate_kb(kb_dir=kb_dir)
    if not is_valid:
        raise ValueError(
            f"Knowledge Base validation failed with {len(errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    # 2. Parse all three KB files
    all_sections: List[Section] = []
    doc_type_counts: Dict[str, int] = {}

    for doc_type, filename in KB_FILES.items():
        file_path = kb_dir / filename
        sections = parse_kb_file(file_path, doc_type=doc_type, include_mitre=include_mitre)
        all_sections.extend(sections)
        doc_type_counts[doc_type] = len(sections)

    n_chunks = len(all_sections)
    logger.info(f"Parsed {n_chunks} total chunks across {len(doc_type_counts)} KB files.")

    # 3. Initialize persistent ChromaDB client if not provided
    db_dir.mkdir(parents=True, exist_ok=True)
    created_internal_client = False
    if client is None:
        client = chromadb.PersistentClient(
            path=str(db_dir),
            settings=Settings(anonymized_telemetry=False),
        )
        created_internal_client = True

    try:
        # Explicit embedding function (MiniLM-L6-v2 ONNX)
        embedding_func = embedding_functions.DefaultEmbeddingFunction()

        # 4. If collection exists, delete and recreate fresh with cosine distance
        existing_collections = [c.name for c in client.list_collections()]
        if COLLECTION_NAME in existing_collections:
            client.delete_collection(name=COLLECTION_NAME)

        collection = client.create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
            embedding_function=embedding_func,
        )

        # 5. Prepare batch records
        ids: List[str] = []
        documents: List[str] = []
        metadatas: List[Dict[str, Union[str, int, float, bool]]] = []

        for sec in all_sections:
            chunk_id = f"{sec.doc_type}::{sec.key_norm}"
            ids.append(chunk_id)
            documents.append(sec.text)
            metadatas.append(
                {
                    "chunk_type": sec.doc_type,
                    "doc_type": sec.doc_type,
                    "normalized_key": sec.key_norm,
                    "key_norm": sec.key_norm,
                    "key": sec.key,
                    "source_file": KB_FILES[sec.doc_type],
                    "severity": sec.severity or "",
                    "urls_json": json.dumps(sec.urls),
                }
            )

        collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

        # 6. Verify collection count and readability of all IDs
        count = collection.count()
        if count != n_chunks:
            raise RuntimeError(
                f"ChromaDB collection count mismatch: expected {n_chunks}, got {count}"
            )

        read_back = collection.get(ids=ids)
        if len(read_back["ids"]) != n_chunks:
            raise RuntimeError(
                f"Failed to read back all chunks from collection: retrieved {len(read_back['ids'])} / {n_chunks}"
            )

        # 7. Write index manifest
        kb_hash = compute_kb_hash(kb_dir=kb_dir, include_mitre=include_mitre)
        file_hashes = compute_file_hashes(kb_dir=kb_dir)
        manifest = {
            "kb_hash": kb_hash,
            "file_hashes": file_hashes,
            "chunk_count": n_chunks,
            "n_chunks": n_chunks,
            "doc_type_counts": doc_type_counts,
            "chromadb_version": chromadb.__version__,
            "embedding_model": "all-MiniLM-L6-v2",
            "include_mitre": include_mitre,
            "built_at": datetime.now(timezone.utc).isoformat(),
        }

        # Write to db_dir / index_manifest.json
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # Also write to rag/kb_manifest.json if building the primary database
        if db_dir == DB_DIR:
            with open(KB_MANIFEST_PATH, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

        return manifest
    finally:
        if created_internal_client:
            if hasattr(client, "close"):
                client.close()
            del client
            try:
                chromadb.api.client.SharedSystemClient.clear_system_cache()
            except Exception:
                pass


def main() -> int:
    """CLI entry point for python -m rag.build_index."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    print("=" * 80)
    print("  AXIDS RAG INDEX BUILDER")
    print(f"  KB Directory   : {KB_DIR}")
    print(f"  DB Directory   : {DB_DIR}")
    print(f"  Collection Name: {COLLECTION_NAME}")
    print(f"  Include MITRE  : {INCLUDE_MITRE}")
    print("=" * 80)

    try:
        manifest = build_index()
        print("\n[Build Summary]")
        print(f"  Total Chunks Indexed: {manifest['n_chunks']}")
        for dt, count in manifest["doc_type_counts"].items():
            print(f"    - {dt:<20}: {count}")
        print(f"  KB SHA-256 Hash     : {manifest['kb_hash']}")
        print(f"  ChromaDB Version    : {manifest['chromadb_version']}")
        print(f"  Embedding Model     : {manifest['embedding_model']}")
        print(f"  Built At            : {manifest['built_at']}")
        print(f"  Manifest Path       : {MANIFEST_PATH}")
        if KB_MANIFEST_PATH.exists():
            print(f"  KB Manifest Path    : {KB_MANIFEST_PATH}")
        print("\n" + "=" * 80)
        print("  INDEX BUILD SUCCESSFUL")
        print("=" * 80)
        return 0
    except Exception as e:
        print(f"\n[ERROR] Index build failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
