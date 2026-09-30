# RAG_TASK.md: Build the AXIDS RAG module (`rag/`)

This is a task specification for a coding agent. `AGENTS.md` (project rules) still applies in full. This file is the specific job. If the two ever conflict, or anything here conflicts with what you find in the repo, **stop and ask the user** instead of choosing.

Correctness matters more than speed. Every step below has a check. Do not skip checks, do not weaken them, and do not report a step as done until its check has actually passed in this session.

---

## 1. Goal and scope

Build the retrieval half of Stage 2: given a predicted attack class and the ranked SHAP feature names for one flow, return the matching knowledge-base (KB) chunks in a structured, JSON-serializable object that the later `llm/` stage can put into a prompt.

**In scope**
- `rag/` package: config, KB parser, KB validator, index builder, retriever, small demo CLI
- Tests for all of it
- `requirements` update, `.gitignore` update, short `rag/README.md`

**Out of scope (do NOT build or touch)**
- `llm/`, prompts, Ollama, alert builder
- Any Stage 1 code: `preprocessing/`, `models/*.py`, `explainability/`, `check_leakage.py`
- Any model artifact: `models/best_model.pkl`, `models/feature_columns.json`, `models/label_encoder.pkl`
- **The KB content itself** (`rag/kb/*.md`). Never edit, reformat, or "fix" it. If you find a problem, report it. The user owns the content.

**Decisions already made (do not reopen)**
1. Vector store: **ChromaDB**, persisted locally.
2. MITRE ATT&CK lines are already inside the KB profiles. Keep them, behind one config flag `INCLUDE_MITRE` (default `True`).
3. Single-pass vs two-pass LLM prompting is irrelevant to this task.

---

## 2. Ground truth: what already exists

### 2.1 KB files

Expected in `rag/kb/`. Canonical names:

| File | Sections | Heading is |
|---|---|---|
| `attack_profiles.md` | 15 | attack class (includes `BENIGN`) |
| `mitigations.md` | 14 | attack class (no `BENIGN`) |
| `feature_glossary.md` | 78 | feature name |

Each `## Heading` is one chunk. Text before the first `##` (a `# Title` and an intro paragraph) is not a chunk. Sections use bold field labels, one per line:

- attack_profiles: `Summary`, `Flow-level signature`, `Typical impact`, `Tools/dataset context`, `MITRE ATT&CK`, `Source`
- mitigations: `Severity`, `Actions` (followed by `- ` bullet lines), `Monitoring`, `Source`
- feature_glossary: `Measures`, `High values`, `Low values`, `Relevant attacks`, `Source`

Field line format: `**Label:** value`. `Source` holds one or more URLs separated by spaces. `Severity` looks like `high — one sentence why` (em dash). Allowed levels: `low`, `medium`, `high`, `critical`.

If the files currently have the names `AXIDS attack profiles.md`, `AXIDS mitigations.md`, `AXIDS feature glossary.md`, move them to the canonical names (move, not edit). Verify byte-identical content by comparing SHA-256 before and after.

### 2.2 Source of truth for names

`models/label_encoder.pkl` (classes) and `models/feature_columns.json` (features, in model order). KB headings must agree with them. **If they disagree, the model artifacts win and the KB gets reported, never edited.** Load the artifacts the same way the existing code does (check `models/predict.py`). Convert class names with `str()`, because they may be `numpy.str_`.

### 2.3 Known KB quirks (expected, not bugs in your code)

- Three classes contain an **en dash (U+2013)**: `Web Attack – Brute Force`, `Web Attack – XSS`, `Web Attack – Sql Injection`. The raw CIC-IDS2017 CSVs sometimes have a garbled character (U+FFFD) or a plain hyphen there instead. Lookups must survive all three.
- Feature `Fwd Header Length.1` is a duplicate column and must stay distinct from `Fwd Header Length`.
- `CWE Flag Count` is the CSV name; the source code calls it CWR. The KB entry says so. Leave it.
- One URL contains parentheses: `.../A7_2017-Cross-Site_Scripting_(XSS)`. A naive URL trimmer breaks it.

### 2.4 Known KB content issues (report in your final report, do NOT fix)

1. `mitigations.md` → `Bot` cites a CISA denial-of-service page that does not cover host-level bot remediation.
2. MITRE IDs are unverified by the user: `T1499.003` (slowloris) and `T1046` (Infiltration, covers only the discovery stage).
3. `feature_glossary.md` "High values" and "Low values" text is repetitive boilerplate across many features (only a handful of distinct sentences). Report the exact count you measure.

---

## 3. Known traps (read before writing code)

**Windows and encoding (the user is on Windows)**
- Open every file with `encoding="utf-8-sig"` (handles a BOM). Never rely on the locale default: on Windows it is cp1252 and turns the en dash into mojibake (`â€“`), which silently breaks every web-attack lookup.
- Use `pathlib` and paths relative to the project root. No absolute paths anywhere.
- Text mode already normalizes `\r\n`. Do not split on a literal `"\n## "`. Match headings with a line-anchored regex such as `^## (.+?)\s*$` in multiline mode.
- ChromaDB's SQLite files stay locked while a client is open. Delete the collection through the client API, never `shutil.rmtree` the folder. In tests, release client references (`del` + `gc.collect()`) before temp-dir cleanup. Do not skip a test to dodge this.

**ChromaDB API**
- Metadata values must be `str`, `int`, `float` or `bool`. **No lists, no `None`.** Store URL lists as a JSON string.
- `collection.get()` returns flat lists. `collection.query()` returns nested lists (one per query). Mixing them up gives silent wrong results.
- A `where` with `$and` needs at least 2 clauses. `$in` needs a non-empty list. Build filters conditionally.
- The distance metric is fixed at collection creation. Verify with a smoke test that distances behave as cosine (identical text is about 0).
- Use the **same embedding function at build time and query time**, passed explicitly.
- Chroma APIs differ between versions. Check the installed version (`pip show chromadb`), write against that version's API, and prove it with a smoke test before building on it.
- Disable telemetry: `Settings(anonymized_telemetry=False)`. This project is local-only.
- The default embedding model (MiniLM via ONNX) downloads its weights once on first use. That is the only network access allowed, and it is a one-time model file, not an API call. Tell the user when it happens. If the download fails, stop and report.

**Dependency safety**
- Installing `chromadb` can upgrade or downgrade shared packages (`numpy`, `pydantic`, and others) and break `xgboost`/`shap`/`scikit-learn`. Run `pip freeze` before and after, diff them, and re-run the existing tests. If anything Stage 1 depends on changed, stop and report the diff. Never upgrade or uninstall existing packages on your own.

**Logic**
- Class names and feature names come from different sources with different spellings. Compare **normalized** keys only (see 4.2). Never compare raw strings.
- Two headings could collide after normalization. Assert they do not.
- A missing feature glossary entry must never be replaced by a semantic guess for a *different* feature. Report it as missing.
- `BENIGN` has no mitigation entry. That is valid, not an error.

---

## 4. Design (implement exactly this)

### 4.1 Files to create

```
rag/
  __init__.py
  config.py        # paths, constants, flags (single place to change anything)
  kb_parser.py     # normalize_key, parse_kb_file, Section, extract_urls
  validate_kb.py   # python -m rag.validate_kb  (gate before indexing)
  build_index.py   # python -m rag.build_index  (KB -> ChromaDB)
  retriever.py     # KnowledgeRetriever, retrieve(), demo CLI
  README.md        # short, presentable
  kb/              # given, read-only
  chroma_db/       # generated, gitignored
tests/
  test_rag.py      # match the runner style of test_pipeline.py (see 7)
```

Every function that reads or writes a path takes it as a parameter with the config value as the default (for example `kb_dir`, `db_dir`). Tests must be able to point at temp folders.

### 4.2 `config.py`

`PROJECT_ROOT = Path(__file__).resolve().parents[1]`, then `KB_DIR`, `DB_DIR`, `MANIFEST_PATH` (`DB_DIR / "index_manifest.json"`), `COLLECTION_NAME = "axids_kb"`, `KB_FILES = {"attack_profiles": "attack_profiles.md", "mitigations": "mitigations.md", "feature_glossary": "feature_glossary.md"}`, `INCLUDE_MITRE = True`, `SEMANTIC_FALLBACK_N = 2`, `MAX_DISTANCE` (calibrated, see 4.7), `SEVERITY_LEVELS = ("low","medium","high","critical")`.

### 4.3 `kb_parser.py`

**`normalize_key(text) -> str`** is the single lookup key function. Reference implementation (reuse it, but you must test it):

```python
import re, unicodedata
_DASHES = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufffd"), "-")

def normalize_key(text: str) -> str:
    t = unicodedata.normalize("NFC", str(text)).translate(_DASHES)
    return re.sub(r"\s+", " ", t).strip().casefold()
```

It must NOT touch `.`, `/`, `_`. Required: `"Web Attack – Brute Force"`, `"Web Attack - Brute Force"` and `"web  attack \ufffd brute force"` normalize equal; `"Fwd Header Length"` and `"Fwd Header Length.1"` do not.

**`extract_urls(text) -> list[str]`**. Reference implementation:

```python
_URL = re.compile(r"https?://[^\s<>\"']+")
def extract_urls(text: str) -> list[str]:
    urls = []
    for u in _URL.findall(text):
        u = u.rstrip(".,;:")
        while u.endswith(")") and u.count(")") > u.count("("):
            u = u[:-1]
        urls.append(u)
    return list(dict.fromkeys(urls))          # de-dupe, keep order
```

**`parse_kb_file(path, doc_type) -> list[Section]`**. `Section` is a dataclass: `doc_type`, `key` (original heading), `key_norm`, `text` (heading line plus body, stripped), `fields: dict[str, str]`, `urls: list[str]`, `severity: str | None`, `actions: list[str]`.
- Field parsing: a line matching `^\*\*(.+?):\*\*\s*(.*)$` starts a field. Following lines that are not a new field are appended to the current one (this is how `Actions` bullets are captured). `actions` = lines starting with `- ` under `Actions`, without the dash.
- `severity` = first word of the `Severity` field, lowercased, must be in `SEVERITY_LEVELS`. Parse it only for `mitigations`.
- `urls` come from the `Source` field via `extract_urls`.
- If `INCLUDE_MITRE` is `False`, drop the `MITRE ATT&CK` line from `text` and `fields`. Validation always runs on the raw file.

### 4.4 `validate_kb.py` (`python -m rag.validate_kb`, exit 0 or 1)

Loads the KB plus the model artifacts. **Errors (exit 1):**
- a KB file missing
- duplicate normalized headings inside one file
- a section missing a required field for its doc type (see 2.1)
- a section with zero URLs in `Source`
- a mitigation with an invalid `Severity` or zero actions
- a model class missing from `attack_profiles`
- a model class other than `BENIGN` missing from `mitigations`
- a model feature missing from `feature_glossary`

**Warnings (exit still 0):** KB headings that match no model class or feature (for example `Fwd Header Length.1` if the model dropped it), sections over 250 words, and a count of sections containing "Not verified".

Print a short summary table. If the model needs a class or feature that the KB lacks: **do not write KB content. Stop and report it.**

### 4.5 `build_index.py` (`python -m rag.build_index`)

`build_index(kb_dir=KB_DIR, db_dir=DB_DIR) -> dict`:
1. Run the validator. Abort on errors.
2. Parse all three files. Chunk text = the section `text`.
3. Create `chromadb.PersistentClient(path=str(db_dir), settings=Settings(anonymized_telemetry=False))`.
4. If the collection exists, `delete_collection` it, then create it fresh with **cosine** distance and the explicit embedding function.
5. Add with `ids = f"{doc_type}::{key_norm}"`, `documents = text`, and metadata `{doc_type, key, key_norm, source_file, severity (or ""), urls_json (JSON string)}`. No lists, no `None`.
6. Verify `collection.count()` equals the number of parsed sections. Verify every id can be read back with `get`.
7. Write `index_manifest.json`: `kb_hash`, `n_chunks`, per-doc-type counts, `chromadb_version`, `embedding_model`, `include_mitre`, `built_at`.
   - `kb_hash` = SHA-256 over the three KB files' bytes (fixed order, with filenames) plus the `INCLUDE_MITRE` flag.
8. Print a summary. It must be **idempotent**: running it twice gives the same count and hash.

Expected count for the current KB: 15 + 14 + 78 = **107**. If you get a different number, explain why before continuing.

### 4.6 `retriever.py`

`KnowledgeRetriever(kb_dir=KB_DIR, db_dir=DB_DIR)` plus a module-level `retrieve(...)` that uses a lazily created shared instance. Loading the embedding model per call is too slow, so cache the client and collection.

**Staleness gate, on init.** Recompute the KB hash and compare with the manifest.
- Manifest missing → raise `IndexMissingError("Run: python -m rag.build_index")`.
- Hash differs → raise `IndexStaleError("KB changed since the index was built. Run: python -m rag.build_index")`.
Fail loudly. Never answer from a stale index.

**`retrieve(attack_class: str, top_features: Sequence[str]) -> RetrievalResult`.** Deterministic first, semantic only as a guarded fallback:

1. `class_norm = normalize_key(attack_class)`.
2. Exact lookup with `get(where=...)` on `key_norm` and `doc_type`:
   - profile from `attack_profiles`
   - mitigation from `mitigations` (may legitimately be absent for `BENIGN`)
3. For each feature in `top_features`, in the given order, de-duplicated, exact lookup in `feature_glossary`. Features with no entry go to `missing_features`. Never substitute another feature.
4. **Semantic fallback** only if the class has no exact profile: query restricted to `doc_type in [attack_profiles, mitigations]`, text `f"{attack_class}. Features: {', '.join(top_features)}"`, `n_results=SEMANTIC_FALLBACK_N`, dropping any hit with `distance > MAX_DISTANCE`. Mark `match_type="semantic"` and add a warning. If nothing survives: `match_type="none"`, `found=False`.
5. Never raise on unknown input. Return a `RetrievalResult` with `found=False` and a warning. It must raise only for the two index errors above.

**`RetrievalResult`** (dataclass, with `to_dict()` that is `json.dumps`-safe):

| Field | Meaning |
|---|---|
| `attack_class` | as given |
| `match_type` | `"exact"`, `"semantic"` or `"none"` |
| `found` | a profile or mitigation was retrieved |
| `profile`, `mitigation` | `Chunk` or `None` |
| `features` | `list[Chunk]`, in SHAP order |
| `missing_features` | names with no glossary entry |
| `severity` | parsed from the mitigation, else `None` |
| `actions` | parsed from the mitigation, else `[]` |
| `sources` | de-duplicated URLs: mitigation first, then profile, then features |
| `kb_files` | KB file names actually used |
| `warnings` | human-readable strings |

`Chunk`: `doc_type`, `key`, `text`, `fields`, `urls`.

Why `severity`, `actions` and `sources` are parsed here: the later alert must take them from the KB, not from what the LLM writes, so they cannot be hallucinated.

**Demo CLI** (for presentations): `python -m rag.retriever --attack-class "DDoS" --features "Flow Duration" "Bwd Packet Length Std"` prints a readable summary. (`--attack-class`, not `--class`, because `class` is a Python keyword.)

### 4.7 Calibrating `MAX_DISTANCE`

Do not guess. After the index is built, measure cosine distances for (a) queries that should hit, such as `"Slowloris"`, `"slow http attack"`, `"ssh brute force"`; and (b) queries that should not, such as `"banana smoothie recipe"`, `"quarterly sales forecast"`. Pick a threshold with a clear margin between the two groups. Record the measured numbers in a comment next to the constant and in your final report. If the groups overlap so badly that no safe threshold exists, set the fallback off (`SEMANTIC_FALLBACK_N = 0`), say so, and let the user decide.

---

## 5. Phases and gates

Work in this order. Do not start a phase until the previous gate passes.

**Phase 0: Preflight (no code yet).** Then produce a plan and **stop for the user's approval.**
- Read `AGENTS.md`, `models/predict.py` (artifact loading), `explainability/explain.py` (**find the exact return structure of `predict_and_explain()`; do not assume key names**), `test_pipeline.py` (test style and how it gets sample flows), and any requirements file.
- Run the existing tests. Record the exact pass counts. If the baseline is not green, stop and report.
- Record SHA-256 of the three `models/` artifacts. You will re-check them at the end.
- Save `pip freeze` output for later diffing. Check the Python version. Check whether `chromadb` is installed.
- Confirm the KB files exist with canonical names (see 2.1).
- Load the label encoder and feature list, and print the classes and the first 10 features, to prove loading works.

**Phase 1: config, parser, validator.** Gate: `python -m rag.validate_kb` exits 0 on the real KB; parser and normalization unit tests pass.

**Phase 2: index builder.** Gate: `python -m rag.build_index` reports 107 chunks, is idempotent, and writes the manifest.

**Phase 3: retriever and calibration.** Gate: every model class retrieves correctly, and calibration numbers are recorded.

**Phase 4: integration and cleanup.** Gate: full test suite green (existing plus new), artifact hashes unchanged, docs and requirements done.

---

## 6. Guardrails

- Never edit `rag/kb/*.md`, Stage 1 code, model artifacts, or existing tests.
- No cloud LLM or cloud API dependencies. No network calls except the one-time embedding model download.
- Do not run `git commit`, `git push`, `git reset`, `git clean` or `git checkout`. Only add missing lines to `.gitignore` (`rag/chroma_db/`, `__pycache__/`, `.pytest_cache/`).
- The only files you may delete are regenerated ones inside `rag/chroma_db/`.
- No `except: pass`, no swallowed exceptions, no silently loosened assertions or thresholds. If a test fails, fix the code or report it. Never edit the test until it passes.
- Python with type hints and docstrings on public functions. Small readable modules. Use `logging` in library code and `print` only in CLIs. This is a student project that will be presented, so clarity beats cleverness.
- Pin the new dependency version you actually tested (for example `chromadb==<installed version>`) in the project's requirements file. Append; do not reorder or bump anything else.

**Stop and ask the user if:** the baseline tests fail; the KB and model artifacts disagree; installing `chromadb` changes packages Stage 1 depends on; the embedding model cannot be downloaded; the `predict_and_explain()` output shape is unclear; or anything here conflicts with the repo.

---

## 7. Tests (required)

Use the runner style of `test_pipeline.py`. If it is plain asserts in a script, write the new file with `unittest` so no new dependency is needed. All Chroma-building tests use temp directories, never the real `rag/chroma_db/`. Test data comes from the real KB and real artifacts, not hardcoded counts.

**Unit (no Chroma):**
- `normalize_key`: the three web-attack spellings match; `Fwd Header Length` vs `Fwd Header Length.1` stay distinct; `.`, `/`, `_` preserved.
- `extract_urls`: the OWASP URL ending in `(XSS)` is kept intact; a trailing period is stripped; duplicates removed.
- Parser: real files parse to the section counts implied by the model artifacts; en dash headings read back as U+2013 (this fails under a wrong encoding); CRLF and BOM inputs parse the same as LF; `severity`, `actions`, `urls` parse correctly for a real mitigation.
- Validator: real KB gives no errors. A deliberately broken temp KB (missing field, duplicate heading, no URL, bad severity, missing class) gives the right errors.
- `INCLUDE_MITRE=False` removes the MITRE line from chunk text.

**Integration (Chroma, temp dir):**
- Build gives the expected count, is idempotent, and the manifest is correct.
- For every model class, `retrieve(cls, five real feature names)` returns `found=True`, the right profile key, a mitigation for everything except `BENIGN`, non-empty `sources` for attacks, and no exceptions. Cover all 15 classes.
- Feature order is preserved; duplicate features de-duplicated; an unknown feature lands in `missing_features` and does not raise.
- `retrieve("Web Attack - Brute Force", ...)` (plain hyphen) matches the en-dash class exactly.
- Semantic fallback: `retrieve("Slowloris", ...)` resolves to `DoS slowloris` with `match_type="semantic"`. A nonsense class gives `found=False` and a warning. If a semantic assertion fails, report it. Do not loosen it silently.
- Staleness: build into a temp dir, change one byte in a temp copy of a KB file, and expect `IndexStaleError`. A missing manifest expects `IndexMissingError`.
- `json.dumps(result.to_dict())` succeeds for a real result.
- **One end-to-end test:** take one real flow the way `test_pipeline.py` obtains sample data → `predict_and_explain()` → extract the feature names using the structure you found in Phase 0 → `retrieve()`. Skip with a clear reason if the dataset is unavailable. Do not load the full dataset into memory for this.

---

## 8. Definition of done

All must be true, with evidence in the final report:

1. `python -m rag.validate_kb` → exit 0.
2. `python -m rag.build_index` → 107 chunks (or an explained number), idempotent.
3. The demo CLI runs and prints a sensible result for at least: `DDoS`, `PortScan`, `Web Attack – XSS`, `BENIGN`, and one nonsense class.
4. Full test suite green: existing tests unchanged in count and passing, plus the new tests. Give before and after counts.
5. SHA-256 of `models/best_model.pkl`, `models/feature_columns.json` and `models/label_encoder.pkl` unchanged from Phase 0.
6. `pip freeze` diff contains only `chromadb` and its own new dependencies. Anything else is explained.
7. `rag/kb/*.md` byte-identical to the versions the user provided (aside from the canonical rename).
8. No absolute paths in code (search for `C:\`, `/Users/`, `/home/`).
9. `.gitignore` and requirements updated. `rag/README.md` written (what it does, how to rebuild, how to query, how to flip `INCLUDE_MITRE`).

---

## 9. Final report format

1. Files created or changed (table).
2. Commands run and their key output (short).
3. Test counts: before and after.
4. `MAX_DISTANCE` calibration numbers and the chosen value.
5. Any deviation from this document, with the reason.
6. KB issues found (include the three known issues in 2.4, with the measured boilerplate count).
7. Anything you could not verify.
8. The `to_dict()` output for one real `DDoS` retrieval, so the user can see the contract the `llm/` stage will consume.

Do not describe anything as done unless its check passed in this session. If a check could not be run, say so plainly.
