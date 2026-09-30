"""Knowledge Base parser for AXIDS RAG module."""

from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
from typing import Dict, List, Optional, Union
import unicodedata

from rag.config import SEVERITY_LEVELS

logger = logging.getLogger(__name__)

# Translate various Unicode dash variants and replacement characters to a plain hyphen '-'
_DASHES = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufffd"), "-")

# Regex to match URLs
_URL = re.compile(r"https?://[^\s<>\"']+")

# Regex to match Markdown ## headings
_HEADING_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)

# Regex to match bold field labels: **Label:** value
_FIELD_RE = re.compile(r"^\*\*([^*]+?):\*\*\s*(.*)$")


def normalize_key(text: str) -> str:
    """Normalize a class name or feature name into a canonical lookup key.

    - Normalizes Unicode to NFC.
    - Translates all dash variants (en dash, em dash, minus, replacement char U+FFFD) to '-'.
    - Collapses multiple whitespace characters to a single space and strips ends.
    - Applies casefold() for case-insensitive matching.
    - Preserves '.', '/', and '_' untouched.
    """
    t = unicodedata.normalize("NFC", str(text)).translate(_DASHES)
    return re.sub(r"\s+", " ", t).strip().casefold()


def extract_urls(text: str) -> List[str]:
    """Extract, clean, and deduplicate URLs from text in original order.

    Handles edge cases like trailing punctuation and URLs with balanced parentheses.
    """
    urls: List[str] = []
    for u in _URL.findall(text):
        u = u.rstrip(".,;:")
        while u.endswith(")") and u.count(")") > u.count("("):
            u = u[:-1]
        urls.append(u)
    return list(dict.fromkeys(urls))  # deduplicate preserving order


@dataclass
class Section:
    """Represents a single parsed chunk / section of the Knowledge Base."""
    doc_type: str
    key: str
    key_norm: str
    text: str
    fields: Dict[str, str] = field(default_factory=dict)
    urls: List[str] = field(default_factory=list)
    severity: Optional[str] = None
    actions: List[str] = field(default_factory=list)


def parse_kb_file(
    path: Union[str, Path],
    doc_type: str,
    include_mitre: bool = True,
) -> List[Section]:
    """Parse a Markdown Knowledge Base file into structured Section objects.

    Args:
        path: Path to the markdown file.
        doc_type: One of 'attack_profiles', 'mitigations', 'feature_glossary'.
        include_mitre: If False, drops MITRE ATT&CK lines from text and fields.

    Returns:
        List[Section]: Parsed section chunks.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"KB file not found: {file_path}")

    content = file_path.read_text(encoding="utf-8-sig")

    # Find heading positions
    matches = list(_HEADING_RE.finditer(content))
    if not matches:
        return []

    sections: List[Section] = []

    for i, match in enumerate(matches):
        key = match.group(1).strip()
        start_body = match.end()
        end_body = matches[i + 1].start() if i + 1 < len(matches) else len(content)

        body_raw = content[start_body:end_body]
        lines = [line.rstrip() for line in body_raw.splitlines()]

        fields: Dict[str, str] = {}
        current_field: Optional[str] = None
        current_field_lines: List[str] = []
        action_bullets: List[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
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
                    if current_field == "Actions" and stripped.startswith("- "):
                        action_bullets.append(stripped[2:].strip())

        if current_field:
            fields[current_field] = "\n".join(current_field_lines).strip()

        # Handle MITRE exclusion if requested
        if not include_mitre:
            fields.pop("MITRE ATT&CK", None)

        # Parse severity for mitigations
        severity: Optional[str] = None
        if doc_type == "mitigations" and "Severity" in fields:
            sev_raw = fields["Severity"].strip()
            first_word = sev_raw.split()[0].lower() if sev_raw else ""
            if first_word in SEVERITY_LEVELS:
                severity = first_word
            else:
                severity = first_word or None

        # Parse URLs from Source field
        source_text = fields.get("Source", "")
        urls = extract_urls(source_text)

        # Build clean section text (Heading + filtered body)
        cleaned_body_lines: List[str] = []
        for line in lines:
            if not include_mitre and line.strip().startswith("**MITRE ATT&CK:**"):
                continue
            cleaned_body_lines.append(line)

        body_text = "\n".join(cleaned_body_lines).strip()
        full_text = f"## {key}\n{body_text}".strip()

        sections.append(
            Section(
                doc_type=doc_type,
                key=key,
                key_norm=normalize_key(key),
                text=full_text,
                fields=fields,
                urls=urls,
                severity=severity,
                actions=action_bullets,
            )
        )

    return sections
