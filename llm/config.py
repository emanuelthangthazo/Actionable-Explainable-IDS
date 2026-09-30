"""Configuration settings and constants for the AXIDS LLM module."""

from pathlib import Path

# Local Ollama connection settings (strictly localhost, no cloud API fallback)
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"
DEFAULT_TIMEOUT = 120.0  # seconds per generation call (Llama 3.2 needs ~60-90s on CPU)

# Retry policy for LLM generation
MAX_RETRIES = 2
BACKOFF_FACTOR = 1.0  # seconds (retry 1: 1s, retry 2: 2s)

# Fallback strings when generation is unavailable or exhausted
FALLBACK_EXPLANATION = "LLM explanation unavailable."
FALLBACK_RECOMMENDATION = "LLM recommendation unavailable."
