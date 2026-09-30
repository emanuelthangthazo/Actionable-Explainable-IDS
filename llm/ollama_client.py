"""Thin, robust client wrapper for the local Ollama API (localhost only)."""

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from llm.config import DEFAULT_MODEL, DEFAULT_OLLAMA_HOST, DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)


class OllamaError(Exception):
    """Base exception for all Ollama client errors."""
    pass


class OllamaConnectionError(OllamaError):
    """Raised when connecting to the local Ollama instance fails (e.g., service not running)."""
    pass


class OllamaTimeoutError(OllamaError):
    """Raised when an Ollama API request times out."""
    pass


class OllamaResponseError(OllamaError):
    """Raised when Ollama returns an HTTP error status or malformed response payload."""
    pass


class OllamaClient:
    """Client for querying a locally-hosted Ollama instance on localhost."""

    def __init__(
        self,
        host: str = DEFAULT_OLLAMA_HOST,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

        # Guard against remote/cloud URLs to ensure strict local privacy
        if not (self.host.startswith("http://localhost") or self.host.startswith("http://127.0.0.1")):
            raise ValueError(
                f"AXIDS OllamaClient requires a local host (localhost/127.0.0.1), got: {self.host}"
            )

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        format_json: bool = True,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Send a generation request to the local Ollama server.

        Args:
            prompt: User prompt text.
            system: Optional system prompt instructions.
            model: Model name (defaults to self.model).
            format_json: If True, passes `format: 'json'` to enforce structured output.
            timeout: Request timeout in seconds (defaults to self.timeout).

        Returns:
            Dict[str, Any]: Parsed JSON response dictionary if format_json=True,
                           or {"response": str} if format_json=False.

        Raises:
            OllamaConnectionError: If Ollama server is unreachable or not running.
            OllamaTimeoutError: If the request exceeds the specified timeout.
            OllamaResponseError: If server responds with HTTP error or malformed payload.
        """
        target_model = model or self.model
        req_timeout = timeout if timeout is not None else self.timeout
        endpoint = f"{self.host}/api/generate"

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
        if format_json:
            payload["format"] = "json"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=req_timeout) as response:
                status_code = response.getcode()
                raw_body = response.read().decode("utf-8")

                if status_code != 200:
                    raise OllamaResponseError(
                        f"Ollama server returned HTTP status {status_code}: {raw_body}"
                    )

                resp_json = json.loads(raw_body)
                response_text = resp_json.get("response", "")

                if format_json:
                    try:
                        return json.loads(response_text)
                    except json.JSONDecodeError as err:
                        raise OllamaResponseError(
                            f"Model output could not be decoded as JSON: {response_text}"
                        ) from err
                else:
                    return {"response": response_text}

        except urllib.error.HTTPError as err:
            error_body = ""
            try:
                error_body = err.read().decode("utf-8")
                parsed = json.loads(error_body)
                if "error" in parsed:
                    error_body = parsed["error"]
            except Exception:
                pass
            raise OllamaResponseError(
                f"Ollama server returned HTTP {err.code}: {error_body or err.reason}"
            ) from err

        except urllib.error.URLError as err:
            # Check if this is a connection refused vs timeout
            if isinstance(err.reason, (socket.timeout, TimeoutError)):
                raise OllamaTimeoutError(
                    f"Ollama request timed out after {req_timeout}s on {endpoint}."
                ) from err
            elif isinstance(err.reason, ConnectionRefusedError) or "refused" in str(err.reason).lower():
                raise OllamaConnectionError(
                    f"Could not connect to Ollama on {self.host}. "
                    "Ensure Ollama is running locally with `ollama serve`."
                ) from err
            else:
                raise OllamaConnectionError(
                    f"Failed to connect to local Ollama instance on {self.host}: {err.reason}"
                ) from err

        except socket.timeout as err:
            raise OllamaTimeoutError(
                f"Ollama request timed out after {req_timeout}s on {endpoint}."
            ) from err

        except json.JSONDecodeError as err:
            raise OllamaResponseError(
                f"Invalid JSON received from Ollama endpoint: {err}"
            ) from err

        except Exception as err:
            if isinstance(err, (OllamaConnectionError, OllamaTimeoutError, OllamaResponseError)):
                raise
            raise OllamaError(f"Unexpected error communicating with Ollama: {err}") from err
