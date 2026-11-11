"""
Google Gemini provider for AgentShield LLM Security Analyst.

Uses the official `google-genai` SDK with schema-constrained JSON output,
sensitive telemetry redaction, transient error retries, and bounded execution.
Strictly read-only; has no tool execution or authorization capabilities.
"""

import copy
import math
import os
import re
import time
from typing import Any, Optional

try:
    from google import genai
    from google.genai import types
    HAS_GOOGLE_GENAI = True
except ImportError:
    HAS_GOOGLE_GENAI = False
    genai = None
    types = None

from agentshield.analyst.models import AnalysisReport, ProviderError
from agentshield.analyst.provider import LLMProvider
from agentshield.audit.store import redact_text_secrets

DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"


def build_gemini_schema(model_or_schema: Any = AnalysisReport) -> dict[str, Any]:
    """Generates an OpenAPI 3.0 / Gemini Developer API-compatible structured output schema.

    The Gemini Developer API enforces strict schema constraints:
    1. Rejects `additionalProperties` / `additional_properties` (which are only supported
       in Gemini Enterprise Agent Platform mode on Vertex AI).
    2. Requires all `object` types to define concrete `properties`. Unconstrained dictionaries
       (such as `raw_metadata: Dict[str, Any]`, which Pydantic expands with additionalProperties)
       are pruned from the generation schema.
    3. Strips dialect metadata such as `$schema`.
    4. Preserves all required fields, enum validation, string formats, numeric bounds, and
       nested model structures. Full Pydantic validation is applied when the response is loaded.
    """
    if hasattr(model_or_schema, "model_json_schema"):
        raw_schema = copy.deepcopy(model_or_schema.model_json_schema())
    elif isinstance(model_or_schema, dict):
        raw_schema = copy.deepcopy(model_or_schema)
    else:
        raise TypeError(f"Expected Pydantic model class or dict schema, got {type(model_or_schema)}")

    def _sanitize(node: Any) -> Any:
        if isinstance(node, dict):
            # Strip keywords rejected by Gemini Developer API
            node.pop("additionalProperties", None)
            node.pop("additional_properties", None)
            node.pop("$schema", None)

            # Inspect object properties
            props = node.get("properties")
            if isinstance(props, dict):
                for prop_name, prop_val in list(props.items()):
                    if isinstance(prop_val, dict):
                        is_object = prop_val.get("type") == "object"
                        has_no_props = not prop_val.get("properties")
                        # Prune unconstrained dictionary/object without defined properties
                        if is_object and has_no_props:
                            props.pop(prop_name, None)
                            reqs = node.get("required")
                            if isinstance(reqs, list) and prop_name in reqs:
                                reqs.remove(prop_name)
                        else:
                            _sanitize(prop_val)

            # Clean definitions and $defs recursively
            for def_key in ("$defs", "definitions"):
                defs_dict = node.get(def_key)
                if isinstance(defs_dict, dict):
                    for sub_def in defs_dict.values():
                        _sanitize(sub_def)

            for k, v in list(node.items()):
                _sanitize(v)

        elif isinstance(node, list):
            for item in node:
                _sanitize(item)

        return node

    return _sanitize(raw_schema)


class GeminiProvider(LLMProvider):
    """Google Gemini model provider using the official google-genai SDK.

    Adheres strictly to the LLMProvider abstraction. All outgoing prompts
    are scrubbed of sensitive secrets before dispatch.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = 30.0,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        use_schema_constraint: bool = True,
        redact_prompt: bool = True,
        client: Optional[Any] = None,
        circuit_breaker: Optional[Any] = None,
        token_tracker: Optional[Any] = None,
        token_budget: Optional[int] = None,
    ):
        raw_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self._api_key = raw_key.strip() if raw_key else None
        self._model = (
            model
            or os.environ.get("AGENTSHIELD_ANALYST_MODEL")
            or DEFAULT_GEMINI_MODEL
        )

        from agentshield.reliability.circuit_breaker import CircuitBreaker
        from agentshield.reliability.limits import TokenBudgetTracker

        self.circuit_breaker = circuit_breaker or CircuitBreaker(
            service_name="gemini",
            failure_threshold=int(os.environ.get("AGENTSHIELD_CB_FAILURE_THRESHOLD", "3")),
            recovery_timeout=float(os.environ.get("AGENTSHIELD_CB_RECOVERY_TIMEOUT", "30.0")),
            half_open_success_threshold=int(os.environ.get("AGENTSHIELD_CB_HALF_OPEN_THRESHOLD", "1")),
        )
        self.token_tracker = token_tracker or TokenBudgetTracker()
        self.token_budget = token_budget or int(os.environ.get("AGENTSHIELD_MAX_TOKEN_BUDGET", "100000"))

        raw_env_timeout = os.environ.get("AGENTSHIELD_ANALYST_TIMEOUT")
        raw_timeout = raw_env_timeout if raw_env_timeout is not None else timeout
        if raw_timeout is None:
            raise ValueError("Timeout cannot be None. Must be a positive number of seconds.")

        try:
            parsed_timeout = float(raw_timeout)
        except (ValueError, TypeError):
            raise ValueError(
                f"Invalid timeout value: {raw_timeout!r}. Must be a positive number of seconds."
            ) from None

        if parsed_timeout <= 0 or math.isnan(parsed_timeout) or math.isinf(parsed_timeout):
            raise ValueError(
                f"Timeout must be a positive number of seconds, got {parsed_timeout}."
            )

        self.timeout = parsed_timeout
        self.max_retries = int(os.environ.get("AGENTSHIELD_ANALYST_MAX_RETRIES", max_retries))
        self.backoff_factor = backoff_factor
        self.use_schema_constraint = use_schema_constraint
        self.redact_prompt = redact_prompt
        self._client = client

        # Validate dependency availability
        if not HAS_GOOGLE_GENAI and self._client is None:
            raise ProviderError(
                "The 'google-genai' SDK is required for GeminiProvider. "
                "Install it via: pip install 'agentshield[gemini]'"
            )

        # Lazy client initialization if not injected
        if self._client is None and self._api_key:
            self._client = self._init_client(self._api_key)

    def _init_client(self, api_key: str) -> Any:
        try:
            return genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(timeout=self.timeout_ms) if types else None,
            )
        except Exception as e:
            raise ProviderError(f"Failed to initialize Gemini client: {self._sanitize_error(e)}") from None

    @property
    def timeout_ms(self) -> int:
        """Converts timeout to milliseconds for google-genai HttpOptions.

        AgentShield timeout is specified in seconds (e.g. 30.0, 45.0, 0.5).
        google-genai types.HttpOptions expects timeout in milliseconds.
        """
        if (
            self.timeout is None
            or not isinstance(self.timeout, (int, float))
            or self.timeout <= 0
            or math.isnan(self.timeout)
            or math.isinf(self.timeout)
        ):
            raise ValueError(f"Timeout must be a positive number of seconds, got {self.timeout!r}.")
        return int(self.timeout * 1000)

    @property
    def model_name(self) -> str:
        return self._model

    def build_response_schema(self) -> dict[str, Any]:
        """Generates the Developer API-compatible structured output schema for AnalysisReport."""
        return build_gemini_schema(AnalysisReport)

    def generate_analysis(self, prompt: str, system_prompt: str) -> str:
        """Sends sanitized telemetry to Gemini and returns raw JSON response text.

        Applies exponential backoff retries for transient errors and raises
        ProviderError for persistent or non-transient failures.
        """
        from agentshield.reliability.circuit_breaker import CircuitState, CircuitBreakerOpenError
        from agentshield.reliability.limits import TokenBudgetExceededError

        # Acquire circuit breaker execution slot (enforces single-probe concurrency in HALF_OPEN)
        if hasattr(self, "circuit_breaker") and self.circuit_breaker:
            self.circuit_breaker.acquire_execution()

        try:
            # Ensure API key is available
            if not self._client:
                api_key = self._api_key or os.environ.get("GEMINI_API_KEY")
                if not api_key:
                    raise ProviderError(
                        "Gemini API key is not configured. Set the GEMINI_API_KEY environment variable "
                        "or pass api_key to GeminiProvider."
                    )
                self._api_key = api_key
                self._client = self._init_client(api_key)

            # Redact secrets from telemetry before transmitting off-box
            sanitized_prompt = redact_text_secrets(prompt) if self.redact_prompt else prompt
            sanitized_system = redact_text_secrets(system_prompt) if self.redact_prompt else system_prompt

            # Configure request with schema constraints
            config_kwargs: dict[str, Any] = {
                "system_instruction": sanitized_system,
                "temperature": 0.1,  # Low temperature for stable deterministic security evaluation
            }

            if types:
                config_kwargs["http_options"] = types.HttpOptions(timeout=self.timeout_ms)
                if self.use_schema_constraint:
                    config_kwargs["response_mime_type"] = "application/json"
                    config_kwargs["response_schema"] = self.build_response_schema()
                else:
                    config_kwargs["response_mime_type"] = "application/json"
                config = types.GenerateContentConfig(**config_kwargs)
            else:
                config = config_kwargs

            last_error: Optional[Exception] = None

            for attempt in range(self.max_retries + 1):
                try:
                    response = self._client.models.generate_content(
                        model=self._model,
                        contents=sanitized_prompt,
                        config=config,
                    )

                    if response is None:
                        raise ProviderError(f"Gemini model '{self._model}' returned a null response.")

                    # Inspect candidates for safety blocks
                    candidates = getattr(response, "candidates", None)
                    if candidates:
                        finish_reason = getattr(candidates[0], "finish_reason", None)
                        if finish_reason:
                            finish_str = str(finish_reason).upper()
                            if "SAFETY" in finish_str:
                                raise ProviderError(f"Gemini response was blocked by safety filters (finish_reason: {finish_reason}).")

                    try:
                        text = getattr(response, "text", None)
                    except Exception as text_err:
                        raise ProviderError(
                            f"Gemini model '{self._model}' response could not be read: {self._sanitize_error(text_err)}"
                        ) from None

                    if not text or not text.strip():
                        raise ProviderError(f"Gemini model '{self._model}' returned an empty response.")

                    if hasattr(self, "circuit_breaker") and self.circuit_breaker:
                        self.circuit_breaker.record_success()

                    # Track token budget
                    if hasattr(self, "token_tracker") and self.token_tracker:
                        usage_meta = getattr(response, "usage_metadata", None)
                        total_tokens = getattr(usage_meta, "total_token_count", None) if usage_meta else None
                        if total_tokens is None or not isinstance(total_tokens, int):
                            total_tokens = max(1, (len(sanitized_prompt) + len(text)) // 4)
                        try:
                            self.token_tracker.record_and_check(
                                context_id=self._model,
                                tokens=total_tokens,
                                budget=self.token_budget,
                            )
                        except TokenBudgetExceededError as tbe:
                            raise ProviderError(str(tbe)) from tbe

                    return text.strip()

                except ProviderError:
                    if hasattr(self, "circuit_breaker") and self.circuit_breaker:
                        self.circuit_breaker.record_failure()
                    raise
                except Exception as e:
                    last_error = e
                    # Check if error is transient and eligible for retry
                    if not self._is_transient_error(e) or attempt >= self.max_retries:
                        break

                    retry_after = self._extract_retry_after(e)
                    if retry_after is not None and retry_after > 0:
                        if retry_after > self.timeout:
                            # Retry-After exceeds client timeout budget; fail fast
                            break
                        sleep_time = retry_after
                    else:
                        sleep_time = self.backoff_factor * (2 ** attempt)

                    sleep_time = min(sleep_time, self.timeout)
                    time.sleep(sleep_time)

            if hasattr(self, "circuit_breaker") and self.circuit_breaker:
                self.circuit_breaker.record_failure(last_error)
            try:
                from agentshield.observability import get_operational_logger, get_metrics_collector
                get_operational_logger().log_provider_failure("gemini", str(last_error))
                get_metrics_collector().record_provider_failure("gemini")
            except Exception:
                pass
            raise self._map_exception(last_error)
        finally:
            if hasattr(self, "circuit_breaker") and self.circuit_breaker:
                self.circuit_breaker.release_probe()

    def _extract_retry_after(self, e: Exception) -> Optional[float]:
        """Extracts Retry-After duration from exception headers or attributes if present."""
        # Check HTTP response headers
        headers = getattr(e, "headers", None)
        if headers is None and hasattr(e, "response"):
            headers = getattr(e.response, "headers", None)
        if headers and hasattr(headers, "get"):
            val = headers.get("retry-after") or headers.get("Retry-After")
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass

        # Check exception attributes (e.g. retry_delay, retry_after)
        for attr in ("retry_after", "retry_delay"):
            val = getattr(e, attr, None)
            if val is not None:
                try:
                    if hasattr(val, "total_seconds"):
                        return float(val.total_seconds())
                    if hasattr(val, "seconds"):
                        return float(val.seconds)
                    return float(val)
                except (ValueError, TypeError):
                    pass

        # Check message text for retry hints e.g. "retry after 4s"
        msg = str(e)
        match = re.search(
            r"(?:retry[-_ ]after|retry in|wait)\s*[:=]?\s*(\d+(?:\.\d+)?)\s*(?:s|sec|seconds)?\b",
            msg,
            re.IGNORECASE,
        )
        if match:
            try:
                return float(match.group(1))
            except (ValueError, TypeError):
                pass

        return None

    def _is_transient_error(self, e: Exception) -> bool:
        """Determines whether an error is transient (e.g. rate limit, 503, timeout)."""
        err_str = str(e).lower()
        err_cls = e.__class__.__name__.lower()

        # Non-transient errors must NOT be retried
        if any(term in err_str for term in (
            "401", "403", "unauthenticated", "permission_denied",
            "api_key_invalid", "invalid_api_key", "invalid api key",
            "400", "invalid_argument", "bad request",
            "404", "not_found", "model not found"
        )):
            return False

        # Transient indicators
        if any(term in err_str for term in (
            "429", "resource_exhausted", "quota", "rate limit", "rate_limit", "throttled",
            "500", "502", "503", "504", "unavailable", "server error", "internal error",
            "timeout", "timed out", "deadline_exceeded", "connection reset", "connection refused",
            "connection error", "broken pipe"
        )):
            return True

        if any(term in err_cls for term in ("timeout", "connecterror", "networkerror", "temporary")):
            return True

        return False

    def _map_exception(self, e: Optional[Exception]) -> ProviderError:
        """Translates provider-specific SDK exceptions into clean ProviderError."""
        if e is None:
            return ProviderError(f"Gemini provider failed unexpectedly on model '{self._model}'.")

        err_str = self._sanitize_error(e)
        lowered = err_str.lower()

        if any(k in lowered for k in ("401", "403", "unauthenticated", "permission_denied", "api_key_invalid", "invalid api key")):
            return ProviderError(f"Gemini authentication failed: invalid API key or credentials ({err_str}).")

        if any(k in lowered for k in ("429", "resource_exhausted", "quota", "rate limit", "throttled")):
            return ProviderError(f"Gemini rate limit or quota exceeded ({err_str}).")

        if any(k in lowered for k in ("404", "not_found", "model not found")):
            return ProviderError(f"Gemini model '{self._model}' is unavailable or does not exist ({err_str}).")

        if any(k in lowered for k in ("timeout", "timed out", "deadline_exceeded")):
            return ProviderError(f"Gemini request timed out after {self.timeout}s ({err_str}).")

        return ProviderError(f"Gemini provider failure on model '{self._model}': {err_str}")

    def _sanitize_error(self, e: Exception) -> str:
        """Strips raw API keys or tokens from exception strings to prevent credential leakage."""
        msg = str(e)
        if self._api_key and len(self._api_key) > 6:
            msg = msg.replace(self._api_key, "[REDACTED_API_KEY]")
        # Apply comprehensive secret redaction across credentials, tokens, and URLs
        msg = redact_text_secrets(msg)
        # Redact generic alphanumeric token-like strings in errors
        msg = re.sub(r"\bAIza[0-9A-Za-z\-_]{30,36}\b", "[REDACTED_API_KEY]", msg)
        msg = re.sub(r"key=[A-Za-z0-9_\-]+", "key=[REDACTED]", msg)
        return msg

