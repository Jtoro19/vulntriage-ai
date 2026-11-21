"""LLM factory: one primary provider plus fallbacks, tool binding that survives wrapping.

Provider switch: VULNTRIAGE_LLM_PROVIDER = gemini | groq | ollama (default gemini).
Fallbacks come from VULNTRIAGE_LLM_FALLBACKS (comma list) or from DEFAULT_FALLBACKS.
Ollama is local, so by default it has NO cloud fallback (engagement data stays on
the machine); gemini and groq fall back to each other and finally to local ollama on rate
limits, 5xx and parse errors.

RunnableWithFallbacks has no bind_tools(), so tools / structured output are bound on
EACH model first and only then wrapped with .with_fallbacks().
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.runnables import Runnable

from vulntriage import config

PROVIDERS = ("gemini", "groq", "ollama")
DEFAULT_FALLBACKS = {"gemini": ["groq", "ollama"], "groq": ["gemini", "ollama"], "ollama": []}
KEY_ENV = {"gemini": "GOOGLE_API_KEY", "groq": "GROQ_API_KEY", "ollama": None}
TIMEOUT_S = 90


def provider_chain(provider: str | None = None, env: dict[str, str] | None = None,
                   have_key: Callable[[str], bool] | None = None) -> list[str]:
    """Ordered provider list: primary first, then usable fallbacks. Pure logic (testable)."""
    env = os.environ if env is None else env
    primary = (provider or env.get("VULNTRIAGE_LLM_PROVIDER") or config.LLM_PROVIDER).lower()
    if primary not in PROVIDERS:
        raise ValueError(f"unknown provider {primary!r}; choose one of {PROVIDERS}")
    raw = env.get("VULNTRIAGE_LLM_FALLBACKS")
    fallbacks = ([p.strip().lower() for p in raw.split(",") if p.strip()]
                 if raw is not None else DEFAULT_FALLBACKS[primary])
    have_key = have_key or (lambda p: KEY_ENV[p] is None or bool(config.secret(KEY_ENV[p])))
    chain = [primary]
    for p in fallbacks:
        if p in PROVIDERS and p not in chain and have_key(p):
            chain.append(p)
    return chain


def model_id(provider: str) -> str:
    return {"gemini": config.GEMINI_MODEL, "groq": config.GROQ_MODEL,
            "ollama": config.OLLAMA_MODEL}[provider]


def build_chat_model(provider: str):
    """Instantiate one chat model (no network call is made here)."""
    t = config.LLM_TEMPERATURE
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(model=config.GEMINI_MODEL, temperature=t,
                                      api_key=config.secret("GOOGLE_API_KEY"),
                                      max_retries=1, timeout=TIMEOUT_S)
    if provider == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(model=config.GROQ_MODEL, temperature=t,
                        api_key=config.secret("GROQ_API_KEY"), max_retries=1, timeout=TIMEOUT_S)
    from langchain_ollama import ChatOllama

    return ChatOllama(model=config.OLLAMA_MODEL, temperature=t, base_url=config.OLLAMA_BASE_URL,
                      client_kwargs={"timeout": 600})


def _with_fallbacks(transform: Callable[[Any], Runnable], provider: str | None = None,
                    retry: bool = True) -> Runnable:
    """Apply `transform` (bind_tools / with_structured_output) per model, then chain them.

    Any error on a provider (429 / ResourceExhausted, 5xx, timeout) hands the call to the next
    provider immediately. If the whole chain is rate limited (e.g. a Groq tokens-per-minute
    window), the chain is retried at most twice after a jittered backoff of 30 to 45 s
    (Groq's 8000 tokens-per-minute window resets within a minute), so a run never stalls for long.
    Gemini free-tier daily quota errors carry
    retry delays of hours, so they are not retried against the same model.
    """
    first, *rest = [transform(build_chat_model(p)) for p in provider_chain(provider)]
    chain = first.with_fallbacks(rest) if rest else first
    if not retry:  # caller enforces its own time budget (format step)
        return chain
    return chain.with_retry(stop_after_attempt=3, wait_exponential_jitter=True,
                            exponential_jitter_params={"initial": 30, "max": 45})


def get_llm(provider: str | None = None, tools: list | None = None) -> Runnable:
    """Chat model with fallbacks; tools (if given) are bound on every model."""
    return _with_fallbacks(lambda m: m.bind_tools(tools) if tools else m, provider)


def get_structured_llm(schema: type, provider: str | None = None, retry: bool = True) -> Runnable:
    """Chat model that returns `schema` instances, with the same fallback chain."""
    return _with_fallbacks(lambda m: m.with_structured_output(schema), provider, retry)


class TraceCallback(BaseCallbackHandler):
    """Records every LLM call (provider/model that answered, latency, tokens) and failures."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.errors: list[dict] = []
        self._start: dict[Any, tuple[float, str]] = {}

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs) -> None:
        name = (serialized or {}).get("id", ["?"])[-1]
        self._start[run_id] = (time.perf_counter(), name)

    def on_llm_end(self, response, *, run_id, **kwargs) -> None:
        t0, cls = self._start.pop(run_id, (time.perf_counter(), "?"))
        msg = response.generations[0][0].message if response.generations else None
        meta = getattr(msg, "response_metadata", {}) or {}
        usage = getattr(msg, "usage_metadata", None) or {}
        self.calls.append({
            "class": cls,
            "model": meta.get("model_name") or meta.get("model") or meta.get("model_version"),
            "latency_s": round(time.perf_counter() - t0, 2),
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
        })

    def on_llm_error(self, error, *, run_id, **kwargs) -> None:
        t0, cls = self._start.pop(run_id, (time.perf_counter(), "?"))
        self.errors.append({"class": cls, "error": f"{type(error).__name__}: {str(error)[:200]}",
                            "latency_s": round(time.perf_counter() - t0, 2)})

    def summary(self) -> dict:
        ins = [c["input_tokens"] for c in self.calls if c["input_tokens"] is not None]
        outs = [c["output_tokens"] for c in self.calls if c["output_tokens"] is not None]
        return {
            "providers_answered": sorted({str(c["model"]) for c in self.calls}),
            "llm_calls": len(self.calls), "llm_errors": len(self.errors),
            "input_tokens": sum(ins) if ins else None,
            "output_tokens": sum(outs) if outs else None,
        }


def call_with_budget(fn: Callable[[], Any], seconds: float) -> Any:
    """Run fn() in a daemon thread and give up after `seconds` (raises TimeoutError)."""
    import threading

    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except Exception as exc:  # re-raised in the caller
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise TimeoutError(f"no answer within {seconds:.0f} s")
    if "error" in box:
        raise box["error"]
    return box["value"]
