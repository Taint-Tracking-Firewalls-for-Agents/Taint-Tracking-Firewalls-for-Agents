"""LLM Agent communicating with OpenAI-compatible chat completion APIs (OpenRouter / NVIDIA NIM / OpenAI)."""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Callable

from dotenv import load_dotenv
import openai
import requests

from agent.base import AgentStep
from firewall.labels import ToolCall

# Load environment variables from .env file if present
load_dotenv()


def call_openrouter_reasoning(
    messages: list[dict[str, Any]],
    model: str = "nvidia/nemotron-3.5-super-vl:free",
    api_key: str | None = None,
    tools: list[dict[str, Any]] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Execute a chat completion request to OpenRouter with reasoning enabled.
    
    Returns the message dictionary containing 'content', optional 'tool_calls',
    and 'reasoning_details' (to be preserved across multi-turn exchanges).
    """
    key = api_key or os.getenv("LLM_API_KEY", "")
    if key.startswith("<") and key.endswith(">"):
        key = key[1:-1]

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "reasoning": {"enabled": True},
    }
    if tools:
        payload["tools"] = tools

    url = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/") + "/chat/completions"
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]


def _make_step(text: str = "", tool_calls: list[ToolCall] | None = None, reasoning_details: Any = None) -> AgentStep:
    """Safely instantiate AgentStep even if an older version of base.py is cached in memory."""
    try:
        return AgentStep(text=text, tool_calls=tool_calls or [], reasoning_details=reasoning_details)
    except Exception:
        pass

    try:
        step = AgentStep(text=text, tool_calls=tool_calls or [])
        try:
            setattr(step, "reasoning_details", reasoning_details)
        except Exception:
            pass
        return step
    except Exception:
        step = AgentStep()
        step.text = text
        step.tool_calls = tool_calls or []
        try:
            setattr(step, "reasoning_details", reasoning_details)
        except Exception:
            pass
        return step


class BudgetExceeded(Exception):
    """Raised when the LLM API request limit is exceeded."""


class LLMAgent:
    """Agent using OpenAI-compatible chat completion models with caching, reasoning, and budget tracking."""

    def __init__(
        self,
        client: Any = None,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        max_requests: int | None = None,
        cache_dir: str | Path | None = None,
        results_dir: str | Path | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        enable_reasoning: bool = True,
    ) -> None:
        self.base_url = base_url or os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "")
        if self.api_key.startswith("<") and self.api_key.endswith(">"):
            self.api_key = self.api_key[1:-1]

        if not self.api_key:
            raise ValueError(
                "Missing required environment variable: LLM_API_KEY. "
                "Please configure LLM_API_KEY in your .env or Streamlit Secrets."
            )

        self.model = model or os.getenv("LLM_MODEL", "nvidia/nemotron-3.5-super-vl:free")
        self.enable_reasoning = enable_reasoning

        env_max = os.getenv("LLM_MAX_REQUESTS", "40")
        try:
            self.max_requests = max_requests if max_requests is not None else int(env_max)
        except ValueError:
            self.max_requests = 40

        self.sleep_fn = sleep_fn
        self.requests_count = 0

        repo_root = Path(__file__).resolve().parents[2]
        self.cache_dir = Path(cache_dir) if cache_dir else (repo_root / "benchmarks" / "cache")
        self.results_dir = Path(results_dir) if results_dir else (repo_root / "benchmarks" / "results")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        if client is None:
            missing = []
            if not self.base_url:
                missing.append("LLM_BASE_URL")
            if not self.api_key:
                missing.append("LLM_API_KEY")
            if not self.model:
                missing.append("LLM_MODEL")
            if missing:
                raise ValueError(f"Missing required environment variable(s): {', '.join(missing)}")
            self.client = openai.OpenAI(base_url=self.base_url, api_key=self.api_key)
        else:
            self.client = client
            if not self.model:
                self.model = os.getenv("LLM_MODEL", "mock-model")

    def _cache_key(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> str:
        serialized = json.dumps(
            {"model": self.model, "messages": messages, "tools": tools, "reasoning": self.enable_reasoning},
            sort_keys=True,
            ensure_ascii=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def step(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AgentStep:
        """Call LLM API or return cached completion step."""
        key = self._cache_key(messages, tools)
        cache_file = self.cache_dir / f"{key}.json"

        # Check disk cache
        if cache_file.exists():
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                calls = [
                    ToolCall(call_id=c["call_id"], name=c["name"], args=c["args"])
                    for c in data.get("tool_calls", [])
                ]
                return _make_step(
                    text=data.get("text", ""),
                    tool_calls=calls,
                    reasoning_details=data.get("reasoning_details"),
                )

        # Check budget
        if self.requests_count >= self.max_requests:
            raise BudgetExceeded(
                f"LLM request limit exceeded: {self.requests_count} >= {self.max_requests}"
            )

        # Prepare kwargs, adding extra_body reasoning for OpenRouter / Nemotron when enabled
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "tools": tools if tools else None,
            "temperature": 0.2,
        }
        if self.enable_reasoning:
            kwargs["extra_body"] = {"reasoning": {"enabled": True}}

        # Execute call with exponential backoff retry on 429 and 5xx errors
        backoffs = [1.0, 2.0, 4.0]
        attempts = 0
        last_err: Exception | None = None

        while attempts <= len(backoffs):
            try:
                response = self.client.chat.completions.create(**kwargs)
                break
            except Exception as e:
                last_err = e
                status_code = getattr(e, "status_code", None)
                is_rate_limit = status_code == 429 or "rate" in str(e).lower()
                is_server_error = (
                    status_code is not None and 500 <= status_code < 600
                )
                if (is_rate_limit or is_server_error) and attempts < len(backoffs):
                    delay = backoffs[attempts]
                    attempts += 1
                    self.sleep_fn(delay)
                else:
                    raise e
        else:
            if last_err:
                raise last_err

        self.requests_count += 1

        # Log request to llm_calls.jsonl (never log API key)
        usage_info = getattr(response, "usage", None)
        usage_dict = usage_info.model_dump() if usage_info and hasattr(usage_info, "model_dump") else (
            dict(usage_info) if isinstance(usage_info, dict) else None
        )
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "model": self.model,
            "usage": usage_dict,
        }
        log_path = self.results_dir / "llm_calls.jsonl"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=True) + "\n")

        # Parse assistant message
        msg = response.choices[0].message
        final_text = getattr(msg, "content", "") or ""
        if not isinstance(final_text, str):
            final_text = str(final_text) if final_text is not None else ""

        tool_calls_raw = getattr(msg, "tool_calls", None) or []
        if not isinstance(tool_calls_raw, (list, tuple)):
            tool_calls_raw = []

        raw_reasoning = getattr(msg, "reasoning_details", None)
        if isinstance(raw_reasoning, (dict, list, str, int, float, bool)) and not type(raw_reasoning).__name__.startswith("MagicMock"):
            reasoning_details = raw_reasoning
        elif hasattr(raw_reasoning, "model_dump") and not type(raw_reasoning).__name__.startswith("MagicMock"):
            try:
                dumped = raw_reasoning.model_dump()
                reasoning_details = dumped if isinstance(dumped, (dict, list, str, int, float, bool)) else None
            except Exception:
                reasoning_details = None
        else:
            reasoning_details = None

        parsed_calls: list[ToolCall] = []
        for tc in tool_calls_raw:
            func = getattr(tc, "function", tc.get("function") if isinstance(tc, dict) else None)
            cid = getattr(tc, "id", tc.get("id") if isinstance(tc, dict) else f"call_{len(parsed_calls) + 1}")
            name = getattr(func, "name", func.get("name") if isinstance(func, dict) else "")
            args_raw = getattr(func, "arguments", func.get("arguments") if isinstance(func, dict) else "{}")

            if isinstance(args_raw, str):
                try:
                    args_parsed = json.loads(args_raw)
                except Exception:
                    args_parsed = {"_error": args_raw}
            elif isinstance(args_raw, dict):
                args_parsed = args_raw
            else:
                args_parsed = {"_error": str(args_raw)}

            parsed_calls.append(ToolCall(call_id=cid, name=name, args=args_parsed))

        step_result = _make_step(
            text=final_text,
            tool_calls=parsed_calls,
            reasoning_details=reasoning_details,
        )

        # Cache response
        cache_data = {
            "text": step_result.text,
            "tool_calls": [
                {"call_id": c.call_id, "name": c.name, "args": c.args}
                for c in step_result.tool_calls
            ],
            "reasoning_details": step_result.reasoning_details,
        }
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2)

        return step_result
