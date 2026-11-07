"""Tests for LLMAgent with mocked OpenAI client only."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from agent.llm_agent import BudgetExceeded, LLMAgent
from firewall.labels import ToolCall


def test_missing_env_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)

    with pytest.raises(ValueError) as excinfo:
        LLMAgent(client=None)
    assert "Missing required environment variable" in str(excinfo.value)


def test_tool_call_parsing_and_invalid_json(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_choice = MagicMock()

    # Create mock message with two tool calls: one valid JSON, one invalid JSON
    tc_valid = MagicMock()
    tc_valid.id = "call_1"
    tc_valid.function.name = "search_notes"
    tc_valid.function.arguments = json.dumps({"query": "recipes"})

    tc_invalid = MagicMock()
    tc_invalid.id = "call_2"
    tc_invalid.function.name = "run_shell"
    tc_invalid.function.arguments = "{invalid_json: true"

    mock_choice.message.content = "Here are the tools"
    mock_choice.message.tool_calls = [tc_valid, tc_invalid]
    mock_client.chat.completions.create.return_value.choices = [mock_choice]
    mock_client.chat.completions.create.return_value.usage = None

    agent = LLMAgent(client=mock_client, model="test-model", cache_dir=tmp_path / "cache", results_dir=tmp_path / "res")
    step = agent.step([{"role": "user", "content": "test"}], [])

    assert len(step.tool_calls) == 2
    assert step.tool_calls[0].name == "search_notes"
    assert step.tool_calls[0].args == {"query": "recipes"}

    assert step.tool_calls[1].name == "run_shell"
    assert "_error" in step.tool_calls[1].args


def test_cache_hit_makes_no_api_call(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Cached response text"
    mock_choice.message.tool_calls = []
    mock_client.chat.completions.create.return_value.choices = [mock_choice]
    mock_client.chat.completions.create.return_value.usage = None

    agent = LLMAgent(client=mock_client, model="test-model", cache_dir=tmp_path / "cache", results_dir=tmp_path / "res")
    messages = [{"role": "user", "content": "hello cache"}]

    # First call: hits mock client
    step1 = agent.step(messages, [])
    assert step1.text == "Cached response text"
    assert mock_client.chat.completions.create.call_count == 1
    assert agent.requests_count == 1

    # Second call with identical input: should hit disk cache, not client
    step2 = agent.step(messages, [])
    assert step2.text == "Cached response text"
    assert mock_client.chat.completions.create.call_count == 1
    assert agent.requests_count == 1  # Budget not consumed


def test_budget_exceeded_raises_exception(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Response"
    mock_choice.message.tool_calls = []
    mock_client.chat.completions.create.return_value.choices = [mock_choice]
    mock_client.chat.completions.create.return_value.usage = None

    agent = LLMAgent(client=mock_client, model="test-model", max_requests=1, cache_dir=tmp_path / "cache", results_dir=tmp_path / "res")

    # First call uses 1 request (limit reached)
    agent.step([{"role": "user", "content": "call 1"}], [])
    assert agent.requests_count == 1

    # Second call should exceed budget
    with pytest.raises(BudgetExceeded) as excinfo:
        agent.step([{"role": "user", "content": "call 2"}], [])
    assert "limit exceeded" in str(excinfo.value)


def test_retry_on_rate_limit(tmp_path: Path) -> None:
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Success after retry"
    mock_choice.message.tool_calls = []

    rate_limit_err = Exception("Rate limit reached (429)")
    rate_limit_err.status_code = 429

    success_resp = MagicMock()
    success_resp.choices = [mock_choice]
    success_resp.usage = None

    # First call fails with 429, second call succeeds
    mock_client.chat.completions.create.side_effect = [rate_limit_err, success_resp]

    slept: list[float] = []
    agent = LLMAgent(
        client=mock_client,
        model="test-model",
        cache_dir=tmp_path / "cache",
        results_dir=tmp_path / "res",
        sleep_fn=slept.append,
    )

    step = agent.step([{"role": "user", "content": "retry test"}], [])
    assert step.text == "Success after retry"
    assert mock_client.chat.completions.create.call_count == 2
    assert slept == [1.0]  # Slept 1 second for first backoff
