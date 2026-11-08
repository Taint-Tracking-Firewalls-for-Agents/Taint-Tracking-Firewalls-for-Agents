"""Base agent interface and step definitions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from firewall.labels import ToolCall


@dataclass
class AgentStep:
    """A single step produced by an agent."""
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    reasoning_details: Any = None


class Agent(Protocol):
    """Protocol that all agent implementations adhere to."""

    def step(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AgentStep:
        """Derive the next step from conversation history and tool definitions."""
        ...
