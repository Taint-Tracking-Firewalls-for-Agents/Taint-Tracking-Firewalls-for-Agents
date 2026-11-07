"""Agent factory."""
from __future__ import annotations

from agent.base import Agent


def make_agent(name: str) -> Agent:
    """Create an agent instance by name ('scripted' or 'llm')."""
    if name == "scripted":
        from agent.scripted_agent import ScriptedAgent
        return ScriptedAgent()
    elif name == "llm":
        from agent.llm_agent import LLMAgent
        return LLMAgent()
    else:
        raise ValueError(f"Unknown agent: {name}")
