"""Labels, segments, decisions, context, and traces for Agent Firewall."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Any


class Label(str, Enum):
    """Data trust label."""
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Verdict(str, Enum):
    """Firewall verdict."""
    ALLOW = "ALLOW"
    ASK = "ASK"
    BLOCK = "BLOCK"


@dataclass
class Segment:
    """A tracked data segment."""
    id: str
    text: str
    label: Label | str
    source: str  # user, webpage, email, file, tool_output, firewall


@dataclass
class ToolCall:
    """An invocation of a tool."""
    call_id: str
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    """Firewall policy decision on a tool call."""
    verdict: Verdict
    reason: str
    rule_id: str
    tainted_by: list[str]
    call: ToolCall


class TaintedContext:
    """Tracks context segments and taint status."""

    def __init__(self) -> None:
        self.segments: list[Segment] = []
        self._counter: int = 0

    def make_segment(self, text: str, label: Label | str, source: str) -> Segment:
        """Create a segment with a sequential id (s1, s2, ...)."""
        self._counter += 1
        seg_id = f"s{self._counter}"
        return Segment(id=seg_id, text=text, label=label, source=source)

    def add(self, segment: Segment) -> None:
        """Add an existing segment to the context."""
        self.segments.append(segment)

    def is_tainted(self) -> bool:
        """Check if any segment in context is UNTRUSTED."""
        return any(
            seg.label == Label.UNTRUSTED or seg.label == "untrusted"
            for seg in self.segments
        )

    def tainted_ids(self) -> list[str]:
        """Return IDs of all untrusted segments."""
        return [
            seg.id
            for seg in self.segments
            if seg.label == Label.UNTRUSTED or seg.label == "untrusted"
        ]

    def trusted_texts(self) -> list[str]:
        """Return texts of all trusted segments."""
        return [
            seg.text
            for seg in self.segments
            if seg.label == Label.TRUSTED or seg.label == "trusted"
        ]

    def untrusted_summary(self) -> str:
        """Return a short summary of untrusted sources, e.g. 'webpage s2, file s3'."""
        untrusted = [
            f"{seg.source} {seg.id}"
            for seg in self.segments
            if seg.label == Label.UNTRUSTED or seg.label == "untrusted"
        ]
        return ", ".join(untrusted)


class TaintStore:
    """Persistent path taint state across tool operations."""

    def __init__(self) -> None:
        self._store: dict[str, Label | str] = {}

    @staticmethod
    def _normalize(path: str | Path) -> str:
        p = str(path).replace("\\", "/").strip()
        while p.startswith("./"):
            p = p[2:]
        return p

    def set(self, path: str | Path, label: Label | str) -> None:
        """Set taint label for path."""
        self._store[self._normalize(path)] = label

    def get(self, path: str | Path, default: Label | str | None = None) -> Label | str | None:
        """Get taint label for path."""
        return self._store.get(self._normalize(path), default)

    def items(self) -> list[tuple[str, Label | str]]:
        """List all path and label items."""
        return list(self._store.items())

    def __setitem__(self, path: str | Path, label: Label | str) -> None:
        self.set(path, label)

    def __getitem__(self, path: str | Path) -> Label | str:
        norm = self._normalize(path)
        if norm not in self._store:
            raise KeyError(norm)
        return self._store[norm]

    def __contains__(self, path: str | Path) -> bool:
        return self._normalize(path) in self._store


class Trace:
    """Execution trace containing timeline events."""

    VALID_TYPES = {
        "segment",
        "tool_call",
        "decision",
        "approval",
        "tool_result",
        "final",
        "error",
    }

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def add(self, event: dict[str, Any]) -> None:
        """Add an event to the trace."""
        event_type = event.get("type")
        if event_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid event type: {event_type}")
        self.events.append(dict(event))

    def to_json(self) -> str:
        """Serialize trace events to JSON string."""
        return json.dumps(self.events, indent=2, ensure_ascii=True)

    def to_dict(self) -> dict[str, Any]:
        """Convert trace to dict."""
        return {"events": [dict(e) for e in self.events]}
