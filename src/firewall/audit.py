"""Audit logging and explanation for firewall decisions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from firewall.labels import Decision, Verdict


class AuditLog:
    """Records firewall decisions and produces human-readable explanations."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []

    def record(self, decision: Decision) -> None:
        """Record decision in memory and optionally append JSONL to file."""
        entry = {
            "verdict": decision.verdict.value,
            "tool": decision.call.name,
            "args": decision.call.args,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "tainted_by": list(decision.tainted_by),
        }
        self.entries.append(entry)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=True) + "\n")

    @staticmethod
    def explain(decision: Decision) -> str:
        """Return a single plain sentence explaining the decision.

        For ALLOW: 'ALLOWED <tool>: <reason>.'
        Otherwise: '<VERDICT> <tool> (<short args>) by rule <rule_id>: <reason>.'
        """
        tool = decision.call.name
        if decision.verdict == Verdict.ALLOW:
            return f"ALLOWED {tool}: {decision.reason}."

        args_parts: list[str] = []
        for k, v in decision.call.args.items():
            s = str(v)
            if len(s) > 40:
                s = s[:37] + "..."
            args_parts.append(f"{k}={s}")
        short_args = ", ".join(args_parts)

        return (
            f"{decision.verdict.value} {tool} ({short_args}) by rule "
            f"{decision.rule_id}: {decision.reason}."
        )
