"""Firewall guard intercepting tool calls."""
from __future__ import annotations

import time
from typing import Any
from firewall.audit import AuditLog
from firewall.labels import Decision, TaintedContext, ToolCall, Verdict
from firewall.policy import Policy


class Guard:
    """Evaluates tool calls against policy and tracks performance statistics."""

    def __init__(
        self,
        policy: Policy,
        audit: AuditLog | None = None,
        enabled: bool = True,
        stage: int = 1,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.enabled = enabled
        self.stage = stage
        self.stats: dict[str, Any] = {
            "checks": 0,
            "overhead_ms_total": 0.0,
            "blocks": 0,
            "asks": 0,
        }

    def check(self, call: ToolCall, context: TaintedContext) -> Decision:
        """Check a tool call against the policy."""
        self.stats["checks"] += 1

        if not self.enabled:
            return Decision(
                verdict=Verdict.ALLOW,
                reason="firewall disabled",
                rule_id="firewall_off",
                tainted_by=[],
                call=call,
            )

        t0 = time.perf_counter()
        decision = self.policy.evaluate(call, context, stage=self.stage)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.stats["overhead_ms_total"] += elapsed_ms

        if decision.verdict == Verdict.BLOCK:
            self.stats["blocks"] += 1
        elif decision.verdict == Verdict.ASK:
            self.stats["asks"] += 1

        if self.audit is not None:
            self.audit.record(decision)

        return decision
