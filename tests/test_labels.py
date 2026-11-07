"""Tests for firewall labels, segments, TaintedContext, TaintStore, and Trace."""
from __future__ import annotations

import json
import pytest

from firewall.labels import (
    Label,
    Verdict,
    Segment,
    ToolCall,
    Decision,
    TaintedContext,
    TaintStore,
    Trace,
)


def test_labels_and_verdicts() -> None:
    assert Label.TRUSTED == "trusted"
    assert Label.UNTRUSTED == "untrusted"
    assert Verdict.ALLOW == "ALLOW"
    assert Verdict.ASK == "ASK"
    assert Verdict.BLOCK == "BLOCK"


def test_tainted_context_ids_and_summary() -> None:
    ctx = TaintedContext()
    assert not ctx.is_tainted()
    assert ctx.tainted_ids() == []
    assert ctx.trusted_texts() == []
    assert ctx.untrusted_summary() == ""

    s1 = ctx.make_segment("Hello user task", Label.TRUSTED, "user")
    assert s1.id == "s1"
    ctx.add(s1)
    assert not ctx.is_tainted()
    assert ctx.trusted_texts() == ["Hello user task"]

    s2 = ctx.make_segment("Malicious payload", Label.UNTRUSTED, "webpage")
    assert s2.id == "s2"
    ctx.add(s2)
    assert ctx.is_tainted()
    assert ctx.tainted_ids() == ["s2"]
    assert ctx.untrusted_summary() == "webpage s2"

    s3 = ctx.make_segment("Untrusted file content", Label.UNTRUSTED, "file")
    assert s3.id == "s3"
    ctx.add(s3)
    assert ctx.is_tainted()
    assert ctx.tainted_ids() == ["s2", "s3"]
    assert ctx.untrusted_summary() == "webpage s2, file s3"


def test_taint_store_operations() -> None:
    store = TaintStore()
    assert store.get("user/notes.txt") is None
    assert store.get("user/notes.txt", Label.TRUSTED) == Label.TRUSTED

    store.set("user/notes.txt", Label.TRUSTED)
    assert store.get("user/notes.txt") == Label.TRUSTED
    assert store["user/notes.txt"] == Label.TRUSTED
    assert "user/notes.txt" in store

    # Cross-platform path normalization
    store.set("downloads\\data.csv", Label.UNTRUSTED)
    assert store.get("downloads/data.csv") == Label.UNTRUSTED
    assert store["downloads/data.csv"] == Label.UNTRUSTED

    items = dict(store.items())
    assert items["user/notes.txt"] == Label.TRUSTED
    assert items["downloads/data.csv"] == Label.UNTRUSTED

    with pytest.raises(KeyError):
        _ = store["missing.txt"]


def test_trace_events_and_serialization() -> None:
    trace = Trace()
    trace.add({"type": "segment", "id": "s1", "label": "trusted", "source": "user", "text": "start"})
    call = ToolCall(call_id="call_1", name="search_notes", args={"query": "test"})
    trace.add({"type": "tool_call", "call_id": call.call_id, "name": call.name, "args": call.args})
    dec = Decision(
        verdict=Verdict.ALLOW,
        reason="no untrusted content in context",
        rule_id="clean_context",
        tainted_by=[],
        call=call,
    )
    trace.add({
        "type": "decision",
        "call_id": dec.call.call_id,
        "verdict": dec.verdict.value,
        "rule_id": dec.rule_id,
        "reason": dec.reason,
        "tainted_by": dec.tainted_by,
    })
    trace.add({"type": "approval", "call_id": "call_1", "approved": True})
    trace.add({"type": "tool_result", "call_id": "call_1", "ok": True, "text": "notes result", "label": "trusted", "source": "tool_output"})
    trace.add({"type": "final", "text": "All done"})
    trace.add({"type": "error", "message": "max steps reached"})

    assert len(trace.events) == 7
    raw_json = trace.to_json()
    loaded = json.loads(raw_json)
    assert len(loaded) == 7
    assert loaded[0]["type"] == "segment"

    d = trace.to_dict()
    assert "events" in d
    assert len(d["events"]) == 7

    with pytest.raises(ValueError):
        trace.add({"type": "invalid_type"})
