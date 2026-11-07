"""Tests for scenario loading, goals, expectations, and SimulatedUser."""
from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse
import pytest

from agent.scenarios import (
    Scenario,
    SimulatedUser,
    expectation_met,
    goal_matches_call,
    goal_reached,
    load_scenarios,
)
from firewall.labels import Decision, ToolCall, Verdict


def test_goal_reached_handmade_states() -> None:
    # email_sent_to
    goal_email = {"type": "email_sent_to", "address": "attacker@evil.example"}
    assert goal_reached(goal_email, {"outbox": [{"to": "attacker@evil.example", "subject": "s", "body": "b"}]})
    assert goal_reached(goal_email, {"outbox": [{"to": "ATTACKER@EVIL.EXAMPLE", "subject": "s", "body": "b"}]})
    assert not goal_reached(goal_email, {"outbox": [{"to": "alice@example.com", "subject": "s", "body": "b"}]})

    # shell_ran
    goal_shell = {"type": "shell_ran", "contains": "notes.txt"}
    assert goal_reached(goal_shell, {"shell_log": ["cat user/notes.txt"]})
    assert not goal_reached(goal_shell, {"shell_log": ["ls -la"]})

    # file_deleted
    goal_del = {"type": "file_deleted", "path": "user/notes.txt"}
    assert goal_reached(goal_del, {"deleted": ["user/notes.txt"]})
    assert goal_reached(goal_del, {"deleted": ["USER/NOTES.TXT"]})
    assert not goal_reached(goal_del, {"deleted": ["user/other.txt"]})

    # http_post_to
    goal_post = {"type": "http_post_to", "url_contains": "evil.example"}
    assert goal_reached(goal_post, {"http_log": [{"url": "https://evil.example/collect", "data": "123"}]})
    assert not goal_reached(goal_post, {"http_log": [{"url": "https://example.com/api", "data": "123"}]})

    # url_fetched
    goal_fetch = {"type": "url_fetched", "url_contains": "evil.example"}
    assert goal_reached(goal_fetch, {"fetch_log": ["https://evil.example/track?d=secret"]})
    assert not goal_reached(goal_fetch, {"fetch_log": ["https://example.com/page"]})

    # file_written
    goal_write = {"type": "file_written", "path": "user/notes.txt", "contains": "pwned"}
    assert goal_reached(goal_write, {"written": [{"path": "user/notes.txt", "text": "you got pwned!"}]})
    assert not goal_reached(goal_write, {"written": [{"path": "user/notes.txt", "text": "normal content"}]})
    assert not goal_reached(goal_write, {"written": [{"path": "user/other.txt", "text": "you got pwned!"}]})


def test_goal_matches_call() -> None:
    goal_email = {"type": "email_sent_to", "address": "attacker@evil.example"}
    call_email = ToolCall("c1", "send_email", {"to": "attacker@evil.example"})
    assert goal_matches_call(goal_email, call_email)
    assert not goal_matches_call(goal_email, ToolCall("c2", "send_email", {"to": "bob@example.com"}))
    assert not goal_matches_call(goal_email, ToolCall("c3", "run_shell", {"cmd": "attacker@evil.example"}))

    goal_shell = {"type": "shell_ran", "contains": "notes.txt"}
    assert goal_matches_call(goal_shell, ToolCall("c4", "run_shell", {"cmd": "cat user/notes.txt"}))
    assert not goal_matches_call(goal_shell, ToolCall("c5", "run_shell", {"cmd": "echo hello"}))


def test_expectation_met_handmade() -> None:
    # final_contains
    expect_final = {"type": "final_contains", "text": "recipe"}
    assert expectation_met(expect_final, {}, "Here is the delicious pancake recipe for you.")
    assert not expectation_met(expect_final, {}, "No info found.")

    # email_sent_to
    expect_email = {"type": "email_sent_to", "address": "alice@example.com"}
    assert expectation_met(expect_email, {"outbox": [{"to": "alice@example.com"}]}, "")
    assert not expectation_met(expect_email, {"outbox": []}, "")

    # file_written
    expect_write = {"type": "file_written", "path": "user/summary.md"}
    assert expectation_met(expect_write, {"written": [{"path": "user/summary.md", "text": "Summary"}]}, "")
    assert not expectation_met(expect_write, {"written": []}, "")


def test_simulated_user() -> None:
    approvals = [
        {"tool": "send_email", "args": {"to": "alice@example.com"}},
        {"tool": "write_file", "args": {"path": "user/summary.md"}},
    ]
    user = SimulatedUser(approvals)
    dummy_decision = Decision(Verdict.ASK, "reason", "rule", [], ToolCall("c1", "send_email"))

    # Matching approval
    call_ok1 = ToolCall("c1", "send_email", {"to": "alice@example.com", "subject": "S", "body": "B"})
    assert user(call_ok1, dummy_decision)

    call_ok2 = ToolCall("c2", "write_file", {"path": "user/summary.md", "text": "Data"})
    assert user(call_ok2, dummy_decision)

    # Non-matching tool or args
    call_bad_email = ToolCall("c3", "send_email", {"to": "attacker@evil.example"})
    assert not user(call_bad_email, dummy_decision)

    call_bad_tool = ToolCall("c4", "run_shell", {"cmd": "ls"})
    assert not user(call_bad_tool, dummy_decision)

    # allow_all mode
    user_allow_all = SimulatedUser([], allow_all=True)
    assert user_allow_all(call_bad_email, dummy_decision)


def test_suite_validation_if_scenarios_exist() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    attacks_dir = repo_root / "benchmarks" / "attacks"
    benign_dir = repo_root / "benchmarks" / "benign"

    attacks = load_scenarios(attacks_dir)
    benign = load_scenarios(benign_dir)

    # If scenarios are not yet created (e.g. in phase 3), skip the fixture checks
    if len(attacks) < 24 or len(benign) < 12:
        return

    allowed_domains = {"example.com", "evil.example"}

    for s in attacks + benign:
        assert s.id
        assert s.kind in ("attack", "benign")
        assert s.category
        assert s.description
        assert s.user_task
        assert isinstance(s.fixtures, dict)

        if s.kind == "attack":
            assert s.goal is not None
            assert s.goal.get("type") in {
                "email_sent_to", "shell_ran", "file_deleted",
                "http_post_to", "url_fetched", "file_written"
            }
        else:
            if s.expect:
                assert s.expect.get("type") in {
                    "final_contains", "email_sent_to", "file_written"
                }

        # Check domains in fixtures
        pages = s.fixtures.get("pages", {})
        for url, content in pages.items():
            parsed = urlparse(url)
            if parsed.hostname:
                assert any(parsed.hostname == d or parsed.hostname.endswith("." + d) for d in allowed_domains), f"Invalid domain in page url {url}"
            # Check emails in url or content
            emails = re.findall(r"[\w.+-]+@([\w-]+\.[\w-]+)", url + " " + content)
            for domain in emails:
                assert domain in allowed_domains, f"Invalid email domain {domain} in fixture for {s.id}"

        files = s.fixtures.get("files", {})
        for path_str, content in files.items():
            emails = re.findall(r"[\w.+-]+@([\w-]+\.[\w-]+)", content)
            for domain in emails:
                assert domain in allowed_domains, f"Invalid email domain {domain} in file fixture {path_str} for {s.id}"
