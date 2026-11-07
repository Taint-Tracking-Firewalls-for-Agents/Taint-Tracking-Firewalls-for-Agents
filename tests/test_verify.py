"""Tests for policy verifier and linter."""
from __future__ import annotations

from pathlib import Path
from firewall.policy import Policy
from firewall.verify import check_policy, lint_policy, spec_executes


def test_lint_default_policy() -> None:
    policy_path = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    policy = Policy.from_yaml(policy_path)
    tools = [
        "search_notes",
        "read_webpage",
        "read_file",
        "write_file",
        "send_email",
        "http_post",
        "run_shell",
        "delete_file",
    ]
    issues = lint_policy(policy, tools)
    assert len(issues) == 0, f"Expected clean lint, got: {issues}"


def test_lint_detects_malformed_policy() -> None:
    malformed = Policy({
        "tools": {
            "send_email": {"tier": "external", "tainted": "allow", "sensitive_args": []},
            "run_shell": {"tier": "external", "tainted": "block", "provenance_override": True, "sensitive_args": ["cmd"]},
            "bad_tool": {"tier": "invalid_tier", "tainted": "block", "output_label": "bad_label"},
        }
    })
    issues = lint_policy(malformed, ["send_email", "run_shell", "missing_tool"])
    assert any("unsafe tainted action" in i for i in issues)
    assert any("provenance_override: false" in i for i in issues)
    assert any("Missing rule for registered tool" in i for i in issues)


def test_spec_executes_logic() -> None:
    # Clean context always executes
    assert spec_executes("external", "send_email", False, False, False, 1, False) is True

    # Read-only always executes
    assert spec_executes("read_only", "search_notes", True, False, False, 1, False) is True

    # Network read requires trusted args
    assert spec_executes("network_read", "read_webpage", True, True, False, 1, False) is True
    assert spec_executes("network_read", "read_webpage", True, False, False, 1, False) is False

    # External blocked in stage 1 without override
    assert spec_executes("external", "send_email", True, True, False, 1, True) is False
    # External allowed in stage 2 with trusted args and override
    assert spec_executes("external", "send_email", True, True, False, 2, True) is True
    # Critical tools NEVER override
    assert spec_executes("external", "run_shell", True, True, False, 2, True) is False
    assert spec_executes("external", "delete_file", True, True, False, 2, True) is False


def test_bounded_verification() -> None:
    policy_path = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    policy = Policy.from_yaml(policy_path)
    report = check_policy(policy, k=2, stages=(1, 2))
    assert report.passed
    assert len(report.violations) == 0
    assert report.invariants_held["I1_Safety_no_unapproved_external_taint"]
    assert report.invariants_held["I2_Shell_and_delete_never_override"]
