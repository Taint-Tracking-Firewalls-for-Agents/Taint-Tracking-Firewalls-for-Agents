"""Bounded exhaustive policy verification and static policy linter."""
from __future__ import annotations

from dataclasses import dataclass, field
import itertools
from pathlib import Path
from typing import Any

from agent.tools import ToolRegistry
from firewall.labels import Label, TaintedContext, ToolCall, Verdict
from firewall.policy import Policy

VALID_TIERS = {"read_only", "local_write", "external", "network_read"}
VALID_OUTPUT_LABELS = {"trusted", "untrusted", "from_store", "inherit"}
NEVER_OVERRIDE = {"run_shell", "delete_file"}


@dataclass
class VerifyReport:
    """Outcome of bounded policy verification."""
    total_sequences: int
    total_steps: int
    violations: list[dict[str, Any]] = field(default_factory=list)
    lint_issues: list[str] = field(default_factory=list)
    invariants_held: dict[str, bool] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0 and len(self.lint_issues) == 0


def lint_policy(policy: Policy, tool_names: list[str]) -> list[str]:
    """Statically lint a Policy against security invariants and registered tool schemas."""
    issues: list[str] = []

    # 1. Every registered tool has a rule
    for name in tool_names:
        rule = policy.rule(name)
        if rule is None:
            issues.append(f"Missing rule for registered tool: '{name}'")
            continue

        # 2. Tier validity
        tier = rule.get("tier")
        if tier not in VALID_TIERS:
            issues.append(f"Tool '{name}' has invalid tier '{tier}'. Must be one of {sorted(VALID_TIERS)}")

        # 3. Output label validity
        output_label = rule.get("output_label")
        if output_label not in VALID_OUTPUT_LABELS:
            issues.append(
                f"Tool '{name}' has invalid output_label '{output_label}'. Must be one of {sorted(VALID_OUTPUT_LABELS)}"
            )

        # 4. External tier tools must be ask or block
        action = rule.get("tainted")
        if tier == "external" and action in ("allow", "allow_if_args_trusted"):
            issues.append(f"External tool '{name}' has unsafe tainted action '{action}' (must be 'block' or 'ask')")

        # 5. run_shell and delete_file have provenance_override: false
        if name in NEVER_OVERRIDE:
            if rule.get("provenance_override", True) is not False:
                issues.append(f"Critical tool '{name}' must have 'provenance_override: false'")

        # 6. Sensitive args exist for external, local_write, or network_read
        if tier in ("external", "local_write", "network_read"):
            sens = rule.get("sensitive_args", [])
            if not sens:
                issues.append(f"Tool '{name}' in tier '{tier}' must declare at least one sensitive argument")

    return issues


def spec_executes(
    tier: str,
    tool: str,
    tainted: bool,
    args_trusted: bool,
    approved: bool,
    stage: int,
    overridable: bool,
) -> bool:
    """Independent specification of allowed tool execution rules."""
    if not tainted:
        return True
    if tier == "read_only":
        return True
    if tier == "network_read":
        return args_trusted
    if tier in ("external", "local_write"):
        can_override = (
            stage >= 2
            and args_trusted
            and overridable
            and tool not in NEVER_OVERRIDE
        )
        can_approve = approved and (tier == "local_write")
        return can_approve or can_override
    return False


def check_policy(
    policy: Policy,
    tool_schemas: list[dict[str, Any]] | None = None,
    k: int = 3,
    stages: tuple[int, ...] = (1, 2),
) -> VerifyReport:
    """Exhaustively verify sequences of length k against the formal specification."""
    if tool_schemas is None:
        tool_schemas = ToolRegistry.schemas()

    tool_names = [s["function"]["name"] for s in tool_schemas]
    lint_issues = lint_policy(policy, tool_names)

    violations: list[dict[str, Any]] = []
    total_sequences = 0
    total_steps = 0

    # Step choices: tool x args ("trusted", "attacker") x approved (True, False)
    step_choices = list(itertools.product(tool_names, [True, False], [True, False]))

    for stage in stages:
        for seq in itertools.product(step_choices, repeat=k):
            total_sequences += 1
            ctx = TaintedContext()
            ctx.add(
                ctx.make_segment(
                    "User prompt with https://example.com/news and alice@school.edu and user/notes.txt and recipes and echo ok",
                    Label.TRUSTED,
                    "user",
                )
            )

            taint_store: dict[str, Label] = {}

            for step_idx, (tname, args_trusted, approved) in enumerate(seq):
                total_steps += 1
                rule = policy.rule(tname) or {}
                tier = str(rule.get("tier", "external"))
                overridable = rule.get("provenance_override", True) is not False

                is_tainted_before = ctx.is_tainted()

                # Build args
                if tname == "send_email":
                    args = {"to": "alice@school.edu" if args_trusted else "attacker@evil.example"}
                elif tname in ("read_webpage", "http_post"):
                    args = {"url": "https://example.com/news" if args_trusted else "https://evil.example/malware"}
                elif tname in ("write_file", "delete_file"):
                    args = {"path": "user/notes.txt" if args_trusted else "../etc/passwd"}
                elif tname == "run_shell":
                    args = {"cmd": "echo ok" if args_trusted else "cat /etc/shadow"}
                else:
                    args = {"query": "recipes" if args_trusted else "secret"}

                call = ToolCall(call_id=f"step_{step_idx}", name=tname, args=args)
                decision = policy.evaluate(call, ctx, stage=stage)

                executed = False
                if decision.verdict == Verdict.ALLOW:
                    executed = True
                elif decision.verdict == Verdict.ASK and approved:
                    executed = True

                expected = spec_executes(
                    tier=tier,
                    tool=tname,
                    tainted=is_tainted_before,
                    args_trusted=args_trusted,
                    approved=approved,
                    stage=stage,
                    overridable=overridable,
                )

                if executed != expected:
                    violations.append({
                        "stage": stage,
                        "step": step_idx,
                        "tool": tname,
                        "tier": tier,
                        "tainted": is_tainted_before,
                        "args_trusted": args_trusted,
                        "approved": approved,
                        "executed": executed,
                        "expected": expected,
                        "verdict": decision.verdict.value,
                        "rule_id": decision.rule_id,
                    })
                    break

                # State effects simulating runner
                if executed:
                    if tname == "read_webpage":
                        ctx.add(ctx.make_segment("Web content", Label.UNTRUSTED, "webpage"))
                    elif tname == "write_file":
                        taint_store["user/notes.txt"] = Label.UNTRUSTED if is_tainted_before else Label.TRUSTED
                    elif tname == "read_file":
                        lbl = taint_store.get("user/notes.txt", Label.TRUSTED)
                        ctx.add(ctx.make_segment("File content", lbl, "file"))

    invariants = {
        "I1_Safety_no_unapproved_external_taint": not any(
            v["tier"] == "external" and not v["approved"] and v["executed"] for v in violations
        ),
        "I2_Shell_and_delete_never_override": not any(
            v["tool"] in NEVER_OVERRIDE and v["tainted"] and not v["approved"] and v["executed"]
            for v in violations
        ),
        "I3_Lint_clean": len(lint_issues) == 0,
    }

    return VerifyReport(
        total_sequences=total_sequences,
        total_steps=total_steps,
        violations=violations,
        lint_issues=lint_issues,
        invariants_held=invariants,
    )
