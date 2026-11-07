"""Firewall policy definition and evaluation."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml

from firewall.labels import Decision, TaintedContext, ToolCall, Verdict
from firewall.provenance import arg_is_trusted


class Policy:
    """Firewall policy rules loaded from configuration."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.default_action: str = config.get("default", "ask")
        self.tools: dict[str, dict[str, Any]] = config.get("tools", {})

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        """Load policy configuration from a YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(data or {})

    def rule(self, tool: str) -> dict[str, Any] | None:
        """Get the rule dict for a tool if present."""
        return self.tools.get(tool)

    def output_label(self, tool: str) -> str:
        """Get the expected output label for a tool (default 'trusted')."""
        rule = self.tools.get(tool)
        if rule and "output_label" in rule:
            return str(rule["output_label"])
        return "trusted"

    def sensitive_args(self, tool: str) -> list[str]:
        """Get the list of sensitive argument names for a tool."""
        rule = self.tools.get(tool)
        if rule and "sensitive_args" in rule:
            return list(rule["sensitive_args"])
        return []

    def evaluate(self, call: ToolCall, context: TaintedContext, stage: int = 1) -> Decision:
        """Evaluate a tool call against the policy under the current context."""
        rule = self.tools.get(call.name)
        if rule is None:
            action = self.default_action
            sensitive: list[str] = []
            rule_id = "default"
            tier = "default"
        else:
            action = rule["tainted"]
            sensitive = list(rule.get("sensitive_args", []))
            rule_id = f"{call.name}:{action}"
            tier = str(rule.get("tier", "action"))

        # 1. If not context.is_tainted(): return ALLOW, rule_id "clean_context"
        if not context.is_tainted():
            return Decision(
                verdict=Verdict.ALLOW,
                reason="no untrusted content in context",
                rule_id="clean_context",
                tainted_by=[],
                call=call,
            )

        # 2. Extract taint info
        tainted_by = context.tainted_ids()
        sources = context.untrusted_summary()

        # Helper: sensitive args are all trusted
        sensitive_all_trusted = (
            len(sensitive) > 0
            and all(
                arg_is_trusted(str(call.args.get(name, "")), context)
                for name in sensitive
            )
        )

        # 3. action "allow": ALLOW
        if action == "allow":
            return Decision(
                verdict=Verdict.ALLOW,
                reason=f"{call.name} is permitted for tainted context",
                rule_id=rule_id,
                tainted_by=tainted_by,
                call=call,
            )

        # 4. action "allow_if_args_trusted"
        if action == "allow_if_args_trusted":
            if sensitive_all_trusted:
                return Decision(
                    verdict=Verdict.ALLOW,
                    reason=f"{call.name} arguments are trusted",
                    rule_id=rule_id,
                    tainted_by=tainted_by,
                    call=call,
                )
            return Decision(
                verdict=Verdict.BLOCK,
                reason=(
                    f"{call.name} argument not found in trusted user input "
                    f"while untrusted content ({sources}) is in context"
                ),
                rule_id=rule_id,
                tainted_by=tainted_by,
                call=call,
            )

        # 5. action "ask" or "block"
        if action in ("ask", "block"):
            provenance_allowed = rule.get("provenance_override", True) is not False if rule else True
            if (
                stage >= 2
                and provenance_allowed
                and len(sensitive) > 0
                and sensitive_all_trusted
            ):
                return Decision(
                    verdict=Verdict.ALLOW,
                    reason=f"{call.name} arguments verified from trusted input",
                    rule_id="provenance_override",
                    tainted_by=tainted_by,
                    call=call,
                )

            verdict = Verdict.ASK if action == "ask" else Verdict.BLOCK
            return Decision(
                verdict=verdict,
                reason=f"{call.name} is a {tier} action and untrusted content ({sources}) is in context",
                rule_id=rule_id,
                tainted_by=tainted_by,
                call=call,
            )

        # Fallback for unrecognized action
        return Decision(
            verdict=Verdict.ASK,
            reason=f"{call.name} is an unrecognized action and untrusted content ({sources}) is in context",
            rule_id=rule_id,
            tainted_by=tainted_by,
            call=call,
        )
