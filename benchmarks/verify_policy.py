"""CLI entrypoint for bounded policy verification and linting."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from firewall.policy import Policy
from firewall.verify import check_policy, lint_policy
from agent.tools import ToolRegistry


def main() -> None:
    parser = argparse.ArgumentParser(description="Formally verify Agent Firewall policy invariants")
    parser.add_argument("--k", type=int, default=2, help="Sequence horizon bound k (default 2)")
    parser.add_argument("--policy", type=str, default="policies/default.yaml", help="Path to policy YAML")
    parser.add_argument("--stages", type=str, default="1,2", help="Comma-separated stages, e.g. '1,2'")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    policy_path = repo_root / args.policy
    policy = Policy.from_yaml(policy_path)
    stages = tuple(int(s.strip()) for s in args.stages.split(",") if s.strip())

    print(f"Linting policy at {policy_path}...")
    tools = [s["function"]["name"] for s in ToolRegistry.schemas()]
    issues = lint_policy(policy, tools)
    if issues:
        print("LINT FAILED with issues:")
        for iss in issues:
            print(f"  - {iss}")
        sys.exit(1)
    print("Lint PASSED: all registered tools covered with valid tiers and constraints.")

    print(f"Running bounded verification with k={args.k}, stages={stages}...")
    report = check_policy(policy, k=args.k, stages=stages)

    print(f"Checked {report.total_sequences} sequences ({report.total_steps} steps total).")
    for inv, held in report.invariants_held.items():
        status = "PASSED" if held else "FAILED"
        print(f"  [{status}] {inv}")

    if not report.passed:
        print(f"\nVERIFICATION FAILED with {len(report.violations)} violations!")
        for v in report.violations[:5]:
            print(f"  Violation at stage {v['stage']}, step {v['step']}: {v['tool']} (executed={v['executed']}, expected={v['expected']})")
        sys.exit(1)

    print("\nVERIFICATION SUCCESSFUL: 0 specification violations detected.")


if __name__ == "__main__":
    main()
