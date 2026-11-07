"""Replay recorded attack traces through the firewall at different stages."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent.scenarios import goal_matches_call, load_scenarios
from firewall.guard import Guard
from firewall.labels import Label, TaintedContext, ToolCall, Verdict
from firewall.policy import Policy


def replay_file(input_path: Path, stages: list[int]) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    policy_path = repo_root / "policies" / "default.yaml"
    policy = Policy.from_yaml(policy_path)

    attacks_dir = repo_root / "benchmarks" / "attacks"
    scenarios_list = load_scenarios(attacks_dir)
    scenarios = {s.id: s for s in scenarios_list}

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    attack_trials = data.get("attack_trials", [])
    if not attack_trials:
        print("No attack trials found in input file.")
        return

    # Track results per stage
    results_by_stage: dict[int, dict[str, int]] = {
        s: {"total": 0, "prevented": 0, "blocked": 0, "asked": 0, "allowed": 0}
        for s in stages
    }

    print(f"Replaying {len(attack_trials)} attack trials from {input_path.name}")
    print("-" * 65)

    for stage in stages:
        for trial in attack_trials:
            sid = trial.get("scenario_id", "")
            scenario = scenarios.get(sid)
            if not scenario or not scenario.goal:
                continue

            results_by_stage[stage]["total"] += 1

            # Walk trace events
            context = TaintedContext()
            guard = Guard(policy=policy, enabled=True, stage=stage)
            goal_verdict = None

            for ev in trial.get("trace", []):
                etype = ev.get("type")
                if etype in ("segment", "tool_result"):
                    lbl = Label.UNTRUSTED if ev.get("label") == "untrusted" else Label.TRUSTED
                    seg = context.make_segment(ev.get("text", ""), lbl, ev.get("source", ""))
                    context.add(seg)
                elif etype == "tool_call":
                    call = ToolCall(ev.get("call_id", ""), ev.get("name", ""), ev.get("args", {}))
                    dec = guard.check(call, context)
                    if goal_matches_call(scenario.goal, call):
                        goal_verdict = dec.verdict
                        break

            if goal_verdict == Verdict.BLOCK:
                results_by_stage[stage]["prevented"] += 1
                results_by_stage[stage]["blocked"] += 1
            elif goal_verdict == Verdict.ASK:
                results_by_stage[stage]["prevented"] += 1
                results_by_stage[stage]["asked"] += 1
            else:
                results_by_stage[stage]["allowed"] += 1

    print(f"{'Stage':<8} | {'Total':<8} | {'Prevented':<12} | {'Blocked':<9} | {'Asked':<8} | {'Allowed':<8}")
    print("-" * 65)
    for stage in stages:
        r = results_by_stage[stage]
        pct = (r["prevented"] / r["total"] * 100) if r["total"] else 0.0
        prev_str = f"{r['prevented']}/{r['total']} ({pct:.0f}%)"
        print(f"Stage {stage:<2} | {r['total']:<8} | {prev_str:<12} | {r['blocked']:<9} | {r['asked']:<8} | {r['allowed']:<8}")
    print("-" * 65)
    print("Replay does not capture how the agent would react after a block.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay attack traces against the firewall")
    parser.add_argument("--input", required=True, help="Path to latest_*_off.json benchmark result file")
    parser.add_argument("--stage", choices=["1", "2", "both"], default="both", help="Firewall stage to evaluate")

    args = parser.parse_args()
    input_file = Path(args.input)
    if not input_file.exists():
        print(f"Error: file not found: {input_file}")
        sys.exit(1)

    stages = [1, 2] if args.stage == "both" else [int(args.stage)]
    replay_file(input_file, stages)


if __name__ == "__main__":
    main()
