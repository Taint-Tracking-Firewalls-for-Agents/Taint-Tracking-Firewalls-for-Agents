"""Benchmark runner for Agent Firewall."""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import tempfile

os.environ.setdefault("MPLCONFIGDIR", tempfile.gettempdir())
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent.factory import make_agent
from agent.runner import run_scenario
from agent.scenarios import Scenario, load_scenarios


def evaluate_mode(
    agent_name: str,
    mode: str,
    attacks: list[Scenario],
    benign: list[Scenario],
    trials: int = 1,
) -> dict:
    agent = make_agent(agent_name)

    non_adaptive = [s for s in attacks if not s.adaptive]
    adaptive = [s for s in attacks if s.adaptive]

    total_checks = 0
    total_overhead_ms = 0.0

    # Run non-adaptive attacks
    non_adaptive_successes = 0
    attack_trials_data = []
    for s in non_adaptive:
        for trial_idx in range(trials):
            res = run_scenario(s, agent, mode=mode)
            total_checks += res.guard_stats.get("checks", 0)
            total_overhead_ms += res.guard_stats.get("overhead_ms_total", 0.0)
            if res.goal_reached:
                non_adaptive_successes += 1
            attack_trials_data.append({
                "scenario_id": s.id,
                "trial": trial_idx,
                "adaptive": False,
                "goal_reached": res.goal_reached,
                "trace": res.trace.to_dict()["events"],
                "state": res.state,
            })

    # Run adaptive attacks
    adaptive_successes = 0
    for s in adaptive:
        for trial_idx in range(trials):
            res = run_scenario(s, agent, mode=mode)
            total_checks += res.guard_stats.get("checks", 0)
            total_overhead_ms += res.guard_stats.get("overhead_ms_total", 0.0)
            if res.goal_reached:
                adaptive_successes += 1
            attack_trials_data.append({
                "scenario_id": s.id,
                "trial": trial_idx,
                "adaptive": True,
                "goal_reached": res.goal_reached,
                "trace": res.trace.to_dict()["events"],
                "state": res.state,
            })

    # Run benign scenarios
    benign_successes = 0
    false_blocks = 0
    total_ask_decisions = 0
    benign_trials_data = []

    for s in benign:
        for trial_idx in range(trials):
            res = run_scenario(s, agent, mode=mode)
            total_checks += res.guard_stats.get("checks", 0)
            total_overhead_ms += res.guard_stats.get("overhead_ms_total", 0.0)

            # Count ASK decisions in trace
            ask_count = sum(
                1 for e in res.trace.events
                if e.get("type") == "decision" and e.get("verdict") == "ASK"
            )
            total_ask_decisions += ask_count

            if res.expectation_met:
                benign_successes += 1
            else:
                # Check for false-block: trace has BLOCK decision or denied ASK
                has_block = any(
                    e.get("type") == "decision" and e.get("verdict") == "BLOCK"
                    for e in res.trace.events
                )
                has_denied_ask = any(
                    e.get("type") == "approval" and e.get("approved") is False
                    for e in res.trace.events
                )
                if has_block or has_denied_ask:
                    false_blocks += 1

            benign_trials_data.append({
                "scenario_id": s.id,
                "trial": trial_idx,
                "expectation_met": res.expectation_met,
                "trace": res.trace.to_dict()["events"],
                "state": res.state,
            })

    total_non_adaptive_trials = len(non_adaptive) * trials
    total_adaptive_trials = len(adaptive) * trials
    total_benign_trials = len(benign) * trials

    asr = (non_adaptive_successes / total_non_adaptive_trials) if total_non_adaptive_trials else 0.0
    adaptive_rate = (adaptive_successes / total_adaptive_trials) if total_adaptive_trials else 0.0
    utility = (benign_successes / total_benign_trials) if total_benign_trials else 0.0
    prompts_per_task = (total_ask_decisions / total_benign_trials) if total_benign_trials else 0.0
    overhead_ms = (total_overhead_ms / total_checks) if total_checks else 0.0

    return {
        "mode": mode,
        "agent": agent_name,
        "trials": trials,
        "non_adaptive_attacks": len(non_adaptive),
        "non_adaptive_successes": non_adaptive_successes,
        "total_non_adaptive_trials": total_non_adaptive_trials,
        "asr": asr,
        "adaptive_attacks": len(adaptive),
        "adaptive_successes": adaptive_successes,
        "total_adaptive_trials": total_adaptive_trials,
        "adaptive_rate": adaptive_rate,
        "benign_scenarios": len(benign),
        "benign_successes": benign_successes,
        "total_benign_trials": total_benign_trials,
        "utility": utility,
        "false_blocks": false_blocks,
        "prompts_per_task": prompts_per_task,
        "total_checks": total_checks,
        "overhead_ms": overhead_ms,
        "attack_trials": attack_trials_data,
        "benign_trials": benign_trials_data,
    }


def generate_artifacts(mode_results: list[dict], results_dir: Path) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)

    # 1. results.md
    md_lines = [
        "# Benchmark Results",
        "",
        "| Mode | ASR (non-adaptive) | Adaptive Attacks | Benign Utility | False Blocks | Approval Prompts / Task | Guard Overhead (ms/call) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for r in mode_results:
        asr_str = f"{r['asr'] * 100:.1f}% ({r['non_adaptive_successes']}/{r['total_non_adaptive_trials']})"
        adapt_str = f"{r['adaptive_rate'] * 100:.1f}% ({r['adaptive_successes']}/{r['total_adaptive_trials']})"
        util_str = f"{r['utility'] * 100:.1f}% ({r['benign_successes']}/{r['total_benign_trials']})"
        ovh_str = f"{r['overhead_ms']:.4f} ms"
        prompts_str = f"{r['prompts_per_task']:.2f}"
        md_lines.append(
            f"| **{r['mode']}** | {asr_str} | {adapt_str} | {util_str} | {r['false_blocks']} | {prompts_str} | {ovh_str} |"
        )
    md_lines.append("")

    results_md_path = results_dir / "results.md"
    results_md_path.write_text("\n".join(md_lines), encoding="utf-8")

    # 2. asr_chart.png
    modes = [r["mode"] for r in mode_results]
    asrs = [r["asr"] * 100 for r in mode_results]
    utilities = [r["utility"] * 100 for r in mode_results]

    x = range(len(modes))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 5))
    rects1 = ax.bar([i - width / 2 for i in x], asrs, width, label="Attack Success Rate (ASR)", color="#d9534f")
    rects2 = ax.bar([i + width / 2 for i in x], utilities, width, label="Benign Utility", color="#5cb85c")

    ax.set_ylabel("Rate (%)")
    ax.set_title("Agent Firewall: Attack Success Rate vs Utility by Mode")
    ax.set_xticks(list(x))
    ax.set_xticklabels([m.upper() for m in modes])
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right")

    # Add count labels
    for idx, rect in enumerate(rects1):
        r = mode_results[idx]
        count_label = f"{r['non_adaptive_successes']}/{r['total_non_adaptive_trials']}"
        ax.annotate(
            f"{asrs[idx]:.0f}%\n({count_label})",
            xy=(rect.get_x() + rect.get_width() / 2, rect.get_height()),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    for idx, rect in enumerate(rects2):
        r = mode_results[idx]
        count_label = f"{r['benign_successes']}/{r['total_benign_trials']}"
        ax.annotate(
            f"{utilities[idx]:.0f}%\n({count_label})",
            xy=(rect.get_x() + rect.get_width() / 2, rect.get_height()),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    fig.tight_layout()
    chart_path = results_dir / "asr_chart.png"
    fig.savefig(chart_path, dpi=150)
    plt.close(fig)


def print_table(results: list[dict]) -> None:
    header = f"{'Mode':<8} | {'ASR (non-adapt)':<18} | {'Adaptive':<12} | {'Benign Utility':<18} | {'False Blk':<9} | {'Overhead':<10}"
    print("-" * len(header))
    print(header)
    print("-" * len(header))
    for r in results:
        asr_str = f"{r['asr'] * 100:.1f}% ({r['non_adaptive_successes']}/{r['total_non_adaptive_trials']})"
        adapt_str = f"{r['adaptive_successes']}/{r['total_adaptive_trials']}"
        util_str = f"{r['utility'] * 100:.1f}% ({r['benign_successes']}/{r['total_benign_trials']})"
        ovh_str = f"{r['overhead_ms']:.3f} ms"
        print(f"{r['mode']:<8} | {asr_str:<18} | {adapt_str:<12} | {util_str:<18} | {r['false_blocks']:<9} | {ovh_str:<10}")
    print("-" * len(header))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Agent Firewall Benchmark")
    parser.add_argument("--agent", choices=["scripted", "llm"], default="scripted")
    parser.add_argument("--mode", choices=["off", "stage1", "stage2", "all"], default="all")
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--out", type=str, default=None)

    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    attacks_dir = repo_root / "benchmarks" / "attacks"
    benign_dir = repo_root / "benchmarks" / "benign"
    results_dir = Path(args.out).parent if args.out else (repo_root / "benchmarks" / "results")
    results_dir.mkdir(parents=True, exist_ok=True)

    attacks = load_scenarios(attacks_dir)
    benign = load_scenarios(benign_dir)

    if args.limit:
        attacks = attacks[:args.limit]
        benign = benign[:args.limit]

    modes_to_run = ["off", "stage1", "stage2"] if args.mode == "all" else [args.mode]
    mode_results = []

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for mode in modes_to_run:
        res = evaluate_mode(args.agent, mode, attacks, benign, trials=args.trials)
        mode_results.append(res)

        # Save result JSONs
        res_file = results_dir / f"{args.agent}_{mode}_{timestamp}.json"
        with open(res_file, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)

        latest_file = results_dir / f"latest_{args.agent}_{mode}.json"
        with open(latest_file, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)

    if args.mode == "all":
        generate_artifacts(mode_results, results_dir)

    print_table(mode_results)


if __name__ == "__main__":
    main()
