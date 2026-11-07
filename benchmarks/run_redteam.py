"""CLI entrypoint to execute red-team fuzzing suite."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redteam.fuzz import format_redteam_markdown, run_redteam_suite


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Agent Firewall Red Team Fuzzing Suite")
    parser.add_argument(
        "--versions",
        type=str,
        default="v1",
        help="Comma-separated provenance versions to evaluate, e.g. 'v1' or 'v1,v2'",
    )
    parser.add_argument(
        "--stages",
        type=str,
        default="1,2",
        help="Comma-separated policy stages to evaluate, e.g. '1,2'",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="Random seed for deterministic fuzzing",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Path to output markdown report file",
    )
    args = parser.parse_args()

    versions = [v.strip() for v in args.versions.split(",") if v.strip()]
    stages = [int(s.strip()) for s in args.stages.split(",") if s.strip()]

    print(f"Running red-team fuzzing with seed={args.seed}, versions={versions}, stages={stages}...")
    report_data = run_redteam_suite(versions=versions, stages=stages, seed=args.seed)

    repo_root = Path(__file__).resolve().parents[1]
    out_md = Path(args.out) if args.out else repo_root / "benchmarks" / "results" / "redteam_report.md"
    out_json = out_md.with_suffix(".json")

    out_md.parent.mkdir(parents=True, exist_ok=True)

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    md_content = format_redteam_markdown(report_data)
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"Wrote report to {out_md} and {out_json}")
    print("\nSummary Table:")
    for ver, s_dict in report_data.items():
        for stg, data in s_dict.items():
            print(
                f"  [{ver} {stg}] Total Cases: {data['total_cases']}, "
                f"Bypasses: {data['total_bypasses']}, False Blocks: {data['total_false_blocks']}"
            )


if __name__ == "__main__":
    main()
