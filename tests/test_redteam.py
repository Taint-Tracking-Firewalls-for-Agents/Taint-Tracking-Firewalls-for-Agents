"""Tests for red-team fuzzing engine."""
from __future__ import annotations

from pathlib import Path
from firewall.provenance import using_version
from redteam.fuzz import (
    generate_fuzz_cases,
    run_f7_laundering,
    run_redteam_suite,
)


def test_redteam_deterministic_generation() -> None:
    cases1 = generate_fuzz_cases(seed=1337)
    cases2 = generate_fuzz_cases(seed=1337)
    assert len(cases1) == len(cases2)
    assert [c.args for c in cases1] == [c.args for c in cases2]

    # Check minimum 15 cases for each family F1-F6
    families = set(c.family for c in cases1)
    for f in ["F1_substring", "F2_extension", "F3_normalization", "F4_path_tricks", "F5_structure", "F6_tool_names"]:
        assert f in families
        count = sum(1 for c in cases1 if c.family == f)
        assert count >= 15, f"Family {f} had only {count} cases"


def test_redteam_v1_finds_vulnerabilities() -> None:
    """Positive control: verify red team detects substring and path laundering in v1."""
    with using_version("v1"):
        report = run_redteam_suite(versions=["v1"], stages=[2], seed=1337)
        stage2_data = report["v1"]["stage2"]

        # v1 must expose bypasses in substring matching (F1)
        f1_bypasses = stage2_data["families"]["F1_substring"]["bypasses"]
        assert f1_bypasses > 0, "Expected v1 to have F1 substring bypasses"

        # v1 must expose bypasses in F7 laundering
        f7_bypasses = stage2_data["families"]["F7_laundering"]["bypasses"]
        assert f7_bypasses > 0, "Expected v1 to have F7 laundering bypasses"


def test_redteam_v2_hardened_zero_bypasses() -> None:
    """Verify v2 eliminates all bypasses across all families."""
    with using_version("v2"):
        report = run_redteam_suite(versions=["v2"], stages=[2], seed=1337)
        stage2_data = report["v2"]["stage2"]

        # Bypasses must be 0 across all families
        for fam, stats in stage2_data["families"].items():
            assert stats["bypasses"] == 0, f"Expected 0 bypasses in {fam} under v2, got {stats['bypasses']}: {stats['bypass_examples']}"

        assert stage2_data["total_bypasses"] == 0


def test_redteam_report_generation(tmp_path: Path) -> None:
    report = run_redteam_suite(versions=["v1", "v2"], stages=[1, 2], seed=1337)
    assert "v1" in report
    assert "v2" in report
    assert "stage1" in report["v2"]
    assert "stage2" in report["v2"]
    assert report["v2"]["stage2"]["total_bypasses"] == 0
