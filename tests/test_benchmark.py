"""Tests for benchmark metrics, smoke run, and results artifact generation."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
import sys

# Ensure benchmarks module can be imported
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from run_benchmark import evaluate_mode, generate_artifacts
from agent.scenarios import Scenario


def test_metric_math_on_handmade_data() -> None:
    # 2 non-adaptive attacks, 1 adaptive attack, 2 benign scenarios
    attacks = [
        Scenario("A01", "attack", "cat", "desc", "task", {}, goal={"type": "email_sent_to", "address": "attacker@evil.example"}, adaptive=False),
        Scenario("A02", "attack", "cat", "desc", "task", {}, goal={"type": "shell_ran", "contains": "cmd"}, adaptive=False),
        Scenario("A21", "attack", "cat", "desc", "task", {}, goal={"type": "email_sent_to", "address": "attacker@evil.example"}, adaptive=True),
    ]
    benign = [
        Scenario("B01", "benign", "cat", "desc", "task", {}, expect={"type": "final_contains", "text": "ok"}),
        Scenario("B05", "benign", "cat", "desc", "task", {}, expect={"type": "email_sent_to", "address": "alice@example.com"}),
    ]

    # Evaluate with mode off
    res_off = evaluate_mode("scripted", "off", attacks, benign, trials=1)
    assert res_off["non_adaptive_attacks"] == 2
    assert res_off["adaptive_attacks"] == 1
    assert res_off["benign_scenarios"] == 2
    assert 0.0 <= res_off["asr"] <= 1.0
    assert 0.0 <= res_off["utility"] <= 1.0


def test_benchmark_smoke_run_and_artifacts(tmp_path: Path) -> None:
    attacks = [
        Scenario("A01", "attack", "cat", "desc", "task", {}, goal={"type": "email_sent_to", "address": "attacker@evil.example"}, adaptive=False),
        Scenario("A21", "attack", "cat", "desc", "task", {}, goal={"type": "email_sent_to", "address": "attacker@evil.example"}, adaptive=True),
    ]
    benign = [
        Scenario("B01", "benign", "cat", "desc", "task", {}, expect={"type": "final_contains", "text": "ok"}),
    ]

    mode_results = [
        evaluate_mode("scripted", "off", attacks, benign, trials=1),
        evaluate_mode("scripted", "stage1", attacks, benign, trials=1),
        evaluate_mode("scripted", "stage2", attacks, benign, trials=1),
    ]

    generate_artifacts(mode_results, tmp_path)

    assert (tmp_path / "results.md").exists()
    assert (tmp_path / "asr_chart.png").exists()

    md_content = (tmp_path / "results.md").read_text(encoding="utf-8")
    assert "Benchmark Results" in md_content
    assert "stage1" in md_content
    assert "stage2" in md_content
