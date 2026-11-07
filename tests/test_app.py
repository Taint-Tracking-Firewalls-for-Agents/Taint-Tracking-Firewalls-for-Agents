"""Tests for Streamlit application using AppTest."""
from __future__ import annotations

from pathlib import Path
from streamlit.testing.v1 import AppTest


def test_app_initial_and_run_button() -> None:
    app_path = Path(__file__).resolve().parents[1] / "app" / "app.py"
    at = AppTest.from_file(str(app_path)).run(timeout=60)
    assert not at.exception

    # Locate and click the 'Run' button
    run_buttons = [b for b in at.button if b.key == "run_btn"]
    assert len(run_buttons) > 0

    run_buttons[0].click().run(timeout=60)
    assert not at.exception


def test_app_side_by_side_button() -> None:
    app_path = Path(__file__).resolve().parents[1] / "app" / "app.py"
    at = AppTest.from_file(str(app_path)).run(timeout=60)
    assert not at.exception

    # Locate and click the 'Run side by side' button
    sbs_buttons = [b for b in at.button if b.key == "side_by_side_btn"]
    assert len(sbs_buttons) > 0

    sbs_buttons[0].click().run(timeout=60)
    assert not at.exception


def test_app_break_it_view() -> None:
    app_path = Path(__file__).resolve().parents[1] / "app" / "app.py"
    at = AppTest.from_file(str(app_path)).run(timeout=60)
    assert not at.exception

    # Switch to Break It view
    radios = at.radio
    assert len(radios) > 0
    radios[0].set_value("Break It (Red Team)").run(timeout=60)
    assert not at.exception

    # Click Test Attack button
    attack_btns = [b for b in at.button if b.key == "test_attack_btn"]
    assert len(attack_btns) > 0
    attack_btns[0].click().run(timeout=60)
    assert not at.exception
