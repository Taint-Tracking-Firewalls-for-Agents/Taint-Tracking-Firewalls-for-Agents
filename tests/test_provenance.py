"""Tests for argument provenance checking."""
from __future__ import annotations

import pytest
from firewall.labels import Label, TaintedContext
from firewall.provenance import arg_is_trusted


def test_provenance_empty_and_short_values() -> None:
    ctx = TaintedContext()
    ctx.add(ctx.make_segment("Send email to alice@example.com please", Label.TRUSTED, "user"))

    assert not arg_is_trusted(None, ctx)
    assert not arg_is_trusted("", ctx)
    assert not arg_is_trusted("  ", ctx)
    assert not arg_is_trusted("ab", ctx)
    assert not arg_is_trusted(" a ", ctx)


def test_provenance_substring_matching_and_case_insensitivity() -> None:
    ctx = TaintedContext()
    ctx.add(ctx.make_segment("Summarize https://example.com/news and email alice@example.com", Label.TRUSTED, "user"))
    ctx.add(ctx.make_segment("Untrusted web content mentioning attacker@evil.example", Label.UNTRUSTED, "webpage"))

    # Trusted matches (case-insensitive substring of trusted segments)
    assert arg_is_trusted("alice@example.com", ctx)
    assert arg_is_trusted("ALICE@EXAMPLE.COM", ctx)
    assert arg_is_trusted("https://example.com/news", ctx)
    assert arg_is_trusted("example.com", ctx)

    # Not in trusted texts (even though present in untrusted)
    assert not arg_is_trusted("attacker@evil.example", ctx)
    assert not arg_is_trusted("https://evil.example/collect", ctx)
    assert not arg_is_trusted("bob@example.com", ctx)
