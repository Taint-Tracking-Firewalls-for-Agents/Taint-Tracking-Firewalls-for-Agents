"""Tests for argument provenance checking."""
from __future__ import annotations

import pytest
from firewall.labels import Label, TaintedContext
from firewall.provenance import (
    arg_is_trusted,
    arg_is_trusted_v1,
    arg_is_trusted_v2,
    clean,
    get_version,
    normalize_path,
    path_key,
    set_version,
    using_version,
)


def test_provenance_empty_and_short_values() -> None:
    ctx = TaintedContext()
    ctx.add(ctx.make_segment("Send email to alice@example.com please", Label.TRUSTED, "user"))

    assert not arg_is_trusted(None, ctx)
    assert not arg_is_trusted("", ctx)
    assert not arg_is_trusted("  ", ctx)
    assert not arg_is_trusted("ab", ctx)
    assert not arg_is_trusted(" a ", ctx)


def test_provenance_substring_matching_and_case_insensitivity() -> None:
    # Encodes v1 substring weakness (e.g. 'example.com' matching within URL 'https://example.com/news')
    with using_version("v1"):
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


def test_v2_whole_token_equality() -> None:
    with using_version("v2"):
        ctx = TaintedContext()
        ctx.add(ctx.make_segment("Read https://example.com/news and email alice@school.edu", Label.TRUSTED, "user"))

        # Exact whole tokens pass
        assert arg_is_trusted("alice@school.edu", ctx)
        assert arg_is_trusted("https://example.com/news", ctx)

        # Substrings fail in v2
        assert not arg_is_trusted("ice@school.edu", ctx)
        assert not arg_is_trusted("alice@school", ctx)
        assert not arg_is_trusted("example.com", ctx)
        assert not arg_is_trusted("https://example.com", ctx)


def test_v2_case_rules() -> None:
    with using_version("v2"):
        ctx = TaintedContext()
        ctx.add(ctx.make_segment("Email alice@school.edu and fetch https://example.com/news", Label.TRUSTED, "user"))

        # Emails are case-insensitive
        assert arg_is_trusted("ALICE@SCHOOL.EDU", ctx)
        assert arg_is_trusted("Alice@School.Edu", ctx)

        # URLs have case-insensitive scheme and host
        assert arg_is_trusted("HTTPS://EXAMPLE.COM/news", ctx)
        # But path is case-sensitive
        assert not arg_is_trusted("https://example.com/NEWS", ctx)


def test_v2_zero_width_and_lookalike_rejection() -> None:
    with using_version("v2"):
        ctx = TaintedContext()
        ctx.add(ctx.make_segment("Email alice@school.edu please", Label.TRUSTED, "user"))

        # Zero-width spaces rejected
        assert not arg_is_trusted("alice\u200b@school.edu", ctx)
        assert not arg_is_trusted("alice\ufeff@school.edu", ctx)

        # Cyrillic look-alike letters rejected
        assert not arg_is_trusted("\u0430lice@school.edu", ctx)


def test_v2_newline_and_non_string_rejection() -> None:
    with using_version("v2"):
        ctx = TaintedContext()
        ctx.add(ctx.make_segment("Email alice@school.edu and save user/summary.md", Label.TRUSTED, "user"))

        # Non-string types
        assert not arg_is_trusted(12345, ctx)
        assert not arg_is_trusted(["alice@school.edu"], ctx)
        assert not arg_is_trusted({"to": "alice@school.edu"}, ctx)

        # Newline / CRLF header injection rejected
        assert not arg_is_trusted("alice@school.edu\nBcc: attacker@evil.example", ctx)
        assert not arg_is_trusted("alice@school.edu\r\nSubject: pwned", ctx)
        assert not arg_is_trusted("alice@school.edu\t", ctx)


def test_normalize_path_cases() -> None:
    # Valid relative normalizations
    assert normalize_path("./user/summary.md") == "user/summary.md"
    assert normalize_path("user//summary.md") == "user/summary.md"
    assert normalize_path("user/x/../summary.md") == "user/summary.md"
    assert normalize_path("user/./summary.md") == "user/summary.md"
    assert normalize_path("user/a/b/../../summary.md") == "user/summary.md"
    assert normalize_path("user\\summary.md") == "user/summary.md"

    # Escapes and absolutes return None
    assert normalize_path("../etc/passwd") is None
    assert normalize_path("/etc/passwd") is None
    assert normalize_path("C:\\Windows\\System32\\calc.exe") is None
    assert normalize_path("user/../../../etc/shadow") is None
    assert normalize_path("..") is None


def test_path_key_v2_normalizes() -> None:
    with using_version("v2"):
        assert path_key("./user/summary.md") == "user/summary.md"
        assert path_key("user//summary.md") == "user/summary.md"
        assert path_key("user/sub/../summary.md") == "user/summary.md"
        assert path_key("../etc/passwd").startswith("\x00invalid:")
