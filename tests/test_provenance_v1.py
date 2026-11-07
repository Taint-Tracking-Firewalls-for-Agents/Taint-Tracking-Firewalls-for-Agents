"""Tests pinning Provenance v1 behavior."""
from __future__ import annotations

import pytest
from firewall.labels import Label, TaintedContext
from firewall.provenance import (
    DEFAULT_VERSION,
    arg_is_trusted,
    arg_is_trusted_v1,
    arg_is_trusted_v2,
    get_version,
    path_key,
    set_version,
    using_version,
)


def test_provenance_versioning() -> None:
    assert DEFAULT_VERSION == "v2"
    assert get_version() == "v2"

    with using_version("v1"):
        assert get_version() == "v1"
        assert arg_is_trusted("alice", TaintedContext()) is False

    assert get_version() == "v2"

    with using_version("v2"):
        assert get_version() == "v2"

    assert get_version() == "v2"


def test_arg_is_trusted_v1_substring_and_min_len() -> None:
    ctx = TaintedContext()
    ctx.add(ctx.make_segment("Send email to alice@school.edu and save user/notes.txt", Label.TRUSTED, "user"))

    # Min length < 3 is False
    assert arg_is_trusted_v1("", ctx) is False
    assert arg_is_trusted_v1("a", ctx) is False
    assert arg_is_trusted_v1("al", ctx) is False
    assert arg_is_trusted_v1(None, ctx) is False

    # Exact match is True
    assert arg_is_trusted_v1("alice@school.edu", ctx) is True
    assert arg_is_trusted_v1("ALICE@SCHOOL.EDU", ctx) is True

    # Substring match (v1 weakness) is True
    assert arg_is_trusted_v1("ice@school.edu", ctx) is True
    assert arg_is_trusted_v1("school", ctx) is True
    assert arg_is_trusted_v1("user/notes.txt", ctx) is True

    # Unrelated string is False
    assert arg_is_trusted_v1("attacker@evil.example", ctx) is False


def test_path_key_v1_raw() -> None:
    with using_version("v1"):
        assert path_key("  user/file.txt  ") == "user/file.txt"
        assert path_key("./user/file.txt") == "./user/file.txt"
        assert path_key("user//file.txt") == "user//file.txt"
        assert path_key("user/sub/../file.txt") == "user/sub/../file.txt"
