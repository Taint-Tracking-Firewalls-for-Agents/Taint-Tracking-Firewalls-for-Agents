"""Data provenance verification for tool call arguments with pluggable versions."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import posixpath
import re
from typing import Any, Generator
import unicodedata
import urllib.parse

from firewall.labels import TaintedContext

DEFAULT_VERSION = "v2"
_active_version: str | None = None

ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff")
PUNCT_CHARS = '.,;:!?()[]{}<>"\'\\'


def get_version() -> str:
    """Return currently active provenance version."""
    return _active_version if _active_version is not None else DEFAULT_VERSION


def set_version(v: str) -> None:
    """Set active provenance version ('v1' or 'v2')."""
    global _active_version
    if v not in ("v1", "v2"):
        raise ValueError(f"Unknown provenance version: {v}")
    _active_version = v


@contextmanager
def using_version(v: str) -> Generator[None, None, None]:
    """Context manager temporarily switching provenance version."""
    global _active_version
    prev = _active_version
    set_version(v)
    try:
        yield
    finally:
        _active_version = prev


def clean(s: str) -> str:
    """NFKC normalize, delete zero-width characters, strip whitespace."""
    if not isinstance(s, str):
        s = str(s)
    s_norm = unicodedata.normalize("NFKC", s)
    for zw in ZERO_WIDTH_CHARS:
        s_norm = s_norm.replace(zw, "")
    return s_norm.strip()


def normalize_path(p: str | Path | None) -> str | None:
    """Normalize path: forward slashes, clean, posixpath.normpath, strip leading ./

    Returns None if absolute, equals '..', or escapes outside root with '../'.
    """
    if p is None or not isinstance(p, (str, Path)):
        return None
    raw = str(p).replace("\\", "/")
    cleaned = clean(raw)
    if not cleaned:
        return None
    while "//" in cleaned:
        cleaned = cleaned.replace("//", "/")
    norm = posixpath.normpath(cleaned)
    while norm.startswith("./"):
        norm = norm[2:]
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        return None
    if norm == ".." or norm.startswith("../"):
        return None
    return norm


def path_key(path: str | Path) -> str:
    """Derive taint store path lookup key for the active version."""
    v = get_version()
    if v == "v1":
        return str(path).replace("\\", "/").strip()
    # v2: normalized posix path or invalid marker
    norm = normalize_path(path)
    if norm is None:
        return f"\x00invalid:{str(path)}"
    return norm


def arg_is_trusted_v1(value: Any, context: TaintedContext) -> bool:
    """Check if value is trusted using v1 substring logic."""
    if value is None:
        return False
    val_str = str(value).strip()
    if len(val_str) < 3:
        return False
    val_lower = val_str.lower()
    for text in context.trusted_texts():
        if val_lower in text.lower():
            return True
    return False


def _extract_trusted_tokens(context: TaintedContext) -> list[str]:
    """Extract distinct trusted semantic tokens from all trusted segments."""
    tokens: set[str] = set()
    for text in context.trusted_texts():
        cleaned_text = clean(text)
        # 1. Emails
        for email in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", cleaned_text):
            tokens.add(email)
        # 2. URLs
        for url in re.findall(r"https?://[^\s<>'\"\)\]\}]+", cleaned_text):
            tokens.add(url.rstrip(PUNCT_CHARS))
        # 3. Delimited spans (backtick, double quote, single quote)
        for span in re.findall(r"`([^`]+)`", cleaned_text):
            tokens.add(span.strip())
        for span in re.findall(r'"([^"]+)"', cleaned_text):
            tokens.add(span.strip())
        for span in re.findall(r"'([^']+)'", cleaned_text):
            tokens.add(span.strip())
        # 4. Whitespace-delimited pieces
        for piece in cleaned_text.split():
            stripped = piece.strip(PUNCT_CHARS)
            if stripped:
                tokens.add(stripped)
    return list(tokens)


def _token_matches(val: str, tok: str) -> bool:
    """Compare a candidate argument against a trusted token according to its kind."""
    # 1. Email check
    is_val_email = bool(re.match(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$", val))
    is_tok_email = bool(re.match(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$", tok))
    if is_val_email and is_tok_email:
        return val.lower() == tok.lower()

    # 2. URL check
    val_lower = val.lower()
    tok_lower = tok.lower()
    is_val_url = val_lower.startswith("http://") or val_lower.startswith("https://")
    is_tok_url = tok_lower.startswith("http://") or tok_lower.startswith("https://")
    if is_val_url and is_tok_url:
        try:
            v_parts = urllib.parse.urlsplit(val)
            t_parts = urllib.parse.urlsplit(tok)
            return (
                v_parts.scheme.lower() == t_parts.scheme.lower()
                and v_parts.netloc.lower() == t_parts.netloc.lower()
                and v_parts.path == t_parts.path
                and v_parts.query == t_parts.query
                and v_parts.fragment == t_parts.fragment
            )
        except Exception:
            return False

    # 3. Path-like check (contains '/' or ends in a file extension like .md, .txt, .csv)
    is_val_path = ("/" in val or bool(re.search(r"\.[a-zA-Z0-9]+$", val))) and not is_val_email and not is_val_url
    is_tok_path = ("/" in tok or bool(re.search(r"\.[a-zA-Z0-9]+$", tok))) and not is_tok_email and not is_tok_url
    if is_val_path and is_tok_path:
        norm_val = normalize_path(val)
        norm_tok = normalize_path(tok)
        if norm_val is None or norm_tok is None:
            return False
        return norm_val == norm_tok

    # 4. Exact equality for general tokens
    return val == tok


def arg_is_trusted_v2(value: Any, context: TaintedContext) -> bool:
    """Check if value is trusted using v2 hardened whole-token logic."""
    if not isinstance(value, str):
        return False

    # Check for zero-width characters in input
    if any(zw in value for zw in ZERO_WIDTH_CHARS):
        return False

    # Check for control characters
    if any(c in value for c in ("\n", "\r", "\t", "\0")):
        return False

    cleaned = clean(value)

    # Strip surrounding punctuation (preserving relative path prefix ./ or .\\)
    lead_dot = cleaned.startswith("./") or cleaned.startswith(".\\")
    res = cleaned.rstrip(PUNCT_CHARS)
    if lead_dot:
        stripped = res.lstrip(',;:!?()[]{}<>"\'\\')
    else:
        stripped = res.lstrip(PUNCT_CHARS)

    if len(stripped) < 3:
        return False

    trusted_tokens = _extract_trusted_tokens(context)
    for tok in trusted_tokens:
        if _token_matches(stripped, tok):
            return True

    return False


def arg_is_trusted(value: Any, context: TaintedContext) -> bool:
    """Dispatch argument trust check to the active provenance version."""
    v = get_version()
    if v == "v1":
        return arg_is_trusted_v1(value, context)
    if v == "v2":
        return arg_is_trusted_v2(value, context)
    raise ValueError(f"Unknown provenance version: {v}")
