"""Data provenance verification for tool call arguments."""
from __future__ import annotations

from typing import Any
from firewall.labels import TaintedContext


def arg_is_trusted(value: Any, context: TaintedContext) -> bool:
    """Check if value is trusted by substring match against trusted texts in context.

    Returns False if stripped value has fewer than 3 characters;
    otherwise True if value.strip().lower() is a substring of some text in
    context.trusted_texts() (also lowercased).
    """
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
