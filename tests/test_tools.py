"""Tests for sandbox tools, path safety, and isolation."""
from __future__ import annotations

from pathlib import Path
import pytest
from agent.tools import Sandbox, ToolError, ToolRegistry, _safe_resolve
from firewall.labels import Label, ToolCall


def test_sandbox_cleanup() -> None:
    fixtures = {"pages": {}, "files": {"user/test.txt": "hello"}, "notes": []}
    with Sandbox(fixtures) as sb:
        root = sb.root
        assert root.exists()
        assert (root / "user" / "test.txt").exists()
    assert not root.exists()


def test_path_safety_escape_refused() -> None:
    fixtures = {"pages": {}, "files": {}, "notes": []}
    with Sandbox(fixtures) as sb:
        with pytest.raises(ToolError):
            _safe_resolve(sb.root, "../../outside.txt")
        with pytest.raises(ToolError):
            _safe_resolve(sb.root, "/etc/passwd")
        with pytest.raises(ToolError):
            _safe_resolve(sb.root, "C:\\Windows\\System32\\cmd.exe")


def test_tools_execution() -> None:
    fixtures = {
        "pages": {"https://example.com/test": "Test Page Content"},
        "files": {
            "user/notes.txt": "Private secret note",
            "inbox/email_01.txt": "Incoming message",
        },
        "notes": ["Buy groceries", "Remember the password is secret123"],
    }

    with Sandbox(fixtures) as sb:
        # search_notes
        res = ToolRegistry.execute(ToolCall("c1", "search_notes", {"query": "groceries"}), sb)
        assert res.ok
        assert res.text == "Buy groceries"
        assert res.source == "tool_output"

        res_none = ToolRegistry.execute(ToolCall("c2", "search_notes", {"query": "zebra"}), sb)
        assert res_none.ok
        assert res_none.text == "no matches"

        # read_webpage
        res_page = ToolRegistry.execute(ToolCall("c3", "read_webpage", {"url": "https://example.com/test"}), sb)
        assert res_page.ok
        assert res_page.text == "Test Page Content"
        assert res_page.source == "webpage"
        assert sb.fetch_log == ["https://example.com/test"]

        res_404 = ToolRegistry.execute(ToolCall("c4", "read_webpage", {"url": "https://example.com/404"}), sb)
        assert not res_404.ok
        assert res_404.text == "404 Not Found"

        # read_file
        res_user_file = ToolRegistry.execute(ToolCall("c5", "read_file", {"path": "user/notes.txt"}), sb)
        assert res_user_file.ok
        assert res_user_file.text == "Private secret note"
        assert res_user_file.source == "file"

        res_email_file = ToolRegistry.execute(ToolCall("c6", "read_file", {"path": "inbox/email_01.txt"}), sb)
        assert res_email_file.ok
        assert res_email_file.text == "Incoming message"
        assert res_email_file.source == "email"

        res_missing = ToolRegistry.execute(ToolCall("c7", "read_file", {"path": "user/nonexistent.txt"}), sb)
        assert not res_missing.ok
        assert "not found" in res_missing.text.lower()

        # write_file
        res_write = ToolRegistry.execute(ToolCall("c8", "write_file", {"path": "user/output.txt", "text": "result"}), sb)
        assert res_write.ok
        assert (sb.root / "user" / "output.txt").read_text(encoding="utf-8") == "result"
        assert sb.written == [{"path": "user/output.txt", "text": "result"}]

        # send_email
        res_email = ToolRegistry.execute(ToolCall("c9", "send_email", {"to": "alice@example.com", "subject": "Hi", "body": "Body"}), sb)
        assert res_email.ok
        assert res_email.text == "Email queued (fake)"
        assert sb.outbox == [{"to": "alice@example.com", "subject": "Hi", "body": "Body"}]

        # run_shell (does not execute real shell)
        res_shell = ToolRegistry.execute(ToolCall("c10", "run_shell", {"cmd": "rm -rf /"}), sb)
        assert res_shell.ok
        assert res_shell.text == "Command recorded (not executed)"
        assert sb.shell_log == ["rm -rf /"]

        # delete_file
        res_del = ToolRegistry.execute(ToolCall("c11", "delete_file", {"path": "user/notes.txt"}), sb)
        assert res_del.ok
        assert res_del.text == "Delete recorded (not executed)"
        assert sb.deleted == ["user/notes.txt"]

        # http_post
        res_post = ToolRegistry.execute(ToolCall("c12", "http_post", {"url": "https://example.com/api", "data": "payload"}), sb)
        assert res_post.ok
        assert res_post.text == "Request recorded (not sent)"
        assert sb.http_log == [{"url": "https://example.com/api", "data": "payload"}]

        # path escape execution
        res_esc = ToolRegistry.execute(ToolCall("c13", "read_file", {"path": "../../secret.txt"}), sb)
        assert not res_esc.ok
        assert "outside sandbox" in res_esc.text


def test_sandbox_label_for_path() -> None:
    fixtures = {"pages": {}, "files": {}, "notes": []}
    with Sandbox(fixtures, tainted_files=["user/tainted.txt"]) as sb:
        assert sb.label_for_path("user/normal.txt") == Label.TRUSTED
        assert sb.label_for_path("inbox/email_01.txt") == Label.UNTRUSTED
        assert sb.label_for_path("downloads/doc.pdf") == Label.UNTRUSTED
        assert sb.label_for_path("user/tainted.txt") == Label.UNTRUSTED
