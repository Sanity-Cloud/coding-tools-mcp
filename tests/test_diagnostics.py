from __future__ import annotations

import json
import io
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.diagnostics import DiagnosticRecorder, classify_failure
from coding_tools_mcp.errors import JsonRpcError
from coding_tools_mcp.server import Runtime


class DiagnosticRecorderTests(unittest.TestCase):
    def test_nonzero_exec_is_classified_even_when_transport_ok(self) -> None:
        failure = classify_failure(
            "exec_command",
            {"ok": True, "status": "exited", "exit_code": 7, "timed_out": False},
        )
        self.assertIsNotNone(failure)
        assert failure is not None
        self.assertEqual(failure["code"], "EXEC_NONZERO_EXIT")

    def test_expected_exec_outcome_is_not_classified_as_failure(self) -> None:
        failure = classify_failure(
            "exec_command",
            {
                "ok": True,
                "status": "exited",
                "exit_code": 7,
                "timed_out": False,
                "outcome_expected": True,
                "expectation_reason": "expected_exit_code",
            },
        )
        self.assertIsNone(failure)

    def test_durable_report_and_ledger_omit_command_content_and_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_root = root / "diagnostics"
            with patch.dict(
                os.environ,
                {
                    "CODING_TOOLS_MCP_DIAGNOSTIC_DIR": str(diagnostic_root),
                    "CODING_TOOLS_MCP_DIAGNOSTICS": "on",
                },
                clear=False,
            ):
                recorder = DiagnosticRecorder(root / "workspace")
                receipt = recorder.record(
                    tool_name="exec_command",
                    args={
                        "argv": ["python", "--token", "super-secret-value"],
                        "stdin": "sensitive-input",
                        "env": {"API_TOKEN": "top-secret"},
                    },
                    payload={
                        "ok": True,
                        "status": "exited",
                        "exit_code": 2,
                        "stdout": "secret output",
                        "stderr": "Bearer abcdefghijklmnop",
                        "stdout_output_bytes": 13,
                        "stderr_output_bytes": 23,
                    },
                    started_at=time.time() - 0.01,
                )
                self.assertTrue(receipt["recorded"])
                report_path = Path(receipt["report_path"])
                ledger_path = Path(receipt["ledger_path"])
                self.assertTrue(report_path.exists())
                self.assertTrue(ledger_path.exists())

                report_text = report_path.read_text(encoding="utf-8")
                self.assertNotIn("super-secret-value", report_text)
                self.assertNotIn("sensitive-input", report_text)
                self.assertNotIn("top-secret", report_text)
                self.assertNotIn("secret output", report_text)
                self.assertNotIn("abcdefghijklmnop", report_text)

                report = json.loads(report_text)
                self.assertEqual(report["code"], "EXEC_NONZERO_EXIT")
                self.assertEqual(report["followup"]["queue"], "debug_and_performance_review")
                self.assertEqual(report["context"]["arguments"]["argv"]["executable"], "python")
                self.assertEqual(report["context"]["arguments"]["argv"]["argument_count"], 2)
                self.assertEqual(len(ledger_path.read_text(encoding="utf-8").splitlines()), 1)

    def test_explicit_failure_payload_gets_stable_grouping_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(
                os.environ,
                {
                    "CODING_TOOLS_MCP_DIAGNOSTIC_DIR": str(root / "diagnostics"),
                    "CODING_TOOLS_MCP_DIAGNOSTICS": "on",
                },
                clear=False,
            ):
                recorder = DiagnosticRecorder(root / "workspace")
                payload = {
                    "ok": False,
                    "error": {
                        "code": "UPSTREAM_SCHEMA_DRIFT",
                        "message": "Completion marker was missing.",
                        "category": "upstream",
                        "retryable": True,
                    },
                }
                first = recorder.record(
                    tool_name="record_diagnostic",
                    args={},
                    payload=payload,
                    started_at=time.time(),
                    component="notion2api",
                )
                second = recorder.record(
                    tool_name="record_diagnostic",
                    args={},
                    payload=payload,
                    started_at=time.time(),
                    component="notion2api",
                )
                self.assertNotEqual(first["incident_id"], second["incident_id"])
                self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_local_incident_fans_into_sanitycloud_native_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_root = root / "diagnostics"
            stderr = io.StringIO()
            with patch.dict(
                os.environ,
                {
                    "CODING_TOOLS_MCP_DIAGNOSTIC_DIR": str(diagnostic_root),
                    "CODING_TOOLS_MCP_DIAGNOSTICS": "on",
                    "SANITYCLOUD_DIAGNOSTIC_CONTRACT_VERSION": "sanitycloud.diagnostic.v1",
                },
                clear=False,
            ), redirect_stderr(stderr):
                recorder = DiagnosticRecorder(root / "workspace")
                receipt = recorder.record(
                    tool_name="exec_command",
                    args={"argv": ["python", "--token", "do-not-emit"]},
                    payload={"ok": True, "status": "exited", "exit_code": 9},
                    started_at=time.time(),
                )

            self.assertTrue(receipt["recorded"])
            line = stderr.getvalue().strip()
            self.assertTrue(line.startswith("SANITYCLOUD_DIAGNOSTIC_EVENT "))
            event = json.loads(line.removeprefix("SANITYCLOUD_DIAGNOSTIC_EVENT "))
            self.assertEqual(event["code"], "EXEC_NONZERO_EXIT")
            self.assertEqual(event["component_id"], "coding-tools-mcp")
            self.assertEqual(event["details"]["fingerprint"], receipt["fingerprint"])
            self.assertNotIn("do-not-emit", line)

    def test_call_tool_failure_returns_diagnostic_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_root = root / "diagnostics"
            workspace = root / "workspace"
            workspace.mkdir()
            with patch.dict(
                os.environ,
                {
                    "CODING_TOOLS_MCP_DIAGNOSTIC_DIR": str(diagnostic_root),
                    "CODING_TOOLS_MCP_DIAGNOSTICS": "on",
                },
                clear=False,
            ):
                runtime = Runtime(workspace)
                result = runtime.call_tool("read_file", {"path": "missing.txt"})
                payload = result["structuredContent"]
                self.assertFalse(payload["ok"])
                self.assertTrue(payload["diagnostic_receipt"]["recorded"])
                self.assertTrue(Path(payload["diagnostic_receipt"]["report_path"]).exists())
                runtime.close()

    def test_expected_nonzero_exec_does_not_create_diagnostic_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_root = root / "diagnostics"
            workspace = root / "workspace"
            workspace.mkdir()
            with patch.dict(
                os.environ,
                {
                    "CODING_TOOLS_MCP_DIAGNOSTIC_DIR": str(diagnostic_root),
                    "CODING_TOOLS_MCP_DIAGNOSTICS": "on",
                },
                clear=False,
            ):
                runtime = Runtime(workspace, permission_mode="trusted")
                result = runtime.call_tool(
                    "exec_command",
                    {
                        "argv": [sys.executable, "-c", "raise SystemExit(7)"],
                        "expected_exit_codes": [7],
                        "timeout_ms": 5000,
                        "yield_time_ms": 5000,
                    },
                )
                payload = result["structuredContent"]
                self.assertEqual(payload.get("exit_code"), 7)
                self.assertIs(payload.get("outcome_expected"), True)
                self.assertNotIn("diagnostic_receipt", payload)
                if diagnostic_root.exists():
                    ledger = diagnostic_root / "errors.jsonl"
                    self.assertFalse(ledger.exists() and ledger.read_text(encoding="utf-8").strip())
                runtime.close()

    def test_invalid_request_is_logged_before_jsonrpc_error_is_reraised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_root = root / "diagnostics"
            workspace = root / "workspace"
            workspace.mkdir()
            with patch.dict(
                os.environ,
                {
                    "CODING_TOOLS_MCP_DIAGNOSTIC_DIR": str(diagnostic_root),
                    "CODING_TOOLS_MCP_DIAGNOSTICS": "on",
                },
                clear=False,
            ):
                runtime = Runtime(workspace)
                with self.assertRaises(JsonRpcError):
                    runtime.call_tool("read_file", {})
                ledger_lines = runtime.diagnostics.ledger_path.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(ledger_lines), 1)
                entry = json.loads(ledger_lines[0])
                self.assertEqual(entry["kind"], "request_error")
                runtime.close()

    def test_explicit_record_tool_captures_application_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diagnostic_root = root / "diagnostics"
            workspace = root / "workspace"
            workspace.mkdir()
            with patch.dict(
                os.environ,
                {
                    "CODING_TOOLS_MCP_DIAGNOSTIC_DIR": str(diagnostic_root),
                    "CODING_TOOLS_MCP_DIAGNOSTICS": "on",
                },
                clear=False,
            ):
                runtime = Runtime(workspace)
                result = runtime.call_tool(
                    "record_diagnostic",
                    {
                        "code": "MISSING_FINISHED_AT",
                        "message": "Upstream stream ended without completion metadata.",
                        "component": "notion2api",
                        "operation": "stream_completion",
                        "kind": "upstream_protocol_error",
                        "category": "upstream",
                        "retryable": True,
                    },
                )
                payload = result["structuredContent"]
                self.assertTrue(payload["ok"])
                self.assertTrue(payload["diagnostic_receipt"]["recorded"])
                runtime.close()


if __name__ == "__main__":
    unittest.main()
