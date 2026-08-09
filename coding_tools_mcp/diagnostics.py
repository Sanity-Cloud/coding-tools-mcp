"""Durable local diagnostic incident records for Coding Tools MCP.

This is deliberately separate from anonymous product telemetry. Diagnostics are
operator-owned, local, durable, and intended for later root-cause/performance
review. Raw command output and secret-bearing arguments are not persisted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .envutils import ENV_PREFIX


_OFF_VALUES = {"0", "off", "false", "no", "disable", "disabled"}
_SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|credential|api[_-]?key|password|passwd|private|cookie|authorization|bearer|session)",
    re.I,
)
_INLINE_SECRET_RE = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]{8,}|gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})"
)
_CONTENT_KEYS = {
    "content",
    "patch",
    "stdin",
    "chars",
    "powershell_script",
    "cmd",
    "stdout",
    "stderr",
    "preview",
}
_MAX_STRING = 1024
_MAX_LIST = 40
_MAX_DEPTH = 5
_SANITYCLOUD_CONTRACT_VERSION = "sanitycloud.diagnostic.v1"
_SANITYCLOUD_EVENT_PREFIX = "SANITYCLOUD_DIAGNOSTIC_EVENT "


def diagnostics_enabled() -> bool:
    raw = (os.environ.get(f"{ENV_PREFIX}_DIAGNOSTICS") or "").strip().lower()
    return raw not in _OFF_VALUES


def diagnostic_root(workspace: Path | None = None) -> Path:
    configured = (os.environ.get(f"{ENV_PREFIX}_DIAGNOSTIC_DIR") or "").strip()
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        base = (os.environ.get("LOCALAPPDATA") or "").strip()
        if base:
            return Path(base) / "coding-tools-mcp" / "diagnostics"
    state_home = (os.environ.get("XDG_STATE_HOME") or "").strip()
    if state_home:
        return Path(state_home) / "coding-tools-mcp" / "diagnostics"
    try:
        return Path.home() / ".local" / "state" / "coding-tools-mcp" / "diagnostics"
    except RuntimeError:
        if workspace is not None:
            return workspace.resolve(strict=False).parent / ".coding-tools-mcp-diagnostics"
        return Path(tempfile.gettempdir()) / "coding-tools-mcp" / "diagnostics"


def _workspace_key(workspace: Path) -> str:
    normalized = str(workspace.resolve(strict=False))
    if os.name == "nt":
        normalized = normalized.casefold()
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _redact_string(value: str) -> str:
    cleaned = _INLINE_SECRET_RE.sub("<redacted-secret>", value)
    if len(cleaned) > _MAX_STRING:
        return cleaned[:_MAX_STRING] + "…<truncated>"
    return cleaned


def _sanitize(value: Any, *, key: str = "", depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return "<depth-limit>"
    if key and _SENSITIVE_KEY_RE.search(key):
        return "<redacted-sensitive-field>"
    if key in _CONTENT_KEYS:
        if isinstance(value, str):
            return {"omitted": True, "bytes": len(value.encode("utf-8", errors="replace"))}
        return "<omitted-content>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, raw_value in list(value.items())[:_MAX_LIST]:
            child_key = str(raw_key)
            result[child_key] = _sanitize(raw_value, key=child_key, depth=depth + 1)
        if len(value) > _MAX_LIST:
            result["_truncated_items"] = len(value) - _MAX_LIST
        return result
    if isinstance(value, (list, tuple)):
        values = list(value)
        result = [_sanitize(item, depth=depth + 1) for item in values[:_MAX_LIST]]
        if len(values) > _MAX_LIST:
            result.append(f"<truncated {len(values) - _MAX_LIST} items>")
        return result
    return _redact_string(repr(value))


def _sanitize_args(args: dict[str, Any]) -> dict[str, Any]:
    safe = _sanitize(args)
    result = safe if isinstance(safe, dict) else {}
    argv = args.get("argv")
    if isinstance(argv, list):
        executable = argv[0] if argv and isinstance(argv[0], str) else None
        result["argv"] = {
            "executable": _redact_string(executable) if executable else None,
            "argument_count": max(0, len(argv) - 1),
            "arguments_omitted": True,
        }
    script_args = args.get("script_args")
    if isinstance(script_args, list):
        result["script_args"] = {"argument_count": len(script_args), "arguments_omitted": True}
    env = args.get("env")
    if isinstance(env, dict):
        result["env"] = {"keys": sorted(str(key) for key in env)[:_MAX_LIST], "values_omitted": True}
    return result


def classify_failure(tool_name: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return a normalized failure classification for durable diagnostics."""

    raw_error = payload.get("error")
    error = raw_error if isinstance(raw_error, dict) else {}
    if payload.get("ok") is False:
        return {
            "kind": "tool_error",
            "code": str(error.get("code") or "TOOL_ERROR"),
            "category": str(error.get("category") or "tool"),
            "message": str(error.get("message") or "Tool call failed."),
            "retryable": bool(error.get("retryable")),
            "severity": "error",
        }

    if tool_name in {"exec_command", "write_stdin"}:
        status = str(payload.get("status") or "").lower()
        if bool(payload.get("timed_out")) or status == "timeout":
            return {
                "kind": "execution_error",
                "code": "EXEC_TIMEOUT",
                "category": "execution",
                "message": "Command execution timed out.",
                "retryable": True,
                "severity": "error",
            }
        if status == "terminated":
            return {
                "kind": "execution_error",
                "code": "EXEC_TERMINATED",
                "category": "execution",
                "message": "Command execution terminated before normal completion.",
                "retryable": True,
                "severity": "error",
            }
        exit_code = payload.get("exit_code")
        if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
            return {
                "kind": "execution_error",
                "code": "EXEC_NONZERO_EXIT",
                "category": "execution",
                "message": f"Command exited with non-zero status {exit_code}.",
                "retryable": False,
                "severity": "error",
            }
    return None


def _emit_sanitycloud_event(report: dict[str, Any], report_path: Path) -> bool:
    """Fan a local CodingTools incident into the architecture-wide supervisor."""

    if os.environ.get("SANITYCLOUD_DIAGNOSTIC_CONTRACT_VERSION") != _SANITYCLOUD_CONTRACT_VERSION:
        return False
    event = {
        "component_id": str(report.get("component") or "coding-tools-mcp"),
        "code": str(report.get("code") or "CODING_TOOLS_ERROR"),
        "message": _redact_string(str(report.get("message") or "CodingTools failure.")),
        "operation": str(report.get("operation") or report.get("tool") or "tool_call"),
        "category": str(report.get("category") or "coding_tools"),
        "severity": str(report.get("severity") or "error"),
        "kind": str(report.get("kind") or "error"),
        "retryable": bool(report.get("retryable")),
        "source": "coding_tools_local_diagnostics",
        "parent_record_id": str(report.get("request_id")) if report.get("request_id") else None,
        "project_id": None,
        "lane_id": None,
        "decision_id": None,
        "details": {
            "tool": report.get("tool"),
            "fingerprint": report.get("fingerprint"),
            "duration_ms": report.get("duration_ms"),
            "local_report_path": str(report_path),
        },
        "evidence": [
            {
                "kind": "local_diagnostic_report",
                "path": str(report_path),
            }
        ],
    }
    try:
        sys.stderr.write(
            _SANITYCLOUD_EVENT_PREFIX
            + json.dumps(event, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        )
        sys.stderr.flush()
        return True
    except Exception:  # pragma: no cover - never replace the primary tool result
        return False


class DiagnosticRecorder:
    """Create per-incident reports plus an append-only workspace-scoped ledger."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.resolve(strict=False)
        self.enabled = diagnostics_enabled()
        self.root = diagnostic_root(self.workspace) / _workspace_key(self.workspace)
        self.incident_dir = self.root / "incidents"
        self.ledger_path = self.root / "errors.jsonl"
        self._lock = threading.Lock()

    def summary(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": "durable_local_incident_ledger",
            "root": str(self.root),
            "ledger": str(self.ledger_path),
            "raw_command_output_persisted": False,
        }

    def record(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        payload: dict[str, Any],
        started_at: float,
        request_id: str | int | None = None,
        exception: BaseException | None = None,
        classification: dict[str, Any] | None = None,
        source: str = "automatic",
        component: str = "coding-tools-mcp",
        operation: str | None = None,
        related_paths: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        failure = classification or classify_failure(tool_name, payload)
        if failure is None:
            return {"recorded": False, "reason": "no_failure_classified"}
        if not self.enabled:
            return {"recorded": False, "reason": "diagnostics_disabled"}

        observed = datetime.now(timezone.utc)
        incident_id = f"diag-{observed.strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}"
        duration_ms = max(0, int((observed.timestamp() - started_at) * 1000))
        fingerprint_basis = "|".join(
            [
                component,
                tool_name,
                str(failure.get("code") or "UNKNOWN"),
                str(failure.get("category") or "unknown"),
                str(failure.get("message") or "")[:256],
            ]
        )
        fingerprint = hashlib.sha256(fingerprint_basis.encode("utf-8", errors="replace")).hexdigest()[:24]

        error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
        report: dict[str, Any] = {
            "schema_version": 1,
            "incident_id": incident_id,
            "fingerprint": fingerprint,
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "source": source,
            "state": "open",
            "severity": str(failure.get("severity") or "error"),
            "kind": str(failure.get("kind") or "error"),
            "component": component,
            "operation": operation or tool_name,
            "tool": tool_name,
            "code": str(failure.get("code") or "UNKNOWN"),
            "category": str(failure.get("category") or "unknown"),
            "message": _redact_string(str(failure.get("message") or "Failure recorded.")),
            "retryable": bool(failure.get("retryable")),
            "duration_ms": duration_ms,
            "request_id": str(request_id) if request_id is not None else None,
            "workspace": str(self.workspace),
            "context": {
                "arguments": _sanitize_args(args),
                "status": payload.get("status"),
                "exit_code": payload.get("exit_code"),
                "signal": payload.get("signal"),
                "timed_out": bool(payload.get("timed_out")),
                "session_id": payload.get("session_id"),
                "execution_mode": payload.get("execution_mode"),
                "truncated": bool(payload.get("truncated")),
                "output_metadata": {
                    "stdout_bytes": payload.get("stdout_output_bytes"),
                    "stderr_bytes": payload.get("stderr_output_bytes"),
                    "stdout_dropped_bytes": payload.get("stdout_dropped_bytes"),
                    "stderr_dropped_bytes": payload.get("stderr_dropped_bytes"),
                },
                "error_details": _sanitize(error.get("details") if isinstance(error, dict) else {}),
                "diagnostics": _sanitize(payload.get("diagnostics") or []),
                "warnings": _sanitize(payload.get("warnings") or []),
                "related_paths": _sanitize(related_paths or []),
                "details": _sanitize(details or {}),
            },
            "followup": {
                "queue": "debug_and_performance_review",
                "objective": "Determine root cause, identify recurrence/patterns, repair flawed workflow or process, and verify the fix.",
                "acceptance_criteria": [
                    "root cause or bounded evidence gap documented",
                    "persistent/repeated fingerprints assessed",
                    "workflow/process defect corrected or explicitly accepted",
                    "regression/performance verification recorded",
                    "incident closed or escalated with evidence",
                ],
            },
        }
        if exception is not None:
            report["exception"] = {
                "type": type(exception).__name__,
                "traceback": _redact_string("".join(traceback.format_exception(exception))),
            }

        report_path = self.incident_dir / f"{incident_id}.json"
        ledger_entry = {
            "incident_id": incident_id,
            "fingerprint": fingerprint,
            "observed_at": report["observed_at"],
            "state": report["state"],
            "severity": report["severity"],
            "kind": report["kind"],
            "component": component,
            "operation": report["operation"],
            "tool": tool_name,
            "code": report["code"],
            "category": report["category"],
            "report_path": str(report_path),
        }

        try:
            with self._lock:
                self.incident_dir.mkdir(parents=True, exist_ok=True)
                tmp_path = report_path.with_suffix(".json.tmp")
                with tmp_path.open("w", encoding="utf-8", newline="\n") as handle:
                    json.dump(report, handle, indent=2, sort_keys=True, ensure_ascii=False)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, report_path)
                with self.ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(json.dumps(ledger_entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
        except OSError as exc:
            if os.environ.get("SANITYCLOUD_DIAGNOSTIC_CONTRACT_VERSION") == _SANITYCLOUD_CONTRACT_VERSION:
                failure_report = dict(report)
                failure_report.update(
                    {
                        "code": "CODING_TOOLS_DIAGNOSTIC_WRITE_FAILED",
                        "message": "CodingTools could not persist its local diagnostic receipt.",
                        "category": "diagnostic_fabric",
                        "kind": "persistence_failure",
                        "retryable": True,
                    }
                )
                _emit_sanitycloud_event(failure_report, report_path)
            return {
                "recorded": False,
                "incident_id": incident_id,
                "fingerprint": fingerprint,
                "reason": "diagnostic_write_failed",
                "error": _redact_string(str(exc)),
            }

        _emit_sanitycloud_event(report, report_path)

        return {
            "recorded": True,
            "incident_id": incident_id,
            "fingerprint": fingerprint,
            "report_path": str(report_path),
            "ledger_path": str(self.ledger_path),
            "review_queue": "debug_and_performance_review",
        }
