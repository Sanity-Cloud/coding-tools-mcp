from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.server import Runtime, input_schemas, landlock_exec_argv


def test_exec_schema_exposes_structured_forms_without_requiring_legacy_cmd() -> None:
    schema = input_schemas()["exec_command"]
    assert "cmd" not in schema.get("required", [])
    assert {
        "cmd",
        "argv",
        "powershell_script",
        "script_args",
        "expected_exit_codes",
        "expected_timeout",
        "diagnostic_mode",
    } <= set(schema["properties"])
    assert schema["oneOf"] == [
        {"required": ["cmd"]},
        {"required": ["argv"]},
        {"required": ["powershell_script"]},
    ]


def test_exec_requires_exactly_one_execution_form() -> None:
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), permission_mode="trusted")
        try:
            with pytest.raises(ToolFailure, match="exactly one execution form"):
                runtime.exec_command({})
            with pytest.raises(ToolFailure, match="exactly one execution form"):
                runtime.exec_command({"cmd": "echo ok", "argv": ["echo", "ok"]})
            with pytest.raises(ToolFailure, match="script_args is only valid"):
                runtime.exec_command({"argv": ["echo", "ok"], "script_args": ["x"]})
        finally:
            runtime.close()


def test_direct_argv_missing_executable_is_a_structured_runtime_error() -> None:
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), permission_mode="trusted")
        try:
            with pytest.raises(ToolFailure) as raised:
                runtime.exec_command({"argv": ["coding-tools-definitely-missing-executable-42"]})
            assert raised.value.code == "EXECUTABLE_NOT_FOUND"
            assert "PowerShell cmdlets/functions" in str(raised.value.details.get("retry_hint", ""))
        finally:
            runtime.close()


def test_expected_nonzero_exit_is_marked_without_hiding_exit_code() -> None:
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), permission_mode="trusted")
        try:
            result = runtime.exec_command(
                {
                    "argv": [sys.executable, "-c", "raise SystemExit(7)"],
                    "expected_exit_codes": [7],
                    "timeout_ms": 5000,
                    "yield_time_ms": 5000,
                }
            )
            assert result["exit_code"] == 7
            assert result["outcome_expected"] is True
            assert result["expectation_reason"] == "expected_exit_code"
        finally:
            runtime.close()


def test_expected_timeout_is_marked_without_hiding_timeout_state() -> None:
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), permission_mode="trusted")
        try:
            result = runtime.exec_command(
                {
                    "argv": [sys.executable, "-c", "import time; time.sleep(1)"],
                    "expected_timeout": True,
                    "timeout_ms": 50,
                    "yield_time_ms": 100,
                }
            )
            assert result["timed_out"] is True
            assert result["outcome_expected"] is True
            assert result["expectation_reason"] == "expected_timeout"
        finally:
            runtime.close()


def test_direct_argv_preserves_shell_metacharacters_quotes_spaces_and_newlines() -> None:
    with TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        helper = workspace / "echo_args.py"
        helper.write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n", encoding="utf-8")
        expected = ["$HOME", 'a"b', "space value", "line1\nline2", r"C:\path\trail\\"]
        runtime = Runtime(workspace, permission_mode="trusted")
        try:
            result = runtime.exec_command(
                {
                    "argv": [sys.executable, "echo_args.py", *expected],
                    "timeout_ms": 5000,
                    "yield_time_ms": 5000,
                }
            )
            assert result["status"] == "exited", result
            assert result["exit_code"] == 0, result
            assert result["execution_mode"] == "argv"
            assert json.loads(result["stdout"]) == expected
        finally:
            runtime.close()


def test_direct_argv_preserves_python_c_source_without_shell_requoting() -> None:
    with TemporaryDirectory() as tmp:
        value = '$value with "quotes", spaces, `ticks`, and \\slashes\\'
        runtime = Runtime(Path(tmp), permission_mode="trusted")
        try:
            result = runtime.exec_command(
                {
                    "argv": [sys.executable, "-c", "import sys; print(sys.argv[1])", value],
                    "timeout_ms": 5000,
                    "yield_time_ms": 5000,
                }
            )
            assert result["exit_code"] == 0, result
            assert result["stdout"].strip() == value
        finally:
            runtime.close()


def test_direct_argv_does_not_treat_dollar_as_shell_expansion_in_safe_mode() -> None:
    with TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        helper = workspace / "echo_arg.py"
        helper.write_text("import sys\nprint(sys.argv[1])\n", encoding="utf-8")
        runtime = Runtime(workspace, permission_mode="safe")
        try:
            result = runtime.exec_command(
                {"argv": [sys.executable, "echo_arg.py", "$HOME"], "timeout_ms": 5000, "yield_time_ms": 5000}
            )
            assert result["exit_code"] == 0, result
            assert result["stdout"].strip() == "$HOME"
        finally:
            runtime.close()


def test_direct_argv_keeps_inline_interpreter_and_network_policy_gates() -> None:
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), permission_mode="safe")
        try:
            with pytest.raises(ToolFailure) as inline:
                runtime.exec_command({"argv": [sys.executable, "-c", "print('ok')"]})
            assert inline.value.details["permission"] == "inline_script"

            with pytest.raises(ToolFailure) as network:
                runtime.exec_command({"argv": ["curl", "https://example.com"]})
            assert network.value.details["permission"] == "network"
        finally:
            runtime.close()


def test_landlock_wrapper_preserves_direct_argv_without_shell_reconstruction() -> None:
    direct = [sys.executable, "script.py", "$HOME", 'a"b', "space value"]
    wrapped = landlock_exec_argv(17, direct, shell=False)
    assert wrapped[-(len(direct) + 1)] == "--argv"
    assert wrapped[-len(direct) :] == direct

    shell = landlock_exec_argv(17, "echo $HOME", shell=True)
    assert shell[-2:] == ["--shell", "echo $HOME"]


def test_windows_powershell_51_is_rejected_before_permission_mode_bypass() -> None:
    with TemporaryDirectory() as tmp, patch("coding_tools_mcp.server.os.name", "nt"):
        runtime = Runtime(Path(tmp), permission_mode="dangerous")
        try:
            with pytest.raises(ToolFailure) as raised:
                runtime.exec_command({"argv": ["powershell.exe", "-NoProfile", "-Command", "Write-Output ok"]})
            assert raised.value.code == "SHELL_VERSION_UNSUPPORTED"
            with pytest.raises(ToolFailure) as legacy_shell:
                runtime.exec_command({"cmd": "powershell.exe -NoProfile -Command Write-Output ok"})
            assert legacy_shell.value.code == "SHELL_VERSION_UNSUPPORTED"
        finally:
            runtime.close()


@pytest.mark.skipif(os.name != "nt", reason="PowerShell quoting regression is Windows-specific")
def test_powershell_script_preserves_literal_argument_and_cleans_temp_source() -> None:
    if not (shutil.which("pwsh.exe") or shutil.which("pwsh")):
        pytest.skip("PowerShell 7 is unavailable")
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), permission_mode="trusted")
        value = '$HOME says "quoted"; line1\nline2; `literal`'
        try:
            result = runtime.exec_command(
                {
                    "powershell_script": "param([string]$Value)\n[Console]::Out.Write($Value)",
                    "script_args": [value],
                    "timeout_ms": 5000,
                    "yield_time_ms": 5000,
                }
            )
            assert result["status"] == "exited", result
            assert result["exit_code"] == 0, result
            assert result["execution_mode"] == "powershell_script"
            assert result["stdout"] == value
            script_dir = runtime.tmp_dir / "powershell-scripts"
            assert not list(script_dir.glob("*.ps1"))
        finally:
            runtime.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows profile recovery is Windows-specific")
def test_powershell_script_receives_recovered_windows_user_profile_context() -> None:
    if not (shutil.which("pwsh.exe") or shutil.which("pwsh")):
        pytest.skip("PowerShell 7 is unavailable")
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), permission_mode="trusted")
        try:
            result = runtime.exec_command(
                {
                    "powershell_script": (
                        "[pscustomobject]@{"
                        "Major=$PSVersionTable.PSVersion.Major;"
                        "PSHome=$HOME;"
                        "UserProfile=$env:USERPROFILE;"
                        "AppData=$env:APPDATA;"
                        "LocalAppData=$env:LOCALAPPDATA;"
                        "EnvHome=$env:HOME"
                        "} | ConvertTo-Json -Compress"
                    ),
                    "timeout_ms": 5000,
                    "yield_time_ms": 5000,
                }
            )
            assert result["status"] == "exited", result
            assert result["exit_code"] == 0, result
            payload = json.loads(result["stdout"])
            assert payload["Major"] >= 7
            assert payload["UserProfile"]
            assert payload["AppData"]
            assert payload["LocalAppData"]
            assert payload["PSHome"] == payload["UserProfile"]
            assert payload["EnvHome"] == payload["UserProfile"]
        finally:
            runtime.close()
