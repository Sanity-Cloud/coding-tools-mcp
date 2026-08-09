from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from coding_tools_mcp import processes
from coding_tools_mcp import server as server_module
from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.server import Runtime


def test_windows_string_commands_are_rewritten_to_pwsh_without_cmd_fallback() -> None:
    captured: dict[str, object] = {}

    class FakeProcess:
        stdin = None
        stdout = None
        stderr = None

    def fake_popen(command: object, **kwargs: object) -> FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProcess()

    with patch.object(processes.os, "name", "nt"), patch.object(
        processes, "_resolve_windows_pwsh", return_value=r"C:\Program Files\PowerShell\7\pwsh.exe"
    ), patch.object(processes.subprocess, "Popen", side_effect=fake_popen):
        processes.spawn_process(
            "Get-Location",
            cwd=r"C:\work",
            shell=True,
            env={"PATH": r"C:\Windows\System32"},
            tty=False,
            popen_kwargs={},
        )

    command = captured["command"]
    assert isinstance(command, list)
    assert command[:5] == [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    ]
    assert command[-1] == "Get-Location"
    assert captured["kwargs"]["shell"] is False  # type: ignore[index]


def test_pwsh_resolution_requires_major_version_7_or_newer() -> None:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        pwsh = root / "pwsh.exe"
        pwsh.touch()
        processes._PWSH_VERSION_CACHE.clear()
        completed = SimpleNamespace(returncode=0, stdout="7\n", stderr="")
        with patch.dict(processes.os.environ, {"CODING_TOOLS_MCP_PWSH_PATH": str(pwsh)}, clear=False), patch.object(
            processes.subprocess, "run", return_value=completed
        ):
            assert processes._resolve_windows_pwsh(cwd=str(workspace), env={"PATH": ""}) == str(pwsh.resolve())

        processes._PWSH_VERSION_CACHE.clear()
        old = SimpleNamespace(returncode=0, stdout="5\n", stderr="")
        with patch.dict(processes.os.environ, {"CODING_TOOLS_MCP_PWSH_PATH": str(pwsh)}, clear=False), patch.object(
            processes.subprocess, "run", return_value=old
        ):
            with pytest.raises(ToolFailure) as raised:
                processes._resolve_windows_pwsh(cwd=str(workspace), env={"PATH": ""})
        assert raised.value.code == "SHELL_VERSION_UNSUPPORTED"


def test_safe_mode_blocks_powershell_dynamic_network_and_recursive_delete_patterns() -> None:
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp))
        try:
            with patch.object(server_module.os, "name", "nt"):
                with pytest.raises(ToolFailure) as dynamic:
                    runtime._check_command_policy("$c='Invoke-WebRequest'; & $c example.com", {})
                assert dynamic.value.details["permission"] == "shell_expansion"

                with pytest.raises(ToolFailure) as network:
                    runtime._check_command_policy("Invoke-WebRequest https://example.com", {})
                assert network.value.details["permission"] == "network"

                with pytest.raises(ToolFailure) as destructive:
                    runtime._check_command_policy("Remove-Item . -Recurse", {})
                assert destructive.value.details["permission"] == "destructive_command"
        finally:
            runtime.close()
