from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from coding_tools_mcp.server import MCPHandler, Runtime, RuntimeHTTPServer, is_stateless_http_client
from coding_tools_mcp.transport_http import HTTPSessionManager


class FakeRuntime:
    def __init__(self, session_id: str) -> None:
        self.http_session_id = session_id
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def test_capacity_reclaims_oldest_idle_session_instead_of_503_loop() -> None:
    now = [100.0]
    created: list[FakeRuntime] = []

    def factory() -> FakeRuntime:
        runtime = FakeRuntime(f"s{len(created) + 1}")
        created.append(runtime)
        return runtime

    manager = HTTPSessionManager(
        factory,
        max_sessions=2,
        ttl_seconds=300,
        eviction_grace_seconds=1,
        clock=lambda: now[0],
    )
    first = manager.create()
    manager.release(first.http_session_id)
    now[0] += 2
    second = manager.create()
    manager.release(second.http_session_id)
    now[0] += 2

    third = manager.create()
    manager.release(third.http_session_id)

    assert first.closed == 1
    assert second.closed == 0
    assert third.closed == 0
    snapshot = manager.snapshot()
    assert snapshot["active_sessions"] == 2
    assert snapshot["evicted_total"] == 1


def test_capacity_never_evicts_in_flight_sessions() -> None:
    now = [100.0]
    counter = [0]

    def factory() -> FakeRuntime:
        counter[0] += 1
        return FakeRuntime(f"s{counter[0]}")

    manager = HTTPSessionManager(
        factory,
        max_sessions=2,
        ttl_seconds=300,
        eviction_grace_seconds=0,
        clock=lambda: now[0],
    )
    manager.create()
    manager.create()
    now[0] += 100

    with pytest.raises(RuntimeError, match="no idle session is reclaimable"):
        manager.create()


def test_prune_skips_in_flight_and_reclaims_after_release() -> None:
    now = [100.0]
    runtime = FakeRuntime("s1")
    manager = HTTPSessionManager(
        lambda: runtime,
        max_sessions=2,
        ttl_seconds=10,
        eviction_grace_seconds=0,
        clock=lambda: now[0],
    )
    manager.create()
    now[0] += 20
    manager.prune()
    assert runtime.closed == 0

    manager.release("s1")
    now[0] += 20
    manager.prune()
    assert runtime.closed == 1
    assert manager.snapshot()["pruned_total"] == 1


def test_snapshot_prunes_expired_idle_sessions_before_reporting_counts() -> None:
    now = [100.0]
    runtime = FakeRuntime("s1")
    manager = HTTPSessionManager(
        lambda: runtime,
        max_sessions=2,
        ttl_seconds=10,
        eviction_grace_seconds=0,
        clock=lambda: now[0],
    )
    created = manager.create()
    manager.release(created.http_session_id)
    now[0] += 20

    snapshot = manager.snapshot()

    assert snapshot["active_sessions"] == 0
    assert snapshot["in_flight"] == 0
    assert snapshot["pruned_total"] == 1
    assert snapshot["oldest_idle_age_seconds"] == 0.0
    assert runtime.closed == 1


def test_snapshot_preserves_expired_in_flight_sessions() -> None:
    now = [100.0]
    runtime = FakeRuntime("s1")
    manager = HTTPSessionManager(
        lambda: runtime,
        max_sessions=2,
        ttl_seconds=10,
        eviction_grace_seconds=0,
        clock=lambda: now[0],
    )
    created = manager.create()
    now[0] += 20

    snapshot = manager.snapshot()

    assert snapshot["active_sessions"] == 1
    assert snapshot["in_flight"] == 1
    assert snapshot["pruned_total"] == 0
    assert runtime.closed == 0

    manager.release(created.http_session_id)
    now[0] += 20
    assert manager.snapshot()["active_sessions"] == 0
    assert runtime.closed == 1


def test_http_runtime_close_does_not_kill_workspace_shared_command_state() -> None:
    with TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        owner = Runtime(workspace)
        child = Runtime(workspace, command_state=owner.command_state)
        sentinel = object()
        owner.sessions["shared-command"] = sentinel  # type: ignore[assignment]
        try:
            child.close()
            assert owner.sessions["shared-command"] is sentinel
            assert child.command_state is owner.command_state
        finally:
            owner.sessions.clear()
            owner.close()


def test_openai_mcp_is_classified_as_stateless_http_client() -> None:
    assert is_stateless_http_client({"name": "openai-mcp"}, "")
    assert is_stateless_http_client({}, "openai-mcp/1.0.0")
    assert not is_stateless_http_client({"name": "other-client"}, "other-client/1.0")


def test_openai_mcp_http_handshake_retains_zero_transport_sessions() -> None:
    with TemporaryDirectory() as tmp:
        runtime = Runtime(Path(tmp), transport="http")
        server = RuntimeHTTPServer(
            ("127.0.0.1", 0),
            MCPHandler,
            runtime,
            runtime.spawn_http_session_runtime,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "openai-mcp/1.0.0",
            "MCP-Protocol-Version": "2025-11-25",
        }

        def post(payload: dict[str, object]) -> tuple[int, dict[str, str], bytes]:
            connection.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
            response = connection.getresponse()
            body = response.read()
            return response.status, {name.lower(): value for name, value in response.getheaders()}, body

        try:
            status, response_headers, body = post(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "clientInfo": {"name": "openai-mcp", "version": "1.0.0"},
                    },
                }
            )
            assert status == 200, body
            assert "mcp-session-id" not in response_headers

            status, response_headers, body = post(
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
            )
            assert status == 202, body
            assert "mcp-session-id" not in response_headers

            status, response_headers, body = post(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            )
            assert status == 200, body
            assert "mcp-session-id" not in response_headers
            payload = json.loads(body)
            assert payload["result"]["tools"]
            assert server.sessions.snapshot()["active_sessions"] == 0
            assert server.sessions.snapshot()["created_total"] == 0
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def test_http_session_runtime_is_lightweight_and_does_not_call_runtime_init(monkeypatch: pytest.MonkeyPatch) -> None:
    with TemporaryDirectory() as tmp:
        owner = Runtime(Path(tmp))
        owner._ensure_runtime_dirs()
        runtime_dir = owner.runtime_dir

        def forbidden_init(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("Runtime.__init__ must not run for an HTTP transport session")

        monkeypatch.setattr(Runtime, "__init__", forbidden_init)
        child = owner.spawn_http_session_runtime()
        try:
            assert child is not owner
            assert child.workspace is owner.workspace
            assert child.project_context is owner.project_context
            assert child.command_state is owner.command_state
            assert child.runtime_dir == owner.runtime_dir
            assert child.http_session_id != owner.http_session_id
            assert child.initialized is False
            assert child.default_cwd == owner.workspace.root
            assert child.telemetry is not owner.telemetry
        finally:
            child.close()
            assert runtime_dir.exists()
            owner.close()


def test_http_session_runtime_keeps_default_cwd_isolated() -> None:
    with TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        (workspace / "one").mkdir()
        owner = Runtime(workspace)
        child = owner.spawn_http_session_runtime()
        try:
            result = child.call_tool("set_default_cwd", {"path": "one"})
            assert result["structuredContent"]["default_cwd"] == "one"
            assert child.default_cwd == workspace / "one"
            assert owner.default_cwd == workspace
        finally:
            child.close()
            owner.close()
