from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


MAX_HTTP_SESSIONS = 128
HTTP_SESSION_TTL_SECONDS = 5 * 60
HTTP_SESSION_EVICTION_GRACE_SECONDS = 5.0


def _close_runtime(runtime: Any) -> None:
    close = getattr(runtime, "close", None)
    if callable(close):
        close()


@dataclass
class HTTPSessionRecord:
    runtime: Any
    last_seen: float
    in_flight: int = 0


class HTTPSessionManager:
    """Own independent Runtime instances for Streamable HTTP sessions."""

    def __init__(
        self,
        factory: Callable[[], Any],
        *,
        max_sessions: int = MAX_HTTP_SESSIONS,
        ttl_seconds: float = HTTP_SESSION_TTL_SECONDS,
        eviction_grace_seconds: float = HTTP_SESSION_EVICTION_GRACE_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._factory = factory
        self._sessions: dict[str, HTTPSessionRecord] = {}
        self._lock = threading.Lock()
        self._creating = 0
        self._closed = False
        self._max_sessions = max(1, int(max_sessions))
        self._ttl_seconds = max(1.0, float(ttl_seconds))
        self._eviction_grace_seconds = max(0.0, float(eviction_grace_seconds))
        self._clock = clock
        self._created_count = 0
        self._evicted_count = 0
        self._pruned_count = 0

    def _pop_oldest_reclaimable_locked(self, now: float) -> HTTPSessionRecord | None:
        cutoff = now - self._eviction_grace_seconds
        candidates = [
            (session_id, record)
            for session_id, record in self._sessions.items()
            if record.in_flight == 0 and record.last_seen <= cutoff
        ]
        if not candidates:
            return None
        session_id, _ = min(candidates, key=lambda item: item[1].last_seen)
        record = self._sessions.pop(session_id)
        self._evicted_count += 1
        return record

    def create(self) -> Any:
        self.prune()
        evicted: HTTPSessionRecord | None = None
        with self._lock:
            if self._closed:
                raise RuntimeError("HTTP session manager is closed")
            if len(self._sessions) + self._creating >= self._max_sessions:
                evicted = self._pop_oldest_reclaimable_locked(self._clock())
                if evicted is None:
                    raise RuntimeError("maximum HTTP session count reached; no idle session is reclaimable")
            self._creating += 1
        if evicted is not None:
            _close_runtime(evicted.runtime)
        runtime: Any | None = None
        installed = False
        try:
            runtime = self._factory()
            record = HTTPSessionRecord(runtime=runtime, last_seen=self._clock(), in_flight=1)
            with self._lock:
                if self._closed:
                    raise RuntimeError("HTTP session manager is closed")
                if runtime.http_session_id in self._sessions:
                    raise RuntimeError("duplicate HTTP session identifier")
                self._sessions[runtime.http_session_id] = record
                self._created_count += 1
                installed = True
            return runtime
        finally:
            with self._lock:
                self._creating -= 1
            if runtime is not None and not installed:
                _close_runtime(runtime)

    def get(self, session_id: str) -> Any | None:
        self.prune()
        with self._lock:
            if self._closed:
                return None
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.last_seen = self._clock()
            record.in_flight += 1
            return record.runtime

    def release(self, session_id: str) -> None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return
            if record.in_flight > 0:
                record.in_flight -= 1
            record.last_seen = self._clock()

    def delete(self, session_id: str) -> bool:
        with self._lock:
            record = self._sessions.pop(session_id, None)
        if record is None:
            return False
        _close_runtime(record.runtime)
        return True

    def prune(self) -> None:
        cutoff = self._clock() - self._ttl_seconds
        with self._lock:
            expired = [
                session_id
                for session_id, record in self._sessions.items()
                if record.in_flight == 0 and record.last_seen < cutoff
            ]
            records = [self._sessions.pop(session_id) for session_id in expired]
            self._pruned_count += len(records)
        for record in records:
            _close_runtime(record.runtime)

    def snapshot(self) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            records = list(self._sessions.values())
            oldest_age = max((max(0.0, now - record.last_seen) for record in records), default=0.0)
            return {
                "active_sessions": len(records),
                "in_flight": sum(record.in_flight for record in records),
                "creating": self._creating,
                "max_sessions": self._max_sessions,
                "ttl_seconds": self._ttl_seconds,
                "eviction_grace_seconds": self._eviction_grace_seconds,
                "oldest_idle_age_seconds": round(oldest_age, 3),
                "created_total": self._created_count,
                "evicted_total": self._evicted_count,
                "pruned_total": self._pruned_count,
            }

    def close(self) -> None:
        with self._lock:
            self._closed = True
            records = list(self._sessions.values())
            self._sessions.clear()
        for record in records:
            _close_runtime(record.runtime)
