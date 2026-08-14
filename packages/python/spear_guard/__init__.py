# spear-guard
#
# Python SDK wrapping the Spear HTTP API (`@spear-secure/api`).
# No reimplementation of gates — every call is an HTTP round-trip.

from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional


class SpearBlockedError(RuntimeError):
    """Raised when Spear blocks a request in enforce mode."""


@dataclass
class GateResult:
    allowed: bool
    reason: Optional[str] = None
    messages: Optional[list[dict[str, Any]]] = None
    output: Optional[str] = None
    canary: Optional[str] = None
    risk_score: float = 0.0
    retry_after_ms: Optional[int] = None
    raw: Optional[dict[str, Any]] = None


def _request(
    method: str,
    url: str,
    body: Optional[dict[str, Any]] = None,
    timeout: float = 10.0,
    retries: int = 3,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    last_error: Exception | None = None
    for attempt in range(max(1, retries)):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8")
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError:
                parsed = {"error": payload}
            raise SpearBlockedError(parsed.get("error") or payload) from exc
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt == retries - 1:
                break
            time.sleep(0.2 * (2**attempt))
    assert last_error is not None
    raise last_error


def _to_result(raw: dict[str, Any]) -> GateResult:
    return GateResult(
        allowed=bool(raw.get("allowed", True)),
        reason=raw.get("reason"),
        messages=raw.get("messages"),
        output=raw.get("output"),
        canary=raw.get("canary"),
        risk_score=float(raw.get("riskScore") or raw.get("risk_score") or 0),
        retry_after_ms=raw.get("retryAfterMs"),
        raw=raw,
    )


class Session:
    """Sync session bound to a Spear API process."""

    def __init__(self, client: "Spear", session_id: str) -> None:
        self._client = client
        self.session_id = session_id

    def step(self, messages: list[dict[str, Any]]) -> GateResult:
        return _to_result(self._client._post(f"/session/{self.session_id}/step", {"messages": messages}))

    def tools(self, tool_calls: list[dict[str, Any]]) -> dict[str, Any]:
        return self._client._post(f"/session/{self.session_id}/tools", {"tool_calls": tool_calls})

    def observe(self, results: list[Any], source: str = "external") -> dict[str, Any]:
        return self._client._post(
            f"/session/{self.session_id}/observe",
            {"results": results, "source": source},
        )

    def complete(self, output: str) -> GateResult:
        return _to_result(self._client._post(f"/session/{self.session_id}/complete", {"output": output}))

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class Spear:
    """Sync HTTP client for the Spear API."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0) -> None:
        self.base_url = (base_url or os.environ.get("SPEAR_URL") or "http://localhost:7700").rstrip("/")
        self.timeout = timeout

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return _request("POST", self.base_url + path, body, timeout=self.timeout)

    def pre(self, messages: list[dict[str, Any]], session_id: str | None = None) -> GateResult:
        payload: dict[str, Any] = {"messages": messages}
        if session_id:
            payload["session_id"] = session_id
        return _to_result(self._post("/pre", payload))

    def post(self, output: str, canary: str | None = None, session_id: str | None = None) -> GateResult:
        payload: dict[str, Any] = {"output": output}
        if canary:
            payload["canary"] = canary
        if session_id:
            payload["session_id"] = session_id
        return _to_result(self._post("/post", payload))

    def session(self, session_id: str, user_id: str | None = None) -> Session:
        body: dict[str, Any] = {"session_id": session_id}
        if user_id:
            body["user_id"] = user_id
        self._post("/session/start", body)
        return Session(self, session_id)


class AsyncSession:
    """Async wrapper around :class:`Session`."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self.session_id = session.session_id

    async def step(self, messages: list[dict[str, Any]]) -> GateResult:
        return await asyncio.to_thread(self._session.step, messages)

    async def tools(self, tool_calls: list[dict[str, Any]]) -> dict[str, Any]:
        return await asyncio.to_thread(self._session.tools, tool_calls)

    async def observe(self, results: list[Any], source: str = "external") -> dict[str, Any]:
        return await asyncio.to_thread(self._session.observe, results, source)

    async def complete(self, output: str) -> GateResult:
        return await asyncio.to_thread(self._session.complete, output)

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class AsyncSpear:
    """Async HTTP client. Uses stdlib urllib in a worker thread (no extra deps)."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0) -> None:
        self._sync = Spear(base_url, timeout)

    async def pre(self, messages: list[dict[str, Any]], session_id: str | None = None) -> GateResult:
        return await asyncio.to_thread(self._sync.pre, messages, session_id)

    async def post(
        self, output: str, canary: str | None = None, session_id: str | None = None
    ) -> GateResult:
        return await asyncio.to_thread(self._sync.post, output, canary, session_id)

    async def session(self, session_id: str, user_id: str | None = None) -> AsyncSession:
        inner = await asyncio.to_thread(self._sync.session, session_id, user_id)
        return AsyncSession(inner)


def quick(profile: str = "balanced", mode: str = "shadow", url: str | None = None) -> Spear:
    """Create a client. Profile/mode are honoured by the API process via env, not this SDK."""
    _ = (profile, mode)
    return Spear(base_url=url)


class SpearCallbackHandler:
    """LangChain-compatible callback (duck-typed BaseCallbackHandler)."""

    def __init__(self, spear_url: str = "http://localhost:7700", mode: str = "enforce") -> None:
        self.spear = Spear(spear_url)
        self.mode = mode
        self._session: Session | None = None

    def _ensure_session(self) -> Session:
        if self._session is None:
            self._session = self.spear.session(f"lc-{os.getpid()}")
        return self._session

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        session = self._ensure_session()
        messages = [{"role": "system", "content": "Spear-guarded LangChain call."}]
        messages.extend({"role": "user", "content": p} for p in prompts)
        result = session.step(messages)
        if not result.allowed and self.mode == "enforce":
            raise SpearBlockedError(result.reason or "blocked")

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        session = self._ensure_session()
        name = serialized.get("name") or serialized.get("id") or "tool"
        result = session.tools([{"name": name, "arguments": {"input": input_str}}])
        blocked = result.get("blocked") or []
        if blocked and self.mode == "enforce":
            reason = blocked[0].get("reason") if isinstance(blocked[0], dict) else "blocked"
            raise SpearBlockedError(reason or "blocked")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        session = self._ensure_session()
        session.observe([output], source="external")

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        text = getattr(response, "content", None) or str(response)
        session = self._ensure_session()
        result = session.complete(text)
        if not result.allowed and self.mode == "enforce":
            raise SpearBlockedError(result.reason or "blocked")
