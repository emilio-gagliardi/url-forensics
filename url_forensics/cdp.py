"""Minimal asyncio Chrome DevTools Protocol client.

Talks to a browser-level DevTools websocket (flattened sessions). It is read-mostly
by design: this project never sends Input.* commands, so nothing clicks or types.
"""
from __future__ import annotations

import asyncio
import json
from typing import Callable


class CdpError(RuntimeError):
    """A CDP command failed or the connection closed."""


class CdpConnection:
    def __init__(self, ws_url: str, on_event: Callable[[str, dict, str | None], None]):
        self.ws_url = ws_url
        self._on_event = on_event
        self._ws = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader: asyncio.Task | None = None

    async def connect(self) -> None:
        try:
            import websockets
        except ImportError as exc:
            raise RuntimeError("DevTools extras missing: pip install -e '.[devtools]'") from exc
        self._ws = await websockets.connect(self.ws_url, max_size=64 * 1024 * 1024,
                                            ping_interval=None, open_timeout=15)
        self._reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        try:
            async for raw in self._ws:
                message = json.loads(raw)
                if "id" in message:
                    future = self._pending.pop(message["id"], None)
                    if future is not None and not future.done():
                        if "error" in message:
                            future.set_exception(CdpError(str(message["error"])[:500]))
                        else:
                            future.set_result(message.get("result", {}))
                elif "method" in message:
                    try:
                        self._on_event(message["method"], message.get("params", {}), message.get("sessionId"))
                    except Exception:  # a recorder bug must not kill the reader
                        pass
        except Exception:
            pass
        finally:
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(CdpError("DevTools connection closed"))
            self._pending.clear()

    async def send(self, method: str, params: dict | None = None, session_id: str | None = None,
                   timeout: float = 15.0) -> dict:
        if method.startswith("Input."):
            raise CdpError("Input.* commands are never sent: this tool does not interact with pages")
        if self._ws is None:
            raise CdpError("Not connected")
        self._next_id += 1
        message = {"id": self._next_id, "method": method, "params": params or {}}
        if session_id:
            message["sessionId"] = session_id
        future = asyncio.get_running_loop().create_future()
        self._pending[self._next_id] = future
        await self._ws.send(json.dumps(message))
        try:
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError as exc:
            self._pending.pop(message["id"], None)
            raise CdpError(f"{method} timed out") from exc

    async def close(self) -> None:
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
        if self._reader is not None:
            self._reader.cancel()
            try:
                await self._reader
            except (asyncio.CancelledError, Exception):
                pass
