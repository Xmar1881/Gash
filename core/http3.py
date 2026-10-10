"""Optional, bounded HTTP/3 GET probe.

The scanner remains usable without aioquic. When the ``http3`` extra is
installed, this module opens one QUIC connection, sends one GET, collects a
small response, and closes it. It never falls back to HTTP/1.1 or HTTP/2 and
never mutates a request body.
"""

from __future__ import annotations

import asyncio
import ssl
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class HTTP3Result:
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""


def available() -> bool:
    """Whether the optional aioquic backend is importable."""
    try:
        import aioquic  # noqa: F401
        return True
    except ImportError:
        return False


class _HTTP3ClientProtocol:
    """Created lazily so importing GASH never requires aioquic."""

    @staticmethod
    def build():
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived

        class Client(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._http = H3Connection(self._quic)
                self._events = deque()
                self._done = None
                self._data_type = DataReceived
                self._headers_type = HeadersReceived

            def quic_event_received(self, event):
                for http_event in self._http.handle_event(event):
                    self.http_event_received(http_event)

            def http_event_received(self, event):
                if not isinstance(event, (self._headers_type, self._data_type)):
                    return
                self._events.append(event)
                if getattr(event, "stream_ended", False) and self._done:
                    if not self._done.done():
                        self._done.set_result(None)

            async def get(self, url: str, headers: dict[str, str], timeout: float):
                parsed = urlparse(url)
                stream_id = self._quic.get_next_available_stream_id()
                self._done = self._loop.create_future()
                wire_headers = [
                    (b":method", b"GET"),
                    (b":scheme", parsed.scheme.encode("ascii")),
                    (b":authority", parsed.netloc.encode("idna")),
                    (b":path", (parsed.path or "/").encode("utf-8")
                     + ((b"?" + parsed.query.encode("utf-8"))
                        if parsed.query else b"")),
                    (b"user-agent", b"GASH-http3-probe"),
                ]
                for key, value in (headers or {}).items():
                    low = str(key).lower()
                    if low in {"connection", "host", "content-length"}:
                        continue
                    wire_headers.append((low.encode("ascii", "ignore"),
                                         str(value).encode("utf-8")))
                self._http.send_headers(stream_id=stream_id,
                                        headers=wire_headers,
                                        end_stream=True)
                self.transmit()
                await asyncio.wait_for(asyncio.shield(self._done), timeout)
                status = 0
                response_headers: dict[str, str] = {}
                body = bytearray()
                for event in self._events:
                    if isinstance(event, self._headers_type):
                        for key, value in event.headers:
                            name = key.decode("ascii", "ignore").lower()
                            val = value.decode("utf-8", "replace")
                            if name == ":status":
                                try:
                                    status = int(val)
                                except ValueError:
                                    status = 0
                            elif not name.startswith(":"):
                                response_headers[name] = val[:300]
                    elif isinstance(event, self._data_type):
                        if len(body) < 65536:
                            body.extend(event.data[:65536 - len(body)])
                return HTTP3Result(status=status, headers=response_headers,
                                   body=bytes(body))

        return Client


async def _get_async(url: str, timeout: float, headers: dict[str, str],
                     insecure: bool) -> HTTP3Result:
    from aioquic.asyncio.client import connect
    from aioquic.h3.connection import H3_ALPN
    from aioquic.quic.configuration import QuicConfiguration

    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return HTTP3Result(error="HTTP/3 requires an https:// target")
    port = parsed.port or 443
    configuration = QuicConfiguration(is_client=True,
                                      alpn_protocols=H3_ALPN)
    if insecure:
        configuration.verify_mode = ssl.CERT_NONE
    else:
        configuration.verify_mode = ssl.CERT_REQUIRED
    protocol_cls = _HTTP3ClientProtocol.build()
    async with connect(parsed.hostname, port, configuration=configuration,
                       create_protocol=protocol_cls) as client:
        return await client.get(url, headers, timeout)


def get(url: str, timeout: int = 8, headers: dict[str, str] | None = None,
        insecure: bool = False) -> HTTP3Result:
    """Run one bounded HTTP/3 GET, returning a non-throwing result."""
    if not available():
        return HTTP3Result(
            error='aioquic is not installed; use py -m pip install -e ".[http3]"'
        )
    try:
        return asyncio.run(_get_async(url, max(1, float(timeout)), headers or {},
                                     insecure))
    except Exception as exc:
        return HTTP3Result(error=f"{type(exc).__name__}: {str(exc)[:120]}")


__all__ = ["HTTP3Result", "available", "get"]
