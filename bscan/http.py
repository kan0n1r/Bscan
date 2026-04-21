from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

import httpx

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 Bscan/0.1"
)


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    text: str
    ok: bool

    @property
    def is_html(self) -> bool:
        return "text/html" in self.headers.get("content-type", "").lower()


class Client:
    def __init__(
        self,
        base_url: str,
        timeout: float = 15.0,
        verify: bool = True,
        proxy: Optional[str] = None,
        user_agent: str = DEFAULT_UA,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self._client = httpx.Client(
            http2=True,
            timeout=timeout,
            verify=verify,
            follow_redirects=True,
            proxy=proxy,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def get(self, path: str, **kwargs) -> Response:
        url = urljoin(self.base_url, path.lstrip("/"))
        try:
            r = self._client.get(url, **kwargs)
        except httpx.HTTPError as e:
            return Response(url=url, status=0, headers={}, text=str(e), ok=False)
        return Response(
            url=str(r.url),
            status=r.status_code,
            headers=dict(r.headers),
            text=r.text,
            ok=r.is_success,
        )

    def head(self, path: str, **kwargs) -> Response:
        url = urljoin(self.base_url, path.lstrip("/"))
        try:
            r = self._client.head(url, **kwargs)
        except httpx.HTTPError as e:
            return Response(url=url, status=0, headers={}, text=str(e), ok=False)
        return Response(
            url=str(r.url),
            status=r.status_code,
            headers=dict(r.headers),
            text="",
            ok=r.is_success,
        )
