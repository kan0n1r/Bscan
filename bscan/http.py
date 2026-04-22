from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 Bscan/0.1"
)


class TransportError(RuntimeError):
    def __init__(self, method: str, url: str, cause: Exception) -> None:
        super().__init__(f"{method} {url} failed: {cause}")
        self.method = method
        self.url = url
        self.cause = cause


@dataclass
class AuthConfig:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return bool(self.headers or self.cookies)

    def to_metadata(self) -> dict:
        return {
            "authenticated": self.enabled,
            "header_names": sorted(self.headers),
            "cookie_names": sorted(self.cookies),
        }


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    text: str
    ok: bool
    content: bytes = b""

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
        auth: Optional[AuthConfig] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        base_headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if auth is not None:
            base_headers.update(auth.headers)
        self._client = httpx.Client(
            http2=True,
            timeout=timeout,
            verify=verify,
            follow_redirects=True,
            proxy=proxy,
            headers=base_headers,
            cookies=auth.cookies if auth is not None else None,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def get(self, path: str, **kwargs) -> Response:
        return self._request("GET", path, **kwargs)

    def head(self, path: str, **kwargs) -> Response:
        return self._request("HEAD", path, **kwargs)

    def _request(self, method: str, path: str, **kwargs) -> Response:
        url = urljoin(self.base_url, path.lstrip("/"))
        try:
            r = self._client.request(method, url, **kwargs)
        except httpx.HTTPError as e:
            raise TransportError(method, url, e) from e
        return Response(
            url=str(r.url),
            status=r.status_code,
            headers=dict(r.headers),
            text="" if method == "HEAD" else r.text,
            ok=r.is_success,
            content=b"" if method == "HEAD" else r.content,
        )
