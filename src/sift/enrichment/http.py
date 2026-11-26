"""HTTP transport abstraction backed by httpx with graceful error normalization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_USER_AGENT = "sift-sec/0.1.0 (+https://github.com/ahmad-muslim/sift)"


class HttpRequestError(RuntimeError):
    """Normalized exception raised when an outbound threat-intel HTTP request fails."""


class HttpResponse(Protocol):
    """Minimal HTTP response interface satisfied by httpx.Response and test doubles."""

    @property
    def status_code(self) -> int: ...

    def json(self) -> Any: ...

    def raise_for_status(self) -> Any: ...


class HttpClient(Protocol):
    """Minimal HTTP client interface satisfied by httpx.Client and test doubles."""

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> HttpResponse: ...

    def close(self) -> None: ...


class HttpxClientAdapter:
    """Thin wrapper around httpx.Client that normalizes transport/status errors."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        import httpx

        self._httpx = httpx
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers={
                "User-Agent": user_agent,
                "Accept": "application/json",
            },
        )

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        try:
            response: HttpResponse = self._client.get(url, params=params)
            response.raise_for_status()
            return response
        except self._httpx.HTTPError as exc:
            raise HttpRequestError(f"HTTP request failed for {url}: {exc}") from exc

    def close(self) -> None:
        self._client.close()


def create_default_http_client(
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    user_agent: str = DEFAULT_USER_AGENT,
) -> HttpClient:
    """Create the default httpx-backed HTTP client."""
    return HttpxClientAdapter(timeout=timeout, user_agent=user_agent)
