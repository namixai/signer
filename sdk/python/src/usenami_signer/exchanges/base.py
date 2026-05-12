from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx

if TYPE_CHECKING:
    from usenami_signer.client import Signer

# Exchanges where signature covers the query string. The SDK must forward
# user params to the gateway via the `query` field so the enclave can sign
# over the full canonical string.
#
# OKX is in this set because its V5 spec signs over `requestPath` which
# INCLUDES the query string. The signer's handle_sign_okx merges `query`
# back into requestPath before computing the HMAC, so forwarding the
# query separately works exactly the same way as for Binance/Bybit.
_SIGN_QUERY_EXCHANGES = {"binance", "binance_futures", "bybit", "okx"}


class BaseExchange:
    """Base class for exchange-specific convenience wrappers."""

    exchange_name: str = ""
    base_url: str = ""

    def __init__(self, signer: Signer, timeout: float = 10.0):
        self._signer = signer
        self._exchange_client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._exchange_client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | str | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a signed request to the exchange API.

        Args:
            method: HTTP method.
            path: API path (e.g. "/api/v1/accounts").
            body: Request body (dict will be JSON-serialized).
            params: Query parameters.

        Returns:
            httpx.Response from the exchange.
        """
        body_str = ""
        if body is not None:
            body_str = body if isinstance(body, str) else json.dumps(body, separators=(",", ":"))

        # For Binance/Bybit, the signature covers the query string. Forward
        # user params to the gateway via the explicit `query` field. KuCoin
        # ignores `query` so it's safe to always set when params present.
        sign_query = ""
        if params and self.exchange_name in _SIGN_QUERY_EXCHANGES:
            # `urlencode` encodes booleans/numbers as strings already; sort
            # keys for deterministic order so the same logical request
            # produces the same canonical string across SDK versions.
            sign_query = urlencode(sorted(params.items()))

        sign_result = self._signer.sign(
            exchange=self.exchange_name,
            method=method,
            path=path,
            body=body_str,
            query=sign_query,
        )

        signed_headers, signed_params = self._split_sign_result(sign_result)

        url = f"{self.base_url}{path}"
        exchange_headers = {
            **signed_headers,
            "Content-Type": "application/json",
        }
        merged_params = {**(params or {}), **signed_params}

        return self._exchange_client.request(
            method=method.upper(),
            url=url,
            headers=exchange_headers,
            params=merged_params or None,
            content=body_str.encode() if body_str else None,
        )

    def _split_sign_result(
        self, sign_result: dict[str, str]
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Split sign result into headers and query params.

        Override in subclasses where some signed fields go into query params
        (e.g. Binance puts signature + timestamp in URL params).
        Default: everything goes into headers.
        """
        return sign_result, {}

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> httpx.Response:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any] | str | None = None) -> httpx.Response:
        return self.request("POST", path, body=body)

    def put(self, path: str, body: dict[str, Any] | str | None = None) -> httpx.Response:
        return self.request("PUT", path, body=body)

    def delete(self, path: str, body: dict[str, Any] | str | None = None) -> httpx.Response:
        return self.request("DELETE", path, body=body)
