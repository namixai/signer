from __future__ import annotations

import time
from typing import Any

import httpx

from usenami_signer.exceptions import (
    SignerBadRequest,
    SignerEnclaveDenied,
    SignerEnclaveUnreachable,
    SignerError,
    SignerInternalError,
)
from usenami_signer.exchanges.binance import BinanceExchange, BinanceFuturesExchange
from usenami_signer.exchanges.bybit import BybitExchange
from usenami_signer.exchanges.hyperliquid_main import HyperliquidMainExchange
from usenami_signer.exchanges.kucoin import KuCoinExchange
from usenami_signer.exchanges.okx import OkxExchange

_ERROR_MAP: dict[str, type[SignerError]] = {
    "bad_request": SignerBadRequest,
    "payload_too_large": SignerBadRequest,
    "kms_decrypt_denied": SignerEnclaveDenied,
    "enclave_unreachable": SignerEnclaveUnreachable,
    "internal_error": SignerInternalError,
}

_RETRIABLE = (SignerEnclaveDenied, SignerEnclaveUnreachable, SignerInternalError)

_VALID_METHODS = {"GET", "POST", "PUT", "DELETE"}


class Signer:
    """Client for the Usenami Signer gateway.

    Usage::

        from usenami_signer import Signer

        signer = Signer("http://signer-demo.usenami.io:8443")

        # Low-level: get signed headers
        headers = signer.sign("kucoin", "GET", "/api/v1/accounts")

        # High-level: make a signed KuCoin API call
        resp = signer.kucoin.request("GET", "/api/v1/accounts")
        print(resp.json())
    """

    def __init__(
        self,
        gateway_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 10.0,
        retries: int = 2,
        http_client: httpx.Client | None = None,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.api_key = api_key
        self.retries = retries
        self._client = http_client or httpx.Client(timeout=timeout)
        self._owns_client = http_client is None

        self.kucoin = KuCoinExchange(self, timeout=timeout)
        self.binance = BinanceExchange(self, timeout=timeout)
        self.binance_futures = BinanceFuturesExchange(self, timeout=timeout)
        self.bybit = BybitExchange(self, timeout=timeout)
        self.okx = OkxExchange(self, timeout=timeout)
        # Phase 1 Stage 2 — Hyperliquid mainnet (EIP-712). Per-venue API:
        # `signer.hyperliquid_main.order(...)` not `signer.hyperliquid("main", ...)`.
        self.hyperliquid_main = HyperliquidMainExchange(self, timeout=timeout)

    def close(self) -> None:
        for exc in (
            self.kucoin,
            self.binance,
            self.binance_futures,
            self.bybit,
            self.okx,
            self.hyperliquid_main,
        ):
            exc.close()
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> Signer:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def healthz(self) -> dict[str, Any]:
        """Check gateway + enclave liveness."""
        resp = self._client.get(f"{self.gateway_url}/healthz")
        if resp.status_code != 200:
            raise SignerEnclaveUnreachable(
                "Health check failed", code="enclave_unreachable", status=resp.status_code
            )
        return resp.json()

    def sign(
        self,
        exchange: str,
        method: str,
        path: str,
        body: str = "",
        *,
        timestamp_ms: int | None = None,
        query: str = "",
    ) -> dict[str, str]:
        """Request signed exchange headers from the enclave.

        Args:
            exchange: Exchange name (e.g. "kucoin").
            method: HTTP method (GET/POST/PUT/DELETE).
            path: Exchange API path (e.g. "/api/v1/accounts").
            body: Request body as string. Empty for GET requests.
            timestamp_ms: Unix timestamp in ms. Auto-filled if omitted.

        Returns:
            Dict of signed headers to attach to the exchange API request.

        Raises:
            SignerBadRequest: Invalid parameters (not retriable).
            SignerEnclaveDenied: KMS policy rejected attestation (retriable).
            SignerEnclaveUnreachable: Enclave down (retriable).
            SignerInternalError: Server error (retriable).
        """
        method = method.upper()
        if method not in _VALID_METHODS:
            raise SignerBadRequest(f"Invalid method: {method}", code="bad_request")

        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)

        payload: dict[str, Any] = {
            "exchange": exchange,
            "method": method,
            "path": path,
            "body": body,
            "timestamp_ms": timestamp_ms,
        }
        if query:
            payload["query"] = query

        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        last_exc: SignerError | None = None
        for attempt in range(1 + self.retries):
            if attempt > 0:
                payload["timestamp_ms"] = int(time.time() * 1000)

            try:
                resp = self._client.post(
                    f"{self.gateway_url}/sign",
                    json=payload,
                    headers=headers,
                )
            except httpx.TransportError as e:
                last_exc = SignerEnclaveUnreachable(str(e), code="enclave_unreachable")
                continue

            if resp.status_code == 200:
                data = resp.json()
                return data["headers"]

            try:
                data = resp.json()
                error_code = data.get("error", "internal_error")
            except Exception:
                error_code = "internal_error"
            exc_cls = _ERROR_MAP.get(error_code, SignerInternalError)
            last_exc = exc_cls(
                f"Signer error: {error_code}", code=error_code, status=resp.status_code
            )

            if not isinstance(last_exc, _RETRIABLE):
                raise last_exc

        raise last_exc  # type: ignore[misc]

    def sign_eip712(
        self,
        *,
        exchange: str,
        kind: str,
        action: dict[str, Any],
        nonce: int,
        vault_address: str | None = None,
    ) -> dict[str, Any]:
        """Request an EIP-712 signature for an action body (Hyperliquid
        family).

        Differs from ``sign()`` in three ways:
          1. Signs over the action JSON, not an HTTP canonical string.
          2. Returns ``{"r": "0x...", "s": "0x...", "v": 27|28}``, NOT
             a dict of HTTP headers.
          3. Requires a ``kind`` argument (``"order"`` / ``"cancel"``)
             because EIP-712 venues have multiple action templates per
             exchange.

        Args:
            exchange: Venue, e.g. ``"hyperliquid_main"``.
            kind: ``"order"`` or ``"cancel"``.
            action: Canonical JSON action object. Caller is responsible for
                key ordering (alphabetical for Hyperliquid).
            nonce: Hyperliquid nonce (Unix ms). MUST monotonically increase
                per address; Hyperliquid rejects ``<=`` last-seen.
            vault_address: Optional ``0x``-prefixed 20-byte vault address.

        Returns:
            Dict with keys ``r``, ``s``, ``v`` ready for inclusion under
            ``body.signature`` of the Hyperliquid ``POST /exchange``
            request.

        Raises:
            Same set as ``sign()``.
        """
        payload: dict[str, Any] = {
            "exchange": exchange,
            "kind": kind,
            "action": action,
            "nonce": nonce,
        }
        if vault_address is not None:
            payload["vault_address"] = vault_address

        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        last_exc: SignerError | None = None
        for attempt in range(1 + self.retries):
            if attempt > 0:
                payload["nonce"] = int(time.time() * 1000)
            try:
                resp = self._client.post(
                    f"{self.gateway_url}/sign",
                    json=payload,
                    headers=headers,
                )
            except httpx.TransportError as e:
                last_exc = SignerEnclaveUnreachable(str(e), code="enclave_unreachable")
                continue

            if resp.status_code == 200:
                data = resp.json()
                sig = data.get("signature")
                if sig is None:
                    raise SignerInternalError(
                        "Gateway returned 200 but no signature field",
                        code="internal_error",
                    )
                return sig

            try:
                data = resp.json()
                error_code = data.get("error", "internal_error")
            except Exception:
                error_code = "internal_error"
            exc_cls = _ERROR_MAP.get(error_code, SignerInternalError)
            last_exc = exc_cls(
                f"Signer error: {error_code}", code=error_code, status=resp.status_code
            )

            if not isinstance(last_exc, _RETRIABLE):
                raise last_exc

        raise last_exc  # type: ignore[misc]
