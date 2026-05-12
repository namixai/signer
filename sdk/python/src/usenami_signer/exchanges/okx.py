from __future__ import annotations

from typing import Any

import httpx

from usenami_signer.exchanges.base import BaseExchange


class OkxExchange(BaseExchange):
    """OKX V5 unified API wrapper with automatic Signer authentication.

    Usage::

        signer = Signer("http://your-gateway:8443")

        resp = signer.okx.get_account_config()
        print(resp.json())

    The signer fills in `OK-ACCESS-KEY`, `OK-ACCESS-SIGN`,
    `OK-ACCESS-TIMESTAMP`, and `OK-ACCESS-PASSPHRASE` headers. Customer's
    API secret + passphrase never leave the AWS Nitro Enclave.

    Notes:
        - OKX uses ISO8601 timestamp with millisecond precision (NOT epoch ms).
          The signer formats this server-side from gateway clock time.
        - The signature covers `requestPath` INCLUDING the query string. The
          SDK forwards user `params` to the gateway via the explicit `query`
          field; the signer reconstructs the full requestPath canonically.
        - OKX V5 has unified-account endpoints under `/api/v5/...` covering
          spot, margin, futures, perp, options. We expose convenience methods
          for the most common read-only paths; everything else is reachable
          via `signer.okx.get(...)` / `signer.okx.post(...)`.
    """

    exchange_name = "okx"
    base_url = "https://www.okx.com"

    def get_account_config(self) -> httpx.Response:
        """Read-only diagnostic endpoint. Returns 200 even on empty account
        — useful as a smoke-test target without funds."""
        return self.get("/api/v5/account/config")

    def get_account_balance(self, *, ccy: str | None = None) -> httpx.Response:
        params = {"ccy": ccy} if ccy else None
        return self.get("/api/v5/account/balance", params=params)

    def get_positions(
        self,
        *,
        inst_type: str | None = None,
        inst_id: str | None = None,
    ) -> httpx.Response:
        params: dict[str, Any] = {}
        if inst_type:
            params["instType"] = inst_type
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/account/positions", params=params or None)

    def get_open_orders(
        self,
        *,
        inst_type: str | None = None,
        inst_id: str | None = None,
    ) -> httpx.Response:
        params: dict[str, Any] = {}
        if inst_type:
            params["instType"] = inst_type
        if inst_id:
            params["instId"] = inst_id
        return self.get("/api/v5/trade/orders-pending", params=params or None)

    def place_order(
        self,
        *,
        inst_id: str,
        td_mode: str,
        side: str,
        ord_type: str = "limit",
        sz: str,
        px: str | None = None,
        cl_ord_id: str | None = None,
    ) -> httpx.Response:
        body: dict[str, Any] = {
            "instId": inst_id,
            "tdMode": td_mode,
            "side": side,
            "ordType": ord_type,
            "sz": sz,
        }
        if px:
            body["px"] = px
        if cl_ord_id:
            body["clOrdId"] = cl_ord_id
        return self.post("/api/v5/trade/order", body=body)

    def cancel_order(
        self,
        *,
        inst_id: str,
        ord_id: str | None = None,
        cl_ord_id: str | None = None,
    ) -> httpx.Response:
        body: dict[str, Any] = {"instId": inst_id}
        if ord_id:
            body["ordId"] = ord_id
        if cl_ord_id:
            body["clOrdId"] = cl_ord_id
        return self.post("/api/v5/trade/cancel-order", body=body)

    def get_ticker(self, inst_id: str) -> httpx.Response:
        # `market/ticker` is public, but OKX accepts signed requests on
        # public endpoints too — exposed as a convenience for symmetry with
        # other exchange wrappers.
        return self.get("/api/v5/market/ticker", params={"instId": inst_id})
