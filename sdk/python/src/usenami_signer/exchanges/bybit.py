from __future__ import annotations

from typing import Any

import httpx

from usenami_signer.exchanges.base import BaseExchange


class BybitExchange(BaseExchange):
    """Bybit V5 API wrapper with automatic Signer authentication.

    Usage::

        signer = Signer("http://your-gateway:8443")

        resp = signer.bybit.get_wallet_balance()
        print(resp.json())
    """

    exchange_name = "bybit"
    base_url = "https://api.bybit.com"

    def get_wallet_balance(self, *, account_type: str = "UNIFIED") -> httpx.Response:
        return self.get("/v5/account/wallet-balance", params={"accountType": account_type})

    def get_positions(
        self,
        *,
        category: str = "linear",
        symbol: str | None = None,
    ) -> httpx.Response:
        params: dict[str, Any] = {"category": category}
        if symbol:
            params["symbol"] = symbol
        return self.get("/v5/position/list", params=params)

    def get_open_orders(
        self,
        *,
        category: str = "linear",
        symbol: str | None = None,
    ) -> httpx.Response:
        params: dict[str, Any] = {"category": category}
        if symbol:
            params["symbol"] = symbol
        return self.get("/v5/order/realtime", params=params)

    def place_order(
        self,
        *,
        category: str = "linear",
        symbol: str,
        side: str,
        order_type: str = "Market",
        qty: str,
        price: str | None = None,
        time_in_force: str = "GTC",
    ) -> httpx.Response:
        body: dict[str, Any] = {
            "category": category,
            "symbol": symbol,
            "side": side.capitalize(),
            "orderType": order_type,
            "qty": qty,
            "timeInForce": time_in_force,
        }
        if price:
            body["price"] = price
        return self.post("/v5/order/create", body=body)

    def cancel_order(
        self,
        *,
        category: str = "linear",
        symbol: str,
        order_id: str | None = None,
    ) -> httpx.Response:
        body: dict[str, Any] = {
            "category": category,
            "symbol": symbol,
        }
        if order_id:
            body["orderId"] = order_id
        return self.post("/v5/order/cancel", body=body)

    def get_tickers(
        self,
        *,
        category: str = "linear",
        symbol: str | None = None,
    ) -> httpx.Response:
        params: dict[str, Any] = {"category": category}
        if symbol:
            params["symbol"] = symbol
        return self.get("/v5/market/tickers", params=params)
