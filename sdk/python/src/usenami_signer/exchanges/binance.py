from __future__ import annotations

from typing import Any

import httpx

from usenami_signer.exchanges.base import BaseExchange

_BINANCE_QUERY_PARAMS = {"signature", "timestamp", "recvWindow", "apiKey"}


class BinanceExchange(BaseExchange):
    """Binance Spot API wrapper with automatic Signer authentication.

    Usage::

        signer = Signer("http://your-gateway:8443")

        resp = signer.binance.get_account()
        print(resp.json())
    """

    exchange_name = "binance"
    base_url = "https://api.binance.com"

    def _split_sign_result(
        self, sign_result: dict[str, str]
    ) -> tuple[dict[str, str], dict[str, str]]:
        headers: dict[str, str] = {}
        params: dict[str, str] = {}
        for k, v in sign_result.items():
            if k in _BINANCE_QUERY_PARAMS:
                params[k] = v
            else:
                headers[k] = v
        return headers, params

    def get_account(self) -> httpx.Response:
        return self.get("/api/v3/account")

    def get_balances(self) -> httpx.Response:
        resp = self.get_account()
        return resp

    def get_open_orders(self, *, symbol: str | None = None) -> httpx.Response:
        params = {"symbol": symbol} if symbol else None
        return self.get("/api/v3/openOrders", params=params)

    def place_order(
        self,
        *,
        symbol: str,
        side: str,
        order_type: str = "MARKET",
        quantity: str | None = None,
        price: str | None = None,
        quote_order_qty: str | None = None,
        time_in_force: str | None = None,
    ) -> httpx.Response:
        body: dict[str, Any] = {
            "symbol": symbol,
            "side": side.upper(),
            "type": order_type.upper(),
        }
        if quantity:
            body["quantity"] = quantity
        if price:
            body["price"] = price
        if quote_order_qty:
            body["quoteOrderQty"] = quote_order_qty
        if time_in_force:
            body["timeInForce"] = time_in_force
        return self.post("/api/v3/order", body=body)

    def cancel_order(self, *, symbol: str, order_id: int | None = None) -> httpx.Response:
        params: dict[str, Any] = {"symbol": symbol}
        if order_id:
            params["orderId"] = order_id
        return self.request("DELETE", "/api/v3/order", params=params)

    def get_ticker_price(self, symbol: str) -> httpx.Response:
        return self.get("/api/v3/ticker/price", params={"symbol": symbol})


class BinanceFuturesExchange(BinanceExchange):
    """Binance USDM Futures API wrapper."""

    exchange_name = "binance_futures"
    base_url = "https://fapi.binance.com"

    def get_positions(self) -> httpx.Response:
        return self.get("/fapi/v3/positionRisk")

    def get_account(self) -> httpx.Response:
        return self.get("/fapi/v3/account")

    def cancel_order(self, *, symbol: str, order_id: int | None = None) -> httpx.Response:
        params: dict[str, Any] = {"symbol": symbol}
        if order_id:
            params["orderId"] = order_id
        return self.request("DELETE", "/fapi/v1/order", params=params)
