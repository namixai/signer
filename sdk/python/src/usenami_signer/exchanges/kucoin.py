from __future__ import annotations

from typing import Any

import httpx

from usenami_signer.exchanges.base import BaseExchange


class KuCoinExchange(BaseExchange):
    """KuCoin API wrapper with automatic Signer authentication.

    Usage::

        signer = Signer("http://signer-demo.usenami.io:8443")

        # List accounts
        resp = signer.kucoin.get("/api/v1/accounts")
        print(resp.json())

        # Place an order
        resp = signer.kucoin.post("/api/v1/orders", body={
            "clientOid": "my-order-001",
            "side": "buy",
            "symbol": "BTC-USDT",
            "type": "market",
            "size": "0.001",
        })
    """

    exchange_name = "kucoin"
    base_url = "https://api.kucoin.com"

    def get_accounts(self, *, currency: str | None = None) -> httpx.Response:
        params = {"currency": currency} if currency else None
        return self.get("/api/v1/accounts", params=params)

    def get_account(self, account_id: str) -> httpx.Response:
        return self.get(f"/api/v1/accounts/{account_id}")

    def get_balances(self) -> httpx.Response:
        return self.get("/api/v1/accounts")

    def get_orders(
        self,
        *,
        symbol: str | None = None,
        status: str = "active",
        **params: Any,
    ) -> httpx.Response:
        query: dict[str, Any] = {"status": status, **params}
        if symbol:
            query["symbol"] = symbol
        return self.get("/api/v1/orders", params=query)

    def place_order(
        self,
        *,
        client_oid: str,
        side: str,
        symbol: str,
        order_type: str = "market",
        size: str | None = None,
        price: str | None = None,
        funds: str | None = None,
    ) -> httpx.Response:
        body: dict[str, Any] = {
            "clientOid": client_oid,
            "side": side,
            "symbol": symbol,
            "type": order_type,
        }
        if size:
            body["size"] = size
        if price:
            body["price"] = price
        if funds:
            body["funds"] = funds
        return self.post("/api/v1/orders", body=body)

    def cancel_order(self, order_id: str) -> httpx.Response:
        return self.delete(f"/api/v1/orders/{order_id}")

    def get_ticker(self, symbol: str) -> httpx.Response:
        return self.get("/api/v1/market/orderbook/level1", params={"symbol": symbol})

    def get_positions(self) -> httpx.Response:
        return self.get("/api/v1/positions")
