"""Tests for OKX V5 exchange wrapper."""

from __future__ import annotations

import json

import httpx
import respx

from usenami_signer import Signer

GATEWAY = "http://test-gateway:8443"
OKX = "https://www.okx.com"

MOCK_HEADERS = {
    "OK-ACCESS-KEY": "key",
    "OK-ACCESS-SIGN": "sig",
    "OK-ACCESS-TIMESTAMP": "2026-05-10T19:00:00.000Z",
    "OK-ACCESS-PASSPHRASE": "pass",
}


class TestOkxExchange:
    def test_get_account_config(self):
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.get(f"{OKX}/api/v5/account/config").mock(
                return_value=httpx.Response(200, json={"code": "0", "data": [{}]})
            )
            with Signer(GATEWAY) as s:
                resp = s.okx.get_account_config()
                assert resp.status_code == 200
                assert resp.json()["code"] == "0"

    def test_account_config_passes_signed_headers(self):
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            okx_route = respx.get(f"{OKX}/api/v5/account/config").mock(
                return_value=httpx.Response(200, json={"code": "0", "data": []})
            )
            with Signer(GATEWAY) as s:
                s.okx.get_account_config()

            req = okx_route.calls[0].request
            # httpx lowercases header names internally, but values are preserved.
            assert req.headers["ok-access-key"] == "key"
            assert req.headers["ok-access-sign"] == "sig"
            assert req.headers["ok-access-timestamp"] == "2026-05-10T19:00:00.000Z"
            assert req.headers["ok-access-passphrase"] == "pass"

    def test_get_balance_with_query_forwards_params_to_signer(self):
        """Crucial OKX-specific test: signature covers requestPath INCLUDING
        the query string. The SDK MUST forward the `ccy` query param to the
        signer via the `query` field so the enclave reconstructs the
        canonical string correctly."""
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.get(f"{OKX}/api/v5/account/balance").mock(
                return_value=httpx.Response(200, json={"code": "0", "data": []})
            )
            with Signer(GATEWAY) as s:
                s.okx.get_account_balance(ccy="USDT")

            sign_body = json.loads(sign_route.calls[0].request.content)
            assert sign_body["exchange"] == "okx"
            assert sign_body["method"] == "GET"
            assert sign_body["path"] == "/api/v5/account/balance"
            # `query` field MUST be present — without it, the signer would
            # compute HMAC over a path WITHOUT `?ccy=USDT`, OKX's server
            # would compute HMAC over the full URL it sees, signatures
            # diverge and request is rejected.
            assert sign_body["query"] == "ccy=USDT"

    def test_place_order_sends_body(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.post(f"{OKX}/api/v5/trade/order").mock(
                return_value=httpx.Response(200, json={"code": "0", "data": [{"ordId": "abc"}]})
            )
            with Signer(GATEWAY) as s:
                resp = s.okx.place_order(
                    inst_id="BTC-USDT",
                    td_mode="cash",
                    side="buy",
                    ord_type="limit",
                    sz="0.001",
                    px="50000",
                )
                assert resp.json()["data"][0]["ordId"] == "abc"

            sign_body = json.loads(sign_route.calls[0].request.content)
            assert sign_body["method"] == "POST"
            assert sign_body["path"] == "/api/v5/trade/order"
            order_body = json.loads(sign_body["body"])
            assert order_body["instId"] == "BTC-USDT"
            assert order_body["side"] == "buy"
            assert order_body["px"] == "50000"

    def test_get_positions_no_params(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.get(f"{OKX}/api/v5/account/positions").mock(
                return_value=httpx.Response(200, json={"code": "0", "data": []})
            )
            with Signer(GATEWAY) as s:
                s.okx.get_positions()

            sign_body = json.loads(sign_route.calls[0].request.content)
            assert sign_body["path"] == "/api/v5/account/positions"
            # No query params -> empty / absent query field on the wire.
            assert sign_body.get("query", "") == ""

    def test_okx_signer_attribute_exists(self):
        """Smoke test: `signer.okx` is a valid attribute and exposes the
        usual Get/Post helpers."""
        s = Signer(GATEWAY)
        try:
            assert hasattr(s, "okx")
            assert s.okx.exchange_name == "okx"
            assert s.okx.base_url == "https://www.okx.com"
            assert hasattr(s.okx, "get")
            assert hasattr(s.okx, "post")
        finally:
            s.close()

    def test_get_ticker_request_shape(self):
        """Public endpoint with single instId param. Even on public OKX
        endpoints, signed requests are accepted, so we use the same wrapper
        path."""
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.get(f"{OKX}/api/v5/market/ticker").mock(
                return_value=httpx.Response(200, json={"code": "0", "data": []})
            )
            with Signer(GATEWAY) as s:
                s.okx.get_ticker("BTC-USDT")

            sign_body = json.loads(sign_route.calls[0].request.content)
            assert sign_body["query"] == "instId=BTC-USDT"
