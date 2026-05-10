import json

import httpx
import respx

from usenami_signer import Signer

GATEWAY = "http://test-gateway:8443"
KUCOIN = "https://api.kucoin.com"

MOCK_HEADERS = {
    "KC-API-KEY": "key",
    "KC-API-SIGN": "sig",
    "KC-API-TIMESTAMP": "1700000000000",
    "KC-API-PASSPHRASE": "pass",
    "KC-API-KEY-VERSION": "2",
}


class TestKuCoinExchange:
    def test_get_accounts(self):
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.get(f"{KUCOIN}/api/v1/accounts").mock(
                return_value=httpx.Response(200, json={"code": "200000", "data": []})
            )
            with Signer(GATEWAY) as s:
                resp = s.kucoin.get_accounts()
                assert resp.status_code == 200
                assert resp.json()["code"] == "200000"

    def test_get_accounts_passes_signed_headers(self):
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            kucoin_route = respx.get(f"{KUCOIN}/api/v1/accounts").mock(
                return_value=httpx.Response(200, json={"code": "200000", "data": []})
            )
            with Signer(GATEWAY) as s:
                s.kucoin.get_accounts()

            req = kucoin_route.calls[0].request
            assert req.headers["kc-api-key"] == "key"
            assert req.headers["kc-api-sign"] == "sig"

    def test_place_order_sends_body(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.post(f"{KUCOIN}/api/v1/orders").mock(
                return_value=httpx.Response(200, json={"code": "200000", "data": {"orderId": "abc"}})
            )
            with Signer(GATEWAY) as s:
                resp = s.kucoin.place_order(
                    client_oid="test-001",
                    side="buy",
                    symbol="BTC-USDT",
                    size="0.001",
                )
                assert resp.json()["data"]["orderId"] == "abc"

            sign_body = json.loads(sign_route.calls[0].request.content)
            assert sign_body["method"] == "POST"
            assert sign_body["path"] == "/api/v1/orders"
            order_body = json.loads(sign_body["body"])
            assert order_body["clientOid"] == "test-001"
            assert order_body["side"] == "buy"

    def test_cancel_order(self):
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            respx.delete(f"{KUCOIN}/api/v1/orders/order-123").mock(
                return_value=httpx.Response(200, json={"code": "200000"})
            )
            with Signer(GATEWAY) as s:
                resp = s.kucoin.cancel_order("order-123")
                assert resp.status_code == 200

    def test_request_with_params(self):
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": MOCK_HEADERS})
            )
            kucoin_route = respx.get(f"{KUCOIN}/api/v1/accounts").mock(
                return_value=httpx.Response(200, json={"code": "200000", "data": []})
            )
            with Signer(GATEWAY) as s:
                s.kucoin.get_accounts(currency="BTC")

            req = kucoin_route.calls[0].request
            assert "currency=BTC" in str(req.url)
