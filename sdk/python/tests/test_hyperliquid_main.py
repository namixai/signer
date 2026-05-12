"""Tests for the Hyperliquid mainnet (EIP-712) exchange wrapper.

These tests cover the SDK's request shaping + response handling. They
mock both the gateway (`/sign`) and Hyperliquid (`/exchange`) endpoints
with `respx`, so no live network is touched.

End-to-end byte-for-byte signature verification against
`hyperliquid-python-sdk` lives in the Rust unit tests (`signer.rs`
EIP-712 module) and in the post-deploy smoke script — both require a real
EC2 enclave + KMS round-trip.
"""

from __future__ import annotations

import json

import httpx
import respx

from usenami_signer import Signer

GATEWAY = "http://test-gateway:8443"
HL = "https://api.hyperliquid.xyz"

MOCK_SIGNATURE = {
    "r": "0x" + "ab" * 32,
    "s": "0x" + "cd" * 32,
    "v": 27,
}


class TestHyperliquidMainOrder:
    """Tests for the `order` action."""

    def test_order_minimum_args_sends_correct_action_shape(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok", "response": {}})
            )

            with Signer(GATEWAY) as s:
                resp = s.hyperliquid_main.order(
                    asset_index=0,
                    is_buy=True,
                    price="50000",
                    size="0.001",
                )
                assert resp.status_code == 200

            sign_body = json.loads(sign_route.calls[0].request.content)
            assert sign_body["exchange"] == "hyperliquid_main"
            assert sign_body["kind"] == "order"
            assert sign_body["action"]["type"] == "order"
            assert sign_body["action"]["grouping"] == "na"
            assert len(sign_body["action"]["orders"]) == 1
            order = sign_body["action"]["orders"][0]
            assert order["a"] == 0
            assert order["b"] is True
            assert order["p"] == "50000"
            assert order["s"] == "0.001"
            assert order["r"] is False
            # Default tif Gtc.
            assert order["t"] == {"limit": {"tif": "Gtc"}}

    def test_order_reduce_only_propagates(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            with Signer(GATEWAY) as s:
                s.hyperliquid_main.order(
                    asset_index=5,
                    is_buy=False,
                    price="1",
                    size="2",
                    reduce_only=True,
                )

            order = json.loads(sign_route.calls[0].request.content)["action"][
                "orders"
            ][0]
            assert order["r"] is True
            assert order["a"] == 5
            assert order["b"] is False

    def test_order_custom_order_type_propagates(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            with Signer(GATEWAY) as s:
                s.hyperliquid_main.order(
                    asset_index=0,
                    is_buy=True,
                    price="50000",
                    size="0.001",
                    order_type={"limit": {"tif": "Ioc"}},
                )

            order = json.loads(sign_route.calls[0].request.content)["action"][
                "orders"
            ][0]
            assert order["t"] == {"limit": {"tif": "Ioc"}}

    def test_order_cloid_propagates_when_provided(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            with Signer(GATEWAY) as s:
                s.hyperliquid_main.order(
                    asset_index=0,
                    is_buy=True,
                    price="50000",
                    size="0.001",
                    cloid="0x" + "00" * 16,
                )

            order = json.loads(sign_route.calls[0].request.content)["action"][
                "orders"
            ][0]
            assert order["c"] == "0x" + "00" * 16

    def test_order_submits_signed_body_to_hyperliquid(self):
        """The gateway returns {r,s,v}; the SDK must wrap that into the
        Hyperliquid POST body shape {action, nonce, signature, vaultAddress}.
        """
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            hl_route = respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            with Signer(GATEWAY) as s:
                s.hyperliquid_main.order(
                    asset_index=0,
                    is_buy=True,
                    price="1",
                    size="1",
                    nonce=1700000000000,
                )

            hl_body = json.loads(hl_route.calls[0].request.content)
            assert hl_body["nonce"] == 1700000000000
            assert hl_body["signature"] == MOCK_SIGNATURE
            assert hl_body["action"]["type"] == "order"
            # No vault by default — explicit null in JSON body so Hyperliquid
            # parses it as a non-vault call.
            assert hl_body["vaultAddress"] is None

    def test_order_vault_address_propagates(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            hl_route = respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            vault = "0x" + "ab" * 20
            with Signer(GATEWAY) as s:
                s.hyperliquid_main.order(
                    asset_index=0,
                    is_buy=True,
                    price="1",
                    size="1",
                    vault_address=vault,
                )
            sign_body = json.loads(sign_route.calls[0].request.content)
            hl_body = json.loads(hl_route.calls[0].request.content)
            assert sign_body["vault_address"] == vault
            assert hl_body["vaultAddress"] == vault

    def test_order_nonce_defaults_to_current_time_ms(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            with Signer(GATEWAY) as s:
                s.hyperliquid_main.order(
                    asset_index=0, is_buy=True, price="1", size="1"
                )
            sign_body = json.loads(sign_route.calls[0].request.content)
            # 2024-01-01 = 1704067200000 ms. Any reasonable current time
            # is well above this.
            assert sign_body["nonce"] > 1_704_067_200_000


class TestHyperliquidMainCancel:
    def test_cancel_basic_shape(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            respx.post(f"{HL}/exchange").mock(
                return_value=httpx.Response(200, json={"status": "ok"})
            )
            with Signer(GATEWAY) as s:
                resp = s.hyperliquid_main.cancel(asset_index=0, oid=12345)
                assert resp.status_code == 200

            sign_body = json.loads(sign_route.calls[0].request.content)
            assert sign_body["exchange"] == "hyperliquid_main"
            assert sign_body["kind"] == "cancel"
            assert sign_body["action"]["type"] == "cancel"
            assert sign_body["action"]["cancels"] == [{"a": 0, "o": 12345}]


class TestHyperliquidMainAttribute:
    def test_signer_has_hyperliquid_main_attribute(self):
        s = Signer(GATEWAY)
        try:
            assert hasattr(s, "hyperliquid_main")
            assert s.hyperliquid_main.exchange_name == "hyperliquid_main"
            assert s.hyperliquid_main.base_url == "https://api.hyperliquid.xyz"
            assert hasattr(s.hyperliquid_main, "order")
            assert hasattr(s.hyperliquid_main, "cancel")
        finally:
            s.close()


class TestSignEip712Method:
    """Low-level `signer.sign_eip712(...)` path tests."""

    def test_sign_eip712_returns_signature_dict(self):
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            with Signer(GATEWAY) as s:
                sig = s.sign_eip712(
                    exchange="hyperliquid_main",
                    kind="order",
                    action={"type": "order", "orders": [], "grouping": "na"},
                    nonce=1700000000000,
                )
            assert sig == MOCK_SIGNATURE

    def test_sign_eip712_propagates_vault_address(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            vault = "0x" + "11" * 20
            with Signer(GATEWAY) as s:
                s.sign_eip712(
                    exchange="hyperliquid_main",
                    kind="order",
                    action={"type": "order", "orders": []},
                    nonce=1,
                    vault_address=vault,
                )
            body = json.loads(sign_route.calls[0].request.content)
            assert body["vault_address"] == vault

    def test_sign_eip712_omits_vault_address_when_none(self):
        with respx.mock:
            sign_route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"signature": MOCK_SIGNATURE})
            )
            with Signer(GATEWAY) as s:
                s.sign_eip712(
                    exchange="hyperliquid_main",
                    kind="order",
                    action={"type": "order", "orders": []},
                    nonce=1,
                )
            body = json.loads(sign_route.calls[0].request.content)
            assert "vault_address" not in body

    def test_sign_eip712_raises_on_gateway_400(self):
        from usenami_signer.exceptions import SignerBadRequest

        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(
                    400, json={"error": "bad_request"}
                )
            )
            with Signer(GATEWAY) as s:
                try:
                    s.sign_eip712(
                        exchange="hyperliquid_main",
                        kind="order",
                        action={},
                        nonce=1,
                    )
                except SignerBadRequest:
                    pass
                else:
                    raise AssertionError("expected SignerBadRequest")
