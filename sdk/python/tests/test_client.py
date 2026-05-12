import time

import httpx
import pytest
import respx

from usenami_signer import (
    Signer,
    SignerBadRequest,
    SignerEnclaveDenied,
    SignerEnclaveUnreachable,
    SignerInternalError,
)

GATEWAY = "http://test-gateway:8443"


class TestSign:
    def test_sign_returns_headers(self):
        expected = {
            "KC-API-KEY": "key123",
            "KC-API-SIGN": "sig==",
            "KC-API-TIMESTAMP": "1700000000000",
            "KC-API-PASSPHRASE": "pass==",
            "KC-API-KEY-VERSION": "2",
        }
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": expected})
            )
            with Signer(GATEWAY) as s:
                headers = s.sign("kucoin", "GET", "/api/v1/accounts")
        assert headers == expected

    def test_sign_auto_fills_timestamp(self):
        with respx.mock:
            route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": {}})
            )
            with Signer(GATEWAY) as s:
                before = int(time.time() * 1000)
                s.sign("kucoin", "GET", "/path")
                after = int(time.time() * 1000)

        sent = route.calls[0].request
        import json
        body = json.loads(sent.content)
        assert before <= body["timestamp_ms"] <= after

    def test_sign_uses_explicit_timestamp(self):
        with respx.mock:
            route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": {}})
            )
            with Signer(GATEWAY) as s:
                s.sign("kucoin", "GET", "/path", timestamp_ms=42)

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["timestamp_ms"] == 42

    def test_sign_uppercases_method(self):
        with respx.mock:
            route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": {}})
            )
            with Signer(GATEWAY) as s:
                s.sign("kucoin", "get", "/path")

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["method"] == "GET"

    def test_sign_rejects_invalid_method(self):
        with Signer(GATEWAY) as s:
            with pytest.raises(SignerBadRequest, match="Invalid method"):
                s.sign("kucoin", "PATCH", "/path")


class TestErrorMapping:
    @pytest.mark.parametrize("code,exc_cls", [
        ("bad_request", SignerBadRequest),
        ("payload_too_large", SignerBadRequest),
        ("kms_decrypt_denied", SignerEnclaveDenied),
        ("enclave_unreachable", SignerEnclaveUnreachable),
        ("internal_error", SignerInternalError),
    ])
    def test_error_codes_map_correctly(self, code, exc_cls):
        status = {"bad_request": 400, "payload_too_large": 413}.get(code, 500)
        with respx.mock:
            respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(status, json={"error": code})
            )
            with Signer(GATEWAY, retries=0) as s:
                with pytest.raises(exc_cls):
                    s.sign("kucoin", "GET", "/path")

    def test_bad_request_not_retried(self):
        with respx.mock:
            route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(400, json={"error": "bad_request"})
            )
            with Signer(GATEWAY, retries=3) as s:
                with pytest.raises(SignerBadRequest):
                    s.sign("kucoin", "GET", "/path")
        assert len(route.calls) == 1

    def test_retriable_errors_retry(self):
        with respx.mock:
            route = respx.post(f"{GATEWAY}/sign").mock(
                side_effect=[
                    httpx.Response(503, json={"error": "enclave_unreachable"}),
                    httpx.Response(503, json={"error": "enclave_unreachable"}),
                    httpx.Response(200, json={"headers": {"h": "v"}}),
                ]
            )
            with Signer(GATEWAY, retries=2) as s:
                result = s.sign("kucoin", "GET", "/path")
        assert result == {"h": "v"}
        assert len(route.calls) == 3

    def test_retries_exhausted_raises(self):
        with respx.mock:
            route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(500, json={"error": "internal_error"})
            )
            with Signer(GATEWAY, retries=1) as s:
                with pytest.raises(SignerInternalError):
                    s.sign("kucoin", "GET", "/path")
        assert len(route.calls) == 2


class TestHealthz:
    def test_healthz_ok(self):
        data = {"status": "ok", "enclave_cid": 16, "enclave_port": 5000}
        with respx.mock:
            respx.get(f"{GATEWAY}/healthz").mock(
                return_value=httpx.Response(200, json=data)
            )
            with Signer(GATEWAY) as s:
                assert s.healthz() == data

    def test_healthz_failure(self):
        with respx.mock:
            respx.get(f"{GATEWAY}/healthz").mock(
                return_value=httpx.Response(503, json={"error": "enclave_unreachable"})
            )
            with Signer(GATEWAY) as s:
                with pytest.raises(SignerEnclaveUnreachable):
                    s.healthz()


class TestContextManager:
    def test_trailing_slash_stripped(self):
        s = Signer("http://host:8443/")
        assert s.gateway_url == "http://host:8443"
        s.close()

    def test_api_key_header(self):
        with respx.mock:
            route = respx.post(f"{GATEWAY}/sign").mock(
                return_value=httpx.Response(200, json={"headers": {}})
            )
            with Signer(GATEWAY, api_key="sk-test") as s:
                s.sign("kucoin", "GET", "/path")

        assert route.calls[0].request.headers["authorization"] == "Bearer sk-test"
