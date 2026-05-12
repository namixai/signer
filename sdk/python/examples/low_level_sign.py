"""Low-level example: get signed headers, make the request yourself."""

import httpx

from usenami_signer import Signer

GATEWAY = "http://signer-demo.usenami.io:8443"

with Signer(GATEWAY) as signer:
    headers = signer.sign("kucoin", "GET", "/api/v1/accounts")
    print("Signed headers:", headers)

    resp = httpx.get(
        "https://api.kucoin.com/api/v1/accounts",
        headers={**headers, "Content-Type": "application/json"},
    )
    print(f"Status: {resp.status_code}")
    print(resp.json())
