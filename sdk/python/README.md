# usenami-signer

Python SDK for [Usenami Signer](https://usenami.io) — keyless exchange authentication via AWS Nitro Enclaves.

Your API keys never leave the enclave. Sign exchange requests without exposing secrets to your application, server, or cloud provider.

## Install

```bash
pip install usenami-signer
```

## Quick start

```python
from usenami_signer import Signer

with Signer("http://your-gateway:8443") as signer:
    # Get signed headers (low-level)
    headers = signer.sign("kucoin", "GET", "/api/v1/accounts")

    # Or make a full signed request (high-level)
    resp = signer.kucoin.get_accounts()
    print(resp.json())
```

## Supported exchanges

| Exchange | Status |
|----------|--------|
| KuCoin   | Live   |
| Binance  | Soon   |
| Bybit    | Soon   |

## License

Apache-2.0
