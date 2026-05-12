"""Fetch KuCoin account balances through Usenami Signer.

The signing key never leaves the Nitro Enclave.
"""

from usenami_signer import Signer

GATEWAY = "http://signer-demo.usenami.io:8443"

with Signer(GATEWAY) as signer:
    health = signer.healthz()
    print(f"Signer OK: enclave CID={health['enclave_cid']}")

    resp = signer.kucoin.get_accounts()
    data = resp.json()

    if data.get("code") == "200000":
        for acct in data["data"]:
            if float(acct["balance"]) > 0:
                print(f"  {acct['currency']:>8s}  {acct['balance']:>16s}  ({acct['type']})")
    else:
        print(f"KuCoin error: {data}")
