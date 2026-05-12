# Customer Onboarding Guide

Get your exchange API calls signed through a Nitro Enclave in under 10 minutes.
Your exchange secrets never leave the enclave — not even we can read them.

---

## Prerequisites

- Python 3.9+
- A KuCoin (or Binance/Bybit) API key with the permissions you need
- The Signer gateway URL (provided after registration)

---

## Step 1: Register

Request access at **signer.usenami.io** (or contact us directly).

You will receive:
- A **gateway URL** (e.g. `https://signer.usenami.io:8443`)
- An **API key** for authenticating to the gateway
- An **encryption command** to seal your exchange secrets

Pilot phase: registration is manual via email/DM. We provision your isolated enclave within 24h.

---

## Step 2: Create exchange API keys

Create API keys on your exchange with the minimum permissions needed:

| Exchange | Recommended Permissions | IP Whitelist |
|----------|------------------------|--------------|
| KuCoin   | General (read-only) or General + Trade | Signer EIP (provided) |
| Binance  | Read + Trade (no withdraw) | Signer EIP |
| Bybit    | Read + Trade (no withdraw) | Signer EIP |

**Critical:** Never enable Withdraw permission. The signer only needs to read balances and place/cancel orders.

---

## Step 3: Encrypt and upload your secrets

Your exchange secrets are encrypted client-side with our KMS public key. The plaintext never touches any server — only the Nitro Enclave can decrypt it (enforced by AWS KMS attestation policy).

### Format your secrets as JSON:

```json
{
  "key": "YOUR_API_KEY",
  "secret": "YOUR_API_SECRET",
  "passphrase": "YOUR_PASSPHRASE_IF_APPLICABLE"
}
```

(Binance/Bybit don't use passphrase — omit or set to empty string.)

### Encrypt with the provided command:

```bash
# We provide this one-liner after registration
usenami-encrypt --kms-key arn:aws:kms:us-east-1:ACCOUNT:key/KEY_ID \
  --input secrets.json \
  --output secrets.enc

# Upload the encrypted blob
usenami-upload --gateway https://signer.usenami.io:8443 \
  --api-key YOUR_API_KEY \
  --file secrets.enc
```

**What happens:**
1. `usenami-encrypt` calls AWS KMS `Encrypt` with the signer's public key
2. The ciphertext can ONLY be decrypted inside the attested Nitro Enclave (PCR0-locked)
3. `usenami-upload` stores the ciphertext blob in S3 (encrypted at rest, accessible only to the enclave IAM role)

After upload, **delete `secrets.json` immediately**. You will never need the plaintext again — the signer handles all signing from this point.

---

## Step 4: Install the SDK

```bash
pip install usenami-signer
```

---

## Step 5: Make your first signed request

```python
from usenami_signer import Signer

# Gateway URL and API key from Step 1
with Signer("https://signer.usenami.io:8443", api_key="sk-your-key") as signer:
    # Verify the enclave is healthy
    health = signer.healthz()
    print(f"Enclave OK (CID={health['enclave_cid']})")

    # Fetch your KuCoin account balances
    resp = signer.kucoin.get_accounts()
    data = resp.json()

    if data["code"] == "200000":
        for acct in data["data"]:
            if float(acct["balance"]) > 0:
                print(f"  {acct['currency']:>6s}: {acct['balance']}")
    else:
        print(f"Error: {data}")
```

That's it. The signing key never left the enclave.

---

## How it works (30-second version)

```
Your app                    Signer Gateway              Nitro Enclave
   │                             │                           │
   │  POST /sign {kucoin,GET,    │                           │
   │    /api/v1/accounts}        │                           │
   │────────────────────────────>│                           │
   │                             │  vsock: sign request      │
   │                             │──────────────────────────>│
   │                             │                           │ KMS Decrypt
   │                             │                           │ (PCR0 attested)
   │                             │                           │ HMAC-SHA256
   │                             │                           │ Zeroize secret
   │                             │  signed headers           │
   │                             │<──────────────────────────│
   │  {KC-API-KEY, KC-API-SIGN,  │                           │
   │   KC-API-TIMESTAMP, ...}    │                           │
   │<────────────────────────────│                           │
   │                             │                           │
   │  GET /api/v1/accounts       │                           │
   │  + signed headers           │                           │
   │─────────────────────────────────────────────────────────────> KuCoin
```

- **Gateway** has no access to your secrets (only encrypted ciphertext)
- **Enclave** decrypts, signs, zeroizes, returns headers — never persists plaintext
- **KMS policy** ensures only the exact enclave binary (PCR0 hash) can decrypt

---

## Security guarantees

| Threat | Mitigation |
|--------|-----------|
| Compromised gateway server | Cannot decrypt — KMS policy requires enclave attestation |
| Compromised AWS account (our side) | KMS key policy denies all principals except attested enclave |
| Malicious signer operator | Enclave code is open-source, PCR0 verifiable, no debug mode |
| Network interception | TLS to gateway + vsock (in-machine, no network) to enclave |
| Key extraction from memory | Secrets zeroized after each request; enclave memory not dumpable |

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `SignerEnclaveUnreachable` | Enclave down or gateway cannot reach it | Wait 30s and retry; contact support if persistent |
| `SignerEnclaveDenied` | KMS policy rejected attestation | Contact support — may indicate enclave rebuild with new PCR0 |
| KuCoin returns `400006` | IP not in API key whitelist | Add the Signer EIP to your KuCoin API key IP whitelist |
| KuCoin returns `400003` | Timestamp drift | Ensure your system clock is accurate (NTP synced) |
| `SignerBadRequest` | Invalid exchange name or method | Check `sign()` parameters |

---

## FAQ

**Q: Can I use this for trading bots?**
A: Yes — that's the primary use case. Your bot calls the SDK, the enclave signs, KuCoin executes. Sub-second latency.

**Q: What if I need to rotate my exchange keys?**
A: Re-encrypt the new keys and re-upload. The old ciphertext is overwritten. Zero downtime.

**Q: Can I use multiple exchange accounts?**
A: Yes — each encrypted blob corresponds to one exchange account. Contact us for multi-account setup.

**Q: What's the latency overhead?**
A: ~200-400ms for the signing round-trip (KMS decrypt + HMAC + network). Negligible for most trading strategies; for HFT, deploy in the same AWS region as the exchange.

**Q: Is this open source?**
A: The enclave code and SDK are open source (Apache-2.0). You can verify the PCR0 matches the published source.
