# Check a refusal yourself

Ask the gateway to sign something its policy forbids and you get back a refusal with
a signature on it: a decision receipt. It says what was decided, why, against which
policy, and where in the tenant's sequence of decisions it sits.

This page is about checking that signature with nothing but this repository, a
Python interpreter, and the refusal itself.

Do it yourself because nothing we run proves anything to you. We could show you a
green screen all day. The receipt earns its keep only when a stranger takes it and
confirms, without asking us, that the key which signed it is the key the enclave
attests to, and that not one byte has moved since.

## What it settles, and what it leaves open

It settles that whoever signed holds the key named in the attestation you fetched
from the lane you asked, and that the signed fields still carry the values that were
signed.

It says nothing about whether the enclave runs the source in this repository. That
is the reproducible build, and it has its own page:
[VERIFY-SIGNER-YOURSELF.md](VERIFY-SIGNER-YOURSELF.md). Neither check is worth much
alone. We would rather point at the seam between them than let you assume it is
sealed.

## Break it before you trust it

```bash
python3 poc/scripts/verify-receipt-yourself.py selftest
```

The selftest signs a receipt, checks it, then goes after it: a byte of the
signature, the sequence number, the policy hash, the reason code, the tenant, the
enclave boot id. Every one of those has to be caught. A guard that stays quiet makes
the selftest exit non-zero and say which one.

Four of the tampered receipts get **re-signed** with the same key before checking.
Without that, this whole selftest would be theatre. The signature covers every
signed field, so any clumsy edit trips the signature check first, and the sequence,
policy and reason guards would never once fire as the reason. Re-signing removes the
signature as the explanation and makes each guard answer on its own. It is also the
real case: someone holding the key has no need to forge.

## Checking a live refusal

Three files, all fetched by you:

```bash
curl -s https://<lane>/attestation > att.json

curl -s -X POST https://<lane>/receipts/heartbeat \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"client_nonce\":\"$(openssl rand -hex 16)\"}" > hb.json

# whatever request you were refused
curl -s -X POST https://<lane>/sign/binance-order \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key_id":"binance","order":{ ...over the cap... }}' > refusal.json
```

Then:

```bash
python3 poc/scripts/verify-receipt-yourself.py verify \
  --attestation att.json --receipt refusal.json --heartbeat hb.json \
  --expect-reason notional_over_cap
```

Hand it the whole response; it digs the receipt out itself.

There are three exit codes, not two. `0` verified. `1` a check did not hold. `2` a
check could not run, which is not a pass. A check you could not run is a hole, and
counting holes as green is how a verifier turns into decoration.

## The four checks

**Signed by the attested key.** The receipt is canonicalised (RFC 8785, keys sorted,
every numeric carried as a decimal string so nothing rounds), hashed under a fixed
domain tag, and the signature recovered to an address. That address has to equal
`data_pubkey_address` in the attestation you fetched. Not one we sent you.

**Bound to a measurement.** The script reads the measurement out of your attestation,
prints it, and stops. It ships no expected value, deliberately. A number written into
a script goes stale the day after a rotation, and whoever trusts it ends up comparing
against something we no longer run, then reading the mismatch as their own mistake.
Pin the measurement out of band and take it to the reproducible build.

**Inside the current chain.** `seq` counts a tenant's decisions since the enclave
booted; `seq_next` in the heartbeat is the one coming. A receipt whose `seq` is not
below `seq_next` claims a decision the enclave never issued. A receipt from another
`boot_id` is not wrong, since enclaves restart, but its count cannot be lined up with
yours, and the script says so instead of guessing.

**Names what it judged against.** A denial carries the hash of the policy it was
judged against. Empty `policy_hash` on a denial means the receipt says no without
saying against what. The script fails on that.

## If it fails

Send us the three files and what the script printed. And if the signature does not
recover to the attested address, do not accept the refusal as ours.
