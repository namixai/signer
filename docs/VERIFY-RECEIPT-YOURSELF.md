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

## Check the attestation on its own first

```bash
NONCE=$(openssl rand -hex 16)
curl -s "https://<lane>/attestation?nonce=$NONCE" > att.json
python3 poc/scripts/verify-receipt-yourself.py attestation --attestation att.json --nonce "$NONCE"
```

No token, nothing touched. It unwraps the document, walks its certificate chain to the
AWS Nitro root pinned in the script, checks the COSE signature, prints the measurement,
and confirms the document echoes the nonce you picked rather than being one cached
earlier. If this step does not pass, nothing after it is worth running.

**This is the step a stranger can finish today, and it is worth being plain about why
the next one is harder.** The attestation is served to anyone who asks. A receipt is
not: it comes back from a decision, and asking for a decision needs a token, which
means a receipt reaches you only if someone hands you one. So the honest order is —
verify the attestation yourself, then ask whoever gave you the receipt where it came
from, and check it against the document you fetched, not one they supplied.

Two things you will run into. The production lane's signed document carries a receipt
key, so a receipt from it can be bound to the attestation. Other lanes may have no key
provisioned, and the script says so and exits 2 rather than passing — a lane that
cannot issue receipts is not a lane whose receipts checked out. And a `2` on the
receipt step is not a failure of the receipt; it means the check could not run.

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

**The attestation document is real before anything inside it is read.** The COSE
document is unwrapped, its certificate chain is required to end at the AWS Nitro root
pinned in the script, and the COSE signature is checked against the certificate that
made it. Order matters here: verifying the signature against a certificate that
arrived in the same document proves nothing, because someone forging the whole thing
signs it with their own key. Only the pinned root makes any of it evidence.

**Signed by the key the enclave attested.** The receipt is canonicalised (RFC 8785,
keys sorted, every numeric a decimal string so nothing rounds), hashed under a fixed
domain tag, and the signature recovered to an address. That address must equal the one
derived from `public_key` **inside the signed document**.

If you are writing your own verifier rather than running this one, two details about
that canonical form will decide whether you ever reach a digest at all.

The canonicalisation is RFC 8785 with one restriction: **JSON numbers are refused, not
encoded.** Every numeric in a receipt — `seq`, `supplied_ts_ms` — travels as a decimal
string, so there is no float to round and no integer whose JSON spelling differs
between one language and the next. If a number reaches the canonicaliser, the receipt
is not the shape we sign, and guessing at an encoding would hand you a signature check
that passes for the wrong reason. Keep those fields as strings when you parse; a
language that helpfully turns `"41"` into `41` will give you a digest nobody signed.

And the signature covers a fixed list of fields, not "the receipt as it arrived":

```text
v, decision, reason_code, customer_id, action, request_hash,
intent_sig_hash, policy_hash, supplied_ts_ms, boot_id, seq
```

Every one must be present — a missing field is a refusal to compute, not a field
skipped. The heartbeat signs its own shorter list: `v`, `boot_id`, `customer_id`,
`seq_next`, `client_nonce`, `registry_version`, `entry_hash`. Anything outside these
lists is not signed, so treat it as the gateway talking, not the enclave.

Not `data_pubkey_address` from the JSON beside it. That field is filled from the
gateway's own configuration and binds nothing; a gateway that is compromised, or just
misconfigured, puts whatever it likes there. The script compares the two and treats a
disagreement as a finding of its own: the gateway is reporting something the enclave
did not sign.

**Signatures are canonical.** A high-`s` signature is a valid twin of a low-`s` one
over the same digest and key. Accepting both would mean two byte-different receipts
are each an authentic record of one decision, which is the thing a receipt exists to
prevent. Low-`s` only, recovery id 27 or 28.

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

## Which lane you can run this on

A lane that has not been given a data-signing key issues no receipts, and its
attestation document carries no `public_key`. That is a real state, not a fault, and
the script says `NOT CHECKED` rather than passing. The demo lane is in that state
today, so this page is exercisable against production and not against demo.

## If it fails

Send us the three files and what the script printed. And if the signature does not
recover to the attested address, do not accept the refusal as ours.
