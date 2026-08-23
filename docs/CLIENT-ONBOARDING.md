# Bringing your own key: encrypt it yourself, hand us the ciphertext

This is the path where **we never see your exchange API secret**. You encrypt it on
your machine, under a KMS key whose Decrypt is gated on the enclave's measurement, and
send us only the ciphertext. Nothing in this document asks you to share a plaintext
credential over any channel.

If you would rather hand us a testnet key and have us wrap it for you, say so — that
path exists and is faster for a first look, but it is not this one and it is not what
we sell.

Scope note, up front: this describes what the tools do **today**. Where you still need
something from us, the step says so.

---

## What you need from us before you start

Four things, and there is no self-serve for them yet:

| what | why it cannot be self-serve today |
|---|---|
| your `customer_id` | it goes in a registry entry signed by an off-box Ed25519 key whose public half is baked into the enclave image |
| a signed policy | the caps and allow-lists that bind your key are signed by a second off-box key; the enclave refuses an unsigned policy on every money venue |
| a short-lived `kms:Encrypt` credential | scoped to **one** venue key, minutes of TTL — enough to encrypt, never enough to decrypt |
| a bearer token | issued with your registry entry |

Ask for them at `business@usenami.io`. You will get back: `customer_id`, the venue key
alias, the credential, and the policy file to review.

## Step 1 — read the policy before you wrap anything

The policy travels **inside** the encrypted blob and the enclave enforces it on every
request. Read it as the thing that bounds your money, because that is what it is:

- `allowed_actions` / `allowed_methods` / `allowed_path_prefixes` — what may be signed
  at all; withdrawal and transfer routes are denied here and again inside the enclave.
- `order_caps[]` — `max_qty` (base asset) and `max_notional` (quote). On a
  contract-sized venue such as OKX these are **contract** units; our ceremony converts
  for you, but check the numbers mean what you think.
- `policy_authority_sig` — our signature over the policy. Change one byte of the policy
  and the enclave refuses the blob.

If a cap is wrong, say so now. Changing it later means a new blob and a new ceremony.

## Step 2 — build the encrypted blob on your machine

```bash
git clone https://github.com/namixai/signer.git && cd signer/poc
cargo build --locked -p signer-policy-cli      # ~15 s, no network at run time
```

Put your credentials in `secret.json` (the shape depends on the venue — Binance and
OKX examples are in the tool's `--help`) and the policy we sent you in `policy.json`.
Then, one of two forms. Both are accepted by the enclave; the first is fewer steps and
keeps no key material on your disk.

**Form A — flat (recommended for a first key).** One command, one artifact:

```bash
./target/debug/signer-policy-wrap --policy policy.json --secret secret.json --output blob.plain.json

aws kms encrypt \
  --key-id alias/signer/prod/binance/v1 \
  --plaintext fileb://blob.plain.json \
  --encryption-context customer_id=YOUR_CUSTOMER_ID,venue_id=binance \
  --output text --query CiphertextBlob > blob.enc.b64

shred -u blob.plain.json secret.json    # or your OS equivalent
```

**Form B — envelope (v2).** A random data key encrypts the blob locally; only that data
key goes to KMS. It binds your identity a second time, as AES-GCM associated data:

```bash
./target/debug/signer-policy-wrap --policy policy.json --secret secret.json \
  envelope --out-dir ./out --customer-id YOUR_CUSTOMER_ID --venue binance
# prints the exact `aws kms encrypt` line for the data key, then:
./target/debug/signer-policy-wrap seal --envelope out/envelope.json \
  --wrapped-dek-b64 THE_OUTPUT_FROM_KMS --output binance.enc
shred -u out/dek.bin secret.json
```

Two details that decide whether this works at all:

- **The encryption context is exactly two pairs, `customer_id` and `venue_id`.** The
  enclave rebuilds it from the identity it resolved and KMS rejects a Decrypt whose
  context differs by one extra pair. Any older recipe with `purpose=dek,version=2`
  produces a blob that can never be opened; if you have one, redo it.
- **Form B binds the same identity as GCM associated data** —
  `customer_id=…\nvenue_id=…\nkey_version=1` — which is why the command asks for it.
  A blob built for one tenant fails the tag under another. The round trip
  (client tool encrypts → enclave code decrypts) is a test in our CI, not a claim:
  `policy-cli/src/main.rs`, module `client_path_tests`.

## Step 3 — send us two files

`blob.enc.b64` (or `binance.enc`) and a one-line context file so nobody guesses:

```json
{"customer_id": "YOUR_CUSTOMER_ID", "venue_id": "binance"}
```

Neither file contains your secret. The ciphertext is useless without a Decrypt that
only an attested enclave can obtain.

## Step 4 — what we do with them

We place the blob on the gateway host under your `customer_id`, add your registry entry
(signed off-box), and restart the gateway so it picks the blob up. Then you get your
bearer token and the endpoint. The gateway has no upload API on purpose: putting a blob
in place is an operator action with a human on it.

At first use the enclave asks KMS to decrypt. If the context or the associated data does
not match what we staged, it fails there — loudly and before any signature.

## What you can check yourself, and what you cannot

You can, without asking us:

- **That the running code is the published code.** `GET /attestation?nonce=<random hex>`
  returns an AWS-signed document; verify it against the Nitro root, check your nonce
  came back, and compare `PCR0` with a build of this repository at the commit named in
  the README's reproducible-build section. See `docs/ATTESTATION-VERIFICATION.md`.
- **That the on-chain record names the same measurement**, and that the address that
  registered it is ours.
- **That a policy denial came from inside.** Since the 2026-08 rotation each decision
  carries a receipt signed by a key bound into the attestation document — a refusal you
  can verify rather than take on faith.

You cannot yet, and we would rather say it than dress it up:

- **Read the KMS key policy for yourself.** It is what makes "only an attested enclave
  can decrypt" true, and today it lives in our private infrastructure tree;
  `aws kms get-key-policy` needs our IAM. Until we publish a snapshot of the live policy
  next to this document, that link in the chain rests on our word. We are aware that is
  the weakest sentence on this page.

## If you are evaluating rather than committing

Use a key you would not mind losing — a testnet key, or a mainnet key with exchange-side
IP allowlisting and withdrawal disabled — until you have run the attestation check
yourself and seen a receipt verify. That is the order we would use.
