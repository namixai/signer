# Usenami Signer — Live Demo Walkthrough

A five-minute proof that your exchange API secrets and DEX private keys
cannot leak from a compromised machine.

No slides. The signing transcripts below are real terminal output from
the Usenami pilot enclave, plus one section (the on-chain verification)
you can repeat yourself in under thirty seconds with no setup.

---

## What is Usenami Signer?

A **remote signing service** for cryptocurrency exchanges (CEX and DEX).

Today, every algorithmic trader keeps API keys somewhere on a working
machine: `.env` files on a laptop, environment variables on a VPS, or
at best a local secrets manager. One piece of malware on that machine
and the account is drained. (One of the authors of this project lost
$30 to clipboard malware on May 12, 2026. It happens to people who know
the threat.)

Usenami Signer moves the keys into an **AWS Nitro Enclave** — a sealed
virtual machine on AWS whose memory cannot be read from the host
operating system, even by AWS engineers. Your trading bot sends a
*signing intent* ("sign this KuCoin balance query"), the enclave
returns the authentication headers, and your bot forwards them to the
exchange. The signing secret never leaves the enclave.

Supported exchanges: Binance USD-M futures (spot order signing is **not**
implemented), OKX V5 perpetual swap, Hyperliquid mainnet, and Asterdex.
KuCoin Futures and Bybit V5 are implemented in the enclave but sign
nowhere today.

---

## How this demo proves the claim

Four steps, each one a single command, total runtime under one minute.

1. **Baseline.** What a plaintext-credentials threat model looks like.
2. **Live signing.** A real call to the pilot signer, returning a
   valid HMAC-signed header set without exposing the secret.
3. **Adversarial probe.** A simulated attacker trying — and failing —
   to extract the secret through the public HTTP surface.
4. **Decentralized verification.** Anyone, including someone who
   distrusts us, can read a public smart contract on Base mainnet to
   confirm our published production build is the measurement we
   registered — and can request a live attestation from the pilot
   enclave to confirm what it is running right now.

Steps 1–3 below are transcripts of what we ran. Step 4 you can repeat
yourself, no allowlist needed, in your browser or with one command.

---

## A note on access

The signing routes at `signer-demo.usenami.io:8443` need a bearer token
we issue; without one they answer `401`. What gates them is the token,
not your address — this section claimed a closed IP allowlist until
2026-08-23, and that is not how the endpoint is protected.

Two consequences worth being plain about. The read-only routes are
open: `/healthz` and `/attestation` answer anyone, by design, because
the attestation document is the thing you are meant to check without
asking us. And the transcripts in steps 2 and 3 are real responses you
cannot reproduce without a token — ask and we will issue one.

The on-chain verification in **Step 4 is fully public** and exists
precisely so a skeptical reader does not have to trust this document.

---

## Step 1 — The plaintext baseline

This is the *before*. Most algorithmic traders have a file like this on
their development machine:

```bash
grep -iE "passphrase|api.?secret|hmac.?secret" ~/path/to/your/.env
```

Typical output:

```
OKX_API_SECRET=████████████████████████████████████████████████
OKX_API_PASSPHRASE=████████████
BINANCE_API_SECRET=████████████████████████████████████████████████████████████████
```

This is what any malware on the machine can read. The moment a
clipboard-watcher, a malicious npm package, or a compromised browser
extension gains read access to your filesystem — the account is gone.

---

## Step 2 — Live signing through the enclave

From an allowlisted source, we ask the signer for the headers required
to authenticate a KuCoin "get balances" request, and we time the
round-trip:

```bash
curl -s -X POST http://signer-demo.usenami.io:8443/sign \
  -H 'Content-Type: application/json' \
  -d '{"exchange":"kucoin","method":"GET","path":"/api/v1/accounts"}' \
  -w '\n# round-trip: %{time_total}s (connect %{time_connect}s, ttfb %{time_starttransfer}s)\n' \
  | python3 -m json.tool || cat
```

The response is the exact header set that KuCoin's v2 API requires:

```json
{
    "headers": {
        "KC-API-KEY": "69fcc1b588d5ca000115bcd7",
        "KC-API-KEY-VERSION": "2",
        "KC-API-PASSPHRASE": "GZhLB1BRbiW/om4ygkvgq6GBpaV8Kdo+/wp0c25nILU=",
        "KC-API-SIGN": "qwahqACKr3s8Or+ekpHEiBgucBUAjFFKUtajlIfVIrc=",
        "KC-API-TIMESTAMP": "1778674666187"
    }
}
# round-trip: 0.41s (connect 0.21s, ttfb 0.41s)
```

`KC-API-SIGN` is an HMAC-SHA256 over `(timestamp + method + path +
body)`, computed inside the enclave with the API secret. Each call
returns a different signature because the timestamp advances; the API
secret is the same on every call but is never present in any response.

The round-trip in this transcript is ~410 ms, of which roughly 210 ms
is the TCP+HTTP overhead from a cross-continental client to AWS
us-east-1, and the remaining ~200 ms covers KMS Decrypt + enclave HMAC
+ STS credential refresh. With a same-region client (a co-located VPS
or a bot running on an EC2 instance in us-east-1), end-to-end latency
drops to **30–80 ms** — well below the inter-tick interval for any
trading strategy except top-tier HFT. We publish realistic
latency-budget guidance for each pilot user.

A trading bot consuming this signer attaches these headers to its
outgoing KuCoin request. The bot never sees the API secret. The host
operating system never sees it. The KMS-encrypted blob is opened only
inside enclave memory, only when the enclave's attestation matches the
KMS key policy, and the plaintext is zeroized on drop.

---

## Step 3 — A simulated attacker probes the gateway

Assume the worst realistic case: an attacker has remote code execution
on the client machine that talks to the signer. They have full HTTP
reachability to the signing gateway. Can they extract the keys?

**Probe 1: standard debug/admin paths.**

```bash
for path in /keys /env /debug /admin /dump /.env /api/keys \
  /internal/secrets /healthz/debug /metrics/internal \
  '/?cmd=cat+/etc/passwd' '/../../passwd' \
  '/sign?debug=1' '/sign?reveal_secret=1'; do
  printf '  %-30s ' "$path"
  curl -s -o /dev/null -w '%{http_code}\n' --max-time 4 \
    "http://signer-demo.usenami.io:8443$path"
done
```

Result:

```
  /keys                          404
  /env                           404
  /debug                         404
  /admin                         404
  /dump                          404
  /.env                          404
  /api/keys                      404
  /internal/secrets              404
  /healthz/debug                 404
  /metrics/internal              404
  /?cmd=cat+/etc/passwd          404
  /../../passwd                  404
  /sign?debug=1                  405
  /sign?reveal_secret=1          405
```

Every introspection endpoint returns 404. The `/sign` route returns 405
(Method Not Allowed) for GET — it accepts only POST. The code for a
debug, admin, or key-dump endpoint does not exist in the gateway
source. You can't accidentally expose what you didn't write.

**Probe 2: inject debug fields into the legitimate signing request.**

```bash
curl -s -X POST http://signer-demo.usenami.io:8443/sign \
  -H 'Content-Type: application/json' \
  -d '{"exchange":"kucoin","method":"GET","path":"/api/v1/accounts",
       "reveal_secret":true,"debug":true,"dump_keys":"yes"}'
```

Result: a normal signed-headers response, identical to step 2. The
fields `reveal_secret`, `debug`, `dump_keys` are silently dropped — they
do not appear in the gateway's request schema, and Rust's `serde`
ignores unknown fields by default.

**Probe 3: malformed input to provoke a verbose error.**

```bash
curl -s -X POST http://signer-demo.usenami.io:8443/sign \
  -H 'Content-Type: application/json' \
  -d '{"exchange":"../etc/passwd","method":"GET","path":"/"}'
```

Result: `{"error":"bad_request"}`. Generic. No stack trace. No path
echoed back. No internal version string. No information leak.

---

## Step 4 — Decentralized verification (you can repeat this in 30 seconds)

This is the part you don't have to trust us on.

Every AWS Nitro Enclave produces a measurement called **PCR0** at boot
time — think of it as a *cryptographic fingerprint of the entire
running code*, computed by AWS's hardware while the enclave starts up.
Technically, PCR0 is a SHA-384 hash over the complete enclave image
(every Rust binary, every Linux config, every library). Change a
single byte and PCR0 changes. AWS measures PCR0 in hardware, so we
cannot forge it ourselves even if we wanted to.

Usenami's production enclave build has its PCR0 registered in a public
smart contract on Base mainnet. Between 2026-08-10 and 2026-08-24 the demo
endpoint ran the same image as production, and this page said one number
covered both boxes. **That stopped being true on 2026-08-24**, and the sentence
stayed. They are two separate facts now, each read from its own `/attestation`:

- Registry contract:
  [`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240)
  (source verified on Basescan)
- Canonical owner address:
  `0x21538eBF6598e5866BA496A954dE8E39097bFB59`
- Active on-chain right now — the **production** enclave:
  `103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3`
  (registered 2026-08-24 by the owner above)
- What the **demo** box is running: `32d25d8c2f0b…`, which the 2026-08-24
  rotation auto-deprecated. Ask the registry about it today and you get
  `false`.

> ⚠️ **This page has now gone stale twice, and both corrections are published rather
> than quietly swapped.** An earlier revision printed `7c9e8b26…` and told you to expect
> `true`; the 2026-08-10 rotation auto-deprecated it. This revision fixes the second
> case: from 2026-08-24 until 2026-08-26 the page called `32d25d8c2f0b…` the production
> measurement, after rotation #4 had already moved production to `103ccd79de6c…`.
>
> 🔴 **The demo box is the one lagging now, and we are not going to hide it.** It still
> runs `32d25d8c2f0b…`, so the on-chain check below returns `false` for the demo's own
> measurement until the demo is rotated. `false` there is our rotation lag, not a
> service failing to be what it claims. The production lane passes the same check
> today; verified 2026-08-26. If you need the check to mean something about the
> enclave that would hold your keys, run it against production.

**Verify with [Foundry's `cast`](https://book.getfoundry.sh/cast/) (one command, no auth required)** — and read carefully what a `true` here does and does not mean; the paragraphs after the command spell it out.

```bash
# The production measurement — the one that answers "would this enclave be safe
# with my keys":
cast call 0x38b42eED740b0fDeb211bBDf773F2238cAEec240 \
  "isPCR0Active(bytes)(bool,address)" \
  0x103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3 \
  --rpc-url https://mainnet.base.org

# Or ask about whatever a box is actually running:
# 🔴 `pcr0_sha384` is the CONVENIENCE MIRROR, not the signed document. A gateway
# that wanted to fool you would put a registered measurement in this field while
# the COSE document carries a different one — and the registry would answer
# `true` about a measurement nothing is running. This shortcut is only worth
# anything AFTER verify.py has validated the signed document; treat a `true`
# here without that step as unproven, not as proof.
# Fail closed on the fetch too: an error page or a missing field would otherwise
# walk an empty value straight into the calldata.
SIGNER_URL=https://signer-demo.usenami.io:8443
PCR0=$(curl -sf "$SIGNER_URL/attestation" | jq -r '.pcr0_sha384 // empty')
if [[ ! $PCR0 =~ ^[0-9a-f]{96}$ ]]; then
  echo "no usable pcr0_sha384 from $SIGNER_URL" >&2
  exit 1
fi
cast call 0x38b42eED740b0fDeb211bBDf773F2238cAEec240 \
  "isPCR0Active(bytes)(bool,address)" "0x$PCR0" --rpc-url https://mainnet.base.org
# On the demo today this prints `false` — see the note above.
```

Or with no tools at all, in your browser:

[`https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240#readContract`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240#readContract)

Click *2. isPCR0Active*, paste the PCR0 hex above, read the result.

**A note on RPC trust for high-stakes verifiers.** The `cast` command
above uses a public RPC endpoint, which is itself a trust assumption.
A sophisticated adversary controlling that RPC could return a fake
`true` response. For verification under high adversarial assumption
(large funds at stake, suspected targeted attack):

- Run your own Base node, or use a self-hosted RPC.
- Query the contract through at least two independent RPC providers
  and require agreement.
- Cross-check via Basescan's UI in your browser, which is served by
  a different infrastructure path.

The on-chain state itself is canonical; only your *view* of it is
RPC-mediated.

Expected output, for the **production** measurement:

```
true
0x21538eBF6598e5866BA496A954dE8E39097bFB59
```

Translation: *the registry reports PCR0 103ccd79de6c… as active right now, with owner
0x21538eBF…, the canonical address Usenami publishes.* Run the same command against
the demo box's current measurement and you get `false` with a zero owner, because
rotation #4 deprecated it and the demo has not been rotated yet.

🔴 **Both lines matter, and the second one carries the weight.** `registerPCR0` is
permissionless: **any** address can register a measurement nobody currently holds and
become its owner. `true` on its own therefore means "somebody has this registered at
this moment" — it is not Usenami vouching for anything. Compare the owner against the
canonical address yourself; a `true` owned by any other address proves nothing about
us. Code that does `if (active) accept` and ignores the owner is exploitable.

⚠️ **`active` is mutable state, not a historical fact.** The getter reads a mapping
that changes with the next registration or deprecation. The part that cannot be
rewritten is the **event log** — `PCR0Registered` / `PCR0Deprecated` and the blocks
carrying them. The getter tells you what is true this second; only the event tells you
*when* it became true and who made it so. **For anything past a smoke test, do not stop
at the getter** — require a matching `PCR0Registered` event carrying this measurement,
the canonical owner in `topics[1]`, and the block or transaction it landed in.
[`docs/VERIFY-SIGNER-YOURSELF.md`](./docs/VERIFY-SIGNER-YOURSELF.md) §1.3 gives the exact
`eth_getLogs` query. Keep that check separate from the live `/attestation` measurement:
they fail independently, which is the entire reason to run both.

**What this call does and does not prove.** It proves that *the address we publish
has this value registered right now*. It does **not** prove that value is running:
swap the enclave and leave the registry untouched, and this call keeps returning
`true` for the old measurement — the chain has no way to notice. That is not
hypothetical. It happened here between 2026-08-10 and 2026-08-12: the enclave rotated
to `32d25d8c…` while this page still pointed at the old `7c9e8b26…`, so the document
and the chain agreed with each other and disagreed with reality.

So the registry is one half of a pair, and the half that moves is the
other one: `/attestation` reports what the enclave *actually* measures,
signed by NSM and verifiable against the AWS Nitro root. A third party
gets the right to trust this signer without trusting Usenami's website
or word when **both** agree — the live measurement, and a registration
of that same measurement by the published owner address.

### Reproducible builds — the PCR0 only matters if you can rebuild

A matching PCR0 hash proves the enclave is running the binary we
published. It does *not* by itself prove the binary lacks a backdoor.
To close that gap, the build must be **reproducible**: anyone with the
source code should produce the same PCR0 we registered on-chain.

In the `namixai/signer` repository:

```bash
git clone https://github.com/namixai/signer.git
cd signer/poc
./scripts/reproducibility-check.sh
# Runs two clean builds of the enclave EIF in throwaway directories,
# extracts PCR0 from each, and exits 0 if they match.
```

This proves our build process itself is deterministic — two clean
builds from the same source produce the same PCR0. To verify *our
registered on-chain PCR0*, run one more step manually after the script
succeeds:

```bash
nitro-cli describe-eif --eif-path signer.eif | jq -r '.Measurements.PCR0'
# Compare the output to the LIVE /attestation document, not to a number printed
# in this file and not to the on-chain registry entry — both can lag the running
# enclave, and as of 2026-08-06 the registry entry does (see Step 4).
# Expected for the strict build at commit 96cd4e46, which is the MAINNET/PRODUCTION
# enclave as of 2026-08-24:
#   103ccd79de6c5dc66b3aa52465fc6f6e025170612de160415c7bc690a7622a36dcb49f57d0b07786d107c6a52b8392e3
# The demo endpoint is a SEPARATE box on a SEPARATE measurement — it still runs the
# pre-rotation image. One number stopped covering both on 2026-08-24. Build the commit
# you mean to check, and compare against that box's own /attestation.
```

If your locally-built PCR0 matches the on-chain registered PCR0, you
have *byte-level confirmation that the production build registered
on-chain is the source code you just inspected*. If it does not match, that is a
security finding — open an issue on the repository.

In practice, achieving fully byte-deterministic Rust builds takes
discipline around timestamps, build paths, toolchain pinning, and the
Linux kernel image embedded in the EIF. We track current
reproducibility status and known gotchas in the repository's `poc/`
directory — read it before claiming reproducibility for your own
deployment.

### Registry governance — who can change what's on-chain

The contract is permissionless to read, and **`registerPCR0` is
permissionless to call as well** — any address may claim a measurement
nobody currently holds and become recorded as its owner
(`UsenamiAttestationRegistry.sol`, no access modifier; the caller is
simply `msg.sender`). Only **`deprecatePCR0` is owner-gated**: it reverts
`NotOwnerOfPCR0()` for anyone but the address that registered that
measurement. This is why every check above compares the returned `owner`
rather than the boolean — "registered" is not a privilege, so it is not
evidence about us on its own.

Today the canonical Usenami PCR0 is registered from a **single
externally-owned account**: `0x21538eBF6598e5866BA496A954dE8E39097bFB59`.
That is Phase 1 governance.

A sophisticated adversary does not need to compromise the enclave —
they only need to compromise that one private key, then call
`deprecatePCR0` followed by `registerPCR0` with a malicious PCR0 under
the same address. The on-chain `isPCR0Active` check would still pass,
**and so would the owner comparison** — which is precisely why the chain
is one half of a pair and the live `/attestation` measurement is the
other. A stolen key can rewrite what the registry says is active today;
it cannot make a Nitro enclave attest a measurement it is not running.

Mitigations in flight:
- **Phase 1 (now)**: the deploy key is on a hardware-isolated Rabby
  wallet on a clean machine, used only for registry operations.
- **Phase 2**: migration of ownership to a 2-of-3 Safe with at least
  one hardware key offline, plus a 24-hour timelock on `registerPCR0`
  to give pilot users a detection window for unauthorized changes.

Until Phase 2 ships, the practical security argument is "key
compromise of one EOA = registry compromise"; we are honest that this
is below where we want the bar.

**Note on historical PCR0s.** The contract enforces single-active-
per-owner: registering a new PCR0 auto-deprecates the previous one in
the same owner's history, and the `activePCR0OwnerByHash` mapping is
cleared for the deprecated hash. A query for an old (deprecated) PCR0
returns `(false, 0x0000…)` — old measurements cannot remain "active in
parallel" with the current one. This matters because a sophisticated
adversary would otherwise target an older enclave version still
marked active. SDKs integrating against the registry should still
check that the *currently registered* PCR0 matches what their session
attestation reports — not just that the registry knows about the
attestation's PCR0.

(Mandatory caveat for any reader integrating against this: when your
software calls `isPCR0Active`, you must strict-check that the returned
owner address equals the canonical Usenami owner address you have
out-of-band. The registry is intentionally permissionless — anyone can
register a PCR0 they control — and the trust is in the *combination*
of PCR0 and owner, not in PCR0 alone.)

### The Nitro attestation document — what binds it all together

PCR0 verified on-chain tells you *which binary should be running*. The
**Nitro attestation document** tells you *what is running right now in
this specific enclave instance*. It is a CBOR-encoded blob signed by
AWS's hardware root of trust that contains, among other fields:

- The current PCR0/PCR1/PCR2 measurements of the running enclave
- The enclave's freshly generated public key
- A nonce supplied by the requester (binds the doc to a specific
  challenge)
- An optional user-data field (binds the doc to application context)
- A timestamp from inside the enclave

A pilot integrating against the signer should:

1. Request an attestation document from the enclave with a fresh
   client nonce.
2. Verify the signature chain against AWS's published root CA (pinned,
   not fetched).
3. Confirm `pcrs[0]` is the measurement you expect — for the on-chain
   production build, the value returned by `isPCR0Active`; for the
   closed-pilot enclave, the attestation document is itself AWS-signed
   proof of the live measurement.
4. Confirm the embedded nonce equals what was sent.
5. Use the enclave's public key from the document to set up a session
   key exchange — every subsequent response is then bound to *this
   specific running enclave instance*, not just *the binary that
   produced this PCR0*.

This is the single piece that converts "we claim our enclave is safe"
into "your client cryptographically refuses to talk to anything except
the right enclave." The signer exposes this live: request a fresh
attestation document with `get_attestation`, verify the AWS signature
chain and your nonce, and read `pcrs[0]` to confirm exactly which
enclave answered — closing the gap between a static measurement and
*the live response you just received over HTTP*.

---

## How your keys get into the enclave (provisioning)

A reasonable question after Step 2: *how do I know `KC-API-PASSPHRASE`
encodes my real KuCoin passphrase, and not yours? I never gave you my
secret in any obvious way.*

There are two provisioning models, used in different phases:

**Path A — we wrap the key for you.** This is how our own dogfood keys
got in, and it is **not what we offer a customer**: it means handing us
a plaintext credential, which is the exact thing this product exists to
avoid. We keep it documented because it is what the screenshots above
were recorded with, and because it is a reasonable choice for a
throwaway testnet key while you evaluate. The mechanics: the key is
transferred out-of-band, we encrypt it to a KMS key whose policy locks
decryption to the current PCR0, and we never persist the plaintext.
It is faster to set up but requires
trusting Usenami operators *during the provisioning window only* — not
during ongoing signing.

We acknowledge this is a real operational risk that a sophisticated
adversary would target specifically. The mitigations we apply during
the window:

- The transfer happens in a single paired session with the pilot user,
  not asynchronously over chat or email.
- The encryption step runs on an ephemeral environment that is torn
  down immediately after the KMS-encrypted blob is produced.
- The plaintext is held in memory only and never written to disk or
  shell history.
- Anyone uncomfortable with handing over a plaintext credential should
  not do it: take Path B below, which is available now. We will not
  push a customer onto Path A.

**Path B — you encrypt it yourself. This is the one we sell, and as of
2026-08 it works end to end.** You clone this repository, build
`signer-policy-wrap`, and produce the encrypted blob on your own
machine:

1. We give you a `customer_id`, the venue key alias, a policy signed by
   our off-box authority key, and a short-lived credential that can
   `kms:Encrypt` under that one key — never decrypt.
2. You put your API secret in a local file and run the tool. It wraps
   the secret together with the policy and encrypts it under the venue
   KMS key with an EncryptionContext of exactly `customer_id` and
   `venue_id`; the envelope form additionally binds the same identity as
   AES-GCM associated data.
3. You send us the ciphertext and a one-line context file. We stage the
   blob on the gateway host and add your registry entry.

The plaintext never leaves your machine. The ciphertext is useless
without a Decrypt that only an attested enclave can obtain.

Three earlier sentences on this page described this path wrongly and are
corrected rather than quietly deleted: there is no "KMS public key" to
fetch (the key is symmetric — what you get is a scoped `kms:Encrypt`
credential); the EncryptionContext binds `{customer_id, venue_id}`, not
a PCR0 and a nonce; and there is no upload endpoint — staging a blob is
an operator action with a human on it, on purpose.

Step-by-step, with the commands and with an explicit list of what you
can and cannot verify yourself: [`docs/CLIENT-ONBOARDING.md`](docs/CLIENT-ONBOARDING.md).
The client tool's output is checked against the enclave's own decrypt
code in CI, so "the published tool produces a blob this enclave can
open" is a test, not a promise.

---

## Gateway is untrusted by design

A note on the trust boundary inside Usenami's own infrastructure.

The `signer-demo.usenami.io:8443` gateway is a thin Rust HTTP server
that forwards signing intents over a vsock channel to the enclave. It
runs on the parent EC2 instance — the same host the enclave runs on.
The gateway does *not* hold any signing secrets. If an attacker
compromised the gateway (RCE, container escape, etc.), they would
gain:

- The ability to refuse signing requests (denial of service).
- The ability to mutate signing intents before they reach the enclave
  — but the enclave applies its own validation and live UPL policy
  enforcement, so a mutated intent that violates policy is rejected at
  the enclave boundary.
- Visibility into which exchange a request targets and the request
  path — *not* the API secret.

They would *not* gain:

- The exchange API secrets (locked in enclave memory).
- The KMS decryption capability (KMS attestation gates require a
  specific PCR0; the gateway's host does not match).
- The ability to forge attestation documents (those are signed by AWS
  hardware, not by the gateway).

The architectural choice to treat the gateway as untrusted is what
allows us to be honest about it: a gateway compromise is recoverable
without secret rotation, because the secrets never lived on the
gateway in the first place.

### What the gateway *does* see — strategy-leakage honesty

The flip side of the gateway's untrusted role: in the current Phase 1
wire format, the gateway sees the request metadata in plaintext. For
the `/sign` POST body, this means:

- The exchange you are trading on.
- The HTTP method and API path you target (e.g.
  `POST /api/v5/trade/order`).
- The request body itself (for HMAC venues) — your order parameters,
  prices, sizes.

It does *not* see exchange API secrets. But a compromised gateway —
or, in the worst case, a malicious Usenami operator — could in
principle observe your trading strategy in real time. For a
funding-arbitrage or stat-arb strategy this is information that has
market value to a sophisticated front-runner.

This is a trust-but-verify property of Phase 1, and we are not
hand-waving it. Phase 2 introduces an enclave-side session key
exchange (via the Nitro attestation document, see above) and shifts
request bodies to ciphertext between client and enclave. After
Phase 2 ships, the gateway sees only an opaque blob plus
non-strategic routing metadata.

If your strategy's value depends on its informational secrecy (not
just on its execution security), you may want to wait for Phase 2.
We will say so explicitly during pilot onboarding.

### KMS policy is the load-bearing constraint

The single most important architectural commitment is in the KMS key
policy that protects the encrypted secret blobs. It must allow
`kms:Decrypt` *only* via Nitro Enclave attestation matching a
specific PCR0 — never via an IAM principal alone, never with an
"admin debug" bypass, never with a wildcard role.

Concretely, the policy uses
`kms:RecipientAttestation:ImageSha384` as a `StringEquals` condition,
locking decryption to the production PCR0 measurement. No IAM user,
not even the AWS root account holder, can `kms:Decrypt` the secret
blob outside the attested enclave. This is the property that makes
the entire architecture mean anything — if KMS could be persuaded to
hand over plaintext to a non-enclave caller, all other defenses are
decorative.

We commit a snapshot of the production KMS key policy alongside the
signer source under `poc/policies/` — **as of this writing the snapshot
is not there yet**, and `poc/policies/README.md` says so plainly rather
than leaving the promise standing; and the Phase 2 roadmap includes a formal
**KMS Key Policy Audit** as part of every pre-production release
checklist — a second pair of eyes confirming no IAM-only decrypt path
ever lands in production.

---

## What this demo does not show

To stay honest:

- **A direct host-level attack** — for example, attempting to read
  enclave memory from the parent EC2 instance. The architectural
  promise of AWS Nitro Enclaves is that this is physically impossible:
  the hypervisor blocks any memory access from the parent to the
  enclave. Demonstrating the failed attempt requires SSH to the host,
  which is intentionally locked down during the closed pilot. We can
  demonstrate this on a longer call.
- **Side-channel attacks** (timing, cache, power). An active research
  area; no public exploit against production Nitro Enclaves has been
  published as of 2026, but the theoretical risk is not zero.
- **Multi-party key rotation ceremonies.** Out of scope for a
  five-minute demo. Documented internally and available on request.
- **Deep UPL policy semantics.** The live Usenami Policy Layer
  enforces coarse-grained limits (allowed venues, allowed methods,
  per-window value caps). It does not currently deep-inspect every
  exchange-specific body parameter for semantic equivalence with a
  declared intent. A sophisticated insider could in principle abuse
  exchange API polymorphism (special order types, hidden parameters)
  to take an action that the UPL rule did not anticipate. A future UPL
  release adds per-exchange semantic models — until then, pilot users
  should treat UPL as a coarse safety net, not a complete sandbox.

---

## How to try Usenami Signer

The signing endpoint is issued per tenant, on request. The line here
read "a closed pilot group as of May 2026" — a date three months stale
by the time you are reading it, which is exactly how a document starts
lying without anyone editing it. If you trade through CEX or DEX APIs
and want to participate:

1. Reach out via the contact channel where you received this document.
2. Pilot users get free access to the live signer, source IP
   allowlisting, and direct support during the testing period.
3. Pricing for general availability is not yet finalized. Pilots help
   us calibrate.

There is no token. There is no fundraising. We are not selling a
position — we are validating a product.

---

## About the project

Usenami Signer is built and maintained as part of the Usenami platform.
The on-chain attestation registry and the signer source code are
open-source under the Apache 2.0 license; the threat model is
published in the repository.

Design principles, in order of priority:

1. **Keys never leave the enclave** — not even to the people who built
   the product.
2. **Decentralized trust** — anyone can verify the running enclave
   matches the published source without contacting us.
3. **Operational paranoia** — the same adversarial mindset we apply to
   external bug-bounty targets is turned inward on our own code.
4. **Honest limits** — when we don't have a guarantee, we say so.

Repository: [`namixai/signer`](https://github.com/namixai/signer)

---

*The signing transcripts in this document are real output from the
Usenami pilot enclave. The on-chain verification step returns the
registered production build's measurement as long as that registration
remains active.*
