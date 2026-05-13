# Usenami Signer — Live Demo Walkthrough

A five-minute proof that your exchange API secrets and DEX private keys
cannot leak from a compromised machine.

No slides. The transcripts below are real terminal output from a
production AWS Nitro Enclave on May 13, 2026, with one section (the
on-chain verification) you can repeat yourself in under thirty seconds
with no setup.

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

Supported exchanges as of May 2026: KuCoin Futures, Binance (spot &
futures), Bybit V5, OKX V5, Hyperliquid mainnet.

---

## How this demo proves the claim

Four steps, each one a single command, total runtime under one minute.

1. **Baseline.** What a plaintext-credentials threat model looks like.
2. **Live signing.** A real call to the production signer, returning a
   valid HMAC-signed header set without exposing the secret.
3. **Adversarial probe.** A simulated attacker trying — and failing —
   to extract the secret through the public HTTP surface.
4. **Decentralized verification.** Anyone, including someone who
   distrusts us, can prove the enclave is running our published build
   by reading a public smart contract on Base mainnet.

Steps 1–3 below are transcripts of what we ran. Step 4 you can repeat
yourself, no allowlist needed, in your browser or with one command.

---

## A note on access

The HTTP signing endpoint at `signer-demo.usenami.io:8443` is reachable
only from IPs on a closed allowlist. This is itself a security
feature — it shrinks the attack surface during the closed-pilot phase.
The transcripts in steps 2 and 3 are real responses; you cannot
reproduce them by running the `curl` directly unless you are a pilot
user (or your IP gets allowlisted on request).

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

The current Usenami Signer build's PCR0 is registered in a public
smart contract on Base mainnet:

- Registry contract:
  [`0x38b42eED740b0fDeb211bBDf773F2238cAEec240`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240)
  (source verified on Basescan)
- Active PCR0:
  `9f6f512f81c3b533333fb53098e9df45aaa0fb31d4536a4b39ab690e056839814ab6a2595859885cc6327c544cf059ab`
- Canonical owner address:
  `0x21538eBF6598e5866BA496A954dE8E39097bFB59`

**Verify with [Foundry's `cast`](https://book.getfoundry.sh/cast/) (one command, no auth required):**

```bash
cast call 0x38b42eED740b0fDeb211bBDf773F2238cAEec240 \
  "isPCR0Active(bytes)(bool,address)" \
  0x9f6f512f81c3b533333fb53098e9df45aaa0fb31d4536a4b39ab690e056839814ab6a2595859885cc6327c544cf059ab \
  --rpc-url https://mainnet.base.org
```

Or with no tools at all, in your browser:

[`https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240#readContract`](https://basescan.org/address/0x38b42eED740b0fDeb211bBDf773F2238cAEec240#readContract)

Click *2. isPCR0Active*, paste the PCR0 hex above, read the result.

Expected output:

```
true
0x21538eBF6598e5866BA496A954dE8E39097bFB59
```

Translation: *PCR0 9f6f512f… is currently active, registered by
0x21538eBF…, which is the canonical owner address Usenami publishes.*

If we had replaced the enclave with malicious code after deployment,
the PCR0 would be different and this call would return `(false,
0x0000…)`. The correspondence between the *running enclave's
measurement* and the *on-chain registration* is what gives a third
party the right to trust the signer without trusting Usenami's
website, marketing, or word.

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
# Compare the output to the PCR0 value from the on-chain registry
# (Step 4 above): 9f6f512f81c3b533333fb53098e9df45aaa0fb31d4536a4b39ab690e056839814ab6a2595859885cc6327c544cf059ab
```

If your locally-built PCR0 matches the on-chain registered PCR0, you
have *byte-level confirmation that the running production enclave is
the source code you just inspected*. If it does not match, that is a
security finding — open an issue on the repository.

In practice, achieving fully byte-deterministic Rust builds takes
discipline around timestamps, build paths, toolchain pinning, and the
Linux kernel image embedded in the EIF. We track current
reproducibility status and known gotchas in the repository's `poc/`
directory — read it before claiming reproducibility for your own
deployment.

### Registry governance — who can change what's on-chain

The contract that holds the active PCR0 list is permissionless to read
but the registration calls require ownership. Today, ownership of the
canonical Usenami PCR0 sits on a **single externally-owned account**:
`0x21538eBF6598e5866BA496A954dE8E39097bFB59`. This is Phase 1
governance.

A sophisticated adversary does not need to compromise the enclave —
they only need to compromise that one private key, then call
`deprecatePCR0` followed by `registerPCR0` with a malicious PCR0 under
the same address. The on-chain `isPCR0Active` check would still pass.

Mitigations in flight:
- **Phase 1 (now)**: the deploy key is on a hardware-isolated Rabby
  wallet on a clean machine, used only for registry operations.
- **Phase 2**: migration of ownership to a 2-of-3 Safe with at least
  one hardware key offline, plus a 24-hour timelock on `registerPCR0`
  to give pilot users a detection window for unauthorized changes.

Until Phase 2 ships, the practical security argument is "key
compromise of one EOA = registry compromise"; we are honest that this
is below where we want the bar.

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
3. Confirm `pcrs[0]` matches the value returned by `isPCR0Active`.
4. Confirm the embedded nonce equals what was sent.
5. Use the enclave's public key from the document to set up a session
   key exchange — every subsequent response is then bound to *this
   specific running enclave instance*, not just *the binary that
   produced this PCR0*.

This is the single piece that converts "we claim our enclave is safe"
into "your client cryptographically refuses to talk to anything except
the right enclave." The attestation endpoint is on the Phase 2
roadmap. Until then, the trust chain has a gap between *the PCR0
on-chain* and *the live response you just received over HTTP* — and a
sufficiently powerful adversary controlling the network path could
exploit that gap. We want pilots to know.

---

## How your keys get into the enclave (provisioning)

A reasonable question after Step 2: *how do I know `KC-API-PASSPHRASE`
encodes my real KuCoin passphrase, and not yours? I never gave you my
secret in any obvious way.*

There are two provisioning models, used in different phases:

**Phase 1 (closed pilot, what we run today):** the pilot user shares
their exchange API credentials with us through an out-of-band channel
(typically a signed credential transfer agreed during onboarding). We
encrypt the secret to an AWS KMS key whose policy locks decryption to
the current PCR0. We never persist the plaintext after encryption; we
verify by performing a live, paper-trading test call against the
exchange in your presence. This is faster to set up but requires
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
- Any pilot who is uncomfortable with this onboarding model should
  wait for Phase 2; we will not pressure anyone to start during
  Phase 1.

**Phase 2 (production target, in active development):**
*customer-side encryption.* You run a small open-source provisioning
tool that:

1. Fetches our KMS public key + the canonical PCR0 from our public
   on-chain registry (the same contract from Step 4).
2. Asks you to paste your exchange API secret into a local terminal
   prompt (no transmission yet).
3. Encrypts the secret under our KMS key with an EncryptionContext
   binding the ciphertext to *your enclave's PCR0 and a one-time
   nonce* — this means the ciphertext can be decrypted *only* by an
   enclave running our published code, and only once for you.
4. Uploads the encrypted blob to our gateway.

The plaintext never leaves your machine in cleartext form. We never
see it. The enclave is the only entity that can read it.

Phase 2 is where the trust model becomes fully cryptographic — even
the *initial provisioning window* no longer requires trusting the
Usenami team. We have the design and the KMS policy in place; the
provisioning CLI is on the Phase 2 roadmap. Pilot users today opt for
Phase 1 with full awareness, and migrate to Phase 2 when the CLI
ships.

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
  — but the enclave applies its own validation and (in Phase 1.5+)
  UPL policy enforcement, so a mutated intent that violates policy is
  rejected at the enclave boundary.
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

---

## How to try Usenami Signer

The signing endpoint is available to a closed pilot group as of May
2026. If you trade through CEX or DEX APIs and want to participate:

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

*Transcripts in this document are from a live production run on
2026-05-13. The on-chain verification step continues to return the
same result as long as the registered PCR0 remains active.*
