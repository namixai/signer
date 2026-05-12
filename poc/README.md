# Usenami Signer — PoC (Day 2)

A Nitro Enclave that signs crypto-exchange API requests without ever exposing
the raw API secret to the parent EC2 instance, the operator, or any other
process. Day 2 ships the Rust workspace skeleton: vsock plumbing, HMAC-SHA256
signer, wire protocol, scripts. NSM attestation + KMS Decrypt + S3 fetch
arrive in **Phase 3** (next pass).

## Layout

```
poc/
├── Cargo.toml              # workspace root, pinned deps
├── rust-toolchain.toml     # pin Rust 1.83.0 (rustfmt + clippy)
├── enclave/                # bin: signer-enclave (vsock listener, HMAC)
│   ├── Cargo.toml
│   ├── Dockerfile          # multi-stage musl + scratch
│   └── src/
│       ├── main.rs
│       ├── proto.rs        # SignRequest / SignResponse types
│       ├── signer.rs       # HMAC-SHA256 + RFC 4231 unit tests
│       ├── handler.rs      # ping / sign dispatcher (stubbed Phase 3)
│       └── vsock_server.rs # length-prefix framing, per-conn task
├── parent/                 # bin: signer-client (CLI test driver)
│   ├── Cargo.toml
│   └── src/main.rs
└── scripts/
    ├── build-eif.sh
    ├── run-enclave-debug.sh
    ├── run-enclave-prod.sh
    ├── start-vsock-proxies.sh
    └── reproducibility-check.sh
```

## Build & test (host workstation, native)

```bash
cd poc
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --workspace --release
```

The musl static build for the actual enclave image only runs on the EC2
build host inside `clux/muslrust:1.83.0-stable`. Local native builds are
just to confirm the source compiles and tests pass.

## Smoke test on EC2 (Day 2 target)

```bash
# 1. Build the EIF and capture PCR0
./scripts/build-eif.sh

# 2. Run in debug mode (PCR0 = all-zeros, console attached)
./scripts/run-enclave-debug.sh
# (in another terminal) note the EnclaveCID via `nitro-cli describe-enclaves`

# 3. From the parent shell, ping
cargo build -p signer-client --release
./target/release/signer-client --cid <ENCLAVE_CID> ping
# expect: signature_base64 == "pong"

# 4. From the parent shell, sign
./target/release/signer-client --cid <ENCLAVE_CID> sign
# expect: signature_base64 == 44-char base64 (HMAC of canonical KuCoin string)
```

## Wire protocol (length-prefix JSON)

Every message: `[u32 BE length][JSON body]`, hard-capped at 64 KiB.

Request — `ping`:
```json
{"action":"ping"}
```
Request — `sign`:
```json
{
  "action":"sign",
  "method":"POST",
  "path":"/api/v1/orders",
  "body":"{\"clientOid\":\"abc\"}",
  "timestamp_ms":1714997000000,
  "key_blob_s3_key":"secrets/test-kucoin.enc",
  "key_id":"alias/signer-poc"
}
```
Response:
```json
{"signature_base64":"<base64-or-pong>","error":null}
```
Error response (signature_base64 is `""`, `error` is one of):
`bad_request`, `payload_too_large`, `internal_error`, `kms_decrypt_denied`.

## Phase 3 TODO (next pass — NOT in this turn)

- [ ] `enclave/src/nsm.rs` — fetch NSM attestation document via
      `aws-nitro-enclaves-nsm-api` (the only `unsafe` site, encapsulated
      by that crate).
- [ ] `enclave/src/kms_client.rs` — sigv4-signed Decrypt over reqwest +
      vsock-proxy:8001, attaching the attestation document so the KMS key
      policy can bind PCR0 -> Decrypt allow.
- [ ] `enclave/src/s3_client.rs` — sigv4-signed GetObject over
      vsock-proxy:8002 to fetch the KMS-encrypted secret blob.
- [ ] Replace the hardcoded `TEST_SECRET` in `handler.rs::load_secret_for`
      with the KMS-decrypted blob (clearly marked TODO today).
- [ ] One external known-good HMAC vector test (currently `#[ignore]` —
      fill the EXPECTED_HEX/EXPECTED_B64 constants from openssl on the
      EC2 build host).
- [ ] Reproducibility check: run `./scripts/reproducibility-check.sh`,
      confirm two clean builds yield the same PCR0.

## Reference docs

- `_signer/01-АРХИТЕКТУРА.md` — full architecture (parent vs enclave,
  trust model, attestation flow).
- `_signer/06-АТАКУЕМ-СЕБЯ.md` — adversarial-mindset doc; the secret
  hygiene rules (no logs, generic errors, zeroize) come from here.
- `_hub/WORKER-PROMPTS/SIGNER-POC-DAY-2-BRIEF.md` — Day 2 scope brief
  this code implements.
