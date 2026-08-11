//! `signer-policy-wrap` — operator/customer tool that produces a
//! UPL-wrapped plaintext blob ready for `aws kms encrypt`.
//!
//! Usage:
//!
//! ```text
//! signer-policy-wrap \
//!     --policy ./binance-prod-policy.json \
//!     --secret ./binance-prod-secret.json \
//!     --output ./blob.plain.json
//!
//! # Then encrypt under the enclave's KMS key with mandatory EncryptionContext.
//! # The context MUST match what the gateway passes in SignRequest.encryption_context
//! # at decrypt time — KMS rejects mismatches. This prevents cross-customer DEK reuse.
//! aws kms encrypt \
//!     --key-id alias/signer-poc \
//!     --plaintext fileb://blob.plain.json \
//!     --encryption-context venue_id=binance,customer_id=acme-prod,purpose=dek,version=2 \
//!     --output text \
//!     --query CiphertextBlob > blob.enc.b64
//!
//! # Stage blob.enc.b64 on the gateway/S3 path the customer configured.
//! # The gateway MUST forward the same encryption_context map in every SignRequest.
//! ```
//!
//! Why a separate tool (and not part of the SDK):
//! - The enclave is the ONLY component that should ever decrypt this blob.
//!   The gateway pulls the ciphertext from S3 and forwards inline — it
//!   never knows the plaintext.
//! - The customer assembles policy + secret on their OWN laptop, with
//!   their OWN AWS credentials, against the enclave's published KMS key
//!   alias. No third-party trust in the wrapping step.
//! - Wrapping is deterministic and trivial — pure JSON. We deliberately
//!   keep AWS SDK dependencies OUT of this tool so the customer can audit
//!   the source in five minutes (~150 LoC) before placing real keys.
//!
//! The wrapped JSON layout matches `enclave::proto::PolicyWrappedSecret`:
//!
//! ```json
//! {
//!   "policy": { ... validated against Policy schema below ... },
//!   "secret": { ... opaque to this tool — exchange-specific shape ... }
//! }
//! ```
//!
//! Policy schema (must stay aligned with `_signer/poc/enclave/src/proto.rs`
//! `pub struct Policy`):
//!   - allowed_actions:          Option<Vec<String>>
//!   - allowed_methods:          Option<Vec<String>>
//!   - allowed_path_prefixes:    Option<Vec<String>>
//!   - denied_path_prefixes:     Option<Vec<String>>
//!   - max_requests_per_minute:  Option<u32>
//!   - label:                    Option<String>  (max 128 chars)
//!   - allowed_asterdex_endpoints: Option<Vec<String>>
//!   - x402:                     Option<X402Policy>   (EIP-3009 spend cap)
//!   - order_caps:               Option<Vec<OrderAssetCap>> (per-asset qty cap)
//!   - allowed_vaults:           Option<Vec<String>>        (CR053 HL vault allow-list, ZN-202)
//!   - hl_order_caps:            Option<Vec<HlOrderCap>>    (CR053 HL per-asset-index size cap)
//!   - signer_pubkey:            Option<String>  (TOFU)
//!   - policy_signature:         Option<String>  (TOFU)
//!
//! CR052: this list MUST be exhaustive. The local `Policy` struct below now
//! mirrors EVERY field the enclave understands AND carries
//! `#[serde(deny_unknown_fields)]`, so a policy.json field this tool does not
//! recognize (a typo, or a NEW enclave field this tool predates) becomes a
//! hard parse error at wrap time instead of being silently dropped — which
//! used to ship an UN-capped blob even when the operator wrote the cap
//! correctly. A round-trip assertion in `load_policy_and_secret` is the
//! belt-and-suspenders companion.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

mod registry;
mod shamir;

/// Local Policy schema. MUST stay in sync with the enclave's
/// `proto::Policy` — field-for-field. Drift used to be tolerated and would
/// surface as `policy_denied` / `bad_request` on the first signing attempt;
/// but for the **policy-enforcement** fields (`order_caps`, `x402`,
/// `allowed_asterdex_endpoints`) drift was far worse: a missing field here
/// caused serde to SILENTLY DROP the operator's cap, shipping an un-capped
/// blob with no warning (CR052). To make any future drift fail LOUD and
/// EARLY, this struct now (a) mirrors all 13 enclave fields and (b) sets
/// `#[serde(deny_unknown_fields)]` — an unrecognized key is a wrap-time error,
/// never a silent drop.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
struct Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_path_prefixes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    denied_path_prefixes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_requests_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    // ── Policy-enforcement fields (these are the ones CR052 was silently
    //    dropping). Order mirrors enclave `proto::Policy` for clarity; field
    //    order does NOT affect the blob (serde matches by name) nor the
    //    enclave-computed policy_hash (the enclave re-serializes in its own
    //    struct order). ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_asterdex_endpoints: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x402: Option<X402Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    order_caps: Option<Vec<OrderAssetCap>>,
    // CR053: HL vault allow-list (ZN-202) + per-asset HL size caps. Order
    // mirrors enclave proto::Policy (after order_caps, before TOFU fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_vaults: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hl_order_caps: Option<Vec<HlOrderCap>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_signature: Option<String>,
    // PR-D1/D2: baked policy-authority signature (mirrors enclave
    // `proto::Policy::policy_authority_sig`, added last). The template-signing
    // command below fills this; it is stripped from the canonical signable
    // bytes exactly like the two TOFU fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_authority_sig: Option<String>,
    // AF-2: the agent's Ed25519 intent pubkey (mirrors enclave
    // `proto::Policy::intent_pubkey`). MUST be declared LAST, exactly as in the
    // enclave, so the canonical signable bytes (fields in declaration order) are
    // byte-identical on both sides. Unlike the three signature fields above it is
    // NOT stripped from the canonical — it is COVERED by `policy_authority_sig`,
    // so a gateway cannot swap the agent key without invalidating the authority
    // signature. `skip_serializing_if` keeps pre-AF-2 policies' canonical bytes
    // unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent_pubkey: Option<String>,
}

/// Per-asset order-size cap. Mirrors enclave `proto::OrderAssetCap`
/// (incl. its `deny_unknown_fields`). `max_qty` is a decimal STRING compared
/// numerically by the enclave — kept opaque here. `max_notional` (B2) is the
/// optional per-order `qty × price` bound: when set, the enclave denies
/// price-less (market-shaped) orders for that symbol fail-closed —
/// notional-capped keys trade limit-type orders only.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
struct OrderAssetCap {
    symbol: String,
    max_qty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_notional: Option<String>,
}

/// CR053: per-asset Hyperliquid order-size cap, keyed by integer asset index
/// (`orders[].a`). Mirrors enclave `proto::HlOrderCap` (incl. deny_unknown_fields).
/// `max_notional` (B2): optional `s × p` bound — when set, the enclave accepts
/// plain limit orders only (trigger orders denied fail-closed).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
struct HlOrderCap {
    asset: u64,
    max_size: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_notional: Option<String>,
}

/// x402 / EIP-3009 spend cap. Mirrors enclave `proto::X402Policy`
/// (incl. its `deny_unknown_fields`). CR050: for this withdrawal primitive the
/// enclave requires BOTH `max_value` AND a non-empty `allowed_recipients` at
/// sign time, else `policy_required`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
struct X402Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowed_recipients: Option<Vec<String>>,
}

/// Wire shape that gets fed into `aws kms encrypt`. Field order is
/// preserved across runs (serde_json with `preserve_order`) so the
/// ciphertext is byte-stable when inputs are byte-stable.
#[derive(Debug, Serialize)]
struct PolicyWrappedSecret {
    policy: Policy,
    secret: serde_json::Value,
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Wrap a UPL policy + exchange secret into a blob for the signer enclave."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the UPL policy JSON file.
    #[arg(long, global = true)]
    policy: Option<PathBuf>,
    /// Path to the exchange-specific secret JSON file.
    #[arg(long, global = true)]
    secret: Option<PathBuf>,
    /// Path where the output blob will be written.
    #[arg(long, global = true)]
    output: Option<PathBuf>,
    /// Skip the policy sanity check.
    #[arg(long, default_value_t = false, global = true)]
    skip_sanity_check: bool,
    /// Target network for this blob. Defaults to `mainnet` (fail-closed): a
    /// mainnet blob for an order-capable key MUST carry order caps, so
    /// forgetting this flag can never silently produce an uncapped mainnet key.
    /// Pass `--profile testnet` for demo/dogfood keys (e.g. keyless-Hummingbot)
    /// where uncapped is acceptable. This gate is ALWAYS on — `--skip-sanity-check`
    /// does NOT bypass it.
    #[arg(long, value_enum, default_value_t = Profile::Mainnet, global = true)]
    profile: Profile,
}

/// Which network a wrapped blob is destined for. `mainnet` is the strict,
/// fail-closed default: an order-capable mainnet key without caps is refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Profile {
    Mainnet,
    Testnet,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Produce an envelope-encrypted blob (v2). Generates a random DEK,
    /// AES-GCM-256 encrypts the secret, and writes the envelope JSON +
    /// a separate `dek.bin` file. The operator then KMS-encrypts dek.bin
    /// and runs `seal` to produce the final blob.
    Envelope {
        /// Directory to write envelope.json and dek.bin.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Finalize an envelope by inserting the KMS-encrypted DEK.
    Seal {
        /// Path to the envelope.json from the `envelope` step.
        #[arg(long)]
        envelope: PathBuf,
        /// Base64-encoded KMS ciphertext of the DEK (output of `aws kms encrypt`).
        #[arg(long)]
        wrapped_dek_b64: String,
        /// Path to write the final .enc blob.
        #[arg(long)]
        output: PathBuf,
    },
    /// Registry control-plane: generate the trust-root keypair and sign a
    /// tenant-registry refresh for the enclave (the off-box SIGNER half).
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },
    /// Sign a policy TEMPLATE with the baked policy-authority key (PR-D2). Fills
    /// `policy_authority_sig` so the enclave's money-venue floor-gate accepts it
    /// under `SIGNER_REQUIRE_POLICY=1`. The signed policy is safe to hand a
    /// partner for Path B import — they can read but not alter the floor. Seed
    /// from $SIGNER_POLICY_PRIVKEY (hex) or --priv-key-file.
    PolicySign {
        /// Path to the floor policy JSON (withdraw-deny + caps). Parsed as Policy.
        #[arg(long)]
        policy_file: PathBuf,
        /// Tenant `customer_id` this template is bound to.
        #[arg(long)]
        customer_id: String,
        /// Venue this template is bound to (`binance`, `okx`, ...).
        #[arg(long)]
        venue: String,
        /// File holding the 64-hex private seed (alternative to $SIGNER_POLICY_PRIVKEY).
        #[arg(long)]
        priv_key_file: Option<PathBuf>,
        /// §E6 2-of-3 ceremony: reconstruct the policy-authority seed from at
        /// least `threshold` Shamir share files instead of $SIGNER_POLICY_PRIVKEY /
        /// --priv-key-file. Repeat `--shares <file>` per share. The seed is
        /// reconstructed in-memory (pubkey-verified) and zeroized after signing;
        /// the full key is never written to disk. Mutually exclusive with
        /// --priv-key-file.
        #[arg(long)]
        shares: Vec<PathBuf>,
        /// Path to write the signed policy JSON (with `policy_authority_sig`).
        #[arg(long)]
        out: PathBuf,
    },
    /// §E6: Shamir-share the control-plane authority seeds (m-of-n redundancy).
    Authority {
        #[command(subcommand)]
        action: AuthorityAction,
    },
}

#[derive(Debug, Subcommand)]
enum AuthorityAction {
    /// Split an authority seed into N Shamir shares, any `threshold` of which
    /// reconstruct it. Writes one share file per holder. The seed comes from the
    /// key's env var ($SIGNER_POLICY_PRIVKEY / $SIGNER_REGISTRY_PRIVKEY) or
    /// --priv-key-file — never a CLI arg.
    ///
    /// ⚠️ MAINNET CEREMONY ONLY. Do NOT run this on a live authority seed on
    /// testnet/demo. Building + unit-testing the tooling does not require it; the
    /// live re-split is a supervised mainnet step (see the ceremony runbook).
    Split {
        /// Which authority seed: `policy-authority` or `registry-authority`.
        #[arg(long)]
        key_label: String,
        /// File holding the 64-hex private seed (alternative to the key's env var).
        #[arg(long)]
        priv_key_file: Option<PathBuf>,
        /// Reconstruction threshold (default 2).
        #[arg(long, default_value_t = 2)]
        threshold: u8,
        /// Holder labels, one per share (default: primary second escrow).
        #[arg(long)]
        holder: Vec<String>,
        /// Directory to write `<key_label>.<holder>.share.json` files.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Verify a set of shares reconstructs a valid authority key WITHOUT exposing
    /// the seed: reconstructs in-memory, prints ONLY the recovered public key, and
    /// zeroizes. Use this to prove shares are good + agree before a grant ceremony.
    Verify {
        /// Share files (repeat `--shares <file>`); need at least `threshold` of them.
        #[arg(long)]
        shares: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum RegistryAction {
    /// Generate a fresh Ed25519 control-plane keypair. Prints the PUBLIC key
    /// hex (bake into the enclave Dockerfile as SIGNER_REGISTRY_PUBKEY — this
    /// is PCR0-determining) and, only with --show-private, the private seed hex
    /// (store OFF-BOX in the vault/HSM; NEVER commit it).
    Keygen {
        /// Also print the private seed hex to stdout. Default off so a casual
        /// `keygen` can't leak the trust-root key into a terminal scrollback.
        #[arg(long, default_value_t = false)]
        show_private: bool,
    },
    /// Sign a registry refresh. Reads entries JSON (`[{token,customer_id,
    /// allowed_venues}]`), a fresh nonce from `registry_challenge`, and a
    /// monotonic version; emits the EXACT bytes to KMS-encrypt plus the
    /// refresh params (nonce, version, signature). The private seed comes from
    /// $SIGNER_REGISTRY_PRIVKEY (hex) or --priv-key-file — never a CLI arg.
    Sign {
        /// Path to entries JSON: `[{"token","customer_id","allowed_venues"}]`.
        #[arg(long)]
        entries: PathBuf,
        /// Fresh 32-byte nonce hex from the enclave's `registry_challenge`.
        #[arg(long)]
        nonce: String,
        /// Monotonic registry version (must exceed the enclave's last-known).
        #[arg(long)]
        version: u64,
        /// File holding the 64-hex private seed (alternative to $SIGNER_REGISTRY_PRIVKEY).
        #[arg(long)]
        priv_key_file: Option<PathBuf>,
        /// §E6 2-of-3 ceremony: reconstruct the registry-authority seed from at
        /// least `threshold` Shamir share files instead of $SIGNER_REGISTRY_PRIVKEY /
        /// --priv-key-file. Repeat `--shares <file>` per share. Reconstructed
        /// in-memory (pubkey-verified) and zeroized. Mutually exclusive with
        /// --priv-key-file.
        #[arg(long)]
        shares: Vec<PathBuf>,
        /// Directory to write `registry_entries.json` (the bytes to KMS-encrypt)
        /// and `refresh.json` (the params the parent forwards to the enclave).
        #[arg(long)]
        out_dir: PathBuf,
    },
}

// ─────────────────────────────────────────────────────────────────────────
// PR-D2: baked policy-authority TEMPLATE signing (the off-box SIGNER half).
//
// MUST byte-match the enclave verifier `enclave/src/handler.rs`:
//   - `policy_canonical_signable`  ↔ enclave `canonical_policy_signable`
//   - `policy_authority_message`   ↔ enclave `policy_authority_message`
// A drift on EITHER side silently breaks the money-venue floor gate, so
// `policy_authority_golden_matches_enclave` (here) and the enclave's
// `policy_authority_message_golden` assert the SAME hardcoded vector.
// ─────────────────────────────────────────────────────────────────────────

/// Domain tag — MUST equal enclave `handler::POLICY_AUTHORITY_DOMAIN`.
const POLICY_AUTHORITY_DOMAIN: &[u8] = b"signer-policy-authority-v1\0";

/// Canonical policy bytes over which the authority signs: the Policy serialized
/// with ALL THREE signature fields cleared (a signature can't cover itself).
/// Field order = struct declaration order (mirrors enclave `proto::Policy`), so
/// the two crates serialize byte-identically.
fn policy_canonical_signable(policy: &Policy) -> Result<Vec<u8>> {
    let mut canonical = policy.clone();
    canonical.signer_pubkey = None;
    canonical.policy_signature = None;
    canonical.policy_authority_sig = None;
    Ok(serde_json::to_vec(&canonical)?)
}

/// The message the policy-authority signs: domain tag, then u32-BE
/// length-prefixed `customer_id` and `venue` (so `{cust:"a",venue:"bc"}` can't
/// collide with `{cust:"ab",venue:"c"}`), then the canonical policy.
fn policy_authority_message(customer_id: &str, venue: &str, canonical_policy: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        POLICY_AUTHORITY_DOMAIN.len()
            + 12
            + customer_id.len()
            + venue.len()
            + canonical_policy.len(),
    );
    msg.extend_from_slice(POLICY_AUTHORITY_DOMAIN);
    msg.extend_from_slice(&(customer_id.len() as u32).to_be_bytes());
    msg.extend_from_slice(customer_id.as_bytes());
    msg.extend_from_slice(&(venue.len() as u32).to_be_bytes());
    msg.extend_from_slice(venue.as_bytes());
    msg.extend_from_slice(&(canonical_policy.len() as u32).to_be_bytes());
    msg.extend_from_slice(canonical_policy);
    msg
}

/// Sign a policy template with the policy-authority seed → hex Ed25519 sig
/// (deterministic, RFC 8032). The signed policy (with `policy_authority_sig`
/// filled) is what a partner KMS-encrypts alongside THEIR secret in the Path B
/// import — they can read the policy but can't alter the withdraw-deny / caps
/// floor without invalidating this signature.
fn sign_policy_authority(
    policy: &Policy,
    customer_id: &str,
    venue: &str,
    seed: &[u8; 32],
) -> Result<String> {
    use ed25519_dalek::{Signer, SigningKey};
    let canonical = policy_canonical_signable(policy)?;
    let msg = policy_authority_message(customer_id, venue, &canonical);
    let sig = SigningKey::from_bytes(seed).sign(&msg);
    Ok(hex::encode(sig.to_bytes()))
}

/// `policy-sign`: fill `policy_authority_sig` on a floor policy so the enclave's
/// money-venue gate accepts it under `SIGNER_REQUIRE_POLICY=1`. Seed from
/// $SIGNER_POLICY_PRIVKEY (hex) or --priv-key-file — never a CLI arg.
fn cmd_policy_sign(
    policy_path: &std::path::Path,
    customer_id: &str,
    venue: &str,
    priv_key_file: Option<&std::path::Path>,
    shares: &[PathBuf],
    out: &std::path::Path,
    profile: Profile,
) -> Result<()> {
    use zeroize::Zeroizing;

    // §E6 seed source: --shares (2-of-3 Shamir, reconstruct in-memory) takes
    // precedence; otherwise the historical env/--priv-key-file path is UNCHANGED.
    let seed: Zeroizing<[u8; 32]> = if !shares.is_empty() {
        anyhow::ensure!(
            priv_key_file.is_none(),
            "pass EITHER --shares or --priv-key-file, not both"
        );
        shamir::reconstruct_seed(shares, Some("policy-authority"))?
    } else {
        let priv_hex: Zeroizing<String> = if let Some(p) = priv_key_file {
            // Gemini #217 HIGH: wrap the RAW file read in Zeroizing BEFORE `.trim()`
            // — otherwise the original `String` (holding the un-trimmed private seed)
            // is dropped without zeroizing and its plaintext lingers in freed heap.
            let raw = Zeroizing::new(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading private-key file {}", p.display()))?,
            );
            Zeroizing::new(raw.trim().to_owned())
        } else {
            Zeroizing::new(
                std::env::var("SIGNER_POLICY_PRIVKEY")
                    .context("set $SIGNER_POLICY_PRIVKEY (64-hex seed) or pass --priv-key-file")?,
            )
        };
        // Reuse the shared, non-allocating (decode_to_slice) seed parser — same
        // validation + error messages as before, one hardened decode path.
        shamir::parse_seed_hex(&priv_hex)?
    };

    let policy_bytes = std::fs::read(policy_path)
        .with_context(|| format!("reading policy file {}", policy_path.display()))?;
    let mut policy: Policy = serde_json::from_slice(&policy_bytes)
        .with_context(|| format!("parsing policy as Policy schema: {}", policy_path.display()))?;
    if policy.policy_authority_sig.is_some() {
        anyhow::bail!("policy already carries policy_authority_sig — refusing to re-sign");
    }

    // Gemini #217 round-2 HIGH: run the SAME always-on validations as the wrap
    // path (`load_policy_and_secret`) before signing. Round-trip (CR052) matters
    // MORE here than at wrap: the authority signs the RE-SERIALIZED canonical
    // policy, so a lossy parse would earn a VALID authority signature over a
    // policy the operator never wrote. sanity_check_policy mirrors enclave
    // enforcement (label len / C19 / C27 / x402 completeness / EVM addresses /
    // C29 policy-alone) so we never ship a signed-but-dead template. There is
    // no venue secret at template-sign time — pass an empty JSON object (the
    // shape the checker's `secret.is_object()` contract expects) so the
    // secret-dependent C29 warning is a structural no-op.
    assert_policy_round_trip(&policy_bytes, &policy)
        .with_context(|| format!("policy round-trip check: {}", policy_path.display()))?;
    sanity_check_policy(&policy, &serde_json::json!({}), Some(policy_path))?;
    // PROVISIONING GUARD (Path B): an authority-signed template is destined for
    // the strict money path — a partner KMS-encrypts their own secret against it,
    // so our wrap-time guard never runs on their side. Refuse to authority-sign
    // an uncapped order-capable mainnet template here too. Gemini review #266.
    enforce_provisioning_profile_invariant(&policy, profile)
        .with_context(|| format!("provisioning guard: {}", policy_path.display()))?;

    let sig = sign_policy_authority(&policy, customer_id, venue, &seed)?;
    policy.policy_authority_sig = Some(sig);

    std::fs::write(out, serde_json::to_vec_pretty(&policy)?)
        .with_context(|| format!("writing signed policy {}", out.display()))?;
    eprintln!(
        "# signed policy → {} (customer_id={customer_id}, venue={venue})",
        out.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Envelope { ref out_dir }) => cmd_envelope(&cli, out_dir),
        Some(Commands::Seal {
            ref envelope,
            ref wrapped_dek_b64,
            ref output,
        }) => cmd_seal(envelope, wrapped_dek_b64, output),
        Some(Commands::Registry { ref action }) => cmd_registry(action),
        Some(Commands::PolicySign {
            ref policy_file,
            ref customer_id,
            ref venue,
            ref priv_key_file,
            ref shares,
            ref out,
        }) => cmd_policy_sign(
            policy_file,
            customer_id,
            venue,
            priv_key_file.as_deref(),
            shares,
            out,
            cli.profile,
        ),
        Some(Commands::Authority { ref action }) => cmd_authority(action),
        None => cmd_wrap_legacy(&cli),
    }
}

/// §E6 dispatch: Shamir split / verify of the control-plane authority seeds.
fn cmd_authority(action: &AuthorityAction) -> Result<()> {
    match action {
        AuthorityAction::Split {
            key_label,
            priv_key_file,
            threshold,
            holder,
            out_dir,
        } => cmd_authority_split(
            key_label,
            priv_key_file.as_deref(),
            *threshold,
            holder,
            out_dir,
        ),
        AuthorityAction::Verify { shares } => cmd_authority_verify(shares),
    }
}

/// Map an authority key_label → the env var carrying its 64-hex seed.
fn authority_env_var(key_label: &str) -> Result<&'static str> {
    match key_label {
        "policy-authority" => Ok("SIGNER_POLICY_PRIVKEY"),
        "registry-authority" => Ok("SIGNER_REGISTRY_PRIVKEY"),
        other => {
            bail!("unknown --key-label {other:?} (expected policy-authority or registry-authority)")
        }
    }
}

/// `authority split`: split an authority seed into Shamir shares.
///
/// ⚠️ MAINNET CEREMONY ONLY — do NOT run on a live seed on testnet/demo. The seed
/// is read from the key's env var or --priv-key-file, split into `holder.len()`
/// shares (threshold-of-n), and one share file per holder is written. The seed is
/// reconstructed once in-memory for the split self-check, then zeroized.
fn cmd_authority_split(
    key_label: &str,
    priv_key_file: Option<&std::path::Path>,
    threshold: u8,
    holders: &[String],
    out_dir: &std::path::Path,
) -> Result<()> {
    use zeroize::Zeroizing;

    // key_label + holder labels flow into share FILENAMES — validate them so an
    // unexpected label (esp. when --priv-key-file bypasses the env-var lookup)
    // can't traverse out of out_dir or produce a surprising filename.
    shamir::validate_key_label(key_label)?;
    let holders: Vec<String> = if holders.is_empty() {
        shamir::default_holders()
    } else {
        holders.to_vec()
    };
    for h in &holders {
        shamir::validate_holder(h)?;
    }

    // Seed source: --priv-key-file (raw read wrapped in Zeroizing BEFORE trim,
    // matching cmd_policy_sign / cmd_registry_sign) else the key's env var.
    let priv_hex: Zeroizing<String> = if let Some(p) = priv_key_file {
        let raw = Zeroizing::new(
            std::fs::read_to_string(p)
                .with_context(|| format!("reading private-key file {}", p.display()))?,
        );
        Zeroizing::new(raw.trim().to_owned())
    } else {
        let env = authority_env_var(key_label)?;
        Zeroizing::new(
            std::env::var(env)
                .with_context(|| format!("set ${env} (64-hex seed) or pass --priv-key-file"))?,
        )
    };
    let seed = shamir::parse_seed_hex(&priv_hex)?;

    let shares = shamir::split_seed(&seed, key_label, threshold, &holders)?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating out-dir {}", out_dir.display()))?;
    for sh in &shares {
        let path = out_dir.join(shamir::share_filename(key_label, &sh.holder));
        // The serialized JSON carries the share — zeroize the in-memory buffer
        // after it hits disk. Create the file 0600 (owner-only) and REFUSE to
        // overwrite an existing path (create_new): shares are the most sensitive
        // material this tool touches, and a clobber could destroy a distributed
        // share or silently mix generations.
        let json = Zeroizing::new(serde_json::to_vec_pretty(sh)?);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).with_context(|| {
            format!(
                "creating share {} (refusing to overwrite an existing file)",
                path.display()
            )
        })?;
        std::io::Write::write_all(&mut f, &json)
            .with_context(|| format!("writing share {}", path.display()))?;
        eprintln!(
            "# wrote share holder={:?} x={} → {} (mode 0600)",
            sh.holder,
            sh.x,
            path.display()
        );
    }
    eprintln!(
        "# split {key_label}: {}-of-{} shares, pubkey={}",
        shares[0].threshold, shares[0].shares_total, shares[0].pubkey
    );
    eprintln!(
        "# Distribute the shares to their holders + the offline escrow, then \
         DESTROY the original whole seed. Verify with `authority verify`."
    );
    Ok(())
}

/// `authority verify`: reconstruct in-memory and print ONLY the recovered pubkey,
/// proving a set of shares is valid + agrees WITHOUT exposing the seed.
fn cmd_authority_verify(shares: &[PathBuf]) -> Result<()> {
    let seed = shamir::reconstruct_seed(shares, None)?;
    let pubkey = {
        use ed25519_dalek::SigningKey;
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    };
    // seed drops (zeroized) here; only the public key is surfaced.
    println!("# {} shares reconstruct authority pubkey:", shares.len());
    println!("{pubkey}");
    Ok(())
}

/// Dispatch the `registry` subcommand group (control-plane keypair + signer).
fn cmd_registry(action: &RegistryAction) -> Result<()> {
    match action {
        RegistryAction::Keygen { show_private } => cmd_registry_keygen(*show_private),
        RegistryAction::Sign {
            entries,
            nonce,
            version,
            priv_key_file,
            shares,
            out_dir,
        } => cmd_registry_sign(
            entries,
            nonce,
            *version,
            priv_key_file.as_deref(),
            shares,
            out_dir,
        ),
    }
}

fn cmd_registry_keygen(show_private: bool) -> Result<()> {
    use std::io::IsTerminal;

    let (pubkey_hex, priv_hex) = registry::keygen();
    println!("# Control-plane registry keypair (Ed25519).");
    println!("# PUBLIC — bake into enclave/Dockerfile (PCR0-determining):");
    println!("SIGNER_REGISTRY_PUBKEY={pubkey_hex}");
    if show_private {
        // NIT 3: the private seed is the registry trust root. Refuse to print it
        // when stderr is NOT an interactive terminal — a `2>seed.log` / `2>&1 |`
        // redirect would silently capture the trust-root key into a file or log.
        // Force the operator to read it off an interactive terminal and paste it
        // straight into the vault.
        if !std::io::stderr().is_terminal() {
            bail!(
                "refusing to print the private seed: stderr is redirected (not a TTY), so the \
                 trust-root key would land in a file/log. Re-run with stderr attached to an \
                 interactive terminal and copy the seed directly into the vault."
            );
        }
        eprintln!(
            "# PRIVATE seed — store OFF-BOX in the vault/HSM, NEVER commit, NEVER pipe/redirect. \
             Used via $SIGNER_REGISTRY_PRIVKEY at sign time:"
        );
        eprintln!("SIGNER_REGISTRY_PRIVKEY={}", priv_hex.as_str());
    } else {
        eprintln!(
            "# (re-run with --show-private on an interactive terminal to reveal the private seed)"
        );
    }
    Ok(())
}

fn cmd_registry_sign(
    entries_path: &std::path::Path,
    nonce_hex: &str,
    version: u64,
    priv_key_file: Option<&std::path::Path>,
    shares: &[PathBuf],
    out_dir: &std::path::Path,
) -> Result<()> {
    use zeroize::Zeroizing;

    // §E6 seed source: --shares (2-of-3 Shamir, reconstruct in-memory) takes
    // precedence; otherwise the historical env/--priv-key-file path is UNCHANGED.
    // Never a CLI arg — that would leak the trust-root key via `ps`/shell history.
    let seed: Zeroizing<[u8; 32]> = if !shares.is_empty() {
        anyhow::ensure!(
            priv_key_file.is_none(),
            "pass EITHER --shares or --priv-key-file, not both"
        );
        shamir::reconstruct_seed(shares, Some("registry-authority"))?
    } else {
        let priv_hex: Zeroizing<String> =
            if let Some(p) = priv_key_file {
                // Gemini #217 HIGH: wrap the RAW file read in Zeroizing BEFORE `.trim()`
                // — otherwise the original `String` (holding the un-trimmed registry
                // trust-root seed) is dropped without zeroizing and its plaintext lingers
                // in freed heap. This key is the control-plane trust root, so it matters
                // MORE than the policy-authority seed fixed identically in cmd_policy_sign.
                let raw = Zeroizing::new(
                    std::fs::read_to_string(p)
                        .with_context(|| format!("reading private-key file {}", p.display()))?,
                );
                Zeroizing::new(raw.trim().to_owned())
            } else {
                Zeroizing::new(std::env::var("SIGNER_REGISTRY_PRIVKEY").context(
                    "set $SIGNER_REGISTRY_PRIVKEY (64-hex seed) or pass --priv-key-file",
                )?)
            };
        // Reuse the shared, non-allocating (decode_to_slice) seed parser — same
        // validation + error messages, no transient unzeroized decode buffer.
        shamir::parse_seed_hex(&priv_hex)?
    };

    // The entries file carries plaintext bearer tokens — Zeroizing the raw bytes
    // so they don't linger in freed heap (review F6). (The parsed
    // Vec<RefreshEntry> String tokens are accepted-risk on the operator machine:
    // the same plaintext is already on disk and written back out to KMS-encrypt.)
    let entries_bytes = Zeroizing::new(
        std::fs::read(entries_path)
            .with_context(|| format!("reading entries file {}", entries_path.display()))?,
    );
    let entries: Vec<registry::RefreshEntry> = serde_json::from_slice(&entries_bytes)
        .context("parsing entries as [{token,customer_id,allowed_venues}] (deny_unknown_fields)")?;

    let signed = registry::sign_refresh(&entries, nonce_hex, version, &seed)?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating out_dir {}", out_dir.display()))?;
    let entries_out = out_dir.join("registry_entries.json");
    let refresh_out = out_dir.join("refresh.json");
    // The EXACT bytes that were hashed+signed — KMS-encrypt THESE verbatim.
    std::fs::write(&entries_out, &signed.entries_json)
        .with_context(|| format!("writing {}", entries_out.display()))?;
    let refresh = serde_json::json!({
        "nonce_hex": signed.nonce_hex,
        "version": signed.version,
        "signature_hex": signed.signature_hex,
        "content_hash_hex": signed.content_hash_hex,
    });
    std::fs::write(&refresh_out, serde_json::to_vec_pretty(&refresh)?)
        .with_context(|| format!("writing {}", refresh_out.display()))?;

    eprintln!(
        "registry refresh signed: version={version} entries={}",
        entries.len()
    );
    eprintln!("  signed bytes  -> {}", entries_out.display());
    eprintln!("  refresh params-> {}", refresh_out.display());
    eprintln!("  content_hash  =  {}", signed.content_hash_hex);
    eprintln!(
        "  (integrity: `sha256sum {}` MUST equal content_hash above before KMS-encrypt —",
        entries_out.display()
    );
    eprintln!("   any edit to the file after signing invalidates the signature)");
    eprintln!();
    eprintln!("# Next: KMS-encrypt the SIGNED bytes VERBATIM (never re-serialize) under the");
    eprintln!("# registry context, using the ATTESTATION-GATED registry key — NOT the legacy");
    eprintln!("# alias/signer-poc (whose Decrypt is not PCR0-gated: a non-attested IAM principal");
    eprintln!("# could read the plaintext bearer tokens off-box). Then hand the ciphertext +");
    eprintln!("# refresh.json to the parent CLI:");
    eprintln!(
        "aws kms encrypt --key-id {} \\\n  \
         --plaintext fileb://{} \\\n  \
         --encryption-context {} \\\n  \
         --output text --query CiphertextBlob > registry.enc.b64",
        registry::registry_kms_alias(),
        entries_out.display(),
        registry::REGISTRY_KMS_CONTEXT,
    );
    Ok(())
}

/// Recursively drop object entries whose value is JSON `null` so that an
/// explicit `"field": null` in the input compares equal to the field being
/// absent — which is how `skip_serializing_if = "Option::is_none"`
/// re-serializes a `None`. Policy arrays hold only strings / cap-objects
/// (never legitimate nulls), so recursing into arrays is harmless.
fn strip_json_nulls(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, val)| !val.is_null())
                .map(|(k, val)| (k, strip_json_nulls(val)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.into_iter().map(strip_json_nulls).collect()),
        other => other,
    }
}

/// CR052 round-trip guarantee: the wrapped policy must be — semantically —
/// byte-for-byte what the operator wrote. `deny_unknown_fields` on `Policy`
/// already rejects an unknown/typo'd key; this catches the residual case where
/// a KNOWN field round-trips lossily, making the no-silent-drop guarantee
/// total. Compares the raw input (nulls stripped) against the re-serialized
/// parsed struct; any drop/alteration is a hard error at wrap time.
fn assert_policy_round_trip(policy_bytes: &[u8], policy: &Policy) -> Result<()> {
    let raw: serde_json::Value = serde_json::from_slice(policy_bytes)
        .context("re-parsing policy bytes for round-trip check")?;
    let reserialized = serde_json::to_value(policy)
        .context("re-serializing parsed policy for round-trip check")?;
    let raw_normalized = strip_json_nulls(raw);
    if raw_normalized != reserialized {
        bail!(
            "policy round-trip mismatch — a field was dropped or altered when this \
             tool parsed the policy. This is exactly the silent-cap-drop CR052 guards \
             against; refusing to wrap. Check for an unknown/misspelled field or a \
             field this tool is too old to understand.\n  input(normalized): {}\n  wrapped:          {}",
            raw_normalized,
            reserialized
        );
    }
    Ok(())
}

/// CEX actions that can obtain an order-placement signature. The generic HMAC
/// actions (`sign`, `sign_kucoin`, `sign_binance`, `sign_bybit`, `sign_okx`,
/// `sign_binance_request`) sign a caller-supplied request that CAN be an order,
/// and for an UNCAPPED key the enclave does not deny `op=order` (CR051 only
/// constrains CAPPED keys). The structured `_order` routes place orders by
/// definition. So any of these on mainnet requires `order_caps`.
const ORDER_CAPABLE_CEX_ACTIONS: &[&str] = &[
    "sign",
    "sign_kucoin",
    "sign_binance",
    "sign_bybit",
    "sign_okx",
    "sign_binance_request",
    "sign_binance_order",
    "sign_okx_order",
    // Asterdex is a money venue that reuses `order_caps` — the enclave's
    // strict-mode floor (`asterdex_floor_denies`) refuses `sign_asterdex` when
    // `order_caps` is absent. Mirror that requirement at provisioning time.
    "sign_asterdex",
];

/// Hyperliquid actions that place orders — these require `hl_order_caps`.
const ORDER_CAPABLE_HL_ACTIONS: &[&str] = &[
    "sign_hyperliquid_main_order",
    "sign_hyperliquid_testnet_order",
];

/// Actions that CANNOT place an order, and therefore need no `order_caps` /
/// `hl_order_caps` to exist on a mainnet key.
///
/// This list exists to close a fail-open in the guard's shape: the cap checks
/// are allow-lists, so an action absent from BOTH order-capable lists is waved
/// through by default. Categorising every known action explicitly — and pinning
/// it with `every_known_action_is_categorised` — means a newly added venue
/// action cannot silently inherit "order-incapable" (Gemini review #266; the
/// `sign_asterdex` miss earlier in this same PR is exactly that failure mode).
///
/// NOTE on `sign_x402_eip3009`: order-incapable is not the same as harmless —
/// it is the EIP-3009 withdrawal primitive. It carries no ORDER caps because it
/// places no orders; it is gated separately and fail-closed in the enclave,
/// which demands both `max_value` and a non-empty `allowed_recipients` and
/// returns `policy_required` when either is absent (CR050).
const ORDER_INCAPABLE_ACTIONS: &[&str] = &[
    "ping",
    // Cancels move no size — they cannot open or increase a position.
    "sign_binance_cancel",
    "sign_okx_cancel",
    "sign_hyperliquid_main_cancel",
    "sign_hyperliquid_testnet_cancel",
    // Withdrawal primitive — capped by x402 `max_value` + `allowed_recipients`,
    // not by `order_caps` (see NOTE above).
    "sign_x402_eip3009",
    // Attested-data signing — moves no funds.
    "sign_data",
    // Operator pre-flight: decrypt + SHA-256 + zeroize.
    "verify_blob",
];

/// Does this decimal-string cap actually BIND anything in the enclave?
///
/// Mirrors the operand-validity rules of the enclave's
/// `signer::cmp_positive_decimals` (digits and at most one dot, at least one
/// digit — see its `split`, incl. the Gemini #78 `"."` case) and additionally
/// requires the value to be strictly positive.
///
/// Gemini review #266 called a dummy entry a way to "bypass" the guard; it is
/// NOT — the enclave is fail-closed on every such shape: a blank symbol never
/// matches (`order_cap_symbol_denied` → `POLICY_DENIED`), an unparseable
/// `max_qty` fails the compare and is attributed to the policy
/// (`order_cap_max_qty_malformed` → `INTERNAL_ERROR`), and `"0"` denies every
/// positive qty (`SIZE_OVER_CAP`). So a dummy cap yields a key that cannot
/// sign at all, never an uncapped one. We refuse it here anyway because the
/// failure otherwise surfaces in production instead of at provisioning time,
/// where the operator can still fix the typo.
/// The enclave's strictest decimal parser (`signer::decimal_digits`, used by the
/// notional check and by the ROT-1 aggregate caps) refuses an operand longer
/// than this. The per-order size comparator has no such bound, so a longer cap
/// would work for single orders and fail for batches — a policy that half-works
/// is worse than one refused here, where the operator can still fix it.
const MAX_CAP_OPERAND_LEN: usize = 64;

fn cap_binds(decimal: &str) -> bool {
    !decimal.is_empty()
        && decimal.len() <= MAX_CAP_OPERAND_LEN
        && decimal.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && decimal.bytes().filter(|c| *c == b'.').count() <= 1
        // Strictly positive ⇒ at least one non-zero digit (this also satisfies
        // the enclave's "at least one digit" rule).
        && decimal.bytes().any(|c| c.is_ascii_digit() && c != b'0')
}

/// PROVISIONING GUARD — the invariant "a mainnet key without order caps cannot
/// physically exist". ALWAYS-ON: called from every wrap path OUTSIDE the
/// `--skip-sanity-check` gate, so it cannot be bypassed. Fail-closed.
///
/// `--profile testnet` is a no-op (demo/dogfood keys may be uncapped;
/// keyless-Hummingbot is the intended case).
///
/// `--profile mainnet` (the default) requires that a policy able to place an
/// order on a money venue carries the matching non-empty caps: any order-capable
/// CEX action (or an AF-2 `intent_pubkey`) requires `order_caps`; any
/// order-capable Hyperliquid action requires `hl_order_caps`. Additionally a
/// mainnet policy must EXPLICITLY scope `allowed_actions` (non-empty) — a
/// permissive-by-omission policy can't be proven order-incapable, so it is
/// refused rather than silently trusted.
fn enforce_provisioning_profile_invariant(p: &Policy, profile: Profile) -> Result<()> {
    // ROT-1 round-3: this one runs on BOTH profiles, deliberately, and is
    // therefore ABOVE the testnet early-return.
    //
    // Every other rule here is a risk judgement about real funds, which is what
    // `--profile testnet` is allowed to waive. This one is not: the enclave
    // refuses an AF-2 policy on `is_hl_venue`, which matches Hyperliquid TESTNET
    // as well. Waiving it for testnet would not produce a laxer key, it would
    // produce a key that mints cleanly and then fails every signature — the
    // provisioning guard's whole purpose is to make that impossible.
    if p.intent_pubkey.is_some() {
        // ABSENT `allowed_actions` permits everything, Hyperliquid included, so
        // it must trip this guard exactly like an explicit HL entry does
        // (CodeRabbit). Only listing explicit entries would let the most
        // permissive policy of all through the gate that exists to catch it —
        // the same "unscoped is not the same as none" reasoning as the
        // empty/absent rule below. `Some(vec![])` is the opposite case and stays
        // out: an empty list denies every action, so it can reach no HL path.
        let hl_actions: Vec<&str> = p
            .allowed_actions
            .iter()
            .flatten()
            .map(String::as_str)
            .filter(|a| a.starts_with("sign_hyperliquid_"))
            .collect();
        let unscoped = p.allowed_actions.is_none();
        if unscoped || !hl_actions.is_empty() {
            let which = if unscoped {
                "an ABSENT allowed_actions (which permits every action, Hyperliquid \
                 included)"
                    .to_owned()
            } else {
                format!("Hyperliquid actions {hl_actions:?}")
            };
            bail!(
                "PROVISIONING GUARD: policy carries intent_pubkey (AF-2) together with \
                 {which}, but the enclave does not verify agent intent on the Hyperliquid \
                 path — those orders would be signed with NO intent check while the policy \
                 advertises one, and the enclave refuses to load such a policy on mainnet \
                 AND testnet alike. Split the AF-2 key from the Hyperliquid key (one policy \
                 each), or drop intent_pubkey. AF-2 for Hyperliquid needs its own signed \
                 canonical over the index-keyed action and is not implemented."
            );
        }
    }

    if profile == Profile::Testnet {
        return Ok(());
    }
    // Mainnet from here.
    let actions = match p.allowed_actions.as_ref() {
        Some(a) if !a.is_empty() => a,
        _ => bail!(
            "PROVISIONING GUARD (mainnet): policy.allowed_actions is empty/absent. A \
             mainnet policy MUST explicitly scope its actions so it can be proven \
             order-incapable or carry the required caps. Add allowed_actions (and \
             order_caps for any order-capable action), or pass --profile testnet for \
             a demo/dogfood key."
        ),
    };
    // Fail-closed on anything this wrapper cannot categorise. The cap checks
    // below are allow-lists, so an unrecognised action would otherwise be waved
    // through UNCAPPED — the same fail-open that let `sign_asterdex` slip. Same
    // reasoning as the empty-allowed_actions rule above: if we cannot prove it
    // order-incapable, we refuse rather than silently trust it.
    let uncategorised: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|a| {
            !ORDER_CAPABLE_CEX_ACTIONS.contains(a)
                && !ORDER_CAPABLE_HL_ACTIONS.contains(a)
                && !ORDER_INCAPABLE_ACTIONS.contains(a)
        })
        .collect();
    if !uncategorised.is_empty() {
        bail!(
            "PROVISIONING GUARD (mainnet): allowed_actions {uncategorised:?} are not \
             categorised by this wrapper, so they cannot be proven order-incapable. Fix \
             the typo, or upgrade signer-policy-wrap and categorise the action \
             (ORDER_CAPABLE_CEX_ACTIONS / ORDER_CAPABLE_HL_ACTIONS if it can place an \
             order, else ORDER_INCAPABLE_ACTIONS). Or pass --profile testnet for a \
             demo/dogfood key."
        );
    }

    let has_order_caps = p.order_caps.as_ref().is_some_and(|c| !c.is_empty());
    let has_hl_caps = p.hl_order_caps.as_ref().is_some_and(|c| !c.is_empty());

    // Every cap entry that IS present must bind something (see `cap_binds`).
    // A present-but-vacuous cap is not a bypass — the enclave refuses to sign
    // under it — but it ships a key that bricks in production, so it dies here.
    for c in p.order_caps.iter().flatten() {
        if c.symbol.trim().is_empty() {
            bail!(
                "PROVISIONING GUARD (mainnet): an order_caps entry has a blank symbol. It \
                 can never match a venue symbol, so the enclave would deny every order \
                 under it (order_cap_symbol_denied). Set the exact venue symbol, e.g. \
                 BTCUSDT."
            );
        }
        if !cap_binds(&c.max_qty) {
            bail!(
                "PROVISIONING GUARD (mainnet): order_caps[{}].max_qty = {:?} is not a \
                 strictly-positive decimal the enclave can compare (digits, at most one \
                 dot). Such a cap bounds nothing and the enclave denies every order under \
                 it. Set a real per-asset bound, e.g. \"0.01\".",
                c.symbol,
                c.max_qty
            );
        }
        if let Some(n) = c.max_notional.as_deref() {
            if !cap_binds(n) {
                bail!(
                    "PROVISIONING GUARD (mainnet): order_caps[{}].max_notional = {:?} is \
                     not a strictly-positive decimal. Drop the field to leave the notional \
                     unbounded, or set a real bound — a vacuous one only breaks signing.",
                    c.symbol,
                    n
                );
            }
        }
    }
    for c in p.hl_order_caps.iter().flatten() {
        if !cap_binds(&c.max_size) {
            bail!(
                "PROVISIONING GUARD (mainnet): hl_order_caps[asset={}].max_size = {:?} is \
                 not a strictly-positive decimal the enclave can compare. Set a real \
                 per-asset bound, e.g. \"1\".",
                c.asset,
                c.max_size
            );
        }
        if let Some(n) = c.max_notional.as_deref() {
            if !cap_binds(n) {
                bail!(
                    "PROVISIONING GUARD (mainnet): hl_order_caps[asset={}].max_notional = \
                     {:?} is not a strictly-positive decimal. Drop the field to leave the \
                     notional unbounded, or set a real bound.",
                    c.asset,
                    n
                );
            }
        }
    }

    // (The AF-2-on-Hyperliquid refusal runs at the TOP of this function, on both
    // profiles — see the comment there for why it is not a mainnet-only rule:
    // the enclave rejects that shape on HL testnet too, so waiving it for the
    // testnet profile would mint a key that cannot sign.)

    let cex_order_actions: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|a| ORDER_CAPABLE_CEX_ACTIONS.contains(a))
        .collect();
    // An AF-2 intent key is order-capable by construction — treat it like an
    // order action for the caps requirement (defence in depth).
    let needs_order_caps = !cex_order_actions.is_empty() || p.intent_pubkey.is_some();
    if needs_order_caps && !has_order_caps {
        let why = if cex_order_actions.is_empty() {
            "intent_pubkey (AF-2 trading key)".to_owned()
        } else {
            format!("order-capable actions {cex_order_actions:?}")
        };
        bail!(
            "PROVISIONING GUARD (mainnet): {why} can place orders, but policy carries \
             no non-empty order_caps. A mainnet key without caps is exactly the \
             cap-bypass risk this gate exists to prevent. Add order_caps (per-asset \
             max_qty / max_notional), OR pass --profile testnet for a demo/dogfood key."
        );
    }

    let hl_order_actions: Vec<&str> = actions
        .iter()
        .map(String::as_str)
        .filter(|a| ORDER_CAPABLE_HL_ACTIONS.contains(a))
        .collect();
    if !hl_order_actions.is_empty() && !has_hl_caps {
        bail!(
            "PROVISIONING GUARD (mainnet): Hyperliquid order actions {hl_order_actions:?} \
             can place orders, but policy carries no non-empty hl_order_caps. Add \
             hl_order_caps (per-asset-index max_size / max_notional), OR pass \
             --profile testnet for a demo/dogfood key."
        );
    }
    Ok(())
}

fn load_policy_and_secret(cli: &Cli) -> Result<(Vec<u8>, Policy, serde_json::Value)> {
    let policy_path = cli.policy.as_ref().context("--policy is required")?;
    let secret_path = cli.secret.as_ref().context("--secret is required")?;

    let policy_bytes = std::fs::read(policy_path)
        .with_context(|| format!("reading policy file: {}", policy_path.display()))?;
    let policy: Policy = serde_json::from_slice(&policy_bytes)
        .with_context(|| format!("parsing policy as Policy schema: {}", policy_path.display()))?;

    // CR052: always-on (NOT gated by --skip-sanity-check — this is a
    // correctness invariant, not a heuristic warning). Prove nothing was
    // silently dropped before we hand the policy to the wrapper.
    assert_policy_round_trip(&policy_bytes, &policy)
        .with_context(|| format!("policy round-trip check: {}", policy_path.display()))?;

    // PROVISIONING GUARD: always-on (like the round-trip check above), NOT gated
    // by --skip-sanity-check. Refuses an uncapped order-capable mainnet blob.
    enforce_provisioning_profile_invariant(&policy, cli.profile)
        .with_context(|| format!("provisioning guard: {}", policy_path.display()))?;

    let secret_bytes = std::fs::read(secret_path)
        .with_context(|| format!("reading secret file: {}", secret_path.display()))?;
    let secret: serde_json::Value = serde_json::from_slice(&secret_bytes)
        .with_context(|| format!("parsing secret file as JSON: {}", secret_path.display()))?;
    if !secret.is_object() {
        bail!(
            "secret file must be a JSON object (got {}): {}",
            secret_kind(&secret),
            secret_path.display()
        );
    }

    if !cli.skip_sanity_check {
        sanity_check_policy(&policy, &secret, Some(policy_path))?;
    } else {
        // Self-review HIGH: --skip-sanity-check used to silently suppress
        // all three checks (C19, C27, C29) with no audit trail. A support
        // runbook saying "if the CLI rejects your policy, try
        // --skip-sanity-check" would silently produce blobs the checks
        // were designed to prevent. At minimum: print a loud warning to
        // stderr listing exactly what's being skipped, so operators
        // staring at CI logs see the bypass.
        eprintln!(
            "WARNING: --skip-sanity-check bypasses C19 (EIP-712 method/path skip), \
             C27 (max_requests_per_minute fail-loud), and C29 (cross-venue PK reuse) \
             checks for policy {}. The resulting blob may be REJECTED by the enclave \
             at sign time (C27 -> unimplemented_policy_field) or carry silent risk \
             (C19 method/path silently skipped, C29 cross-venue PK reuse).",
            policy_path.display()
        );
    }

    Ok((policy_bytes, policy, secret))
}

fn cmd_wrap_legacy(cli: &Cli) -> Result<()> {
    let output = cli.output.as_ref().context("--output is required")?;
    let (policy_bytes, policy, secret) = load_policy_and_secret(cli)?;

    let wrapped = PolicyWrappedSecret { policy, secret };
    let plaintext = serde_json::to_vec(&wrapped).context("serializing wrapped blob")?;

    std::fs::write(output, &plaintext)
        .with_context(|| format!("writing output: {}", output.display()))?;

    eprintln!(
        "Wrapped {} bytes of policy + secret → {} ({} bytes).",
        policy_bytes.len(),
        output.display(),
        plaintext.len()
    );
    eprintln!(
        "Next step: `aws kms encrypt --key-id <alias> --plaintext fileb://{} \
         --encryption-context venue_id=<VENUE>,customer_id=<CUSTOMER>,purpose=dek,version=2 \
         --output text --query CiphertextBlob`",
        output.display()
    );
    Ok(())
}

fn cmd_envelope(cli: &Cli, out_dir: &std::path::Path) -> Result<()> {
    use aes_gcm::{aead::Aead, aead::KeyInit, aead::OsRng, AeadCore, Aes256Gcm};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use zeroize::Zeroizing;

    let (_, policy, secret) = load_policy_and_secret(cli)?;

    let wrapped = PolicyWrappedSecret { policy, secret };
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&wrapped).context("serializing wrapped blob")?);

    // One fresh DEK + nonce per envelope. DEK MUST NOT be reused across envelopes.
    let dek = Zeroizing::new(Aes256Gcm::generate_key(OsRng).to_vec());
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|_| anyhow::anyhow!("invalid DEK length for AES-256-GCM"))?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;

    #[derive(Serialize)]
    struct PreEnvelope {
        version: u64,
        wrapped_dek: String,
        nonce: String,
        ciphertext: String,
    }

    let env = PreEnvelope {
        version: 2,
        wrapped_dek: "PLACEHOLDER_RUN_SEAL_AFTER_KMS_ENCRYPT".into(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(&ciphertext),
    };

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating output dir: {}", out_dir.display()))?;

    let env_path = out_dir.join("envelope.json");
    let dek_path = out_dir.join("dek.bin");

    std::fs::write(&env_path, serde_json::to_vec_pretty(&env)?)
        .with_context(|| format!("writing {}", env_path.display()))?;

    // Write DEK with restricted permissions (owner-only). The plaintext DEK
    // is the most sensitive artifact in the envelope workflow — limit exposure
    // in case the operator forgets to run `seal` or the process is interrupted.
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&dek_path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(&dek)
                })
                .with_context(|| format!("writing {}", dek_path.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&dek_path, &*dek)
                .with_context(|| format!("writing {}", dek_path.display()))?;
        }
    }

    eprintln!("Envelope created:");
    eprintln!(
        "  {} (AES-GCM encrypted secret, {} bytes ciphertext)",
        env_path.display(),
        ciphertext.len()
    );
    eprintln!("  {} (32-byte DEK, PROTECT THIS FILE)", dek_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. KMS-encrypt the DEK:");
    eprintln!("     aws kms encrypt \\");
    eprintln!("       --key-id alias/signer/prod/<venue>/v1 \\");
    eprintln!("       --plaintext fileb://{} \\", dek_path.display());
    eprintln!("       --encryption-context venue_id=<venue>,customer_id=<uuid> \\");
    eprintln!("       --output text --query CiphertextBlob");
    eprintln!();
    eprintln!("  2. Seal the envelope:");
    eprintln!("     signer-policy-wrap seal \\");
    eprintln!("       --envelope {} \\", env_path.display());
    eprintln!("       --wrapped-dek-b64 <output-from-step-1> \\");
    eprintln!("       --output <venue>.enc");
    eprintln!();
    eprintln!("  3. Delete {}", dek_path.display());

    Ok(())
}

fn cmd_seal(
    envelope_path: &std::path::Path,
    wrapped_dek_b64: &str,
    output: &std::path::Path,
) -> Result<()> {
    let env_bytes = std::fs::read(envelope_path)
        .with_context(|| format!("reading {}", envelope_path.display()))?;

    let mut env: serde_json::Value =
        serde_json::from_slice(&env_bytes).context("parsing envelope.json")?;

    let version = env
        .get("version")
        .and_then(|v| v.as_u64())
        .context("missing version field")?;
    if version != 2 {
        bail!("unsupported envelope version: {}", version);
    }

    let trimmed = wrapped_dek_b64.trim();
    if trimmed.is_empty() {
        bail!("--wrapped-dek-b64 is empty");
    }
    {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .context("--wrapped-dek-b64 is not valid base64")?;
    }

    env["wrapped_dek"] = serde_json::Value::String(trimmed.to_string());

    let sealed = serde_json::to_vec(&env).context("serializing sealed envelope")?;

    {
        use base64::Engine;
        let check: serde_json::Value =
            serde_json::from_slice(&sealed).context("re-parse sealed blob")?;
        let dek_len = check
            .get("wrapped_dek")
            .and_then(|v| v.as_str())
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .map(|v| v.len())
            .unwrap_or(0);
        if dek_len < 128 {
            bail!(
                "wrapped_dek decodes to {} bytes — expected ≥128 for KMS RSA ciphertext",
                dek_len
            );
        }
    }

    std::fs::write(output, &sealed).with_context(|| format!("writing {}", output.display()))?;

    let dek_path = envelope_path.with_file_name("dek.bin");
    if dek_path.exists() {
        std::fs::write(&dek_path, [0u8; 32]).ok();
        if let Err(e) = std::fs::remove_file(&dek_path) {
            eprintln!("warning: could not delete {}: {}", dek_path.display(), e);
        } else {
            eprintln!("Deleted {} (plaintext DEK removed)", dek_path.display());
        }
    }

    eprintln!(
        "Sealed envelope → {} ({} bytes). Upload to S3.",
        output.display(),
        sealed.len()
    );
    Ok(())
}

fn secret_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Known signing actions as of UPL v0. The CLI warns (not errors) on
/// any allowed_action not in this list, so a customer can use a future
/// enclave build that the tool hasn't been updated for. Must stay in
/// sync with the enclave's dispatch table at handler.rs:`handle`.
const KNOWN_SIGN_ACTIONS: &[&str] = &[
    "ping",
    "sign",
    "sign_kucoin",
    "sign_binance",
    "sign_bybit",
    "sign_okx",
    // Structured, cap-enforced order/cancel routes (binance + okx).
    "sign_binance_order",
    "sign_binance_cancel",
    "sign_okx_order",
    "sign_okx_cancel",
    "sign_hyperliquid_main_order",
    "sign_hyperliquid_main_cancel",
    "sign_hyperliquid_testnet_order",
    "sign_hyperliquid_testnet_cancel",
    "sign_asterdex",
    // CR050: x402 / EIP-3009 transferWithAuthorization (withdrawal primitive).
    "sign_x402_eip3009",
    // Op-based payload-aware Binance route (query-string canonical, D1/D2
    // floor-gate track). Distinct from the structured order/cancel routes.
    "sign_binance_request",
    // Attested-data signing (keccak256(domain ‖ canonical-v1) → recoverable
    // secp256k1). Carries no HTTP method/path but is NOT EIP-712 typed data,
    // so it is deliberately absent from EIP712_ACTIONS (C19 names the EIP-712
    // venue class; sign_data moves no funds).
    "sign_data",
    // Path B-lite operator pre-flight: decrypt + SHA-256 + zeroize. Operator
    // policies legitimately allow-list it.
    "verify_blob",
    // Control-plane ops (registry_challenge / registry_refresh /
    // provision_data_key) are deliberately NOT listed: they dispatch before
    // the tenant-identity gate, so their presence in a customer policy's
    // allowed_actions is a mistake worth warning about.
];

/// EIP-712 sign actions — these don't carry HTTP method/path, so the
/// enclave's `allowed_methods` / `allowed_path_prefixes` checks are
/// silently skipped for them. Customers who set those fields expecting
/// universal enforcement need a wrap-time warning (C19).
///
/// INVARIANT: every entry here MUST also appear in `KNOWN_SIGN_ACTIONS`.
/// Enforced by `eip712_actions_subset_of_known_actions` unit test —
/// without this, a new EIP-712 venue added to one list but not the other
/// would silently miss the C19 warning.
const EIP712_ACTIONS: &[&str] = &[
    "sign_hyperliquid_main_order",
    "sign_hyperliquid_main_cancel",
    // Testnet HL signs the same EIP-712 typed data as mainnet (source="b") —
    // method/path checks are skipped identically, so C19 must cover it.
    "sign_hyperliquid_testnet_order",
    "sign_hyperliquid_testnet_cancel",
    "sign_asterdex",
    // x402/EIP-3009 is EIP-712 typed data — no HTTP method/path, so the
    // enclave's method/path checks are skipped here too (C19 applies).
    "sign_x402_eip3009",
];

fn is_eip712_action(a: &str) -> bool {
    EIP712_ACTIONS.contains(&a)
}

/// Returns true if the policy will accept at least one EIP-712 action.
/// `None` (no whitelist) is permissive — implicitly allows everything,
/// including EIP-712 actions.
fn policy_permits_any_eip712(p: &Policy) -> bool {
    match &p.allowed_actions {
        None => true,
        Some(actions) => actions.iter().any(|a| is_eip712_action(a)),
    }
}

/// C29: detect whether the secret blob carries a secp256k1 `private_key`
/// field, the canonical shape for HL/Asterdex EIP-712 secrets. The presence
/// of this field is the wrap-time trigger for the cross-venue reuse warning.
fn secret_has_private_key(secret: &serde_json::Value) -> bool {
    secret.get("private_key").and_then(|v| v.as_str()).is_some()
}

/// Returns a short string identifying which file is being checked,
/// used as a prefix on warnings so operators running the CLI across
/// many blobs in CI can attribute warnings to a specific policy file.
fn policy_tag(path: Option<&std::path::Path>) -> String {
    match path {
        Some(p) => format!("policy {}", p.display()),
        None => "policy".to_string(),
    }
}

/// Local mirror of the enclave's `enforce_policy` static checks. Catches
/// obvious mistakes client-side. NOT a replacement for the enclave's
/// own validation — it's a fast-fail convenience.
///
/// `policy_path` is informational only — used to tag warnings so
/// operators running across many blobs can attribute them.
fn sanity_check_policy(
    p: &Policy,
    secret: &serde_json::Value,
    policy_path: Option<&std::path::Path>,
) -> Result<()> {
    let tag = policy_tag(policy_path);
    // Label length: char count, max 128 (enclave-side limit). We mirror
    // the `chars().count()` semantic so a customer can stage UTF-8
    // labels (cyrillic, kanji, etc) up to 128 grapheme-ish units.
    if let Some(ref label) = p.label {
        let len = label.chars().count();
        if len > 128 {
            bail!(
                "policy.label must be ≤128 chars, got {} chars (UTF-8 byte len = {})",
                len,
                label.len()
            );
        }
    }

    // Use the module-scope KNOWN_SIGN_ACTIONS list so the drift-check
    // unit test can compare it against EIP712_ACTIONS at compile time.
    if let Some(ref actions) = p.allowed_actions {
        for a in actions {
            if !KNOWN_SIGN_ACTIONS.contains(&a.as_str()) {
                eprintln!(
                    "warning: policy.allowed_actions contains unrecognized action '{}' — \
                     will be rejected by the enclave unless this tool is out of date.",
                    a
                );
            }
        }
    }

    // Known HTTP methods. Same warning policy.
    const KNOWN_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE"];
    if let Some(ref methods) = p.allowed_methods {
        for m in methods {
            if !KNOWN_METHODS.contains(&m.as_str()) {
                eprintln!(
                    "warning: policy.allowed_methods contains unrecognized method '{}'.",
                    m
                );
            }
        }
    }

    // Path prefixes should start with `/` — if they don't, the
    // boundary-safe matcher in the enclave still works, but the customer
    // probably meant to write an absolute path.
    //
    // Empty string in allowed_path_prefixes is a HARD ERROR (not a warning):
    // an empty prefix would (or would, absent enclave-side hardening)
    // unconditionally match every path and silently disable the allowlist.
    // The enclave now rejects empty prefixes too, but we fail at wrap time
    // so the operator never ships a broken policy. Gemini round-4 catch.
    if let Some(ref prefixes) = p.allowed_path_prefixes {
        for prefix in prefixes {
            if prefix.is_empty() {
                anyhow::bail!(
                    "policy.allowed_path_prefixes contains an empty string. \
                     An empty prefix would bypass the allowlist (matches any \
                     path). Remove the empty entry or use `[]` for an \
                     allow-nothing list."
                );
            }
            if !prefix.starts_with('/') {
                eprintln!(
                    "warning: policy.allowed_path_prefixes entry '{}' does not start with '/'.",
                    prefix
                );
            }
        }
    }
    if let Some(ref prefixes) = p.denied_path_prefixes {
        for prefix in prefixes {
            if prefix.is_empty() {
                anyhow::bail!(
                    "policy.denied_path_prefixes contains an empty string. \
                     An empty denial prefix would deny every request. Remove \
                     the empty entry or use `[]` to opt out of denials."
                );
            }
            if !prefix.starts_with('/') {
                eprintln!(
                    "warning: policy.denied_path_prefixes entry '{}' does not start with '/'.",
                    prefix
                );
            }
        }
    }
    // Mirror the empty-string guard for allowed_asterdex_endpoints (final-review
    // NIT): an empty entry matches a request with no path (path_only == "") and
    // silently disables the allow-list. Hard error at wrap time.
    if let Some(ref endpoints) = p.allowed_asterdex_endpoints {
        for ep in endpoints {
            if ep.is_empty() {
                anyhow::bail!(
                    "policy.allowed_asterdex_endpoints contains an empty string. \
                     An empty entry matches a request with no path and disables \
                     the allow-list. Remove it or use `[]` to deny all paths."
                );
            }
        }
    }

    // ─── C19 (ZLODEY 2026-05-18): EIP-712 method/path skip warning ─────
    //
    // EIP-712 venues (Hyperliquid, Asterdex) sign typed-data structs, not
    // HTTP requests. They carry no method/path on the wire. The enclave's
    // `enforce_policy` silently SKIPS allowed_methods / allowed_path_prefixes
    // checks for these actions. If a customer sets those fields expecting
    // universal enforcement, they get a false sense of security.
    //
    // We warn at wrap time so the customer either (a) understands the gap
    // and accepts it, or (b) tightens `allowed_actions` to exclude EIP-712
    // venues.
    let has_method_or_path = p.allowed_methods.is_some() || p.allowed_path_prefixes.is_some();
    if has_method_or_path && policy_permits_any_eip712(p) {
        let scope = match &p.allowed_actions {
            None => {
                "allowed_actions is None (implicit allow-all, includes EIP-712 actions)".to_string()
            }
            Some(actions) => {
                let eip712: Vec<&str> = actions
                    .iter()
                    .filter(|a| is_eip712_action(a))
                    .map(|s| s.as_str())
                    .collect();
                format!(
                    "allowed_actions permits EIP-712 venues: {}",
                    eip712.join(", ")
                )
            }
        };
        eprintln!(
            "WARNING (C19) [{}]: allowed_methods / allowed_path_prefixes are \
             silently skipped by the enclave for EIP-712 actions (Hyperliquid, \
             Asterdex). Current policy: {}. If you need to restrict these venues, \
             narrow allowed_actions to exclude them or accept that method/path \
             constraints don't apply.",
            tag, scope
        );
    }

    // ─── C27 (ZLODEY 2026-05-18): fail-loud on max_requests_per_minute ──
    //
    // Schema field is accepted but the enclave does NOT enforce it
    // (stateful rate-limiting deferred). We reject at wrap time so the
    // operator never ships a blob containing a constraint that silently
    // does nothing. Mirrors the enclave's `unimplemented_policy_field`
    // rejection (PR #39).
    if p.max_requests_per_minute.is_some() {
        anyhow::bail!(
            "{}: policy.max_requests_per_minute is set but the enclave does NOT \
             enforce this field (UPL v0; enforcement deferred to v0.1). \
             Wrapping a blob with this field would be rejected by the enclave \
             at sign time. Remove the field from the policy until enforcement \
             ships.",
            tag
        );
    }

    // ─── CR050: x402 mandatory-cap completeness (dead-key guard) ───────────
    //
    // The enclave now REQUIRES a complete x402 clause for `sign_x402_eip3009`
    // (max_value + non-empty allowed_recipients), else it refuses with
    // `policy_required`. A blob that intends x402 but omits these would ship a
    // dead-on-arrival key. We treat the operator as INTENDING x402 when either
    // (a) the action is EXPLICITLY listed, OR (b) an `x402` clause is present at
    // all (Gemini #200: a present-but-incomplete clause signals intent even
    // under implicit allow-all). We do NOT block implicit allow-all `None`
    // policies that carry NO x402 clause — those don't intend x402.
    let x402_action_enabled = p
        .allowed_actions
        .as_ref()
        .map(|a| a.iter().any(|s| s == "sign_x402_eip3009"))
        .unwrap_or(false);
    let x402_intended = x402_action_enabled || p.x402.is_some();
    if x402_intended {
        let incomplete = match p.x402.as_ref() {
            None => true,
            Some(x) => {
                x.chain_id.is_none()
                    || x.token_address.is_none()
                    || x.max_value.is_none()
                    || x.allowed_recipients
                        .as_ref()
                        .map(|r| r.is_empty())
                        .unwrap_or(true)
            }
        };
        if incomplete {
            anyhow::bail!(
                "{}: policy intends x402 (action listed and/or an x402 clause is \
                 present) but the x402 clause is incomplete. The enclave makes the \
                 x402 cap MANDATORY: policy.x402 must set ALL of `chain_id`, \
                 `token_address`, `max_value`, AND a non-empty `allowed_recipients`, \
                 or the enclave refuses to sign (policy_required) — a dead key.",
                tag
            );
        }
    }

    // ─── Wrap-time EVM-address validation (Gemini final-review) ────────────
    //
    // The enclave fail-closes on a malformed token/recipient/vault at sign time
    // (→ policy_denied), but that ships a DEAD key the operator only discovers on
    // first sign. Validate the format here so a typo is caught at wrap. Lenient
    // (optional 0x + 40 hex) so we never reject an address the enclave accepts.
    fn is_evm_address(s: &str) -> bool {
        let h = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit())
    }
    if let Some(ref x) = p.x402 {
        if let Some(ref tok) = x.token_address {
            if !is_evm_address(tok) {
                anyhow::bail!(
                    "{}: policy.x402.token_address is not a valid EVM address: {}",
                    tag,
                    tok
                );
            }
        }
        if let Some(ref recips) = x.allowed_recipients {
            for r in recips {
                if !is_evm_address(r) {
                    anyhow::bail!(
                        "{}: policy.x402.allowed_recipients contains a non-EVM-address: {}",
                        tag,
                        r
                    );
                }
            }
        }
    }
    if let Some(ref vaults) = p.allowed_vaults {
        for v in vaults {
            if !is_evm_address(v) {
                anyhow::bail!(
                    "{}: policy.allowed_vaults contains a non-EVM-address: {}",
                    tag,
                    v
                );
            }
        }
    }

    // ─── C29 (ZLODEY 2026-05-18): cross-venue PK reuse hygiene ─────────
    //
    // EIP-712 secrets carry a `private_key` field (secp256k1 hex). The
    // same private key valid on Hyperliquid is also valid on Asterdex
    // (both chains derive an EVM address from the same curve). If a
    // customer wraps the SAME PK into two separate blobs (one per venue),
    // a compromise of either venue grants signing on both.
    //
    // Strongest case: a SINGLE blob's policy permits BOTH HL and Asterdex —
    // either explicit (allowed_actions = ["sign_hyperliquid_main_order",
    // "sign_asterdex"]) or implicit (allowed_actions = None, all venues).
    // We bail on the POLICY alone — even with an HMAC secret today, the
    // same policy stored and re-used with a PK tomorrow would be exploitable
    // (self-review HIGH-2: don't let unsafe policies through just because
    // today's secret happens not to carry a PK).
    let (permits_hl, permits_asterdex) = match &p.allowed_actions {
        None => (true, true), // implicit allow-all
        Some(actions) => (
            actions.iter().any(|a| a.starts_with("sign_hyperliquid")),
            actions.iter().any(|a| a == "sign_asterdex"),
        ),
    };
    if permits_hl && permits_asterdex {
        let dual_scope = match &p.allowed_actions {
            None => "allowed_actions is None (implicit allow-all permits both venues)",
            Some(_) => "allowed_actions explicitly permits both venues",
        };
        anyhow::bail!(
            "{}: policy permits BOTH Hyperliquid AND Asterdex actions in a single blob \
             ({}). A compromise of either venue grants signing on the other \
             (C29 cross-venue PK reuse risk). Split into two blobs with separate \
             private keys: one for Hyperliquid (sign_hyperliquid_main_*), one for \
             Asterdex (sign_asterdex). If you need an implicit allow-all key, narrow \
             allowed_actions to one venue family.",
            tag,
            dual_scope
        );
    }

    // Weaker case: a single-venue policy with a PK secret. We can't detect
    // cross-blob reuse without persistent state, so emit a wrap-time
    // warning whenever a blob carries `private_key`, reminding the customer
    // to maintain (venue, derived_address) pairs offline.
    if secret_has_private_key(secret) {
        eprintln!(
            "WARNING (C29) [{}]: this blob wraps a secp256k1 `private_key`. \
             If you ever wrap THIS SAME private key into another blob for a \
             different venue, a compromise of either venue grants signing \
             on both. Maintain one private key per venue, and keep an \
             offline (venue, derived_address) registry to audit your blobs.",
            tag
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_policy() {
        let json = "{}";
        let p: Policy = serde_json::from_str(json).expect("parse");
        assert!(p.allowed_actions.is_none());
        assert!(p.label.is_none());
    }

    // ── PROVISIONING GUARD (mainnet: no uncapped order-capable key) ──

    fn actions(a: &[&str]) -> Option<Vec<String>> {
        Some(a.iter().map(|s| (*s).to_owned()).collect())
    }
    fn btc_cap() -> Option<Vec<OrderAssetCap>> {
        Some(vec![OrderAssetCap {
            symbol: "BTCUSDT".to_owned(),
            max_qty: "0.01".to_owned(),
            max_notional: None,
        }])
    }
    fn hl_cap() -> Option<Vec<HlOrderCap>> {
        Some(vec![HlOrderCap {
            asset: 0,
            max_size: "1".to_owned(),
            max_notional: None,
        }])
    }
    fn guard(p: &Policy, prof: Profile) -> Result<()> {
        enforce_provisioning_profile_invariant(p, prof)
    }

    #[test]
    fn testnet_uncapped_order_capable_is_allowed() {
        // keyless-Hummingbot dogfood: uncapped is fine on testnet.
        let p = Policy {
            allowed_actions: actions(&["sign_binance_request"]),
            ..Policy::default()
        };
        assert!(guard(&p, Profile::Testnet).is_ok());
    }

    #[test]
    fn mainnet_uncapped_order_capable_is_refused() {
        // Every order-capable CEX action must be refused uncapped on mainnet.
        for a in ORDER_CAPABLE_CEX_ACTIONS {
            let p = Policy {
                allowed_actions: actions(&[a]),
                ..Policy::default()
            };
            let e = guard(&p, Profile::Mainnet).expect_err(a);
            assert!(format!("{e}").contains("PROVISIONING GUARD"), "{a}");
        }
    }

    #[test]
    fn mainnet_order_capable_with_caps_is_allowed() {
        let p = Policy {
            allowed_actions: actions(&["sign_binance_request"]),
            order_caps: btc_cap(),
            ..Policy::default()
        };
        assert!(guard(&p, Profile::Mainnet).is_ok());
    }

    #[test]
    fn mainnet_empty_order_caps_is_still_refused() {
        // A present-but-empty caps list must NOT satisfy the invariant.
        let p = Policy {
            allowed_actions: actions(&["sign_binance"]),
            order_caps: Some(vec![]),
            ..Policy::default()
        };
        assert!(guard(&p, Profile::Mainnet).is_err());
    }

    #[test]
    fn mainnet_read_only_policy_needs_no_caps() {
        // Explicitly scoped, order-incapable actions → allowed uncapped.
        let p = Policy {
            allowed_actions: actions(&["sign_binance_cancel", "verify_blob", "sign_data"]),
            ..Policy::default()
        };
        assert!(guard(&p, Profile::Mainnet).is_ok());
    }

    #[test]
    fn mainnet_absent_or_empty_actions_is_refused() {
        // Permissive-by-omission can't be proven order-incapable → fail closed.
        assert!(guard(&Policy::default(), Profile::Mainnet).is_err());
        let empty = Policy {
            allowed_actions: Some(vec![]),
            ..Policy::default()
        };
        assert!(guard(&empty, Profile::Mainnet).is_err());
        // …but on testnet an empty/absent action set is not this gate's business.
        assert!(guard(&Policy::default(), Profile::Testnet).is_ok());
    }

    #[test]
    fn mainnet_intent_key_without_caps_is_refused() {
        // AF-2 intent key is order-capable by construction even with no CEX
        // order action listed.
        let p = Policy {
            allowed_actions: actions(&["sign_data"]),
            intent_pubkey: Some("deadbeef".to_owned()),
            ..Policy::default()
        };
        let e = guard(&p, Profile::Mainnet).expect_err("intent");
        assert!(format!("{e}").contains("intent_pubkey"));
        // with caps it is fine
        let ok = Policy {
            order_caps: btc_cap(),
            ..p
        };
        assert!(guard(&ok, Profile::Mainnet).is_ok());
    }

    #[test]
    fn mainnet_intent_key_with_hyperliquid_actions_is_refused() {
        // ROT-1 round-3: AF-2 is not wired on the HL path, so a policy that
        // carries intent_pubkey together with any HL action advertises a check
        // the enclave will not run. Refuse it at mint — including the shape that
        // would otherwise SATISFY every other gate (both cap kinds present).
        for a in [
            "sign_hyperliquid_main_order",
            "sign_hyperliquid_main_cancel",
            "sign_hyperliquid_testnet_order",
            "sign_hyperliquid_testnet_cancel",
        ] {
            let p = Policy {
                allowed_actions: actions(&[a]),
                intent_pubkey: Some("deadbeef".to_owned()),
                hl_order_caps: hl_cap(),
                order_caps: btc_cap(), // the decorative cap that hides the hole
                ..Policy::default()
            };
            let e = guard(&p, Profile::Mainnet).expect_err("HL + intent_pubkey must be refused");
            let msg = format!("{e}");
            assert!(
                msg.contains("intent_pubkey") && msg.contains("Hyperliquid"),
                "{a}: message must name both halves of the conflict, got: {msg}"
            );
            // …and on TESTNET too. The enclave's refusal keys on `is_hl_venue`,
            // which matches hyperliquid_testnet, so a testnet-profile waiver
            // would mint a key that cannot sign a single request.
            assert!(
                guard(&p, Profile::Testnet).is_err(),
                "{a}: the testnet profile must not waive a shape the enclave rejects"
            );
        }
        // A MIXED policy is refused too: AF-2-protected on the CEX half and
        // silently unprotected on the HL half is exactly the half-true
        // guarantee this exists to stop.
        let mixed = Policy {
            allowed_actions: actions(&["sign_binance_order", "sign_hyperliquid_main_order"]),
            intent_pubkey: Some("deadbeef".to_owned()),
            hl_order_caps: hl_cap(),
            order_caps: btc_cap(),
            ..Policy::default()
        };
        assert!(guard(&mixed, Profile::Mainnet).is_err());

        // Falsification handles — the rule must not be a blanket refusal:
        // (a) HL WITHOUT intent_pubkey still mints;
        let hl_only = Policy {
            allowed_actions: actions(&["sign_hyperliquid_main_order"]),
            hl_order_caps: hl_cap(),
            ..Policy::default()
        };
        assert!(guard(&hl_only, Profile::Mainnet).is_ok());
        // (b) intent_pubkey WITHOUT HL actions still mints.
        let cex_only = Policy {
            allowed_actions: actions(&["sign_binance_order"]),
            intent_pubkey: Some("deadbeef".to_owned()),
            order_caps: btc_cap(),
            ..Policy::default()
        };
        assert!(guard(&cex_only, Profile::Mainnet).is_ok());
    }

    #[test]
    fn intent_key_with_unscoped_actions_is_refused_on_both_profiles() {
        // CodeRabbit: an ABSENT allowed_actions permits every action, so it
        // permits Hyperliquid — the most permissive policy of all must not slip
        // through the guard that exists to catch HL+AF-2. This matters most on
        // `--profile testnet`, where the mainnet "scope your actions" rule never
        // runs, so this guard is the ONLY thing between an unscoped AF-2 policy
        // and a key whose HL requests the enclave rejects on every call.
        let unscoped = Policy {
            allowed_actions: None,
            intent_pubkey: Some("deadbeef".to_owned()),
            hl_order_caps: hl_cap(),
            order_caps: btc_cap(),
            ..Policy::default()
        };
        for profile in [Profile::Testnet, Profile::Mainnet] {
            let e = guard(&unscoped, profile).expect_err("unscoped AF-2 must be refused");
            let msg = format!("{e}");
            assert!(
                msg.contains("intent_pubkey") && msg.contains("ABSENT allowed_actions"),
                "{profile:?}: the message must name the unscoped list, got: {msg}"
            );
        }

        // `Some(vec![])` is the OPPOSITE case: an empty list denies every action,
        // so it can reach no Hyperliquid path and this guard must not fire.
        // (Mainnet refuses it later for being unscoped-by-emptiness; testnet is
        // where the distinction is observable.)
        let deny_all = Policy {
            allowed_actions: Some(vec![]),
            intent_pubkey: Some("deadbeef".to_owned()),
            ..Policy::default()
        };
        assert!(
            guard(&deny_all, Profile::Testnet).is_ok(),
            "an empty action list denies everything — the HL guard must not fire on it"
        );

        // And an unscoped policy WITHOUT intent_pubkey is untouched by this rule
        // on testnet — the refusal is about the AF-2 claim, not about scoping.
        let unscoped_no_af2 = Policy {
            allowed_actions: None,
            hl_order_caps: hl_cap(),
            ..Policy::default()
        };
        assert!(guard(&unscoped_no_af2, Profile::Testnet).is_ok());
    }

    #[test]
    fn mainnet_asterdex_requires_order_caps() {
        // Asterdex reuses order_caps (enclave asterdex_floor_denies) — the guard
        // must mirror it, else a mainnet asterdex key could ship uncapped.
        let p = Policy {
            allowed_actions: actions(&["sign_asterdex"]),
            ..Policy::default()
        };
        assert!(guard(&p, Profile::Mainnet).is_err());
        let ok = Policy {
            order_caps: btc_cap(),
            ..p
        };
        assert!(guard(&ok, Profile::Mainnet).is_ok());
    }

    #[test]
    fn every_known_action_is_categorised() {
        // Drift guard (Gemini review #266). The cap checks are allow-lists, so
        // an action in NEITHER order-capable list is waved through. Forcing an
        // explicit category for every known action means adding a venue action
        // without deciding its cap requirement fails HERE, not in production.
        for a in KNOWN_SIGN_ACTIONS {
            let cex = ORDER_CAPABLE_CEX_ACTIONS.contains(a);
            let hl = ORDER_CAPABLE_HL_ACTIONS.contains(a);
            let incapable = ORDER_INCAPABLE_ACTIONS.contains(a);
            assert!(
                cex || hl || incapable,
                "{a} is in KNOWN_SIGN_ACTIONS but categorised nowhere — add it to \
                 ORDER_CAPABLE_CEX_ACTIONS / ORDER_CAPABLE_HL_ACTIONS if it can place an \
                 order, else to ORDER_INCAPABLE_ACTIONS"
            );
            assert!(
                u8::from(cex) + u8::from(hl) + u8::from(incapable) == 1,
                "{a} is categorised more than once (cex={cex} hl={hl} incapable={incapable})"
            );
        }
        // And nothing is categorised that the wrapper does not even know about.
        for a in ORDER_CAPABLE_CEX_ACTIONS
            .iter()
            .chain(ORDER_CAPABLE_HL_ACTIONS)
            .chain(ORDER_INCAPABLE_ACTIONS)
        {
            assert!(
                KNOWN_SIGN_ACTIONS.contains(a),
                "{a} is categorised but missing from KNOWN_SIGN_ACTIONS"
            );
        }
    }

    #[test]
    fn mainnet_uncategorised_action_is_refused() {
        // The fail-open this closes: an action in no category (new venue, or a
        // typo) previously passed the guard uncapped, because both cap checks
        // are allow-lists.
        for a in ["sign_newvenue_order", "sign_binance_ordr", "totally_bogus"] {
            let p = Policy {
                allowed_actions: actions(&[a]),
                ..Policy::default()
            };
            let e = guard(&p, Profile::Mainnet).expect_err(a);
            assert!(format!("{e}").contains("PROVISIONING GUARD"), "{a}: {e}");
            // Testnet stays permissive.
            assert!(guard(&p, Profile::Testnet).is_ok(), "{a}");
        }
        // Caps do NOT buy an uncategorised action a pass — we still cannot say
        // which cap dimension would bound it.
        let with_caps = Policy {
            allowed_actions: actions(&["sign_newvenue_order"]),
            order_caps: btc_cap(),
            ..Policy::default()
        };
        assert!(guard(&with_caps, Profile::Mainnet).is_err());
    }

    #[test]
    fn order_incapable_actions_need_no_caps_on_mainnet() {
        // The other half of the invariant: an explicitly order-incapable action
        // must still be provisionable uncapped on mainnet (a cancel-only or
        // attested-data key is a legitimate production key).
        for a in ORDER_INCAPABLE_ACTIONS {
            let p = Policy {
                allowed_actions: actions(&[a]),
                ..Policy::default()
            };
            assert!(
                guard(&p, Profile::Mainnet).is_ok(),
                "{a} should need no caps"
            );
        }
    }

    #[test]
    fn cap_binds_matches_enclave_operand_rules() {
        // Mirrors enclave signer.rs `cmp_positive_decimals` vectors, plus "> 0".
        for good in ["1", "0.01", "0.5", ".5", "5.", "10", "1.500"] {
            assert!(cap_binds(good), "should bind: {good:?}");
        }
        // "" / "." / non-digit / multi-dot are unparseable for the enclave;
        // "0" / "0.0" parse but bound nothing.
        for bad in [
            "", ".", "0", "0.0", "00.000", "-1", "1e5", "1.2.3", "1 ", "abc",
        ] {
            assert!(!cap_binds(bad), "should not bind: {bad:?}");
        }
        // ROT-1 round-3: length. The enclave's aggregate caps parse the POLICY
        // operand with a 64-byte bound that the per-order comparator does not
        // have, so a longer cap yields a key that works for one order and fails
        // for a batch. Refuse it here, where it is still a typo and not an
        // incident.
        let at_limit = "1".repeat(MAX_CAP_OPERAND_LEN);
        assert!(cap_binds(&at_limit), "exactly the limit must bind");
        let over_limit = "1".repeat(MAX_CAP_OPERAND_LEN + 1);
        assert!(
            !cap_binds(&over_limit),
            "one byte over the limit must not bind"
        );
    }

    #[test]
    fn mainnet_vacuous_order_cap_entry_is_refused() {
        // Gemini review #266. NOT a cap bypass: the enclave is fail-closed on
        // each shape below (blank symbol never matches → POLICY_DENIED,
        // malformed max_qty → INTERNAL_ERROR, "0" → SIZE_OVER_CAP). It is an
        // operator footgun — the key would brick at sign time — so the guard
        // refuses it at provisioning, where the message is actionable.
        for (sym, qty) in [
            ("", "0.01"),
            ("   ", "0.01"),
            ("BTCUSDT", ""),
            ("BTCUSDT", "0"),
            ("BTCUSDT", "."),
            ("BTCUSDT", "1e5"),
        ] {
            let p = Policy {
                allowed_actions: actions(&["sign_binance_order"]),
                order_caps: Some(vec![OrderAssetCap {
                    symbol: sym.to_owned(),
                    max_qty: qty.to_owned(),
                    max_notional: None,
                }]),
                ..Policy::default()
            };
            let e = guard(&p, Profile::Mainnet).expect_err(&format!("{sym:?}/{qty:?}"));
            assert!(
                format!("{e}").contains("PROVISIONING GUARD"),
                "{sym:?}/{qty:?}: {e}"
            );
            // Testnet stays a no-op — demo keys are allowed to be sloppy.
            assert!(guard(&p, Profile::Testnet).is_ok(), "{sym:?}/{qty:?}");
        }
        // A present-but-empty list is "no caps at all" and already refused.
        let empty = Policy {
            allowed_actions: actions(&["sign_binance_order"]),
            order_caps: Some(vec![]),
            ..Policy::default()
        };
        assert!(guard(&empty, Profile::Mainnet).is_err());
        // Positive control: a real bound still passes.
        let ok = Policy {
            allowed_actions: actions(&["sign_binance_order"]),
            order_caps: btc_cap(),
            ..Policy::default()
        };
        assert!(guard(&ok, Profile::Mainnet).is_ok());
    }

    #[test]
    fn mainnet_vacuous_notional_and_hl_size_are_refused() {
        // An optional bound that is PRESENT must still bind (absent = unbounded
        // by design, and stays allowed).
        let notional = Policy {
            allowed_actions: actions(&["sign_binance_order"]),
            order_caps: Some(vec![OrderAssetCap {
                symbol: "BTCUSDT".to_owned(),
                max_qty: "0.01".to_owned(),
                max_notional: Some("0".to_owned()),
            }]),
            ..Policy::default()
        };
        assert!(guard(&notional, Profile::Mainnet).is_err());

        let hl_bad = Policy {
            allowed_actions: actions(&["sign_hyperliquid_main_order"]),
            hl_order_caps: Some(vec![HlOrderCap {
                asset: 0,
                max_size: "0".to_owned(),
                max_notional: None,
            }]),
            ..Policy::default()
        };
        assert!(guard(&hl_bad, Profile::Mainnet).is_err());

        let hl_ok = Policy {
            allowed_actions: actions(&["sign_hyperliquid_main_order"]),
            hl_order_caps: hl_cap(),
            ..Policy::default()
        };
        assert!(guard(&hl_ok, Profile::Mainnet).is_ok());
    }

    #[test]
    fn mainnet_hl_order_requires_hl_caps() {
        let p = Policy {
            allowed_actions: actions(&["sign_hyperliquid_main_order"]),
            ..Policy::default()
        };
        assert!(guard(&p, Profile::Mainnet).is_err());
        let ok = Policy {
            hl_order_caps: hl_cap(),
            ..p
        };
        assert!(guard(&ok, Profile::Mainnet).is_ok());
        // CEX order_caps do NOT satisfy an HL order requirement.
        let wrong = Policy {
            allowed_actions: actions(&["sign_hyperliquid_main_order"]),
            order_caps: btc_cap(),
            ..Policy::default()
        };
        assert!(guard(&wrong, Profile::Mainnet).is_err());
    }

    // ── PR-D2: policy-authority template signing ──

    /// MUST equal the hex the enclave test `policy_authority_message_golden`
    /// asserts for the SAME fixed input (empty policy, customer_id="c1",
    /// venue="binance"). Cross-crate pin against silent canonical/message drift.
    const GOLDEN_AUTHORITY_MSG: &str = "7369676e65722d706f6c6963792d617574686f726974792d7631000000000263310000000762696e616e6365000000027b7d";

    fn sample_floor_policy() -> Policy {
        Policy {
            allowed_actions: Some(vec!["sign_binance".to_owned()]),
            denied_path_prefixes: Some(vec!["/sapi/v1/capital/withdraw".to_owned()]),
            order_caps: Some(vec![OrderAssetCap {
                symbol: "BTCUSDT".to_owned(),
                max_qty: "0.01".to_owned(),
                max_notional: None,
            }]),
            ..Policy::default()
        }
    }

    #[test]
    fn policy_authority_sign_then_verify_roundtrip() {
        use ed25519_dalek::{SigningKey, Verifier};
        let seed = [7u8; 32];
        let mut p = sample_floor_policy();
        let sig_hex = sign_policy_authority(&p, "cust-1", "binance", &seed).unwrap();
        p.policy_authority_sig = Some(sig_hex.clone());

        let vk = SigningKey::from_bytes(&seed).verifying_key();
        let sig_bytes: [u8; 64] = hex::decode(&sig_hex).unwrap().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // Verify over the message the enclave re-derives (sig field stripped).
        let canonical = policy_canonical_signable(&p).unwrap();
        let msg = policy_authority_message("cust-1", "binance", &canonical);
        assert!(vk.verify(&msg, &sig).is_ok());

        // Tamper the floor (strip withdraw-deny) → sig no longer verifies.
        let mut tampered = p.clone();
        tampered.denied_path_prefixes = None;
        let canonical_t = policy_canonical_signable(&tampered).unwrap();
        let msg_t = policy_authority_message("cust-1", "binance", &canonical_t);
        assert!(vk.verify(&msg_t, &sig).is_err());
    }

    #[test]
    fn policy_canonical_strips_all_sig_fields() {
        let base = sample_floor_policy();
        let mut with_sigs = base.clone();
        with_sigs.signer_pubkey = Some("aa".to_owned());
        with_sigs.policy_signature = Some("bb".to_owned());
        with_sigs.policy_authority_sig = Some("cc".to_owned());
        assert_eq!(
            policy_canonical_signable(&base).unwrap(),
            policy_canonical_signable(&with_sigs).unwrap()
        );
    }

    #[test]
    fn policy_authority_golden_matches_enclave() {
        let canonical = policy_canonical_signable(&Policy::default()).unwrap();
        assert_eq!(canonical, b"{}"); // empty policy serializes compact
        let msg = policy_authority_message("c1", "binance", &canonical);
        assert_eq!(hex::encode(&msg), GOLDEN_AUTHORITY_MSG);
    }

    #[test]
    fn parses_full_policy() {
        let json = r#"{
            "allowed_actions": ["sign_binance", "sign_okx"],
            "allowed_methods": ["POST", "DELETE"],
            "allowed_path_prefixes": ["/api/v1/order"],
            "denied_path_prefixes": ["/sapi/v1/withdraw"],
            "max_requests_per_minute": 60,
            "label": "binance-prod-trading"
        }"#;
        let p: Policy = serde_json::from_str(json).expect("parse");
        assert_eq!(p.allowed_actions.as_ref().unwrap().len(), 2);
        assert_eq!(p.allowed_methods.as_ref().unwrap()[0], "POST");
        assert_eq!(p.max_requests_per_minute, Some(60));
        assert_eq!(p.label.as_deref(), Some("binance-prod-trading"));
    }

    #[test]
    fn round_trip_preserves_fields() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".into()]),
            allowed_methods: Some(vec!["POST".into()]),
            label: Some("test".into()),
            ..Policy::default()
        };
        let s = serde_json::to_string(&p).unwrap();
        let p2: Policy = serde_json::from_str(&s).unwrap();
        assert_eq!(p.allowed_actions, p2.allowed_actions);
        assert_eq!(p.allowed_methods, p2.allowed_methods);
        assert_eq!(p.label, p2.label);
    }

    // ─── CR052: policy-enforcement fields must NOT be silently dropped ───

    #[test]
    fn cr052_order_caps_survive_parse_and_reserialize() {
        // The exact shape CR052 reported as silently dropped (un-capped blob).
        let json = r#"{
            "allowed_actions": ["sign_binance_order"],
            "order_caps": [{"symbol": "BTCUSDT", "max_qty": "0.01"}]
        }"#;
        let p: Policy = serde_json::from_str(json).expect("parse");
        let caps = p
            .order_caps
            .as_ref()
            .expect("order_caps must be preserved, not silently dropped");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].symbol, "BTCUSDT");
        assert_eq!(caps[0].max_qty, "0.01");
        // …and it survives the wrap re-serialization that produces the blob.
        let back = serde_json::to_value(&p).unwrap();
        assert_eq!(back["order_caps"][0]["max_qty"], "0.01");
    }

    #[test]
    fn cr052_x402_and_asterdex_endpoints_survive() {
        let json = r#"{
            "allowed_actions": ["sign_x402_eip3009", "sign_asterdex"],
            "x402": {"chain_id": 8453, "token_address": "0xabc", "max_value": "1000000"},
            "allowed_asterdex_endpoints": ["/fapi/v3/order"]
        }"#;
        let p: Policy = serde_json::from_str(json).expect("parse");
        let x = p.x402.as_ref().expect("x402 preserved");
        assert_eq!(x.chain_id, Some(8453));
        assert_eq!(x.max_value.as_deref(), Some("1000000"));
        assert_eq!(
            p.allowed_asterdex_endpoints.as_ref().unwrap()[0],
            "/fapi/v3/order"
        );
    }

    #[test]
    fn cr052_unknown_field_is_hard_error_not_silent_drop() {
        // A typo'd cap key ("order_cap" singular) used to be silently dropped,
        // shipping an UN-capped blob. deny_unknown_fields makes it a wrap-time
        // error that names the offending field.
        let json = r#"{
            "allowed_actions": ["sign_binance_order"],
            "order_cap": [{"symbol": "BTCUSDT", "max_qty": "0.01"}]
        }"#;
        let err = serde_json::from_str::<Policy>(json).unwrap_err();
        assert!(
            err.to_string().contains("order_cap"),
            "error should name the unknown field, got: {err}"
        );
    }

    #[test]
    fn cr052_nested_unknown_field_in_order_cap_is_hard_error() {
        // deny_unknown_fields propagates into OrderAssetCap. (This test used
        // `max_notional` as its unknown-field example before B2 made that a
        // real field — a typo'd variant keeps the guarantee pinned.)
        let json =
            r#"{"order_caps": [{"symbol": "BTCUSDT", "max_qty": "0.01", "max_notionall": "5"}]}"#;
        assert!(serde_json::from_str::<Policy>(json).is_err());
    }

    #[test]
    fn b2_max_notional_survives_parse_and_reserialize() {
        // B2 mirror-sync: a notional-capped entry must round-trip through the
        // wrap path (the CR052 guarantee extended to the new field), and an
        // entry WITHOUT it must serialize with the field omitted entirely
        // (skip_serializing_if) so pre-B2 canonical bytes stay byte-identical.
        let json = r#"{
            "order_caps": [{"symbol": "BTCUSDT", "max_qty": "0.01", "max_notional": "1000"}],
            "hl_order_caps": [{"asset": 0, "max_size": "1", "max_notional": "1000"}]
        }"#;
        let p: Policy = serde_json::from_str(json).expect("max_notional must parse");
        assert_eq!(
            p.order_caps.as_ref().unwrap()[0].max_notional.as_deref(),
            Some("1000")
        );
        assert_eq!(
            p.hl_order_caps.as_ref().unwrap()[0].max_notional.as_deref(),
            Some("1000")
        );
        let back = serde_json::to_value(&p).unwrap();
        assert_eq!(back["order_caps"][0]["max_notional"], "1000");
        assert_eq!(back["hl_order_caps"][0]["max_notional"], "1000");
        // Absent → omitted, not null (canonical-bytes compatibility).
        let pre_b2: Policy =
            serde_json::from_str(r#"{"order_caps":[{"symbol":"B","max_qty":"1"}]}"#).unwrap();
        let s = serde_json::to_string(&pre_b2).unwrap();
        assert!(
            !s.contains("max_notional"),
            "absent field must be omitted: {s}"
        );
    }

    #[test]
    fn cr052_round_trip_assert_passes_for_capped_policy() {
        let json = br#"{"allowed_actions":["sign_binance_order"],"order_caps":[{"symbol":"BTCUSDT","max_qty":"0.01"}]}"#;
        let p: Policy = serde_json::from_slice(json).unwrap();
        assert_policy_round_trip(json, &p).expect("valid capped policy round-trips");
    }

    #[test]
    fn cr052_round_trip_assert_tolerates_explicit_nulls() {
        // Explicit "field": null == absent under skip_serializing_if; must not
        // be reported as a dropped field.
        let json = br#"{"allowed_actions":["sign_binance"],"label":null,"order_caps":null}"#;
        let p: Policy = serde_json::from_slice(json).unwrap();
        assert_policy_round_trip(json, &p).expect("explicit nulls tolerated");
    }

    #[test]
    fn cr052_strip_json_nulls_is_recursive() {
        let v = serde_json::json!({"a": null, "b": {"c": null, "d": 1}, "e": [1, 2]});
        assert_eq!(
            strip_json_nulls(v),
            serde_json::json!({"b": {"d": 1}, "e": [1, 2]})
        );
    }

    // ─── CR050: policy-cli x402 dead-key guard + action recognition ─────────

    #[test]
    fn cr050_x402_action_without_clause_is_rejected() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".into()]),
            ..Policy::default()
        };
        let err = sanity_check_policy(&p, &eip712_secret(), None).unwrap_err();
        assert!(
            err.to_string().contains("x402"),
            "error should mention x402, got: {err}"
        );
    }

    #[test]
    fn cr050_x402_action_missing_recipients_is_rejected() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".into()]),
            x402: Some(X402Policy {
                max_value: Some("1000000".into()),
                ..X402Policy::default()
            }),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_err());
    }

    #[test]
    fn cr050_x402_action_empty_recipients_is_rejected() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".into()]),
            x402: Some(X402Policy {
                max_value: Some("1000000".into()),
                allowed_recipients: Some(vec![]),
                ..X402Policy::default()
            }),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_err());
    }

    #[test]
    fn cr050_x402_action_with_complete_clause_ok() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".into()]),
            x402: Some(X402Policy {
                chain_id: Some(8453),
                token_address: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
                max_value: Some("1000000".into()),
                allowed_recipients: Some(vec!["0x000000000000000000000000000000000000bEEF".into()]),
            }),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_ok());
    }

    #[test]
    fn cr050_x402_clause_present_incomplete_without_action_rejected() {
        // Gemini #200: a present-but-incomplete x402 clause signals intent even
        // when sign_x402_eip3009 isn't in allowed_actions → reject (dead key).
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance_order".into()]),
            x402: Some(X402Policy {
                max_value: Some("1000000".into()),
                ..X402Policy::default()
            }),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_err());
    }

    #[test]
    fn cr050_x402_clause_complete_without_action_ok() {
        // A complete x402 clause alongside a non-x402 action is fine (not a
        // dead key — the clause is fully specified: chain+token+value+recipients).
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance_order".into()]),
            x402: Some(X402Policy {
                chain_id: Some(8453),
                token_address: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
                max_value: Some("1000000".into()),
                allowed_recipients: Some(vec!["0x000000000000000000000000000000000000bEEF".into()]),
            }),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_ok());
    }

    #[test]
    fn cr050_x402_clause_missing_chain_or_token_rejected() {
        // chain_id + token_address are now mandatory (a value cap without a
        // token/chain pin is meaningless).
        let base = || Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".into()]),
            x402: Some(X402Policy {
                chain_id: Some(8453),
                token_address: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
                max_value: Some("1000000".into()),
                allowed_recipients: Some(vec!["0x000000000000000000000000000000000000bEEF".into()]),
            }),
            ..Policy::default()
        };
        let mut no_chain = base();
        no_chain.x402.as_mut().unwrap().chain_id = None;
        assert!(sanity_check_policy(&no_chain, &empty_secret(), None).is_err());
        let mut no_token = base();
        no_token.x402.as_mut().unwrap().token_address = None;
        assert!(sanity_check_policy(&no_token, &empty_secret(), None).is_err());
    }

    #[test]
    fn cr050_invalid_evm_address_rejected_at_wrap() {
        // Gemini final-review: catch a typo'd token/recipient/vault at wrap
        // (would otherwise ship a dead key that fails policy_denied at sign).
        let good_tok = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
        let good_rcpt = "0x000000000000000000000000000000000000bEEF";
        // bad token
        let p = Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".into()]),
            x402: Some(X402Policy {
                chain_id: Some(8453),
                token_address: Some("0xNOTHEX".into()),
                max_value: Some("1000000".into()),
                allowed_recipients: Some(vec![good_rcpt.into()]),
            }),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_err());
        // bad recipient (too short)
        let p2 = Policy {
            allowed_actions: Some(vec!["sign_x402_eip3009".into()]),
            x402: Some(X402Policy {
                chain_id: Some(8453),
                token_address: Some(good_tok.into()),
                max_value: Some("1000000".into()),
                allowed_recipients: Some(vec!["0xbeef".into()]),
            }),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p2, &empty_secret(), None).is_err());
        // bad vault
        let pv = Policy {
            allowed_vaults: Some(vec!["nope".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&pv, &empty_secret(), None).is_err());
    }

    #[test]
    fn cr050_x402_and_structured_actions_are_recognized() {
        for a in [
            "sign_x402_eip3009",
            "sign_binance_order",
            "sign_binance_cancel",
            "sign_okx_order",
            "sign_okx_cancel",
        ] {
            assert!(
                KNOWN_SIGN_ACTIONS.contains(&a),
                "{a} must be a known action"
            );
        }
        assert!(is_eip712_action("sign_x402_eip3009"));
    }

    #[test]
    fn known_actions_cover_full_dispatch_table() {
        // Mirror of handler.rs `handle` dispatch arms that customer policies
        // legitimately allow-list (pre-gate `ping` + every post-identity-gate
        // arm). Set-equality both ways: a dispatch arm missing here fires the
        // wrap-time unknown-action warning on a valid policy; a KNOWN entry
        // missing here is either dead (enclave dropped it) or a control-plane
        // op that must not be suppressed.
        const DISPATCH_TABLE_ACTIONS: &[&str] = &[
            "ping",
            "sign",
            "sign_kucoin",
            "sign_binance",
            "sign_binance_request",
            "sign_bybit",
            "sign_okx",
            "sign_binance_order",
            "sign_binance_cancel",
            "sign_okx_order",
            "sign_okx_cancel",
            "sign_hyperliquid_main_order",
            "sign_hyperliquid_main_cancel",
            "sign_hyperliquid_testnet_order",
            "sign_hyperliquid_testnet_cancel",
            "sign_asterdex",
            "sign_data",
            "sign_x402_eip3009",
            "verify_blob",
        ];
        for a in DISPATCH_TABLE_ACTIONS {
            assert!(KNOWN_SIGN_ACTIONS.contains(a), "{a} must be a known action");
        }
        for a in KNOWN_SIGN_ACTIONS {
            assert!(
                DISPATCH_TABLE_ACTIONS.contains(a),
                "{a} is KNOWN but not in the dispatch-table mirror — dead action or missing mirror entry"
            );
        }
        // Testnet HL signs EIP-712 like mainnet → C19 coverage. sign_data
        // (keccak/canonical-v1) and the HMAC binance-request route are not
        // EIP-712 and must not trip C19.
        assert!(is_eip712_action("sign_hyperliquid_testnet_order"));
        assert!(is_eip712_action("sign_hyperliquid_testnet_cancel"));
        assert!(!is_eip712_action("sign_data"));
        assert!(!is_eip712_action("verify_blob"));
        assert!(!is_eip712_action("sign_binance_request"));
        // Control-plane ops stay unknown on purpose (they dispatch before the
        // tenant-identity gate; their presence in a customer policy is a
        // mistake the warning should surface).
        for a in [
            "registry_challenge",
            "registry_refresh",
            "provision_data_key",
        ] {
            assert!(!KNOWN_SIGN_ACTIONS.contains(&a), "{a} must stay unknown");
        }
    }

    // ─── CR053: HL caps + vaults survive the wrap (parity / no silent drop) ──

    #[test]
    fn cr053_hl_caps_and_vaults_survive_wrap() {
        let json = r#"{
            "allowed_actions": ["sign_hyperliquid_main_order"],
            "allowed_vaults": ["0x00000000000000000000000000000000000000A1"],
            "hl_order_caps": [{"asset": 0, "max_size": "5"}]
        }"#;
        let p: Policy = serde_json::from_str(json).expect("parse");
        assert_eq!(
            p.allowed_vaults.as_ref().unwrap()[0],
            "0x00000000000000000000000000000000000000A1"
        );
        let caps = p.hl_order_caps.as_ref().expect("hl_order_caps preserved");
        assert_eq!(caps[0].asset, 0);
        assert_eq!(caps[0].max_size, "5");
        let back = serde_json::to_value(&p).unwrap();
        assert_eq!(back["hl_order_caps"][0]["max_size"], "5");
        assert_eq!(
            back["allowed_vaults"][0],
            "0x00000000000000000000000000000000000000A1"
        );
    }

    #[test]
    fn cr053_hl_order_cap_nested_unknown_is_error() {
        // (`max_notional` was this test's unknown-field example before B2 made
        // it a real field — a typo'd variant keeps the guarantee pinned.)
        let json = r#"{"hl_order_caps": [{"asset": 0, "max_size": "5", "max_notionall": "9"}]}"#;
        assert!(serde_json::from_str::<Policy>(json).is_err());
    }

    /// Helper: empty HMAC-style secret for tests that don't care about
    /// secret content.
    fn empty_secret() -> serde_json::Value {
        serde_json::json!({"key": "k", "secret": "s"})
    }

    /// Helper: EIP-712-shaped secret (carries private_key).
    fn eip712_secret() -> serde_json::Value {
        serde_json::json!({
            "private_key": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "wallet_address": "0x1234567890123456789012345678901234567890"
        })
    }

    #[test]
    fn sanity_check_rejects_long_label_chars() {
        let p = Policy {
            label: Some("a".repeat(129)),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_err());
    }

    #[test]
    fn sanity_check_accepts_128_char_label() {
        // Narrow allowed_actions to a single HMAC venue so the new C29
        // implicit-allow-all bail doesn't fire — this test only checks
        // the label-length path.
        let p = Policy {
            label: Some("a".repeat(128)),
            allowed_actions: Some(vec!["sign_binance".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_ok());
    }

    #[test]
    fn sanity_check_accepts_128_cyrillic_chars() {
        // 128 cyrillic chars = 256 bytes, must pass char-count check.
        let label: String = "а".repeat(128);
        assert_eq!(label.chars().count(), 128);
        assert_eq!(label.len(), 256);
        let p = Policy {
            label: Some(label),
            allowed_actions: Some(vec!["sign_binance".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_ok());
    }

    // ─── C27 (PR #41): fail-loud on max_requests_per_minute ────────────

    #[test]
    fn sanity_check_rejects_max_requests_per_minute() {
        let p = Policy {
            max_requests_per_minute: Some(60),
            ..Policy::default()
        };
        let err = sanity_check_policy(&p, &empty_secret(), None).unwrap_err();
        assert!(err.to_string().contains("max_requests_per_minute"));
        assert!(err.to_string().contains("does NOT"));
    }

    #[test]
    fn sanity_check_accepts_when_max_requests_per_minute_absent() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_ok());
    }

    // ─── C19: EIP-712 method/path skip warning ─────────────────────────

    #[test]
    fn is_eip712_action_recognizes_hl_and_asterdex() {
        assert!(is_eip712_action("sign_hyperliquid_main_order"));
        assert!(is_eip712_action("sign_hyperliquid_main_cancel"));
        assert!(is_eip712_action("sign_asterdex"));
        assert!(!is_eip712_action("sign_binance"));
        assert!(!is_eip712_action("sign_kucoin"));
        assert!(!is_eip712_action("ping"));
    }

    #[test]
    fn policy_permits_any_eip712_with_none_actions_is_true() {
        let p = Policy::default(); // allowed_actions = None
        assert!(policy_permits_any_eip712(&p));
    }

    #[test]
    fn policy_permits_any_eip712_with_only_hmac_actions_is_false() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".into(), "sign_okx".into()]),
            ..Policy::default()
        };
        assert!(!policy_permits_any_eip712(&p));
    }

    #[test]
    fn policy_permits_any_eip712_with_hl_action_is_true() {
        let p = Policy {
            allowed_actions: Some(vec![
                "sign_binance".into(),
                "sign_hyperliquid_main_order".into(),
            ]),
            ..Policy::default()
        };
        assert!(policy_permits_any_eip712(&p));
    }

    // C19 doesn't fail (it warns) — but we still want to assert that the
    // warning path doesn't error out. We can't easily capture stderr in a
    // unit test without restructuring, so we just verify the function
    // returns Ok when warnings would fire.
    #[test]
    fn sanity_check_c19_eip712_with_methods_returns_ok_with_warning() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_asterdex".into()]),
            allowed_methods: Some(vec!["POST".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_ok());
    }

    #[test]
    fn sanity_check_c19_implicit_eip712_now_caught_by_c29_dual_venue() {
        // Post-self-review: allowed_actions = None used to just emit a
        // C19 warning. Now it also triggers C29 dual-venue bail because
        // the policy implicitly permits both HL and Asterdex. This is
        // the intended new behavior — implicit allow-all + PK secret is
        // the most permissive cross-venue blob possible.
        let p = Policy {
            allowed_path_prefixes: Some(vec!["/api/v1/orders".into()]),
            ..Policy::default()
        };
        // With non-PK secret it still bails (HIGH-2 says bail on policy alone).
        let err = sanity_check_policy(&p, &empty_secret(), None).unwrap_err();
        assert!(err.to_string().contains("BOTH Hyperliquid AND Asterdex"));
    }

    // ─── C29: cross-venue PK reuse detection ───────────────────────────

    #[test]
    fn secret_has_private_key_detects_eip712_shape() {
        assert!(secret_has_private_key(&eip712_secret()));
        assert!(!secret_has_private_key(&empty_secret()));
        // private_key present but not a string → not detected (defensive).
        let weird = serde_json::json!({"private_key": 42});
        assert!(!secret_has_private_key(&weird));
    }

    #[test]
    fn sanity_check_c29_rejects_dual_eip712_venues_in_single_blob() {
        let p = Policy {
            allowed_actions: Some(vec![
                "sign_hyperliquid_main_order".into(),
                "sign_asterdex".into(),
            ]),
            ..Policy::default()
        };
        let err = sanity_check_policy(&p, &eip712_secret(), None).unwrap_err();
        assert!(err.to_string().contains("BOTH Hyperliquid AND Asterdex"));
        assert!(err.to_string().contains("Split into two blobs"));
    }

    #[test]
    fn sanity_check_c29_rejects_dual_with_cancel_action() {
        // Either HL action triggers the dual-venue check.
        let p = Policy {
            allowed_actions: Some(vec![
                "sign_hyperliquid_main_cancel".into(),
                "sign_asterdex".into(),
            ]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_err());
    }

    #[test]
    fn sanity_check_c29_accepts_hl_only_blob() {
        let p = Policy {
            allowed_actions: Some(vec![
                "sign_hyperliquid_main_order".into(),
                "sign_hyperliquid_main_cancel".into(),
            ]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_ok());
    }

    #[test]
    fn sanity_check_c29_accepts_asterdex_only_blob() {
        let p = Policy {
            allowed_actions: Some(vec!["sign_asterdex".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_ok());
    }

    #[test]
    fn sanity_check_c29_warns_on_private_key_without_dual_venue() {
        // Single-venue EIP-712 blob — warning only, not error. We verify
        // it returns Ok() (the warning goes to stderr, not return value).
        let p = Policy {
            allowed_actions: Some(vec!["sign_asterdex".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &eip712_secret(), None).is_ok());
    }

    #[test]
    fn sanity_check_c29_no_warn_on_hmac_secret() {
        // HMAC secret (no private_key) → no C29 warning, no error.
        let p = Policy {
            allowed_actions: Some(vec!["sign_binance".into()]),
            ..Policy::default()
        };
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_ok());
    }

    #[test]
    fn sanity_check_c29_dual_venue_bails_on_policy_alone_regardless_of_secret() {
        // Gemini round-1 catch: original name `..._only_triggers_when_pk_present`
        // was misleading — post-self-review the check fires on the POLICY
        // alone, regardless of secret content. Renamed for clarity.
        //
        // If the secret has no private_key but the policy claims both
        // venues, we still bail because the policy itself is unsafe.
        // Self-review HIGH-2: a customer could wrap dual-venue policy
        // with HMAC secret today, store the policy file, and later wrap
        // the same policy with a PK secret — that would be the C29
        // exploit. Better to fail loud the first time the policy is seen.
        let p = Policy {
            allowed_actions: Some(vec![
                "sign_hyperliquid_main_order".into(),
                "sign_asterdex".into(),
            ]),
            ..Policy::default()
        };
        // HMAC secret here — the bail is on the POLICY, not the secret shape.
        let err = sanity_check_policy(&p, &empty_secret(), None).unwrap_err();
        assert!(err.to_string().contains("BOTH Hyperliquid AND Asterdex"));
    }

    // ─── HIGH-2 follow-up: None allowed_actions + dual-venue implicit allow

    #[test]
    fn sanity_check_c29_rejects_implicit_allow_all_with_pk() {
        // The most permissive cross-venue blob possible: allowed_actions
        // is None (implicit allow-all), so the same PK secret can sign
        // for ALL venues including both HL and Asterdex. Self-review
        // HIGH: original code skipped the dual-venue check when
        // allowed_actions was None — must bail here.
        let p = Policy::default(); // allowed_actions = None
        let err = sanity_check_policy(&p, &eip712_secret(), None).unwrap_err();
        assert!(err.to_string().contains("BOTH Hyperliquid AND Asterdex"));
        assert!(err.to_string().contains("implicit allow-all"));
    }

    #[test]
    fn sanity_check_c29_rejects_implicit_allow_all_even_with_hmac_secret() {
        // Same case as above but with HMAC secret. Still bails — the
        // policy itself is unsafe regardless of today's secret shape.
        let p = Policy::default();
        assert!(sanity_check_policy(&p, &empty_secret(), None).is_err());
    }

    // ─── MEDIUM-1: EIP712_ACTIONS ⊆ KNOWN_SIGN_ACTIONS drift check

    #[test]
    fn eip712_actions_subset_of_known_actions() {
        // Self-review MEDIUM: if a new EIP-712 action is added to
        // KNOWN_SIGN_ACTIONS but not EIP712_ACTIONS, the C19 warning
        // silently misses it. This test guards against the drift.
        for action in EIP712_ACTIONS {
            assert!(
                KNOWN_SIGN_ACTIONS.contains(action),
                "EIP712_ACTIONS contains '{}' but it's not in KNOWN_SIGN_ACTIONS — \
                 the two lists must stay in sync. If you added a new EIP-712 \
                 action, update BOTH lists.",
                action
            );
        }
    }

    #[test]
    fn known_sign_actions_includes_all_eip712_venues() {
        // Sanity: KNOWN_SIGN_ACTIONS should at minimum include all the
        // EIP-712 action names we currently handle (otherwise the
        // unknown-action warning would fire on legitimate EIP-712 calls).
        for &expected in &[
            "sign_hyperliquid_main_order",
            "sign_hyperliquid_main_cancel",
            "sign_asterdex",
        ] {
            assert!(KNOWN_SIGN_ACTIONS.contains(&expected));
        }
    }
}
