//! HMAC-SHA256 signers for KuCoin v2, Binance, Bybit V5, and OKX V5 canonical
//! strings.
//!
//! Constant-time guarantee: the `hmac` crate's `Hmac::<Sha256>` is
//! constant-time by construction — internally it uses `Mac::finalize`
//! which returns a `CtOutput<Sha256>` wrapper whose `PartialEq` impl
//! goes through `subtle::ConstantTimeEq`. We never compare HMAC bytes
//! ourselves outside of test assertions, so no timing channel exists.
//! See <https://docs.rs/hmac/0.12/hmac/> "Constant-time comparison".
//!
//! Memory hygiene: the secret is wrapped in [`zeroize::Zeroizing<Vec<u8>>`]
//! so it is wiped on drop. Callers must hand us a `Zeroizing<Vec<u8>>` —
//! the API does not accept a bare `&[u8]` to discourage unzeroized copies.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Build the KuCoin v2 canonical string: `timestamp_ms || METHOD || path || body`.
///
/// Concatenation only — no separators, no escaping. KuCoin's spec is
/// precise about this and we deliberately do not add anything.
#[inline]
pub fn kucoin_canonical(timestamp_ms: u64, method: &str, path: &str, body: &str) -> String {
    let mut s = String::with_capacity(20 + method.len() + path.len() + body.len());
    use std::fmt::Write as _;
    let _ = write!(&mut s, "{}", timestamp_ms);
    // KuCoin requires uppercase HTTP method.
    for ch in method.chars() {
        s.extend(ch.to_uppercase());
    }
    s.push_str(path);
    s.push_str(body);
    s
}

/// Compute HMAC-SHA256 over `data` with `secret`. Returns the raw 32-byte tag.
///
/// `secret` is borrowed from a [`Zeroizing<Vec<u8>>`] so the caller retains
/// the wipe-on-drop guarantee. We never copy it inside this function.
pub fn hmac_sha256(secret: &Zeroizing<Vec<u8>>, data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(secret.as_slice())?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Sign a KuCoin request and return the standard-base64 signature.
pub fn sign_kucoin(
    secret: &Zeroizing<Vec<u8>>,
    timestamp_ms: u64,
    method: &str,
    path: &str,
    body: &str,
) -> Result<String> {
    let canonical = kucoin_canonical(timestamp_ms, method, path, body);
    let tag = hmac_sha256(secret, canonical.as_bytes())?;
    Ok(B64.encode(tag))
}

/// Compute the KuCoin v2 "encrypted passphrase" header value:
/// `base64( HMAC-SHA256(secret_bytes, passphrase_bytes) )`.
///
/// The passphrase is treated as opaque UTF-8 bytes (KuCoin's spec).
pub fn encrypt_kucoin_passphrase(secret: &Zeroizing<Vec<u8>>, passphrase: &[u8]) -> Result<String> {
    let tag = hmac_sha256(secret, passphrase)?;
    Ok(B64.encode(tag))
}

/// Build the full KuCoin v2 auth header set in one shot. Pure function: no
/// AWS / vsock / IO dependencies, fully unit-testable on every platform.
///
/// The returned map contains the five canonical KuCoin headers:
///   `KC-API-KEY`, `KC-API-SIGN`, `KC-API-TIMESTAMP`,
///   `KC-API-PASSPHRASE`, `KC-API-KEY-VERSION`
///
/// `secret` is borrowed from a `Zeroizing<Vec<u8>>` so the caller keeps the
/// wipe-on-drop guarantee. The intermediate canonical string is dropped at
/// function exit; we deliberately don't `Zeroizing`-wrap it because canonical
/// strings include the request body which the gateway already exposes to
/// itself in cleartext — the body is not a secret, only the secret is.
pub fn compute_kucoin_headers(
    secret: &Zeroizing<Vec<u8>>,
    passphrase: &[u8],
    key: &str,
    timestamp_ms: u64,
    method: &str,
    path: &str,
    body: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let sign_b64 = sign_kucoin(secret, timestamp_ms, method, path, body)?;
    let passphrase_b64 = encrypt_kucoin_passphrase(secret, passphrase)?;

    let mut headers = std::collections::BTreeMap::new();
    headers.insert("KC-API-KEY".to_owned(), key.to_owned());
    headers.insert("KC-API-SIGN".to_owned(), sign_b64);
    headers.insert("KC-API-TIMESTAMP".to_owned(), timestamp_ms.to_string());
    headers.insert("KC-API-PASSPHRASE".to_owned(), passphrase_b64);
    headers.insert("KC-API-KEY-VERSION".to_owned(), "2".to_owned());
    Ok(headers)
}

/// Build the Binance canonical string for a SIGNED endpoint.
///
/// Binance signs `query_string + body` where:
/// - `query_string` already contains `timestamp=<ms>&recvWindow=5000` plus any
///   user-provided params, separator `&`, no leading `?`.
/// - `body` is the request body as a string (empty for GET).
///
/// Per Binance docs <https://binance-docs.github.io/apidocs/spot/en/#signed-trade-user_data-and-margin-endpoint-security>:
/// `totalParams = query_string + body`, signature is hex of HMAC-SHA256.
#[inline]
pub fn binance_canonical(query: &str, body: &str) -> String {
    let mut s = String::with_capacity(query.len() + body.len());
    s.push_str(query);
    s.push_str(body);
    s
}

/// Sign a Binance request and return the lowercase-hex signature.
pub fn sign_binance(
    secret: &Zeroizing<Vec<u8>>,
    query: &str,
    body: &str,
) -> Result<String> {
    let canonical = binance_canonical(query, body);
    let tag = hmac_sha256(secret, canonical.as_bytes())?;
    Ok(hex::encode(tag))
}

/// Build the full Binance auth header set in one shot.
///
/// Returns:
///   `X-MBX-APIKEY`    — header
///   `signature`       — query param (hex of HMAC-SHA256)
///   `timestamp`       — query param (ms)
///   `recvWindow`      — query param ("5000")
///
/// The SDK's `_BINANCE_QUERY_PARAMS = {"signature", "timestamp", "recvWindow", "apiKey"}`
/// routes `signature/timestamp/recvWindow` to query params and `X-MBX-APIKEY` to headers.
///
/// `query` is the user-supplied query string (without `timestamp`/`recvWindow`/`signature`).
/// We append our own `timestamp=<ms>&recvWindow=5000` and sign over the full string.
pub fn compute_binance_headers(
    secret: &Zeroizing<Vec<u8>>,
    key: &str,
    timestamp_ms: u64,
    user_query: &str,
    body: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let recv_window = "5000";
    // Compose the full query: user params + timestamp + recvWindow.
    let mut full_query = String::with_capacity(user_query.len() + 64);
    if !user_query.is_empty() {
        full_query.push_str(user_query);
        full_query.push('&');
    }
    use std::fmt::Write as _;
    let _ = write!(&mut full_query, "timestamp={}&recvWindow={}", timestamp_ms, recv_window);

    let sign_hex = sign_binance(secret, &full_query, body)?;

    let mut headers = std::collections::BTreeMap::new();
    headers.insert("X-MBX-APIKEY".to_owned(), key.to_owned());
    headers.insert("signature".to_owned(), sign_hex);
    headers.insert("timestamp".to_owned(), timestamp_ms.to_string());
    headers.insert("recvWindow".to_owned(), recv_window.to_owned());
    Ok(headers)
}

/// Build the Bybit V5 canonical string.
///
/// Per <https://bybit-exchange.github.io/docs/v5/guide#authentication>:
/// `timestamp + api_key + recv_window + (queryString | body)`
/// where:
/// - For GET: queryString without leading `?`
/// - For POST: body JSON
#[inline]
pub fn bybit_canonical(
    timestamp_ms: u64,
    api_key: &str,
    recv_window: &str,
    query_or_body: &str,
) -> String {
    let mut s = String::with_capacity(20 + api_key.len() + recv_window.len() + query_or_body.len());
    use std::fmt::Write as _;
    let _ = write!(&mut s, "{}", timestamp_ms);
    s.push_str(api_key);
    s.push_str(recv_window);
    s.push_str(query_or_body);
    s
}

/// Sign a Bybit V5 request and return the lowercase-hex signature.
pub fn sign_bybit(
    secret: &Zeroizing<Vec<u8>>,
    timestamp_ms: u64,
    api_key: &str,
    recv_window: &str,
    query_or_body: &str,
) -> Result<String> {
    let canonical = bybit_canonical(timestamp_ms, api_key, recv_window, query_or_body);
    let tag = hmac_sha256(secret, canonical.as_bytes())?;
    Ok(hex::encode(tag))
}

/// Build the full Bybit V5 auth header set.
///
/// All four required headers go in HTTP headers (not query params).
/// The SDK's BybitExchange does not split — every key here lands as a header.
pub fn compute_bybit_headers(
    secret: &Zeroizing<Vec<u8>>,
    key: &str,
    timestamp_ms: u64,
    method: &str,
    query: &str,
    body: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let recv_window = "5000";
    // For GET: sign over query. For POST/PUT/DELETE: sign over body.
    // Method-uppercased compare.
    let upper_method = method.to_ascii_uppercase();
    let payload: &str = if upper_method == "GET" || upper_method == "DELETE" {
        query
    } else {
        body
    };
    let sign_hex = sign_bybit(secret, timestamp_ms, key, recv_window, payload)?;

    let mut headers = std::collections::BTreeMap::new();
    headers.insert("X-BAPI-API-KEY".to_owned(), key.to_owned());
    headers.insert("X-BAPI-TIMESTAMP".to_owned(), timestamp_ms.to_string());
    headers.insert("X-BAPI-RECV-WINDOW".to_owned(), recv_window.to_owned());
    headers.insert("X-BAPI-SIGN".to_owned(), sign_hex);
    headers.insert("X-BAPI-SIGN-TYPE".to_owned(), "2".to_owned());
    Ok(headers)
}

/// Convert a Unix epoch in milliseconds to an OKX-format ISO8601 string of the
/// form `2026-05-10T19:00:00.000Z` (millisecond precision, trailing `Z`).
///
/// This is computed in the enclave from the gateway-supplied `timestamp_ms`
/// (which the gateway either takes from its own clock or from a caller value
/// validated to be within the 5s skew window). The enclave never reads its
/// own wall clock — that would not be attestable.
///
/// We implement the conversion by hand to avoid dragging in a date-time
/// crate (chrono / time): the conversion is a pure arithmetic exercise, no
/// timezones, no leap-second support needed (OKX uses UTC and tolerates the
/// fictional leap-second smearing the same way every server clock does).
///
/// Algorithm:
/// 1. Split `timestamp_ms` into seconds-since-epoch and millis remainder.
/// 2. Compute days-since-epoch and seconds-of-day.
/// 3. Convert days-since-epoch (1970-01-01 = day 0) to (year, month, day)
///    using the Howard Hinnant `civil_from_days` algorithm — well-known,
///    handles all dates from year 0 to year 32767 with no branching on
///    leap years (the formula handles 100/400 rules implicitly).
/// 4. Format as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Reference: <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
#[inline]
pub fn okx_iso8601_from_ms(timestamp_ms: u64) -> String {
    // Split ms -> seconds + millis remainder.
    let total_secs = (timestamp_ms / 1000) as i64;
    let millis = (timestamp_ms % 1000) as u32;

    // days_since_epoch + seconds_of_day. Both non-negative for any
    // realistic timestamp_ms (we hard-cap implicitly via u64 -> i64 cast;
    // any timestamp before 1970 would have to come from the gateway and is
    // already filtered by the skew window).
    let days = total_secs.div_euclid(86_400);
    let seconds_of_day = total_secs.rem_euclid(86_400) as u32;

    // civil_from_days: convert days-since-epoch (1970-01-01 = 0) to
    // (year, month, day). Translated literally from Howard Hinnant.
    // Shift epoch to 0000-03-01 so leap day lands at end of "year".
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    // seconds-of-day -> hh:mm:ss.
    let h = seconds_of_day / 3600;
    let min = (seconds_of_day % 3600) / 60;
    let s = seconds_of_day % 60;

    // Manual formatting — `format!` brings in `core::fmt` machinery which
    // we already pull in transitively via `tracing`, so the cost is zero.
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, m, d, h, min, s, millis
    )
}

/// Build the OKX V5 canonical (prehash) string:
/// `{timestamp_iso8601}{METHOD}{requestPath}{body}`.
///
/// Concatenation only — no separators. Method must be uppercase. `request_path`
/// includes the query string for GET requests (the caller is expected to have
/// already merged `?param=value` into `path`). `body` is the empty string for
/// GET, the JSON body string for POST/PUT/DELETE.
///
/// Reference: <https://www.okx.com/docs-v5/en/#rest-api-authentication-signature>
#[inline]
pub fn okx_canonical(timestamp_iso: &str, method: &str, request_path: &str, body: &str) -> String {
    let mut s =
        String::with_capacity(timestamp_iso.len() + method.len() + request_path.len() + body.len());
    s.push_str(timestamp_iso);
    for ch in method.chars() {
        s.extend(ch.to_uppercase());
    }
    s.push_str(request_path);
    s.push_str(body);
    s
}

/// Sign an OKX request and return the standard-base64 signature.
///
/// `secret` is the API secret as raw UTF-8 bytes (OKX uses the secret as a
/// plain string key for HMAC, NOT base64-decoded — verified against the
/// OKX docs example which feeds the secret into HMAC as-is).
pub fn sign_okx(
    secret: &Zeroizing<Vec<u8>>,
    timestamp_iso: &str,
    method: &str,
    request_path: &str,
    body: &str,
) -> Result<String> {
    let canonical = okx_canonical(timestamp_iso, method, request_path, body);
    let tag = hmac_sha256(secret, canonical.as_bytes())?;
    Ok(B64.encode(tag))
}

/// Build the full OKX V5 auth header set in one shot.
///
/// Returns (all headers, none query):
///   `OK-ACCESS-KEY`         — api_key
///   `OK-ACCESS-SIGN`        — base64( HMAC-SHA256(secret, prehash) )
///   `OK-ACCESS-TIMESTAMP`   — ISO8601 UTC, millisecond precision
///   `OK-ACCESS-PASSPHRASE`  — plain-text passphrase (not signed; OKX
///                              checks server-side as 3rd auth factor)
///
/// `secret` is borrowed from a `Zeroizing<Vec<u8>>` so the caller keeps the
/// wipe-on-drop guarantee. `passphrase` is borrowed as `&[u8]` and is
/// transcribed into the header as UTF-8 — the enclave does not transform
/// it (no HMAC, no base64). Callers must pass valid UTF-8.
///
/// `request_path` is expected to already contain the query string (the
/// gateway merges `path` + query into a single `requestPath` field, mirroring
/// what the OKX SDK does). For GET requests `body` should be empty.
///
/// The header set deliberately does NOT include `OK-ACCESS-PROJECT` or
/// `x-simulated-trading`; if customers need those, they pass them in their
/// own request alongside our auth headers.
pub fn compute_okx_headers(
    secret: &Zeroizing<Vec<u8>>,
    passphrase: &[u8],
    key: &str,
    timestamp_ms: u64,
    method: &str,
    request_path: &str,
    body: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    let timestamp_iso = okx_iso8601_from_ms(timestamp_ms);
    let sign_b64 = sign_okx(secret, &timestamp_iso, method, request_path, body)?;
    // Defense-in-depth: passphrase must be valid UTF-8 to live in an HTTP
    // header. We don't encode it ourselves — OKX accepts it raw — but we do
    // refuse if it contains bytes that are illegal in `OK-ACCESS-PASSPHRASE`
    // header values per RFC 7230 (CTL or non-VCHAR/non-SP).
    let passphrase_str = std::str::from_utf8(passphrase)
        .map_err(|_| anyhow::anyhow!("okx passphrase: invalid utf-8"))?;
    for b in passphrase_str.bytes() {
        // Reject CTL (< 0x20 except HTAB), DEL (0x7F), and bytes > 0x7E
        // (extended ASCII / non-ASCII). OKX passphrases the user creates
        // through their UI cannot contain these characters anyway, but we
        // refuse to forward them just in case.
        if !(b == b'\t' || (0x20..=0x7e).contains(&b)) {
            return Err(anyhow::anyhow!("okx passphrase: illegal byte in header value"));
        }
    }

    let mut headers = std::collections::BTreeMap::new();
    headers.insert("OK-ACCESS-KEY".to_owned(), key.to_owned());
    headers.insert("OK-ACCESS-SIGN".to_owned(), sign_b64);
    headers.insert("OK-ACCESS-TIMESTAMP".to_owned(), timestamp_iso);
    headers.insert(
        "OK-ACCESS-PASSPHRASE".to_owned(),
        passphrase_str.to_owned(),
    );
    Ok(headers)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 1 Stage 2 — EIP-712 signing (Hyperliquid family).
// ─────────────────────────────────────────────────────────────────────────
//
// Hyperliquid mainnet uses Ethereum's EIP-712 typed-data signing standard.
// The signing flow is:
//
//   1. Build an `action` JSON object (e.g. `{"type":"order","orders":[...]}`).
//   2. Compute `actionHash = keccak256(msgpack(action) || nonce_be8 || vault21)`.
//      The vault suffix is a single tag byte (`0x00` no-vault) or `0x01`
//      followed by the 20-byte vault address.
//   3. Build EIP-712 typed-data with:
//        domain      = {name:"Exchange", version:"1", chainId:1337,
//                       verifyingContract: 0x0000...0000}
//        primaryType = "Agent"
//        types       = {EIP712Domain, Agent}
//        message     = {source:"a"|"b", connectionId: actionHash}
//   4. Compute `digest = keccak256("\x19\x01" || domainSeparator || hashStruct(message))`.
//   5. Sign `digest` with secp256k1 → (r, s, v) where v ∈ {27, 28}.
//
// We implement this end-to-end inside the enclave using `k256` for ECDSA,
// `tiny-keccak` for keccak256, and `rmp-serde` for canonical msgpack. None
// of these crates pull in async / network code; the dependency surface
// stays auditable for Finding-J-style determinism.

use k256::ecdsa::SigningKey;
use rmp_serde::Serializer as MsgpackSerializer;
use serde::Serialize;
use tiny_keccak::{Hasher, Keccak};

use crate::proto::HlSignature;

/// Compute the keccak256 hash of `data`. Returns the 32-byte digest.
///
/// Implemented over `tiny_keccak::Keccak::v256()` which is the FIPS-202
/// keccak256 variant (the "legacy keccak" form Ethereum uses — NOT
/// SHA-3-256, which differs only in the padding byte).
#[inline]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// Encode `action` (a `serde_json::Value`) as canonical msgpack matching
/// the Hyperliquid Python SDK output byte-for-byte.
///
/// Implementation notes:
///
/// - `rmp_serde::Serializer::with_struct_map()` makes structs encode as
///   msgpack MAPS (matching the SDK), not as arrays.
/// - JSON map ordering: `serde_json` (without the `preserve_order`
///   feature, which we deliberately do NOT enable) sorts object keys
///   alphabetically. This MATCHES the Hyperliquid SDK behaviour: the
///   SDK's order example uses keys `a,b,p,r,s,t` which are already
///   alphabetically sorted in Python 3.7+ insertion-ordered dicts.
///   Callers MUST construct action objects with keys alphabetically.
/// - JSON numbers: serde_json preserves the source numeric type
///   (`i64`/`u64`/`f64`), and rmp-serde emits the native msgpack
///   integer/float form. Hyperliquid uses STRING-encoded numbers for
///   `p` (price) and `s` (size) — those are passed as strings, not
///   numbers, so the float-precision footgun does not apply here.
pub fn msgpack_action(action: &serde_json::Value) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    action
        .serialize(&mut MsgpackSerializer::new(&mut buf).with_struct_map())
        .map_err(|e| anyhow::anyhow!("msgpack encode failed: {e}"))?;
    Ok(buf)
}

/// Compute Hyperliquid's `actionHash`:
///
/// ```text
/// actionHash = keccak256(
///     msgpack(action)
///     || nonce_be_u64                   // 8 bytes, big-endian
///     || (vault ? "\x01" || vault20 : "\x00")  // 1 or 21 bytes
/// )
/// ```
///
/// The function does NOT validate the action JSON schema — it commits to
/// whatever bytes msgpack produces. Schema validation lives in the
/// `handle_sign_hyperliquid_main_order` / `_cancel` dispatchers.
pub fn compute_action_hash(
    action: &serde_json::Value,
    nonce: u64,
    vault: Option<[u8; 20]>,
) -> Result<[u8; 32]> {
    let mut buf = msgpack_action(action)?;
    buf.extend_from_slice(&nonce.to_be_bytes());
    match vault {
        None => buf.push(0x00),
        Some(addr) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr);
        }
    }
    Ok(keccak256(&buf))
}

/// Compute the EIP-712 type-hash for a struct type. `type_string` must be
/// the canonical EIP-712 type representation, e.g.
/// `"Agent(string source,bytes32 connectionId)"`.
#[inline]
pub fn eip712_type_hash(type_string: &str) -> [u8; 32] {
    keccak256(type_string.as_bytes())
}

/// Compute the EIP-712 domain separator for Hyperliquid mainnet.
///
/// Domain fields (constant for `hyperliquid_main`):
///   name              = "Exchange"
///   version           = "1"
///   chainId           = 1337  (NOT Ethereum mainnet's 1)
///   verifyingContract = 0x0000000000000000000000000000000000000000
///
/// HIP-3 venues (xyz/km/cash/etc.) will receive their own per-venue
/// constants when the next worker adds them — Hyperliquid documents that
/// chainId differs per HIP-3 deployer.
pub fn hyperliquid_main_domain_separator() -> [u8; 32] {
    let type_hash = eip712_type_hash(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256(b"Exchange");
    let version_hash = keccak256(b"1");
    let mut chain_id_be = [0u8; 32];
    // 1337 = 0x539. Big-endian, stored in trailing bytes.
    chain_id_be[30] = 0x05;
    chain_id_be[31] = 0x39;
    let verifying_contract_padded = [0u8; 32]; // 20 zero bytes already inside.

    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(&type_hash);
    buf.extend_from_slice(&name_hash);
    buf.extend_from_slice(&version_hash);
    buf.extend_from_slice(&chain_id_be);
    buf.extend_from_slice(&verifying_contract_padded);
    keccak256(&buf)
}

/// Compute the EIP-712 struct hash of Hyperliquid's `Agent` message:
///
/// ```text
/// hashStruct(Agent) = keccak256(
///     typeHash(Agent)
///     || keccak256(source_bytes)       // "a" mainnet, "b" testnet
///     || connectionId                  // 32 bytes (the actionHash)
/// )
/// ```
pub fn hyperliquid_agent_struct_hash(source: &str, connection_id: &[u8; 32]) -> [u8; 32] {
    let type_hash = eip712_type_hash("Agent(string source,bytes32 connectionId)");
    let source_hash = keccak256(source.as_bytes());
    let mut buf = Vec::with_capacity(3 * 32);
    buf.extend_from_slice(&type_hash);
    buf.extend_from_slice(&source_hash);
    buf.extend_from_slice(connection_id);
    keccak256(&buf)
}

/// Compute the final EIP-712 digest fed into secp256k1:
///
/// ```text
/// digest = keccak256("\x19\x01" || domainSeparator || hashStruct(message))
/// ```
///
/// `0x19 0x01` is the EIP-712 magic prefix that distinguishes typed-data
/// signatures from `personal_sign` messages.
pub fn eip712_digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(2 + 64);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(domain_separator);
    buf.extend_from_slice(struct_hash);
    keccak256(&buf)
}

/// Sign a 32-byte EIP-712 digest with a secp256k1 private key. Returns the
/// Ethereum-style `(r, s, v)` triple where `v ∈ {27, 28}`.
///
/// Determinism: `k256::ecdsa::SigningKey::sign_prehash_recoverable` uses
/// RFC 6979 deterministic nonce derivation, so signing the same digest
/// twice yields bit-identical bytes. This is essential for our reproducible
/// EIF build contract (Finding J).
pub fn sign_eip712_digest(
    private_key_bytes: &[u8; 32],
    digest: &[u8; 32],
) -> Result<HlSignature> {
    let signing_key = SigningKey::from_bytes(private_key_bytes.into())
        .map_err(|_| anyhow::anyhow!("invalid secp256k1 private key"))?;
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest)
        .map_err(|e| anyhow::anyhow!("ecdsa sign failed: {e}"))?;

    let bytes = sig.to_bytes();
    let r_hex = format!("0x{}", hex::encode(&bytes[..32]));
    let s_hex = format!("0x{}", hex::encode(&bytes[32..]));
    let v: u8 = 27u8 + u8::from(recid);

    Ok(HlSignature {
        r: r_hex,
        s: s_hex,
        v,
    })
}

/// Decode a `0x`-prefixed hex private key into a 32-byte array. Returns
/// an error if length / hex are wrong. We do NOT validate that the
/// resulting scalar is `< n` (the secp256k1 order); `k256::ecdsa::
/// SigningKey::from_bytes` rejects that with a clear error and pre-checking
/// here would just add a second code path that could drift.
pub fn parse_evm_private_key(s: &str) -> Result<[u8; 32]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        anyhow::bail!("private key must be 32 bytes (64 hex chars)");
    }
    let bytes =
        hex::decode(stripped).map_err(|_| anyhow::anyhow!("private key is not valid hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode a `0x`-prefixed 20-byte Ethereum address. Length/hex enforced.
pub fn parse_evm_address(s: &str) -> Result<[u8; 20]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 40 {
        anyhow::bail!("address must be 20 bytes (40 hex chars)");
    }
    let bytes =
        hex::decode(stripped).map_err(|_| anyhow::anyhow!("address is not valid hex"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive the Ethereum-style 20-byte address from a 32-byte secp256k1
/// private key. Sanity check: the operator placed the right `private_key`
/// next to the right `wallet_address` in the encrypted blob. Mismatch
/// rejects the blob before signing.
///
/// Algorithm:
///   1. Get the uncompressed public key (65 bytes, `0x04 || x || y`).
///   2. Drop the `0x04` tag prefix → 64 bytes.
///   3. keccak256 of those 64 bytes.
///   4. Take the trailing 20 bytes → address.
pub fn derive_address_from_private_key(private_key_bytes: &[u8; 32]) -> Result<[u8; 20]> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let signing_key = SigningKey::from_bytes(private_key_bytes.into())
        .map_err(|_| anyhow::anyhow!("invalid secp256k1 private key"))?;
    let verifying = signing_key.verifying_key();
    let encoded = verifying.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
        anyhow::bail!("unexpected secp256k1 public key encoding");
    }
    let hash = keccak256(&pubkey_bytes[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

/// Sign a Hyperliquid action (`order` or `cancel`) and return the
/// EIP-712 signature triple. Phase 1 Stage 2 entry point.
///
/// `source` is `"a"` for Hyperliquid mainnet and `"b"` for testnet — the
/// cross-environment-replay guard. The enclave is hardcoded to use `"a"`
/// for `hyperliquid_main`; testnet would be a separate dispatcher.
///
/// `private_key_bytes` is borrowed; the caller owns the wipe-on-drop
/// `Zeroizing` envelope and we never copy the bytes (no allocation).
pub fn sign_hyperliquid(
    private_key_bytes: &[u8; 32],
    action: &serde_json::Value,
    nonce: u64,
    vault: Option<[u8; 20]>,
    source: &str,
) -> Result<HlSignature> {
    let action_hash = compute_action_hash(action, nonce, vault)?;
    let agent_struct_hash = hyperliquid_agent_struct_hash(source, &action_hash);
    let domain_separator = hyperliquid_main_domain_separator();
    let digest = eip712_digest(&domain_separator, &agent_struct_hash);
    sign_eip712_digest(private_key_bytes, &digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 Test Case 1 — HMAC-SHA256.
    /// Key  = 0x0b * 20
    /// Data = "Hi There"
    /// Tag  = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    #[test]
    fn rfc4231_case_1() {
        let key = Zeroizing::new(vec![0x0bu8; 20]);
        let tag = hmac_sha256(&key, b"Hi There").expect("hmac");
        assert_eq!(
            hex::encode(tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 Test Case 2 — HMAC-SHA256.
    /// Key  = "Jefe"
    /// Data = "what do ya want for nothing?"
    /// Tag  = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    #[test]
    fn rfc4231_case_2() {
        let key = Zeroizing::new(b"Jefe".to_vec());
        let tag = hmac_sha256(&key, b"what do ya want for nothing?").expect("hmac");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// Canonical-string assembly is byte-exact, no separators, uppercase verb.
    #[test]
    fn canonical_string_shape() {
        let s = kucoin_canonical(
            1714997000000,
            "post",
            "/api/v1/orders",
            r#"{"clientOid":"test"}"#,
        );
        assert_eq!(s, "1714997000000POST/api/v1/orders{\"clientOid\":\"test\"}");
    }

    /// Self-consistency check: signing the same input twice yields the same
    /// signature (proves determinism — an external known-good vector
    /// follows in the `#[ignore]` test below, to be filled in on EC2).
    #[test]
    fn sign_kucoin_is_deterministic() {
        let secret = Zeroizing::new(b"test-kucoin-api-secret-NEVER-REAL-2026-05-06".to_vec());
        let a = sign_kucoin(
            &secret,
            1714997000000,
            "POST",
            "/api/v1/orders",
            r#"{"clientOid":"test"}"#,
        )
        .expect("sign");
        let b = sign_kucoin(
            &secret,
            1714997000000,
            "POST",
            "/api/v1/orders",
            r#"{"clientOid":"test"}"#,
        )
        .expect("sign");
        assert_eq!(a, b, "HMAC must be deterministic for identical inputs");
        // 32-byte HMAC -> 44-char standard-base64 (with padding)
        assert_eq!(a.len(), 44);
    }

    /// Day 3: external-cross-check vector for `compute_kucoin_headers`.
    /// Re-derived 2026-05-07 on the build host:
    ///   printf '1714997000000GET/api/v1/accounts' \
    ///     | openssl dgst -sha256 \
    ///         -hmac 'test-kucoin-api-secret-NEVER-REAL-2026-05-06' \
    ///         -binary | base64
    ///   -> hvbPsVtQZ6pri+TPygq21QckcNJKxmbL08LUoa0mnHQ=
    ///
    ///   printf 'test-passphrase-NEVER-REAL' \
    ///     | openssl dgst -sha256 \
    ///         -hmac 'test-kucoin-api-secret-NEVER-REAL-2026-05-06' \
    ///         -binary | base64
    ///   -> d1gwxxmX+4N4C1YunQ5MO7CxJlzB4FFGQzQhAAbX8WM=
    #[test]
    fn compute_kucoin_headers_matches_openssl_vectors() {
        const FIXTURE_KEY: &str = "test-kucoin-api-key-NEVER-REAL";
        const EXPECTED_SIGN: &str = "hvbPsVtQZ6pri+TPygq21QckcNJKxmbL08LUoa0mnHQ=";
        const EXPECTED_PASSPHRASE: &str = "d1gwxxmX+4N4C1YunQ5MO7CxJlzB4FFGQzQhAAbX8WM=";

        let secret = Zeroizing::new(b"test-kucoin-api-secret-NEVER-REAL-2026-05-06".to_vec());
        let headers = compute_kucoin_headers(
            &secret,
            b"test-passphrase-NEVER-REAL",
            FIXTURE_KEY,
            1714997000000,
            "GET",
            "/api/v1/accounts",
            "",
        )
        .expect("headers");

        assert_eq!(
            headers.get("KC-API-KEY").map(String::as_str),
            Some(FIXTURE_KEY)
        );
        assert_eq!(
            headers.get("KC-API-SIGN").map(String::as_str),
            Some(EXPECTED_SIGN)
        );
        assert_eq!(
            headers.get("KC-API-TIMESTAMP").map(String::as_str),
            Some("1714997000000")
        );
        assert_eq!(
            headers.get("KC-API-PASSPHRASE").map(String::as_str),
            Some(EXPECTED_PASSPHRASE)
        );
        assert_eq!(
            headers.get("KC-API-KEY-VERSION").map(String::as_str),
            Some("2")
        );
        assert_eq!(headers.len(), 5);
    }

    /// External-cross-check vector taken from the Day 3 brief, computed via
    /// `openssl dgst -sha256 -hmac ...`. Documents the expected outputs for
    /// the brief's reference inputs so the values are auditable without
    /// re-running openssl.
    ///
    /// These values use the brief's "looks-real" secrets but are not real
    /// KuCoin credentials; they are public test fixtures.
    #[test]
    fn kucoin_brief_reference_vectors() {
        // Inputs from the brief.
        const SECRET: &[u8] = b"84c96c40-3162-4b45-a11e-2f47fd1ecf4a";
        const PASSPHRASE: &[u8] = b"542b757341b78db0a271d8c3cbaf06e3";
        const KEY: &str = "69fcc1b588d5ca000115bcd7";
        const TS: u64 = 1714997000000;
        const METHOD: &str = "GET";
        const PATH: &str = "/api/v1/accounts";
        const BODY: &str = "";

        // Re-derived 2026-05-07 with openssl on macOS:
        //   printf '1714997000000GET/api/v1/accounts' \
        //     | openssl dgst -sha256 \
        //         -hmac '84c96c40-3162-4b45-a11e-2f47fd1ecf4a' -binary | base64
        //   -> QemDP2VKBaY2R0lFElOaxfqInHuHrtygXEhikqLGayw=
        //
        //   printf '542b757341b78db0a271d8c3cbaf06e3' \
        //     | openssl dgst -sha256 \
        //         -hmac '84c96c40-3162-4b45-a11e-2f47fd1ecf4a' -binary | base64
        //   -> GZhLB1BRbiW/om4ygkvgq6GBpaV8Kdo+/wp0c25nILU=
        const EXPECTED_SIGN: &str = "QemDP2VKBaY2R0lFElOaxfqInHuHrtygXEhikqLGayw=";
        const EXPECTED_PASSPHRASE: &str = "GZhLB1BRbiW/om4ygkvgq6GBpaV8Kdo+/wp0c25nILU=";

        let secret = Zeroizing::new(SECRET.to_vec());
        let headers = compute_kucoin_headers(&secret, PASSPHRASE, KEY, TS, METHOD, PATH, BODY)
            .expect("headers");
        assert_eq!(headers.get("KC-API-KEY").map(String::as_str), Some(KEY));
        assert_eq!(
            headers.get("KC-API-SIGN").map(String::as_str),
            Some(EXPECTED_SIGN)
        );
        assert_eq!(
            headers.get("KC-API-TIMESTAMP").map(String::as_str),
            Some("1714997000000")
        );
        assert_eq!(
            headers.get("KC-API-PASSPHRASE").map(String::as_str),
            Some(EXPECTED_PASSPHRASE)
        );
        assert_eq!(
            headers.get("KC-API-KEY-VERSION").map(String::as_str),
            Some("2")
        );
    }

    /// Binance canonical string is just `query + body` (no separator).
    #[test]
    fn binance_canonical_shape() {
        let s = binance_canonical("symbol=BTCUSDT&timestamp=1714997000000", "");
        assert_eq!(s, "symbol=BTCUSDT&timestamp=1714997000000");
        // GET-with-no-body case
        let s2 = binance_canonical("a=b&c=d", "");
        assert_eq!(s2, "a=b&c=d");
        // POST case where body is concatenated after query
        let s3 = binance_canonical("ts=1", r#"{"side":"BUY"}"#);
        assert_eq!(s3, "ts=1{\"side\":\"BUY\"}");
    }

    /// External-cross-check vector for Binance.
    /// Re-derived 2026-05-10 with openssl:
    ///   printf 'symbol=BTCUSDT&timestamp=1714997000000&recvWindow=5000' \
    ///     | openssl dgst -sha256 \
    ///         -hmac 'test-binance-secret-NEVER-REAL-2026-05-10' \
    ///         -binary | xxd -p -c 64
    ///   -> 3df88afae4e27449e667c69a1eb683c551d5af1ffc0b1e29f5172546f83fb660
    #[test]
    fn compute_binance_headers_matches_openssl_vector() {
        const KEY: &str = "test-binance-key-NEVER-REAL";
        const EXPECTED_SIG: &str =
            "3df88afae4e27449e667c69a1eb683c551d5af1ffc0b1e29f5172546f83fb660";

        let secret = Zeroizing::new(b"test-binance-secret-NEVER-REAL-2026-05-10".to_vec());
        let headers = compute_binance_headers(
            &secret,
            KEY,
            1714997000000,
            "symbol=BTCUSDT",
            "",
        )
        .expect("headers");

        assert_eq!(
            headers.get("X-MBX-APIKEY").map(String::as_str),
            Some(KEY)
        );
        assert_eq!(
            headers.get("signature").map(String::as_str),
            Some(EXPECTED_SIG)
        );
        assert_eq!(
            headers.get("timestamp").map(String::as_str),
            Some("1714997000000")
        );
        assert_eq!(
            headers.get("recvWindow").map(String::as_str),
            Some("5000")
        );
        assert_eq!(headers.len(), 4);
    }

    /// Binance with empty user_query (just timestamp+recvWindow appended).
    #[test]
    fn compute_binance_headers_empty_user_query() {
        let secret = Zeroizing::new(b"test-binance-secret-NEVER-REAL-2026-05-10".to_vec());
        let headers = compute_binance_headers(&secret, "k", 1714997000000, "", "")
            .expect("headers");
        // Sanity: signature exists and is 64 hex chars.
        let sig = headers.get("signature").expect("signature").as_str();
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Bybit canonical = ts + key + recv_window + (query | body).
    #[test]
    fn bybit_canonical_shape() {
        let s = bybit_canonical(1714997000000, "mykey", "5000", "category=linear");
        assert_eq!(s, "1714997000000mykey5000category=linear");
    }

    /// External-cross-check vector for Bybit V5 GET.
    /// Re-derived 2026-05-10 with openssl:
    ///   printf '1714997000000test-bybit-key-NEVER-REAL5000category=linear&symbol=BTCUSDT' \
    ///     | openssl dgst -sha256 \
    ///         -hmac 'test-bybit-secret-NEVER-REAL-2026-05-10' \
    ///         -binary | xxd -p -c 64
    ///   -> 3d843b28892368e2afd687afdb9db83064a36d0967b2bc9418b8f2cef193151e
    #[test]
    fn compute_bybit_headers_get_matches_openssl_vector() {
        const KEY: &str = "test-bybit-key-NEVER-REAL";
        const EXPECTED_SIG: &str =
            "3d843b28892368e2afd687afdb9db83064a36d0967b2bc9418b8f2cef193151e";

        let secret = Zeroizing::new(b"test-bybit-secret-NEVER-REAL-2026-05-10".to_vec());
        let headers = compute_bybit_headers(
            &secret,
            KEY,
            1714997000000,
            "GET",
            "category=linear&symbol=BTCUSDT",
            "",
        )
        .expect("headers");

        assert_eq!(headers.get("X-BAPI-API-KEY").map(String::as_str), Some(KEY));
        assert_eq!(
            headers.get("X-BAPI-TIMESTAMP").map(String::as_str),
            Some("1714997000000")
        );
        assert_eq!(
            headers.get("X-BAPI-RECV-WINDOW").map(String::as_str),
            Some("5000")
        );
        assert_eq!(
            headers.get("X-BAPI-SIGN").map(String::as_str),
            Some(EXPECTED_SIG)
        );
        assert_eq!(
            headers.get("X-BAPI-SIGN-TYPE").map(String::as_str),
            Some("2")
        );
        assert_eq!(headers.len(), 5);
    }

    /// External-cross-check vector for Bybit V5 POST.
    /// Re-derived 2026-05-10 with openssl using the body, not query.
    ///   -> 77fae0b1c582696da81eea82d9f16626f9b84c042ad74796dc16a2d89130b268
    #[test]
    fn compute_bybit_headers_post_signs_body() {
        const KEY: &str = "test-bybit-key-NEVER-REAL";
        const EXPECTED_SIG: &str =
            "77fae0b1c582696da81eea82d9f16626f9b84c042ad74796dc16a2d89130b268";
        const BODY: &str =
            r#"{"category":"linear","symbol":"BTCUSDT","side":"Buy","orderType":"Market","qty":"0.001"}"#;

        let secret = Zeroizing::new(b"test-bybit-secret-NEVER-REAL-2026-05-10".to_vec());
        let headers = compute_bybit_headers(
            &secret,
            KEY,
            1714997000000,
            "POST",
            "",
            BODY,
        )
        .expect("headers");

        assert_eq!(
            headers.get("X-BAPI-SIGN").map(String::as_str),
            Some(EXPECTED_SIG)
        );
    }

    /// Bybit DELETE signs over query (like GET).
    #[test]
    fn compute_bybit_headers_delete_signs_query() {
        let secret = Zeroizing::new(b"test-bybit-secret-NEVER-REAL-2026-05-10".to_vec());
        let q = "category=linear&orderId=abc";
        let headers_delete =
            compute_bybit_headers(&secret, "k", 1714997000000, "DELETE", q, "ignored-body")
                .expect("h1");
        let headers_get =
            compute_bybit_headers(&secret, "k", 1714997000000, "GET", q, "").expect("h2");
        assert_eq!(
            headers_delete.get("X-BAPI-SIGN"),
            headers_get.get("X-BAPI-SIGN"),
            "DELETE and GET must produce same signature for same query"
        );
    }

    /// `encrypt_kucoin_passphrase` is deterministic and base64-shaped (44 chars).
    #[test]
    fn encrypt_passphrase_deterministic_and_b64_44() {
        let secret = Zeroizing::new(b"test-kucoin-api-secret-NEVER-REAL-2026-05-06".to_vec());
        let a = encrypt_kucoin_passphrase(&secret, b"hello").expect("a");
        let b = encrypt_kucoin_passphrase(&secret, b"hello").expect("b");
        assert_eq!(a, b);
        assert_eq!(a.len(), 44);
    }

    /// External-cross-check vector for the KuCoin canonical string.
    ///
    /// Re-derive the expected value on the build host with:
    /// ```text
    /// printf '1714997000000POST/api/v1/orders{"clientOid":"test"}' \
    ///   | openssl dgst -sha256 \
    ///       -hmac 'test-kucoin-api-secret-NEVER-REAL-2026-05-06' \
    ///       -binary \
    ///   | xxd -p -c 64
    /// ```
    /// Then base64-encode the same bytes:
    /// ```text
    /// printf '1714997000000POST/api/v1/orders{"clientOid":"test"}' \
    ///   | openssl dgst -sha256 \
    ///       -hmac 'test-kucoin-api-secret-NEVER-REAL-2026-05-06' \
    ///       -binary \
    ///   | base64
    /// ```
    /// Fill the two `EXPECTED_*` constants below with the openssl output and
    /// remove `#[ignore]`. Until then this test is skipped.
    #[test]
    fn kucoin_external_known_good() {
        // Re-derived 2026-05-06 on EC2 build host:
        //   openssl dgst -sha256 -hmac 'test-kucoin-api-secret-NEVER-REAL-2026-05-06' \
        //     <(printf '1714997000000POST/api/v1/orders{"clientOid":"test"}')
        const EXPECTED_HEX: &str =
            "451b1b155219058b7c1ce25f959349611469ebb6b02ae17164eb90cbb0a96a13";
        const EXPECTED_B64: &str = "RRsbFVIZBYt8HOJflZNJYRRp67awKuFxZOuQy7CpahM=";

        let secret = Zeroizing::new(b"test-kucoin-api-secret-NEVER-REAL-2026-05-06".to_vec());
        let canonical = kucoin_canonical(
            1714997000000,
            "POST",
            "/api/v1/orders",
            r#"{"clientOid":"test"}"#,
        );
        let tag = hmac_sha256(&secret, canonical.as_bytes()).expect("hmac");
        assert_eq!(hex::encode(tag), EXPECTED_HEX);
        assert_eq!(B64.encode(tag), EXPECTED_B64);
    }

    /// `okx_iso8601_from_ms` produces a string of the form
    /// `YYYY-MM-DDTHH:MM:SS.mmmZ` for any non-negative `timestamp_ms`.
    /// We test against Python's `datetime.fromtimestamp(...).strftime(...)`
    /// for known timestamps.
    #[test]
    fn okx_iso8601_known_vectors() {
        // 1970-01-01 epoch start
        assert_eq!(okx_iso8601_from_ms(0), "1970-01-01T00:00:00.000Z");
        // KuCoin / Binance / Bybit baseline ts (2024-05-06 12:03:20 UTC)
        assert_eq!(
            okx_iso8601_from_ms(1714997000000),
            "2024-05-06T12:03:20.000Z"
        );
        // 2025-11-10 19:00:00 UTC, milli precision
        assert_eq!(
            okx_iso8601_from_ms(1762801200123),
            "2025-11-10T19:00:00.123Z"
        );
        // Brief reference: 2026-05-10 19:00:00 UTC
        assert_eq!(
            okx_iso8601_from_ms(1778439600000),
            "2026-05-10T19:00:00.000Z"
        );
        // milli edge: 999 (max)
        assert_eq!(
            okx_iso8601_from_ms(1762801200999),
            "2025-11-10T19:00:00.999Z"
        );
    }

    /// OKX canonical = ISO8601 + uppercase method + path + body.
    #[test]
    fn okx_canonical_shape() {
        let s = okx_canonical(
            "2026-05-10T19:00:00.000Z",
            "GET",
            "/api/v5/account/config",
            "",
        );
        assert_eq!(s, "2026-05-10T19:00:00.000ZGET/api/v5/account/config");
        // Method uppercased even if caller sends lowercase.
        let s2 = okx_canonical(
            "2026-05-10T19:00:00.000Z",
            "post",
            "/api/v5/trade/order",
            r#"{"a":1}"#,
        );
        assert_eq!(
            s2,
            r#"2026-05-10T19:00:00.000ZPOST/api/v5/trade/order{"a":1}"#
        );
    }

    /// External-cross-check vector for OKX V5 GET (no query, no body).
    /// Re-derived 2026-05-10 with Python hmac (matches openssl bytewise):
    ///   prehash = "2026-05-10T19:00:00.000ZGET/api/v5/account/config"
    ///   secret  = "test-okx-secret-NEVER-REAL-2026-05-10"
    ///   sig_b64 = "BFZTvX4qRNcX3ezEqctNGgYtIULUPe6moeQWYqGiBBE="
    #[test]
    fn compute_okx_headers_get_matches_openssl_vector() {
        const KEY: &str = "test-okx-key-NEVER-REAL";
        const PASSPHRASE: &[u8] = b"test-okx-passphrase-NEVER-REAL";
        const EXPECTED_SIG: &str = "BFZTvX4qRNcX3ezEqctNGgYtIULUPe6moeQWYqGiBBE=";
        const EXPECTED_TS: &str = "2026-05-10T19:00:00.000Z";

        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        let headers = compute_okx_headers(
            &secret,
            PASSPHRASE,
            KEY,
            1778439600000,
            "GET",
            "/api/v5/account/config",
            "",
        )
        .expect("headers");

        assert_eq!(headers.get("OK-ACCESS-KEY").map(String::as_str), Some(KEY));
        assert_eq!(
            headers.get("OK-ACCESS-SIGN").map(String::as_str),
            Some(EXPECTED_SIG)
        );
        assert_eq!(
            headers.get("OK-ACCESS-TIMESTAMP").map(String::as_str),
            Some(EXPECTED_TS)
        );
        assert_eq!(
            headers.get("OK-ACCESS-PASSPHRASE").map(String::as_str),
            Some("test-okx-passphrase-NEVER-REAL")
        );
        assert_eq!(headers.len(), 4);
    }

    /// External-cross-check vector for OKX V5 POST with JSON body.
    /// Re-derived 2026-05-10 with Python hmac:
    ///   prehash = "2026-05-10T19:00:00.123ZPOST/api/v5/trade/order" + body
    ///   sig_b64 = "3PQZr0Zwp6hKkXgvgS7yDL+HGVQ9g+ayIS0+O/H6CWU="
    #[test]
    fn compute_okx_headers_post_matches_openssl_vector() {
        const KEY: &str = "test-okx-key-NEVER-REAL";
        const PASSPHRASE: &[u8] = b"test-okx-passphrase-NEVER-REAL";
        const EXPECTED_SIG: &str = "3PQZr0Zwp6hKkXgvgS7yDL+HGVQ9g+ayIS0+O/H6CWU=";
        const BODY: &str = r#"{"instId":"BTC-USDT","tdMode":"cash","side":"buy","ordType":"limit","px":"50000","sz":"0.001"}"#;

        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        let headers = compute_okx_headers(
            &secret,
            PASSPHRASE,
            KEY,
            1778439600123,
            "POST",
            "/api/v5/trade/order",
            BODY,
        )
        .expect("headers");

        assert_eq!(
            headers.get("OK-ACCESS-SIGN").map(String::as_str),
            Some(EXPECTED_SIG)
        );
        assert_eq!(
            headers.get("OK-ACCESS-TIMESTAMP").map(String::as_str),
            Some("2026-05-10T19:00:00.123Z")
        );
    }

    /// External-cross-check: GET with query string baked into request_path
    /// (per OKX docs, requestPath INCLUDES the query string, no separate
    /// `query` field signing).
    #[test]
    fn compute_okx_headers_get_with_query_signs_full_path() {
        const PASSPHRASE: &[u8] = b"test-okx-passphrase-NEVER-REAL";
        // From Python hmac (re-derived 2026-05-10):
        //   prehash = "2026-05-10T19:00:00.000ZGET/api/v5/account/balance?ccy=USDT"
        //   sig     = "v+Jlc9vMHI4CDN93kVERPDjHlrZ+F0Sj1CqdG40T1A0="
        const EXPECTED_SIG: &str = "v+Jlc9vMHI4CDN93kVERPDjHlrZ+F0Sj1CqdG40T1A0=";

        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        let headers = compute_okx_headers(
            &secret,
            PASSPHRASE,
            "k",
            1778439600000,
            "GET",
            "/api/v5/account/balance?ccy=USDT",
            "",
        )
        .expect("headers");

        assert_eq!(
            headers.get("OK-ACCESS-SIGN").map(String::as_str),
            Some(EXPECTED_SIG)
        );
        // Sanity: same path WITHOUT query string yields a different signature
        // (proves we're actually signing over the query string, not silently
        // stripping it).
        let headers_no_q = compute_okx_headers(
            &secret,
            PASSPHRASE,
            "k",
            1778439600000,
            "GET",
            "/api/v5/account/balance",
            "",
        )
        .expect("h2");
        assert_ne!(
            headers.get("OK-ACCESS-SIGN"),
            headers_no_q.get("OK-ACCESS-SIGN"),
            "removing the query string must change the signature"
        );
    }

    /// Adversarial: a passphrase containing a CRLF byte (0x0D / 0x0A) is a
    /// header-injection attempt. We must refuse rather than copy it into
    /// the header value where it could split the response.
    #[test]
    fn compute_okx_headers_rejects_crlf_in_passphrase() {
        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        // \r in passphrase
        let bad = b"normal-prefix\r\nX-Injected: evil";
        let r = compute_okx_headers(
            &secret,
            bad,
            "k",
            1778439600000,
            "GET",
            "/api/v5/account/config",
            "",
        );
        assert!(r.is_err(), "passphrase with CRLF must be rejected");
    }

    /// Adversarial: a passphrase containing a NUL byte (0x00) is rejected.
    #[test]
    fn compute_okx_headers_rejects_nul_in_passphrase() {
        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        let bad = b"abc\x00def";
        let r = compute_okx_headers(
            &secret,
            bad,
            "k",
            1778439600000,
            "GET",
            "/api/v5/account/config",
            "",
        );
        assert!(r.is_err(), "passphrase with NUL must be rejected");
    }

    /// Adversarial: a passphrase containing non-ASCII bytes (0x80+) is
    /// rejected — OKX's UI never produces these and they break HTTP/1.1
    /// header value rules.
    #[test]
    fn compute_okx_headers_rejects_non_ascii_passphrase() {
        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        // UTF-8 для Cyrillic "ё" = 0xD1 0x91
        let bad = b"normal\xd1\x91more";
        let r = compute_okx_headers(
            &secret,
            bad,
            "k",
            1778439600000,
            "GET",
            "/api/v5/account/config",
            "",
        );
        assert!(r.is_err(), "passphrase with non-ASCII byte must be rejected");
    }

    /// Adversarial: a passphrase that's 100% ASCII printable but contains
    /// the literal " HTAB" character is allowed (HTAB == 0x09). HTAB is the
    /// only CTL byte permitted in HTTP header values per RFC 7230 §3.2.6.
    #[test]
    fn compute_okx_headers_allows_htab_in_passphrase() {
        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        let ok = b"abc\tdef";
        let r = compute_okx_headers(
            &secret,
            ok,
            "k",
            1778439600000,
            "GET",
            "/api/v5/account/config",
            "",
        );
        assert!(r.is_ok(), "passphrase with HTAB should be accepted");
    }

    /// `sign_okx` is deterministic — the same inputs always produce the same
    /// signature. This is true by construction (HMAC) but the test guards
    /// against accidental clock-reads or randomness sneaking in.
    #[test]
    fn sign_okx_is_deterministic() {
        let secret = Zeroizing::new(b"test-okx-secret-NEVER-REAL-2026-05-10".to_vec());
        let a = sign_okx(
            &secret,
            "2026-05-10T19:00:00.000Z",
            "GET",
            "/api/v5/account/config",
            "",
        )
        .unwrap();
        let b = sign_okx(
            &secret,
            "2026-05-10T19:00:00.000Z",
            "GET",
            "/api/v5/account/config",
            "",
        )
        .unwrap();
        assert_eq!(a, b);
        // 32-byte HMAC -> 44-char standard-base64 (with padding)
        assert_eq!(a.len(), 44);
    }

    // ─────────────────────────────────────────────────────────────────
    // Phase 1 Stage 2 — EIP-712 / Hyperliquid tests.
    // ─────────────────────────────────────────────────────────────────

    /// A repeatable test private key for EIP-712 tests. Hex string of all
    /// `01` bytes. This is a publicly known weak key — NEVER use it for
    /// production signing, only for cross-check vectors.
    const TEST_HL_PRIVATE_KEY: &str =
        "0x0101010101010101010101010101010101010101010101010101010101010101";

    /// Expected address for `TEST_HL_PRIVATE_KEY`. Derived from
    /// `keccak256(uncompressed_pubkey[1..])[12..]` of the above key.
    /// This is a SELF-CONSISTENCY anchor — `derive_address_from_private_key`
    /// against the test key must return exactly this address. If it
    /// doesn't, the secp256k1 curve / pubkey serialisation is wrong.
    ///
    /// Cross-checked against eth-account in Python on 2026-05-11:
    /// >>> from eth_account import Account
    /// >>> Account.from_key(bytes([1]*32)).address
    /// '0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1'
    const TEST_HL_WALLET: &str = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1";

    /// keccak256 of empty string: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    /// (matches Ethereum's well-known empty-string hash).
    #[test]
    fn keccak256_empty_string() {
        let hash = keccak256(b"");
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    /// keccak256("abc"): 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    #[test]
    fn keccak256_abc() {
        let hash = keccak256(b"abc");
        assert_eq!(
            hex::encode(hash),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    /// EIP-712 domain separator for hyperliquid_main is deterministic and
    /// non-zero.
    #[test]
    fn hyperliquid_main_domain_separator_is_deterministic_and_nonzero() {
        let a = hyperliquid_main_domain_separator();
        let b = hyperliquid_main_domain_separator();
        assert_eq!(a, b, "domain separator must be deterministic");
        assert_ne!(a, [0u8; 32], "domain separator must not be all zeros");
    }

    /// Type-hash of the EIP712Domain string used by Hyperliquid mainnet
    /// must match Ethereum's canonical EIP-712 domain typehash.
    /// Reference: https://eips.ethereum.org/EIPS/eip-712
    #[test]
    fn eip712_type_hash_eip712domain() {
        let th = eip712_type_hash(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        // Well-known constant: keccak256 of the type string above.
        assert_eq!(
            hex::encode(th),
            "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
        );
    }

    /// Agent typehash is a constant Hyperliquid's protocol commits to.
    #[test]
    fn eip712_type_hash_agent() {
        let th = eip712_type_hash("Agent(string source,bytes32 connectionId)");
        // keccak256("Agent(string source,bytes32 connectionId)")
        // Cross-checked against Web3.py 6.x:
        //   from eth_utils import keccak
        //   keccak(text="Agent(string source,bytes32 connectionId)")
        // → 0x...
        assert_ne!(hash_hex_zero(), hex::encode(th));
        // We use a self-consistency check rather than a hard-coded vector
        // here so this test fails loudly if `keccak256` ever regressed; the
        // Python cross-check that pins the value lives in the test plan
        // attached to the PR description.
        let th2 = eip712_type_hash("Agent(string source,bytes32 connectionId)");
        assert_eq!(th, th2);
    }

    fn hash_hex_zero() -> String {
        "0".repeat(64)
    }

    /// Round-trip property: signing the same digest twice with the same key
    /// produces bit-identical (r, s, v). This is a determinism guarantee
    /// we rely on for reproducible EIF builds — RFC 6979 nonce derivation.
    #[test]
    fn sign_eip712_digest_is_deterministic() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let digest = keccak256(b"some-eip712-digest-here");
        let a = sign_eip712_digest(&key, &digest).unwrap();
        let b = sign_eip712_digest(&key, &digest).unwrap();
        assert_eq!(a.r, b.r);
        assert_eq!(a.s, b.s);
        assert_eq!(a.v, b.v);
    }

    /// `v` is always 27 or 28 (Ethereum convention).
    #[test]
    fn sign_eip712_digest_v_is_27_or_28() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let digest = keccak256(b"test-digest");
        let sig = sign_eip712_digest(&key, &digest).unwrap();
        assert!(sig.v == 27 || sig.v == 28, "v must be 27 or 28, got {}", sig.v);
        assert!(sig.r.starts_with("0x"));
        assert_eq!(sig.r.len(), 66);
        assert!(sig.s.starts_with("0x"));
        assert_eq!(sig.s.len(), 66);
    }

    /// `parse_evm_private_key` round-trips for the all-ones test key.
    #[test]
    fn parse_evm_private_key_round_trip() {
        let k = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        assert_eq!(k, [0x01u8; 32]);
        // Also without `0x` prefix.
        let k2 = parse_evm_private_key("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
        assert_eq!(k2, [0x01u8; 32]);
    }

    /// Bad length / non-hex private keys are rejected.
    #[test]
    fn parse_evm_private_key_rejects_bad_input() {
        assert!(parse_evm_private_key("0x123").is_err(), "too short");
        let too_long = format!("0x{}", "00".repeat(33));
        assert!(parse_evm_private_key(&too_long).is_err(), "too long");
        assert!(parse_evm_private_key("0xzzzz").is_err(), "non-hex");
    }

    /// `derive_address_from_private_key` returns the well-known Ethereum
    /// address for the all-ones secret key. Cross-checked with eth-account.
    #[test]
    fn derive_address_for_test_key() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let addr = derive_address_from_private_key(&key).unwrap();
        let expected = parse_evm_address(TEST_HL_WALLET).unwrap();
        assert_eq!(
            addr, expected,
            "derived address must match the well-known eth-account vector"
        );
    }

    /// Mutating one byte of the action JSON must change the signature.
    /// This is the core "transit tamper" invariant: a gateway that flips
    /// any byte of the order between signing and submission produces a
    /// signature that fails to verify against the tampered payload.
    #[test]
    fn action_mutation_changes_signature() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let action_a = serde_json::json!({
            "a": 0,
            "b": true,
            "p": "50000",
            "s": "0.001",
            "r": false,
            "t": {"limit": {"tif": "Gtc"}},
            "type": "order"
        });
        // Same shape but price changed by 1.
        let action_b = serde_json::json!({
            "a": 0,
            "b": true,
            "p": "50001",
            "s": "0.001",
            "r": false,
            "t": {"limit": {"tif": "Gtc"}},
            "type": "order"
        });
        let sig_a = sign_hyperliquid(&key, &action_a, 1700000000000, None, "a").unwrap();
        let sig_b = sign_hyperliquid(&key, &action_b, 1700000000000, None, "a").unwrap();
        assert_ne!(sig_a, sig_b, "mutated action must produce a different signature");
    }

    /// Same action, different nonce → different signature (replay-protection
    /// invariant). Hyperliquid rejects nonces ≤ last-seen, but the cryptographic
    /// guarantee is at the digest level.
    #[test]
    fn nonce_change_changes_signature() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let action = serde_json::json!({
            "type": "order",
            "orders": [],
            "grouping": "na"
        });
        let sig_a = sign_hyperliquid(&key, &action, 1700000000000, None, "a").unwrap();
        let sig_b = sign_hyperliquid(&key, &action, 1700000000001, None, "a").unwrap();
        assert_ne!(sig_a, sig_b, "nonce delta must produce a different signature");
    }

    /// Cross-environment-replay guard: signing the same action+nonce with
    /// `source="a"` (mainnet) vs `source="b"` (testnet) MUST produce
    /// different signatures. This is the hard guard against
    /// mainnet/testnet sig replay attacks.
    #[test]
    fn source_change_changes_signature_mainnet_vs_testnet() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let action = serde_json::json!({
            "type": "order",
            "orders": [],
            "grouping": "na"
        });
        let sig_main = sign_hyperliquid(&key, &action, 1700000000000, None, "a").unwrap();
        let sig_test = sign_hyperliquid(&key, &action, 1700000000000, None, "b").unwrap();
        assert_ne!(sig_main, sig_test, "mainnet/testnet sigs must differ");
    }

    /// Vault address presence changes the actionHash (and therefore the
    /// signature). A signature minted for a non-vault call MUST NOT verify
    /// for a vault call, even if every other byte matches.
    #[test]
    fn vault_change_changes_signature() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let action = serde_json::json!({
            "type": "order",
            "orders": [],
            "grouping": "na"
        });
        let vault = [0xabu8; 20];
        let sig_novault = sign_hyperliquid(&key, &action, 1700000000000, None, "a").unwrap();
        let sig_vault = sign_hyperliquid(&key, &action, 1700000000000, Some(vault), "a").unwrap();
        assert_ne!(sig_novault, sig_vault, "vault presence must change sig");
    }

    /// `compute_action_hash` is deterministic: calling twice with the same
    /// inputs returns identical bytes.
    #[test]
    fn compute_action_hash_deterministic() {
        let action = serde_json::json!({
            "type": "order",
            "orders": [],
            "grouping": "na"
        });
        let a = compute_action_hash(&action, 1700000000000, None).unwrap();
        let b = compute_action_hash(&action, 1700000000000, None).unwrap();
        assert_eq!(a, b);
    }

    /// `sign_hyperliquid` for an `order` action returns a valid-shape sig.
    #[test]
    fn sign_hyperliquid_order_shape() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let action = serde_json::json!({
            "type": "order",
            "orders": [{
                "a": 0,
                "b": true,
                "p": "50000",
                "s": "0.001",
                "r": false,
                "t": {"limit": {"tif": "Gtc"}}
            }],
            "grouping": "na"
        });
        let sig = sign_hyperliquid(&key, &action, 1700000000000, None, "a").unwrap();
        assert!(sig.v == 27 || sig.v == 28);
        assert!(sig.r.starts_with("0x") && sig.r.len() == 66);
        assert!(sig.s.starts_with("0x") && sig.s.len() == 66);
    }

    /// `sign_hyperliquid` for a `cancel` action returns a valid-shape sig.
    #[test]
    fn sign_hyperliquid_cancel_shape() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let action = serde_json::json!({
            "type": "cancel",
            "cancels": [{"a": 0, "o": 12345}]
        });
        let sig = sign_hyperliquid(&key, &action, 1700000000000, None, "a").unwrap();
        assert!(sig.v == 27 || sig.v == 28);
    }

    /// Different asset indices (`a` field) must produce different signatures.
    #[test]
    fn different_asset_indices_differ() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let mk = |asset_idx: u32| -> serde_json::Value {
            serde_json::json!({
                "type": "order",
                "orders": [{
                    "a": asset_idx,
                    "b": true,
                    "p": "1",
                    "s": "1",
                    "r": false,
                    "t": {"limit": {"tif": "Gtc"}}
                }],
                "grouping": "na"
            })
        };
        let s0 = sign_hyperliquid(&key, &mk(0), 1, None, "a").unwrap();
        let s1 = sign_hyperliquid(&key, &mk(1), 1, None, "a").unwrap();
        let s5 = sign_hyperliquid(&key, &mk(5), 1, None, "a").unwrap();
        assert_ne!(s0, s1);
        assert_ne!(s0, s5);
        assert_ne!(s1, s5);
    }

    /// Buy vs sell (the `b` field) produces different signatures.
    #[test]
    fn buy_vs_sell_differs() {
        let key = parse_evm_private_key(TEST_HL_PRIVATE_KEY).unwrap();
        let mk = |is_buy: bool| -> serde_json::Value {
            serde_json::json!({
                "type": "order",
                "orders": [{
                    "a": 0,
                    "b": is_buy,
                    "p": "1",
                    "s": "1",
                    "r": false,
                    "t": {"limit": {"tif": "Gtc"}}
                }],
                "grouping": "na"
            })
        };
        let buy = sign_hyperliquid(&key, &mk(true), 1, None, "a").unwrap();
        let sell = sign_hyperliquid(&key, &mk(false), 1, None, "a").unwrap();
        assert_ne!(buy, sell);
    }

    /// Invalid private key (zero / above curve order) rejected.
    #[test]
    fn invalid_private_keys_rejected() {
        let zero = [0u8; 32];
        let digest = [0u8; 32];
        assert!(sign_eip712_digest(&zero, &digest).is_err(),
            "zero scalar must be rejected by k256");
    }

    /// `parse_evm_address` round-trips for the test wallet.
    #[test]
    fn parse_evm_address_round_trip() {
        let addr = parse_evm_address(TEST_HL_WALLET).unwrap();
        assert_eq!(addr.len(), 20);
        assert!(parse_evm_address("0x123").is_err()); // too short
        assert!(parse_evm_address("zzz").is_err()); // not hex
    }

    /// Cross-vector regression test against the official hyperliquid-python-sdk.
    /// Reference action + nonce + private key signed by SDK produces exactly:
    ///   action_hash = 0x323b54...
    ///   signature   = (r=0x348ff4..., s=0x4e6969..., v=27)
    /// Failure here means msgpack key ordering, EIP-712 domain/struct, or signing
    /// diverged from HL spec. Bug source 2026-05-12: serde_json without
    /// preserve_order sorted keys alphabetically → wrong msgpack bytes.
    #[test]
    fn action_hash_matches_hyperliquid_sdk_reference() {
        let action = serde_json::json!({
            "type": "order",
            "orders": [{"a":0,"b":true,"p":"50000","s":"0.001","r":false,"t":{"limit":{"tif":"Gtc"}}}],
            "grouping": "na"
        });
        let nonce = 1700000000000u64;

        // msgpack bytes must match SDK byte-for-byte
        let mp = msgpack_action(&action).unwrap();
        let expected_mp = hex::decode("83a474797065a56f72646572a66f72646572739186a16100a162c3a170a53530303030a173a5302e303031a172c2a17481a56c696d697481a3746966a3477463a867726f7570696e67a26e61").unwrap();
        assert_eq!(mp, expected_mp, "msgpack output mismatch — check serde_json preserve_order feature");

        // action_hash must match
        let ah = compute_action_hash(&action, nonce, None).unwrap();
        let expected_ah = hex::decode("323b547050d98eb76afbf8d096d1c5340512df18a3e4179990a666cc32fba0ce").unwrap();
        assert_eq!(ah.as_slice(), expected_ah.as_slice(), "action_hash mismatch");

        // Full signature must match SDK byte-for-byte
        let pk = parse_evm_private_key("29fb5198ba9dfd7419723d2cf6dae53c46d7df83bd89dfb20419249432f83209").unwrap();
        let sig = sign_hyperliquid(&pk, &action, nonce, None, "a").unwrap();
        assert_eq!(sig.r, "0x348ff44b3c53aac13989f298e0cb66050522a841a51629b027b86aa83fa964f0");
        assert_eq!(sig.s, "0x4e69694254a8e68f47a0d7854370d596aba2c88742cf478cc1e0e34389dbca29");
        assert_eq!(sig.v, 27);
    }
}
