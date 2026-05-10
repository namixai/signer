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
}
