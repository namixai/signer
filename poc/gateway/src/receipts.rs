//! Gateway side of decision receipts (`enclave/src/receipt.rs`,
//! `docs/DECISION-RECEIPTS-DESIGN.md` §2).
//!
//! The enclave signs a receipt for every tenant decision; the gateway is a
//! courier and an archivist, never an author:
//!
//! 1. **Courier** — the receipt rides in the HTTP response to the client
//!    (`receipt` on the success bodies of the trade routes, and inside the
//!    explainable-denial body on a refusal), so the party that asked for the
//!    decision holds the proof.
//! 2. **Archivist** — every receipt the gateway sees is appended to
//!    `$SIGNER_RECEIPTS_DIR/<customer>/<utc-date>.jsonl` (default
//!    `/var/lib/signer/receipts`). This is the forensic material that survives
//!    an enclave restart (the enclave keeps nothing); a gap in `seq` inside one
//!    `boot_id` here means the gateway lost or hid a decision — the file is the
//!    place an auditor checks that.
//!
//! The log is append-only, best-effort and NEVER blocks a response: a write
//! failure is logged at ERROR (`receipt_log_failed`) and the client still gets
//! the receipt. Lines are not fsync'ed individually (a receipt is already in
//! the client's hands); durability of the archive is the box's disk, and
//! shipping off-box is the design's phase 2.
//!
//! `decided_by` on denials is derived BY CONSTRUCTION, not by hand: responses
//! built from an enclave reply say `enclave`, responses the gateway produced
//! on its own say `gateway` (`proto::ErrorResponse::{from_enclave,new}`).

use std::io::Write;
use std::path::PathBuf;

use tracing::error;

pub const DEFAULT_RECEIPTS_DIR: &str = "/var/lib/signer/receipts";
pub const RECEIPTS_DIR_ENV: &str = "SIGNER_RECEIPTS_DIR";

/// Resolved once: the env is process-wide state and this used to be read on
/// every decision (Gemini).
fn receipts_dir() -> &'static PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        std::env::var(RECEIPTS_DIR_ENV)
            .ok()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_RECEIPTS_DIR))
    })
}

fn utc_date(now_unix: u64) -> String {
    // Civil date from days since epoch (Howard Hinnant's algorithm) — no chrono.
    let days = (now_unix / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn safe_label(customer: &str) -> String {
    customer
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Append one receipt to the customer's daily JSONL file. Never fails the
/// caller. `dir` is injectable for tests.
pub fn record_in(
    dir: &std::path::Path,
    customer: &str,
    receipt: &serde_json::Value,
    now_unix: u64,
) {
    let d = dir.join(safe_label(customer));
    let path = d.join(format!("{}.jsonl", utc_date(now_unix)));
    let res = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&d)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let mut line = serde_json::to_vec(receipt)?;
        line.push(b'\n');
        f.write_all(&line)?;
        f.flush()
    })();
    if let Err(e) = res {
        error!(event = "receipt_log_failed", customer = %customer, path = %path.display(), error = %e, "receipt delivered to the client but NOT archived");
    }
}

/// Archive a receipt the enclave just issued for `customer`.
///
/// Runs OFF the request path: the append goes to the blocking pool, so a
/// stalled filesystem delays the archive, never the response the client is
/// waiting for (Gemini + CodeRabbit). Outside a runtime (tests, one-shot
/// tooling) it writes inline.
///
/// Deliberately NOT a bounded queue that drops when full: a dropped archival
/// line is exactly the gap an auditor reads as "the gateway hid a decision",
/// which is the property this file exists to support. Volume is bounded
/// upstream by the per-token rate limits and each item is a few hundred bytes.
pub fn record(customer: &str, receipt: &serde_json::Value) {
    let now = crate::limits::now_unix_secs();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let customer = customer.to_owned();
            let receipt = receipt.clone();
            handle.spawn_blocking(move || record_in(receipts_dir(), &customer, &receipt, now));
        }
        Err(_) => record_in(receipts_dir(), customer, receipt, now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_date_is_correct() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(1_700_000_000), "2023-11-14");
        assert_eq!(utc_date(1_755_820_800), "2025-08-22");
    }

    #[test]
    fn appends_one_line_per_receipt_in_daily_file() {
        let dir = std::env::temp_dir().join(format!("receipts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let r1 = serde_json::json!({"seq":"0","decision":"deny"});
        let r2 = serde_json::json!({"seq":"1","decision":"allow"});
        record_in(&dir, "cust/../x", &r1, 1_700_000_000);
        record_in(&dir, "cust/../x", &r2, 1_700_000_000);
        // "/" and "." are both mapped to "_" — no path traversal through a label.
        let path = dir.join("cust____x").join("2023-11-14.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"seq\":\"0\""));
        assert!(lines[1].contains("\"seq\":\"1\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_failure_does_not_panic() {
        let parent = std::env::temp_dir().join(format!("receipts-file-{}", std::process::id()));
        std::fs::write(&parent, b"not a dir").unwrap();
        record_in(&parent, "c", &serde_json::json!({}), 1);
        let _ = std::fs::remove_file(&parent);
    }
}
