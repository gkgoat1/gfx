//! Timestamp transforms (plan §4.4): canonical raw regeneration, UTC
//! bucketing, and seeded jitter. Pure functions of their inputs — no
//! clocks, no RNG.

use crate::TimeBucketUnit;
use alloc::string::String;
use bstr::BString;

/// Canonical ident-time raw: `"<epoch> ±HHMM"` with a leading `-` for
/// pre-1970 epochs. Only used for *altered* fields — unaltered fields keep
/// their original raw bytes (plan §4.2 canonicalization rule).
pub(crate) fn format_raw(epoch: i64, tz_offset_min: i16) -> BString {
    let sign = if tz_offset_min < 0 { '-' } else { '+' };
    let abs = tz_offset_min.unsigned_abs();
    let raw = alloc::format!("{epoch} {sign}{:02}{:02}", abs / 60, abs % 60);
    BString::from(raw.into_bytes())
}

/// Floor an epoch to a UTC boundary. Handles negative epochs via
/// `div_euclid`-style arithmetic; deterministic, no DST/local-time logic.
pub(crate) fn bucket_floor(epoch: i64, unit: TimeBucketUnit) -> Option<i64> {
    match unit {
        TimeBucketUnit::Day => Some(epoch.div_euclid(86_400) * 86_400),
        TimeBucketUnit::Week => {
            // Days since epoch; 1970-01-01 was a Thursday (dow 3 with
            // Monday = 0), so Monday-aligned day index is
            // (days + 3).rem_euclid(7).
            let days = epoch.div_euclid(86_400);
            let back = (days + 3).rem_euclid(7);
            Some((days - back) * 86_400)
        }
        TimeBucketUnit::Month => {
            let days = epoch.div_euclid(86_400);
            let (y, m, _d) = civil_from_days(days);
            let first = days_from_civil(y, m, 1);
            // Floor to midnight of the 1st: keeping the time-of-day would
            // leak exactly the activity hours this mode exists to hide.
            first.checked_mul(86_400)
        }
    }
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (y, m, d).
/// Valid for the `i64` range we accept; documented for UTC.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Howard Hinnant's `days_from_civil`: (y, m, d) → days since 1970-01-01.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400); // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Keyed non-crypto digest over `(seed, role_tag, original_raw_bytes)`:
/// splitmix64 finalizer over an FNV-1a walk. Deterministic and
/// allocation-light; honest about what it is (plan §4.4: obfuscation with a
/// retained seed, not cryptography).
pub(crate) fn keyed_hash(seed: u64, role_tag: u8, raw: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325 ^ seed.rotate_left(17);
    for b in core::iter::once(&role_tag).chain(raw.iter()) {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // splitmix64 finalizer
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Jittered epoch: `epoch + (H mod (2J+1)) - J`, checked.
pub(crate) fn fuzz_shift(
    epoch: i64,
    seed: u64,
    role_tag: u8,
    raw: &[u8],
    jitter_secs: u64,
) -> Option<i64> {
    // Span in u128 so a huge jitter cannot wrap the modulo.
    let span = 2u128 * u128::from(jitter_secs) + 1;
    let h = u128::from(keyed_hash(seed, role_tag, raw));
    let delta = i128::try_from(h % span).ok()? - i128::from(jitter_secs);
    let shifted = i128::from(epoch) + delta;
    i64::try_from(shifted).ok()
}

/// 8-hex digest for [`crate::PseudonymStyle::Hash`] pseudonyms.
pub(crate) fn hex8(h: u64) -> String {
    alloc::format!("{h:08x}")
}

/// FNV-1a over name bytes, a separator, then email bytes.
pub(crate) fn ident_digest(name: &[u8], email: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.iter().chain(core::iter::once(&0x00)).chain(email.iter()) {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
