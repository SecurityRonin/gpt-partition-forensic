//! Shannon entropy over byte slices.
//!
//! Used to spot **hidden encrypted volumes**: a partition whose content is
//! near-maximal entropy (≈ 8 bits/byte) with no readable filesystem structure is
//! consistent with an encrypted container (`VeraCrypt` / detached LUKS).

/// Entropy (bits/byte) above which a region is treated as encrypted/random
/// rather than a structured filesystem.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

/// Compute the Shannon entropy (bits per byte, range 0.0–8.0) of `data`.
///
/// Returns `0.0` for an empty slice.
#[must_use]
#[allow(clippy::cast_precision_loss)] // counts/len fit f64 exactly for realistic inputs
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
