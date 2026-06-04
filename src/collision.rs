//! Cross-disk GPT disk-GUID collision detection.
//!
//! A GPT disk GUID is meant to be unique per physical disk. Two images that
//! share the same disk GUID indicate one was **cloned or imaged** from the other
//! — the GPT analogue of the NT disk-signature collision in `mbr-forensic`. This
//! is a cross-disk utility: a caller analyses several images and passes their
//! disk GUIDs in.
//!
//! It also provides [`find_duplicate_partition_guids`] for the intra-disk case:
//! two partition entries sharing one unique GUID (a cloned/duplicated entry).

use crate::entry::GptEntry;

/// A set of disks that share one (non-zero) GPT disk GUID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct GuidCollision {
    /// The shared disk GUID (uppercase canonical form).
    pub guid: String,
    /// Indices (into the caller's input slice) of every disk carrying it,
    /// in ascending order.
    pub members: Vec<usize>,
}

/// The all-zero GUID — the "unset" convention, never a real shared identity.
const ZERO_GUID: &str = "00000000-0000-0000-0000-000000000000";

/// Find all disk-GUID collisions across `guids` (compared case-insensitively).
///
/// `guids[i]` is disk `i`'s GPT disk GUID. Returns one [`GuidCollision`] per
/// value shared by two or more disks, ordered by first appearance. The all-zero
/// GUID is excluded.
#[must_use]
pub fn find_disk_guid_collisions(guids: &[&str]) -> Vec<GuidCollision> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
    for (i, g) in guids.iter().enumerate() {
        let key = g.to_ascii_uppercase();
        if key == ZERO_GUID {
            continue;
        }
        let entry = groups.entry(key.clone()).or_default();
        if entry.is_empty() {
            order.push(key);
        }
        entry.push(i);
    }
    order
        .into_iter()
        .filter_map(|guid| {
            let members = groups.remove(&guid).unwrap_or_default();
            (members.len() >= 2).then_some(GuidCollision { guid, members })
        })
        .collect()
}

/// Find pairs of partition entries that share a unique GUID — a duplicated or
/// cloned entry within a single disk. Returns each colliding `(a, b)` index pair
/// once, with `a < b`, in ascending order. The all-zero unique GUID is ignored.
#[must_use]
pub fn find_duplicate_partition_guids(entries: &[GptEntry]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for a in 0..entries.len() {
        if entries[a].unique_guid.is_zero() {
            continue;
        }
        for b in (a + 1)..entries.len() {
            if entries[a].unique_guid == entries[b].unique_guid {
                out.push((a, b));
            }
        }
    }
    out
}
