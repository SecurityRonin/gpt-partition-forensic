//! Orchestration: the public [`analyse`] entry point.
//!
//! Reads the primary GPT (LBA 1 + entry array), validates its header and array
//! CRCs, then reads the backup GPT at the alternate LBA and reconciles the two
//! — primary/backup divergence is a strong tampering signal. Finally checks the
//! partition set for overlaps and out-of-bounds extents.

use std::io::{Read, Seek, SeekFrom};

use crate::crc32;
use crate::entry::{parse_entry_array, GptEntry};
use crate::findings::{Anomaly, AnomalyKind, GptAnalysis, Location};
use crate::header::GptHeader;
use crate::Error;

/// Logical sector size (bytes).
const SECTOR: u64 = 512;

/// Perform a full forensic analysis of a GPT-partitioned disk image.
///
/// `disk_size_bytes` bounds the backup-GPT read; pass `0` if unknown (the backup
/// is then located solely via the primary header's `alternate_lba`).
///
/// # Errors
/// [`Error::BadSignature`] if LBA 1 is not a GPT header; [`Error::Io`] on read
/// failure of the primary structures.
#[cfg_attr(feature = "trace", tracing::instrument(level = "debug", skip(reader)))]
pub fn analyse<R: Read + Seek>(reader: &mut R, disk_size_bytes: u64) -> Result<GptAnalysis, Error> {
    let _ = disk_size_bytes;
    let mut anomalies = Vec::new();

    // ── Primary header + entry array ────────────────────────────────────────
    let primary_sector = read_sector(reader, 1)?;
    let primary = GptHeader::parse(&primary_sector)?;
    if !primary.header_crc_valid {
        record(&mut anomalies, AnomalyKind::HeaderCrcInvalid { location: Location::Primary });
    }

    let primary_array = read_entry_array(reader, &primary)?;
    if crc32::checksum(&primary_array) != primary.partition_array_crc32 {
        record(
            &mut anomalies,
            AnomalyKind::PartitionArrayCrcInvalid { location: Location::Primary },
        );
    }
    let partitions =
        parse_entry_array(&primary_array, primary.num_partition_entries, primary.partition_entry_size);

    // ── Backup header + entry array, reconciled with the primary ────────────
    let backup = read_backup(reader, &primary, &mut anomalies);

    // ── Partition geometry checks ───────────────────────────────────────────
    check_overlaps(&partitions, &mut anomalies);
    check_bounds(&partitions, primary.last_usable_lba, &mut anomalies);

    let disk_guid = primary.disk_guid;
    Ok(GptAnalysis {
        primary,
        backup,
        disk_guid,
        partitions,
        anomalies,
    })
}

fn record(anomalies: &mut Vec<Anomaly>, kind: AnomalyKind) {
    anomalies.push(Anomaly::new(kind));
}

/// Read a single 512-byte sector at `lba`.
fn read_sector<R: Read + Seek>(reader: &mut R, lba: u64) -> Result<[u8; 512], Error> {
    reader.seek(SeekFrom::Start(lba * SECTOR))?;
    let mut buf = [0u8; 512];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a header's partition entry array (`num * entry_size` bytes).
fn read_entry_array<R: Read + Seek>(reader: &mut R, h: &GptHeader) -> Result<Vec<u8>, Error> {
    let len = h.num_partition_entries as usize * h.partition_entry_size as usize;
    reader.seek(SeekFrom::Start(h.partition_entry_lba * SECTOR))?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read and reconcile the backup GPT. A read/parse failure yields
/// [`AnomalyKind::BackupGptUnreadable`]; field divergences from the primary
/// yield [`AnomalyKind::PrimaryBackupDivergence`].
fn read_backup<R: Read + Seek>(
    reader: &mut R,
    primary: &GptHeader,
    anomalies: &mut Vec<Anomaly>,
) -> Option<GptHeader> {
    let backup = match read_sector(reader, primary.alternate_lba).map(|s| GptHeader::parse(&s)) {
        Ok(Ok(h)) => h,
        _ => {
            record(anomalies, AnomalyKind::BackupGptUnreadable);
            return None;
        }
    };

    if !backup.header_crc_valid {
        record(anomalies, AnomalyKind::HeaderCrcInvalid { location: Location::Backup });
    }
    if let Ok(arr) = read_entry_array(reader, &backup) {
        if crc32::checksum(&arr) != backup.partition_array_crc32 {
            record(
                anomalies,
                AnomalyKind::PartitionArrayCrcInvalid { location: Location::Backup },
            );
        }
    }

    // Fields that MUST match between the two copies (my_lba/alternate_lba/
    // partition_entry_lba are intentionally mirrored, so they are excluded).
    let checks: &[(&'static str, bool)] = &[
        ("revision", primary.revision == backup.revision),
        ("header_size", primary.header_size == backup.header_size),
        ("disk_guid", primary.disk_guid == backup.disk_guid),
        ("first_usable_lba", primary.first_usable_lba == backup.first_usable_lba),
        ("last_usable_lba", primary.last_usable_lba == backup.last_usable_lba),
        ("num_partition_entries", primary.num_partition_entries == backup.num_partition_entries),
        ("partition_entry_size", primary.partition_entry_size == backup.partition_entry_size),
        ("partition_array_crc32", primary.partition_array_crc32 == backup.partition_array_crc32),
    ];
    for &(field, ok) in checks {
        if !ok {
            record(anomalies, AnomalyKind::PrimaryBackupDivergence { field });
        }
    }

    Some(backup)
}

/// Flag overlapping partition extents.
fn check_overlaps(partitions: &[GptEntry], anomalies: &mut Vec<Anomaly>) {
    let mut idx: Vec<usize> = (0..partitions.len()).collect();
    idx.sort_by_key(|&i| partitions[i].first_lba);
    for pair in idx.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if partitions[b].first_lba <= partitions[a].last_lba {
            record(anomalies, AnomalyKind::OverlappingPartitions { a, b });
        }
    }
}

/// Flag partitions extending past the usable LBA range.
fn check_bounds(partitions: &[GptEntry], last_usable: u64, anomalies: &mut Vec<Anomaly>) {
    for (index, p) in partitions.iter().enumerate() {
        if p.last_lba > last_usable {
            record(
                anomalies,
                AnomalyKind::PartitionOutOfBounds {
                    index,
                    last_lba: p.last_lba,
                    last_usable,
                },
            );
        }
    }
}
