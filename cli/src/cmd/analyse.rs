//! `gpt analyse` — render a full forensic analysis as a fixed-width ASCII report.

use std::fmt::Write as _;
use std::io::{Read, Seek};

use gpt_forensic::{analyse, Error};

/// Width of the report's horizontal rules.
const RULE: usize = 80;

/// Run a full GPT forensic analysis over `reader` and format an ASCII report.
///
/// `disk_size` bounds the backup-GPT read (`0` = locate it via the primary
/// header alone); `image_name` is echoed into the report header.
pub fn run<R: Read + Seek>(
    reader: &mut R,
    disk_size: u64,
    image_name: &str,
) -> Result<String, Error> {
    let a = analyse(reader, disk_size)?;
    let mut out = String::new();

    writeln!(out, "GPT Forensic Analysis: {image_name}").unwrap();
    out.push_str(&"=".repeat(RULE));
    out.push('\n');

    let rev_hi = a.primary.revision >> 16;
    let rev_lo = a.primary.revision & 0xFFFF;
    writeln!(out, "Disk GUID:       {}", a.disk_guid).unwrap();
    writeln!(out, "Revision:        {rev_hi}.{rev_lo}").unwrap();
    writeln!(
        out,
        "Header CRC:      {}",
        if a.primary.header_crc_valid {
            "valid"
        } else {
            "INVALID"
        }
    )
    .unwrap();
    writeln!(
        out,
        "Usable LBAs:     {}..{}",
        a.primary.first_usable_lba, a.primary.last_usable_lba
    )
    .unwrap();
    writeln!(out, "Sector size:     {} bytes", a.sector_size).unwrap();
    writeln!(out, "GPT SHA-256:     {}", a.gpt_sha256).unwrap();
    match &a.backup {
        Some(b) => writeln!(out, "Backup GPT:      present (LBA {})", b.my_lba).unwrap(),
        None => out.push_str("Backup GPT:      MISSING\n"),
    }
    out.push('\n');

    // ── Partition table ─────────────────────────────────────────────────────
    writeln!(out, "Partitions ({}):", a.partitions.len()).unwrap();
    writeln!(
        out,
        "{:<3} {:<31} {:<12} {:<11} NAME",
        "#", "TYPE", "FIRST LBA", "LAST LBA"
    )
    .unwrap();
    writeln!(
        out,
        "{} {} {} {} {}",
        "-".repeat(3),
        "-".repeat(31),
        "-".repeat(12),
        "-".repeat(11),
        "-".repeat(24)
    )
    .unwrap();
    for (i, p) in a.partitions.iter().enumerate() {
        // Resolve the type GUID to a human name, falling back to the raw GUID.
        let ty = p
            .type_name()
            .map_or_else(|| p.type_guid.to_string(), ToString::to_string);
        writeln!(
            out,
            "{i:<3} {ty:<31} {:<12} {:<11} {}",
            p.first_lba, p.last_lba, p.name
        )
        .unwrap();
    }
    out.push('\n');

    // ── Anomalies ───────────────────────────────────────────────────────────
    if a.anomalies.is_empty() {
        out.push_str("Anomalies:       none\n");
    } else {
        writeln!(out, "Anomalies ({}):", a.anomalies.len()).unwrap();
        for an in &a.anomalies {
            writeln!(out, "  [{}] {}: {}", an.severity, an.code, an.note).unwrap();
        }
    }
    out.push('\n');

    out.push_str(&"=".repeat(RULE));
    out.push('\n');
    match a.max_severity() {
        None => out.push_str("Result:          clean (no anomalies detected)\n"),
        Some(sev) => writeln!(
            out,
            "Result:          {} anomaly(ies), max severity {sev}",
            a.anomalies.len()
        )
        .unwrap(),
    }
    Ok(out)
}
