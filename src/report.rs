//! Human-readable text rendering of a [`GptAnalysis`].
//!
//! Dependency-free `String` building, mirroring `mbr-forensic` and
//! `apm-forensic`, so the unified `disk-forensic` CLI can render a full GPT
//! report. Machine-readable output is available via the `serde` feature.

use core::fmt::Write as _;

use crate::findings::GptAnalysis;

/// Width of the report's horizontal rules.
const RULE: usize = 80;

/// Render a full GPT forensic analysis as a fixed-width ASCII report.
#[must_use]
pub fn text_report(a: &GptAnalysis) -> String {
    let mut out = String::new();
    out.push_str("GPT Forensic Analysis\n");
    out.push_str(&"=".repeat(RULE));
    out.push('\n');

    let rev_hi = a.primary.revision >> 16;
    let rev_lo = a.primary.revision & 0xFFFF;
    let _ = writeln!(out, "Disk GUID:       {}", a.disk_guid);
    let _ = writeln!(out, "Revision:        {rev_hi}.{rev_lo}");
    let _ = writeln!(
        out,
        "Header CRC:      {}",
        if a.primary.header_crc_valid {
            "valid"
        } else {
            "INVALID"
        }
    );
    let _ = writeln!(
        out,
        "Usable LBAs:     {}..{}",
        a.primary.first_usable_lba, a.primary.last_usable_lba
    );
    let _ = writeln!(out, "Sector size:     {} bytes", a.sector_size);
    let _ = writeln!(out, "GPT SHA-256:     {}", a.gpt_sha256);
    match &a.backup {
        Some(b) => {
            let _ = writeln!(out, "Backup GPT:      present (LBA {})", b.my_lba);
        }
        None => out.push_str("Backup GPT:      MISSING\n"),
    }
    out.push('\n');

    let _ = writeln!(out, "Partitions ({}):", a.partitions.len());
    let _ = writeln!(
        out,
        "{:<3} {:<31} {:<12} {:<11} NAME",
        "#", "TYPE", "FIRST LBA", "LAST LBA"
    );
    let _ = writeln!(
        out,
        "{} {} {} {} {}",
        "-".repeat(3),
        "-".repeat(31),
        "-".repeat(12),
        "-".repeat(11),
        "-".repeat(24)
    );
    for (i, p) in a.partitions.iter().enumerate() {
        let ty = p
            .type_name()
            .map_or_else(|| p.type_guid.to_string(), ToString::to_string);
        let _ = writeln!(
            out,
            "{i:<3} {ty:<31} {:<12} {:<11} {}",
            p.first_lba, p.last_lba, p.name
        );
    }
    out.push('\n');

    if a.anomalies.is_empty() {
        out.push_str("Anomalies:       none\n");
    } else {
        let _ = writeln!(out, "Anomalies ({}):", a.anomalies.len());
        for an in &a.anomalies {
            let _ = writeln!(out, "  [{}] {}: {}", an.severity, an.code, an.note);
        }
    }
    out.push('\n');

    out.push_str(&"=".repeat(RULE));
    out.push('\n');
    match a.max_severity() {
        None => out.push_str("Result:          clean (no anomalies detected)\n"),
        Some(sev) => {
            let _ = writeln!(
                out,
                "Result:          {} anomaly(ies), max severity {sev}",
                a.anomalies.len()
            );
        }
    }
    out
}
