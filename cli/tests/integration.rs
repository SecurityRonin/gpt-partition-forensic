//! CLI integration tests — exercise the `cmd` functions directly against an
//! in-memory GPT image, with no spawned process.

use std::io::Cursor;

use gpt_forensic_cli::cmd;

mod common;
use common::{build_gpt, corrupt_primary_header, DISK_GUID};

fn reader() -> Cursor<Vec<u8>> {
    Cursor::new(build_gpt())
}

// ── analyse ────────────────────────────────────────────────────────────────

#[test]
fn analyse_names_the_image() {
    let mut r = reader();
    let len = r.get_ref().len() as u64;
    let out = cmd::analyse::run(&mut r, len, "evidence.img").unwrap();
    assert!(out.contains("evidence.img"), "report must name the image:\n{out}");
}

#[test]
fn analyse_shows_disk_guid() {
    let mut r = reader();
    let out = cmd::analyse::run(&mut r, 0, "disk.img").unwrap();
    assert!(out.contains(DISK_GUID), "report must show the disk GUID:\n{out}");
}

#[test]
fn analyse_resolves_partition_type_names() {
    let mut r = reader();
    let out = cmd::analyse::run(&mut r, 0, "disk.img").unwrap();
    assert!(
        out.contains("Linux filesystem data"),
        "Linux type name missing:\n{out}"
    );
    assert!(
        out.contains("EFI System Partition"),
        "EFI type name missing:\n{out}"
    );
}

#[test]
fn analyse_shows_partition_labels() {
    let mut r = reader();
    let out = cmd::analyse::run(&mut r, 0, "disk.img").unwrap();
    assert!(out.contains("Linux"), "partition label 'Linux' missing:\n{out}");
    assert!(out.contains("EFI System"), "partition label 'EFI System' missing:\n{out}");
}

#[test]
fn analyse_clean_image_reports_no_anomalies() {
    let mut r = reader();
    let out = cmd::analyse::run(&mut r, 0, "disk.img").unwrap();
    assert!(out.contains("Result:"), "report needs a Result line:\n{out}");
    assert!(
        out.to_lowercase().contains("clean") || out.contains("0 anomal"),
        "clean image must say so:\n{out}"
    );
}

#[test]
fn analyse_indicates_backup_present() {
    let mut r = reader();
    let out = cmd::analyse::run(&mut r, 0, "disk.img").unwrap();
    assert!(out.contains("Backup"), "report must mention the backup GPT:\n{out}");
}

#[test]
fn analyse_is_pure_ascii() {
    let mut r = reader();
    let out = cmd::analyse::run(&mut r, 0, "disk.img").unwrap();
    assert!(out.is_ascii(), "analyse report must be pure ASCII:\n{out}");
}

#[test]
fn analyse_flags_corrupt_header_crc() {
    let mut disk = build_gpt();
    corrupt_primary_header(&mut disk);
    let mut r = Cursor::new(disk);
    let out = cmd::analyse::run(&mut r, 0, "tampered.img").unwrap();
    assert!(out.contains("GPT-HDR-CRC"), "header-CRC anomaly code missing:\n{out}");
    assert!(out.contains("HIGH"), "header-CRC severity (HIGH) missing:\n{out}");
}

// ── dump ───────────────────────────────────────────────────────────────────

#[test]
fn dump_lba1_shows_efi_part_signature() {
    let mut r = reader();
    let out = cmd::dump::run(&mut r, 1).unwrap();
    assert!(
        out.contains("45 46 49 20 50 41 52 54"),
        "EFI PART signature bytes missing from hex:\n{out}"
    );
    assert!(out.contains("EFI PART"), "EFI PART must appear in the ASCII column:\n{out}");
}

#[test]
fn dump_has_lba_header_line() {
    let mut r = reader();
    let out = cmd::dump::run(&mut r, 1).unwrap();
    assert!(out.contains("LBA 1"), "dump must label the LBA:\n{out}");
}

#[test]
fn dump_has_dash_separator() {
    let mut r = reader();
    let out = cmd::dump::run(&mut r, 1).unwrap();
    let has_sep = out.lines().any(|l| l.len() > 4 && l.chars().all(|c| c == '-'));
    assert!(has_sep, "dump must have a dash separator line:\n{out}");
}

#[test]
fn dump_is_pure_ascii() {
    let mut r = reader();
    let out = cmd::dump::run(&mut r, 1).unwrap();
    assert!(out.is_ascii(), "dump must be pure ASCII:\n{out}");
}

#[test]
fn dump_raw_returns_full_512_byte_sector() {
    let mut r = reader();
    let bytes = cmd::dump::run_raw(&mut r, 1).unwrap();
    assert_eq!(bytes.len(), 512, "raw sector must be exactly 512 bytes");
    assert_eq!(&bytes[0..8], b"EFI PART", "LBA 1 must begin with the GPT signature");
}
