//! End-to-end tests for the `gpt` binary.
//!
//! The GPT fixture is synthesised in memory and written to a tempfile, so these
//! tests are hermetic — no committed sample image is required.

use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::{build_gpt, build_gpt_unknown_type, DISK_GUID};

fn bin() -> Command {
    Command::cargo_bin("gpt").unwrap()
}

/// Write a fresh GPT fixture into `dir` and return its path as a String.
fn fixture(dir: &tempfile::TempDir) -> String {
    let path = dir.path().join("disk.img");
    std::fs::write(&path, build_gpt()).unwrap();
    path.to_str().unwrap().to_string()
}

// ── top-level ──────────────────────────────────────────────────────────────

#[test]
fn help_prints_usage() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Forensic inspection"));
}

#[test]
fn version_prints() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("gpt"));
}

#[test]
fn no_args_is_error() {
    bin().assert().failure();
}

#[test]
fn unknown_subcommand_is_error() {
    bin().arg("frobnicate").assert().failure();
}

#[test]
fn no_help_subcommand() {
    bin().arg("help").assert().failure();
}

// ── analyse ────────────────────────────────────────────────────────────────

#[test]
fn analyse_runs_on_valid_image() {
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["analyse", &fixture(&dir)])
        .assert()
        .success()
        .stdout(predicate::str::contains(DISK_GUID))
        .stdout(predicate::str::contains("Linux filesystem data"))
        .stdout(predicate::str::contains("Result:"));
}

#[test]
fn analyze_alias_works() {
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["analyze", &fixture(&dir)])
        .assert()
        .success()
        .stdout(predicate::str::contains(DISK_GUID));
}

#[test]
fn analyse_renders_raw_guid_for_unknown_type() {
    // A partition whose type GUID has no known name must fall back to printing
    // the raw GUID in the report.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unknown.img");
    std::fs::write(&path, build_gpt_unknown_type()).unwrap();
    bin()
        .args(["analyse", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("DEADBEEF"));
}

#[test]
fn analyse_missing_file_is_error() {
    bin()
        .args(["analyse", "/nonexistent/xyz.img"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot open"));
}

// ── dump ───────────────────────────────────────────────────────────────────

#[test]
fn dump_default_lba_shows_signature() {
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["dump", &fixture(&dir)])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("EFI PART")
                .or(predicate::str::contains("45 46 49 20 50 41 52 54")),
        );
}

#[test]
fn dump_explicit_lba() {
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["dump", &fixture(&dir), "--lba", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("LBA 1"));
}

#[test]
fn dump_raw_emits_binary_sector() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .args(["dump", &fixture(&dir), "--lba", "1", "--raw"])
        .assert()
        .success();
    let bytes = &out.get_output().stdout;
    assert_eq!(
        bytes.len(),
        512,
        "raw dump must be exactly one 512-byte sector"
    );
    assert_eq!(&bytes[0..8], b"EFI PART");
}
