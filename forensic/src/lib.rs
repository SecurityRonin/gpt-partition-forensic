//! # gpt-partition-forensic
//!
//! Forensic-grade GUID Partition Table (GPT) analyzer. A sibling to
//! [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic): where that
//! crate analyses the legacy MBR, this one analyses the GPT that a protective
//! MBR advertises — validating the header and partition-array **CRC32**
//! integrity, reconciling the **primary and backup** GPT (divergence is a strong
//! tampering signal), and surfacing structural anomalies as graded
//! [`forensicnomicon::report::Observation`]s.
//!
//! The pure on-disk decoder lives in the companion `gpt` crate
//! ([`gpt-partition-core`](https://crates.io/crates/gpt-partition-core)); this crate adds
//! the orchestration and the forensic findings on top. Like its sibling, the
//! analysis is a pure `Read + Seek` operation with no image-format decoding of
//! its own — compose it with the container crates (`ewf`, `vhd`, `vmdk`, …) for
//! E01/VHD/VMDK input.

// Production code is panic-free (enforced by the workspace lints); tests opt out.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod collision;
pub mod entropy;
pub mod findings;

mod analyse;

// ── Parser layer, re-exported from `gpt-partition-core` so the analyzer's
//    public surface stays self-contained ──────────────────────────────────────
pub use gpt::{crc32, entry, guid, header, mbr, sha256};
pub use gpt::{Error, GptEntry, GptHeader, Guid};

// ── Analyzer surface ────────────────────────────────────────────────────────
pub use analyse::{analyse, analyse_with_options, AnalyseOptions};
pub use findings::{Anomaly, AnomalyKind, GptAnalysis, Location, Severity};
