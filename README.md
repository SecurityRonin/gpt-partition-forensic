# gpt-partition-forensic

[![Crates.io: gpt-partition-core](https://img.shields.io/crates/v/gpt-partition-core.svg?label=gpt-partition-core)](https://crates.io/crates/gpt-partition-core)
[![Crates.io: gpt-partition-forensic](https://img.shields.io/crates/v/gpt-partition-forensic.svg?label=gpt-partition-forensic)](https://crates.io/crates/gpt-partition-forensic)
[![docs.rs](https://img.shields.io/docsrs/gpt-partition-forensic)](https://docs.rs/gpt-partition-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/gpt-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/gpt-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A GUID Partition Table parser that grades what it reads** — validate header and partition-array **CRC32** integrity, reconcile the **primary against the backup** GPT, and surface overlaps, out-of-bounds extents, hybrid-MBR hidden partitions, and protective-MBR inconsistencies as severity-ranked findings that ordinary GPT crates silently accept.

## See it work in 30 seconds

```toml
[dependencies]
gpt-partition-forensic = "0.4"
```

```rust
use gpt_partition_forensic::analyse;
use std::fs::File;

let mut img = File::open("disk.img")?;
let size = img.metadata()?.len();
let report = analyse(&mut img, size)?;

println!("disk GUID:   {}", report.disk_guid);
println!("partitions:  {}", report.partitions.len());
println!("GPT SHA-256: {}", report.gpt_sha256);

for a in &report.anomalies {
    // each anomaly is a graded forensicnomicon::report::Observation
    println!("[{:?}] {}: {}", a.severity, a.code, a.note);
}
# Ok::<(), gpt_partition_forensic::Error>(())
```

```text
disk GUID:   E86E657A-D840-4C09-AFE3-A1A5F665CF44
partitions:  2
GPT SHA-256: 6e4309388564459a83eae7dcd8bf6765d93db6923c951bee98392f236e632e94
[Critical] GPT-PART-OVERLAP: partitions 0 and 1 claim overlapping LBA ranges
```

A tampered disk does not stay quiet: a flipped byte in the partition array, a backup GPT that disagrees with the primary, or two partitions claiming the same sectors each surface as a severity-ranked anomaly with a stable `code` and the on-disk location.

For a ready-made command line that auto-detects the partitioning scheme and prints this for *any* disk, install the unified [`disk4n6`](https://github.com/SecurityRonin/disk-forensic) tool (`cargo install disk-forensic`).

## Two crates, one workspace

| Crate | Role | What it gives you |
| --- | --- | --- |
| [`gpt-partition-core`](https://crates.io/crates/gpt-partition-core) | **Reader** | Pure `Read + Seek` GPT decoder — header, partition entries, GUIDs, CRC32, SHA-256, and the protective/legacy MBR. No findings. |
| [`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic) | **Analyzer** | Runs the reader, then grades the structure into [`forensicnomicon::report::Observation`] findings. Re-exports the reader, so you depend on one crate. |

> The reader publishes as `gpt-partition-core` (the bare `gpt-core` name is taken by a third party), but the import path is the ergonomic `use gpt::…`.

## What it detects

`analyse()` returns a `GptAnalysis` — the parsed `primary` and (when readable) `backup` headers, `disk_guid`, in-use `partitions`, an auto-detected `sector_size`, a `gpt_sha256` chain-of-custody fingerprint of the header sector plus entry array, and the graded `anomalies`. Each anomaly carries a stable `code`:

| Code | Severity | Meaning |
| --- | --- | --- |
| `GPT-HDR-CRC` | High | Header self-CRC32 does not match its contents. |
| `GPT-HDR-SLACK` | High | Non-zero bytes in the header's reserved slack region. |
| `GPT-HDR-LBA` | High | Header's self-referencing LBA does not match where it was read. |
| `GPT-ARRAY-CRC` | High | Partition-array CRC32 does not match the entries. |
| `GPT-BACKUP-MISSING` | High | Backup GPT is missing or unreadable — the disk cannot self-repair. |
| `GPT-BACKUP-NOTATEND` | High | Backup GPT is not at the last LBA — a trailing region is hidden. |
| `GPT-DIVERGENCE` | High | A field diverges between the primary and backup GPT. |
| `GPT-PART-OVERLAP` | Critical | Two partitions claim overlapping LBA ranges. |
| `GPT-PART-DUPGUID` | High | Two partition entries share the same unique GUID. |
| `GPT-PART-ENCRYPTED` | High | A partition's content entropy is consistent with a hidden encrypted volume. |
| `GPT-PART-OOB` | High | A partition extends past the last usable LBA. |
| `GPT-PART-RESERVED` | High | A partition starts before the first usable LBA, in the reserved GPT area. |
| `GPT-MBR-NOPROT` | High | GPT present but the MBR has no protective (`0xEE`) entry guarding it. |
| `GPT-MBR-UNDERSIZED` | High | The protective MBR covers less than the whole disk — the tail is exposed to GPT-unaware tools. |
| `GPT-MBR-HYBRID-HIDDEN` | High | A hybrid-MBR entry matches no GPT partition — legacy-visible but hidden from the GPT. |

Sector size is auto-detected by locating `EFI PART` at 512- and 4096-byte boundaries; override it with `analyse_with_options` and `AnalyseOptions { sector_size }` when the header magic is corrupt.

## Reader only

When you only need to decode the table (no grading), depend on the reader directly:

```toml
[dependencies]
gpt-partition-core = "0.4"
```

```rust
// Import path stays `gpt::…` despite the published name.
use gpt::{GptHeader, GptEntry, Guid};
```

It is a pure `Read + Seek` library with **no image-format decoding of its own** — compose it with the container crates (`ewf`, `vhd`, `vmdk`, …) to analyse E01 / VHD / VMDK evidence without first carving out a raw image. The analyzer is a drop-in for [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic), which calls into it automatically when a protective MBR is found, so the cross-MBR↔GPT reconciliation is available whether you start from the MBR or the GPT.

## Trust, but verify

- **Dependency-light** — CRC32 (ISO-HDLC) and SHA-256 (FIPS 180-4) are implemented from scratch and verified against zlib / NIST vectors; the runtime dependencies are `thiserror` and `forensicnomicon` (the shared findings model).
- **Panic-free** — production code carries no `unwrap`/`expect`/`panic!`, enforced by the workspace's `unwrap_used`/`expect_used = deny` lints, with bounds-checked integer reads on attacker-controllable input.
- **`unsafe`-free** — `#![forbid(unsafe_code)]` across the workspace.
- **Fuzzed** — a `cargo fuzz` workspace drives both the parser and the full `analyse` pipeline; the invariant is "must not panic."
- **Validated against independent oracles** — the from-scratch CRC-32/ISO-HDLC and SHA-256 are checked against third-party known-answer vectors (zlib's canonical CRC value, the NIST/FIPS 180-4 SHA-256 vectors). The **GPT structural parse** (partition LBAs, type/unique GUIDs, names, disk GUID) is validated on a **real GPT disk image** cross-decoded by two independent tools — `sgdisk` (GPT fdisk) minted it, TSK `mmls` independently re-decoded the same bytes. The anomaly **detectors** (divergence, overlap, concealment, MBR↔GPT) still rest on synthetic fixtures, since a clean image trips none of them. See [the validation page](https://securityronin.github.io/gpt-partition-forensic/validation/) for the per-capability evidence tiers.
- **Secure by default** — the zero-config `analyse()` path performs every integrity check; you cannot accidentally skip CRC validation.

## Sibling crates

One forensic parser per partitioning scheme — each a pure `Read + Seek` library that composes with the same container crates:

- [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) — Master Boot Record (legacy BIOS partitioning; auto-delegates here for protective-MBR/GPT disks)
- [`apm-forensic`](https://github.com/SecurityRonin/apm-forensic) — Apple Partition Map (classic Mac and hybrid optical media)
- [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) — **orchestrator**: point it at any disk, it auto-detects the scheme and dispatches to the right parser above

---

[Privacy Policy](https://securityronin.github.io/gpt-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/gpt-partition-forensic/terms/) · © 2026 Security Ronin Ltd
