# gpt-forensic

[![Crates.io](https://img.shields.io/crates/v/gpt-forensic.svg)](https://crates.io/crates/gpt-forensic)
[![docs.rs](https://img.shields.io/docsrs/gpt-forensic)](https://docs.rs/gpt-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/gpt-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/gpt-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Forensic-grade GUID Partition Table (GPT) parser for Rust** — validates header and partition-array **CRC32** integrity, reconciles the **primary against the backup** GPT, and flags overlaps, out-of-bounds extents, and protective-MBR inconsistencies that ordinary GPT crates silently accept.

## See it work in 30 seconds

```console
$ cargo install gpt-forensic-cli
$ gpt analyse disk.img
```

```text
GPT Forensic Analysis: disk.img
================================================================================
Disk GUID:       E86E657A-D840-4C09-AFE3-A1A5F665CF44
Revision:        1.0
Header CRC:      valid
Usable LBAs:     34..8158
Sector size:     512 bytes
GPT SHA-256:     6e4309388564459a83eae7dcd8bf6765d93db6923c951bee98392f236e632e94
Backup GPT:      present (LBA 8191)

Partitions (2):
#   TYPE                            FIRST LBA    LAST LBA    NAME
--- ------------------------------- ------------ ----------- ------------------------
0   Linux filesystem data           2048         2175        Linux filesystem
1   Linux filesystem data           4096         4223        Linux filesystem

Anomalies:       none

================================================================================
Result:          clean (no anomalies detected)
```

A tampered disk does not stay quiet — a flipped byte in the partition array, a
backup GPT that disagrees with the primary, or two partitions claiming the same
sectors each surface as a severity-ranked anomaly with the exact byte location.

## What it detects

- **CRC32 integrity** — header CRC and partition-array CRC, checked independently (a tool that rewrites one partition but forgets to fix the array CRC is caught here).
- **Primary ⇄ backup divergence** — the backup GPT at the last LBA is parsed and compared field-by-field; divergence is a strong tampering signal.
- **Structural anomalies** — overlapping partitions, out-of-bounds extents, entries past the usable range, zero-length-but-named entries.
- **Protective MBR cross-check** — reads LBA 0 itself and reconciles the protective MBR with the GPT it advertises.
- **Sector-size auto-detection** — locates `EFI PART` at 512- and 4096-byte sectors; override with `AnalyseOptions` when the header magic is corrupt.

## Rust library

```toml
[dependencies]
gpt-forensic = "0.1"
```

```rust
use gpt_forensic::analyse;
use std::fs::File;

let mut img = File::open("disk.img")?;
let size = img.metadata()?.len();
let report = analyse(&mut img, size)?;

for a in &report.anomalies {
    println!("[{:?}] {}: {}", a.severity, a.kind.code(), a.kind.note());
}
# Ok::<(), gpt_forensic::Error>(())
```

It is a pure `Read + Seek` library with **no image-format decoding of its own** —
compose it with the container crates (`ewf`, `vhd`, `vmdk`, …) to analyse E01 /
VHD / VMDK evidence without first carving out a raw image. The same property
makes it a drop-in for [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic),
which calls into this crate automatically when a protective MBR is found, so the
cross-MBR↔GPT reconciliation is available whether you start from the MBR or the GPT.

## Design

- **Dependency-light** — CRC32 (ISO-HDLC) and SHA-256 (FIPS 180-4) are implemented from scratch and verified against zlib / NIST vectors; the only runtime dependency is `thiserror`.
- **`#![forbid(unsafe_code)]`**, fuzz-tested (`cargo fuzz`), and validated against real disk images, not only synthetic fixtures.
- **Secure by default** — the zero-config `analyse()` path performs every integrity check; you cannot accidentally skip CRC validation.

## Sibling crates

One forensic parser per partitioning scheme — each a pure `Read + Seek` library that composes with the same container crates:

- [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) — Master Boot Record (legacy BIOS partitioning; auto-delegates here for protective-MBR/GPT disks)
- [`apm-forensic`](https://github.com/SecurityRonin/apm-forensic) — Apple Partition Map (classic Mac and hybrid optical media)
- [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) — **orchestrator**: point it at any disk, it auto-detects the scheme and dispatches to the right parser above

---

[Privacy Policy](https://securityronin.github.io/gpt-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/gpt-forensic/terms/) · © 2026 Security Ronin Ltd
