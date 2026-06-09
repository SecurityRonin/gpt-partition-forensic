# gpt-partition-forensic

[![Crates.io: gpt-partition-forensic](https://img.shields.io/crates/v/gpt-partition-forensic.svg?label=gpt-partition-forensic)](https://crates.io/crates/gpt-partition-forensic)
[![Crates.io: gpt-partition-core](https://img.shields.io/crates/v/gpt-partition-core.svg?label=gpt-partition-core)](https://crates.io/crates/gpt-partition-core)
[![docs.rs](https://img.shields.io/docsrs/gpt-partition-forensic)](https://docs.rs/gpt-partition-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)
[![CI](https://github.com/SecurityRonin/gpt-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/gpt-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A GUID Partition Table analyzer that grades what it reads** — point `analyse()` at a disk image and get back the parsed table *plus* severity-ranked findings: CRC32 mismatches, primary/backup divergence, partition overlaps, out-of-bounds extents, and hidden hybrid-MBR partitions that ordinary GPT crates silently accept.

## Grade a GPT in 30 seconds

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
println!("GPT SHA-256: {}", report.gpt_sha256);

for a in &report.anomalies {
    // each anomaly implements forensicnomicon::report::Observation
    println!("[{:?}] {}: {}", a.severity, a.code, a.note);
}
# Ok::<(), gpt_partition_forensic::Error>(())
```

```text
disk GUID:   E86E657A-D840-4C09-AFE3-A1A5F665CF44
GPT SHA-256: 6e4309388564459a83eae7dcd8bf6765d93db6923c951bee98392f236e632e94
[Critical] GPT-PART-OVERLAP: partitions 0 and 1 claim overlapping LBA ranges
```

`analyse()` returns a `GptAnalysis`: the parsed `primary` and (when readable) `backup` headers, `disk_guid`, in-use `partitions`, an auto-detected `sector_size`, a `gpt_sha256` chain-of-custody fingerprint, and the graded `anomalies`. Call `GptAnalysis::max_severity()` for the single worst finding. When the header magic is corrupt, force the sector size with `analyse_with_options` and `AnalyseOptions { sector_size }`.

## Findings it emits

Every `Anomaly` implements `forensicnomicon::report::Observation` and carries a stable `code` — observations, never legal conclusions:

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

## Two-crate split

This analyzer is built on the [`gpt-partition-core`](https://crates.io/crates/gpt-partition-core) reader — the pure `Read + Seek` GPT decoder (header, entries, GUIDs, CRC32, SHA-256, protective MBR) with no findings of its own. `gpt-partition-forensic` re-exports the reader (`GptHeader`, `GptEntry`, `Guid`, `Error`, and the `crc32`/`entry`/`guid`/`header`/`mbr`/`sha256` modules), so you only ever depend on one crate.

It is a pure `Read + Seek` analysis with **no image-format decoding of its own** — compose it with the container crates (`ewf`, `vhd`, `vmdk`, …) to analyse E01 / VHD / VMDK evidence without first carving out a raw image. It is also a drop-in for [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic), which calls into it automatically when a protective MBR is found, so the cross-MBR↔GPT reconciliation is available whether you start from the MBR or the GPT.

## Trust, but verify

- **Dependency-light** — CRC32 (ISO-HDLC) and SHA-256 (FIPS 180-4) are implemented from scratch and verified against zlib / NIST vectors; runtime dependencies are `thiserror`, `gpt-partition-core`, and `forensicnomicon` (the shared findings model).
- **Panic-free** — no `unwrap`/`expect`/`panic!` in production code, enforced by the workspace's `unwrap_used`/`expect_used = deny` lints, with bounds-checked integer reads on attacker-controllable input.
- **`unsafe`-free** — `#![forbid(unsafe_code)]` across the workspace.
- **Fuzzed** — a `cargo fuzz` workspace drives both the parser and the full `analyse` pipeline; the invariant is "must not panic."
- **Validated against real disk images**, not only synthetic fixtures.
- **Secure by default** — the zero-config `analyse()` path performs every integrity check; you cannot accidentally skip CRC validation.

## Optional features

- `serde` — derive `Serialize` on `GptAnalysis`, `Anomaly`, and `AnomalyKind` (also pulls in the reader's and `forensicnomicon`'s serde support).
- `trace` — forward internal diagnostics to the `tracing` ecosystem.

---

[Privacy Policy](https://securityronin.github.io/gpt-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/gpt-partition-forensic/terms/) · © 2026 Security Ronin Ltd
