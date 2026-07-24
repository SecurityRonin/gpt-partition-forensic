# gpt-partition-forensic — Design & Scope

*A reverse-written design note grounded in a same-session read of `core/src/`,
`forensic/src/`, and the workspace manifests (2026-07-24). The load-bearing
decisions live as ADRs under [`docs/decisions/`](decisions/); this note states
what the crates are, who consumes them, and where the boundaries sit. This is a
**library**, not an examiner-facing product — there is no bundled CLI (see
[ADR 0005](decisions/0005-pure-library-no-cli.md)).*

## Purpose

A GUID Partition Table reader that **grades what it reads**. Ordinary GPT crates
decode the table and trust it; this one validates header and partition-array
**CRC32** integrity, reconciles the **primary GPT against the backup**, and
surfaces overlaps, out-of-bounds extents, hybrid-MBR hidden partitions, and
protective-MBR inconsistencies as severity-ranked findings on the shared
`forensicnomicon::report` model.

## Consumers (who links this, and why)

This crate is *linked*, never run directly:

- **`disk-forensic` / `disk4n6`** — the examiner-facing orchestrator that
  auto-detects the partitioning scheme and dispatches to this crate (or
  `mbr-forensic` / `apm-forensic`). It owns all presentation.
- **`mbr-forensic`** — delegates here when it finds a protective MBR, so the
  MBR↔GPT reconciliation is available whether analysis starts from the MBR or the
  GPT.
- **Filesystem readers via `forensic-vfs`** — with the optional `vfs` feature,
  `GptVolumes` exposes each partition as a byte window so `E01 → GPT → NTFS`
  composes without the filesystem layer knowing a GPT sits beneath it
  ([ADR 0003](decisions/0003-forensic-vfs-volume-system.md),
  [ADR 0004](decisions/0004-vfs-optional-feature.md)).
- **Container crates** (`ewf`, `vhd`, `vmdk`, …) — supply the `Read + Seek`
  byte source; this crate does no image-format decoding of its own.

## What the crates do

Two crates, one workspace
([ADR 0001](decisions/0001-reader-analyzer-split.md)):

| Crate | Role | Surface |
| --- | --- | --- |
| `gpt-partition-core` (imports as `gpt`) | **Reader** | `GptHeader`, `GptEntry`, `Guid`, `crc32`, `sha256`, `mbr`; pure `Read + Seek`, no findings |
| `gpt-partition-forensic` | **Analyzer** | `analyse()` / `analyse_with_options()` → `GptAnalysis`; re-exports the reader |

`analyse()` returns a `GptAnalysis`: the parsed `primary` and (when readable)
`backup` headers, `disk_guid`, in-use `partitions`, an auto-detected
`sector_size`, a `gpt_sha256` chain-of-custody fingerprint, and the graded
`anomalies`. Each anomaly carries a stable scheme-prefixed `code` (`GPT-HDR-CRC`,
`GPT-DIVERGENCE`, `GPT-PART-OVERLAP`, `GPT-MBR-HYBRID-HIDDEN`, …) derived from its
`AnomalyKind` so severity/code/note cannot drift
([ADR 0008](decisions/0008-findings-on-forensicnomicon-report.md)). The full code
table is in the README.

Sector size is auto-detected by locating `EFI PART` at 512- and 4096-byte
boundaries (`analyse::detect_sector_size`); `AnalyseOptions { sector_size }`
overrides it when the header magic is corrupt.

## Scope

- Decode the GPT: header, partition entry array, GUIDs, attributes, names; the
  protective/legacy MBR entries needed to reconcile MBR↔GPT.
- Grade structural integrity: header/array CRC32, header self-LBA, reserved
  slack, primary/backup divergence, partition overlaps/OOB/reserved-area,
  duplicate GUIDs, hidden-encrypted-volume entropy, protective-MBR sizing, and
  hybrid-MBR hidden partitions.
- Emit a SHA-256 evidence fingerprint of the header sector plus entry array.
- Expose partitions as `forensic-vfs` volumes behind the `vfs` feature.

## Non-goals

- **No image-format decoding.** E01/VHD/VMDK come from the container crates.
- **No filesystem parsing.** This crate stops at the partition byte window; NTFS
  / ext4 / APFS are separate readers above the VFS boundary.
- **No presentation.** No CLI, no text/JSON rendering — that lives in `disk4n6`
  ([ADR 0005](decisions/0005-pure-library-no-cli.md)).
- **No legal conclusions.** Findings are graded observations ("consistent with"),
  never verdicts.
- **No security-grade cryptography.** The from-scratch CRC-32/SHA-256 are a
  checksum and a tamper-evidence fingerprint, not a MAC or key derivation
  ([ADR 0006](decisions/0006-from-scratch-crc32-sha256.md)).

## Robustness & validation posture

The crates parse untrusted, attacker-controllable disk images, so they run the
Paranoid Gatekeeper posture: `#![forbid(unsafe_code)]`, panic-free by
`unwrap_used`/`expect_used = deny` lints, all integer reads through the audited
`safe-read` crate, allocation caps on length fields, and a `cargo fuzz` workspace
whose invariant is "must not panic"
([ADR 0007](decisions/0007-paranoid-gatekeeper-posture.md)).

Validation tiers (detail in [`validation.md`](validation.md)): the CRC-32 and
SHA-256 primitives are checked against independent third-party vectors (zlib's
canonical CRC, NIST/FIPS 180-4 SHA-256) — tier 1; the GPT **structural parse** is
validated on a real GPT disk cross-decoded by two independent tools (`sgdisk`
minted it, TSK `mmls` re-decoded it) — tier 1; the anomaly **detectors** rest on
synthetic fixtures, since a clean image trips none of them — tier 3, honestly
labeled.
