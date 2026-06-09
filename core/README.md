# gpt-partition-core

[![Crates.io: gpt-partition-core](https://img.shields.io/crates/v/gpt-partition-core.svg?label=gpt-partition-core)](https://crates.io/crates/gpt-partition-core)
[![Crates.io: gpt-partition-forensic](https://img.shields.io/crates/v/gpt-partition-forensic.svg?label=gpt-partition-forensic)](https://crates.io/crates/gpt-partition-forensic)
[![docs.rs](https://img.shields.io/docsrs/gpt-partition-core)](https://docs.rs/gpt-partition-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../LICENSE)
[![CI](https://github.com/SecurityRonin/gpt-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/gpt-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A pure-Rust, read-only GUID Partition Table reader** — decode the GPT header, partition entries, GUIDs, and the protective/legacy MBR over any `Read + Seek`, with CRC32 and SHA-256 implemented from scratch. No `unsafe`, no findings, no image-format assumptions.

## Read a GPT in 30 seconds

```toml
[dependencies]
gpt-partition-core = "0.4"
```

> The crates.io package is `gpt-partition-core` (the bare `gpt-core` name is taken by a third party), but the import path is the ergonomic `use gpt::…`.

```rust
use gpt::{GptHeader, GptEntry, Guid};

// Decode the on-disk structures: header, partition entries, GUIDs, and the
// protective/legacy MBR — plus CRC32 integrity over any Read + Seek source.
```

The reader carries **no forensic findings of its own** — no `report::Observation`, no anomaly grading. It is a pure structure decoder. For severity-ranked anomaly analysis (CRC mismatch, primary/backup divergence, partition overlaps, hidden hybrid-MBR partitions), add the companion analyzer [`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic), which re-exports this reader.

## What it decodes

| Module | Contents |
| --- | --- |
| `header` | `GptHeader` — the GPT header at LBA 1 (signature, revision, self-referencing LBAs, partition-array location, CRC32 fields). |
| `entry` | `GptEntry` — a single 128-byte partition entry (type GUID, unique GUID, first/last LBA, attributes, name). |
| `guid` | `Guid` — mixed-endian GPT GUID parsing and display. |
| `crc32` | CRC32 (ISO-HDLC), implemented from scratch and verified against zlib vectors. |
| `sha256` | SHA-256 (FIPS 180-4), implemented from scratch and verified against NIST vectors. |
| `mbr` | The four protective/legacy MBR partition entries needed to reconcile the MBR against the GPT. |

Errors are a single `Error` enum: `BadSignature` (no `EFI PART` magic), `TooShort { need, got }` (buffer too small), and `Io` (read failure).

## No image-format coupling

This is a `Read + Seek` library with no image-format decoding of its own — compose it with the container crates (`ewf`, `vhd`, `vmdk`, …) to read GPTs out of E01 / VHD / VMDK evidence without first carving a raw image.

## Trust, but verify

- **Dependency-light** — CRC32 and SHA-256 are written from scratch and checked against zlib / NIST vectors; the runtime dependencies are `thiserror` and `forensicnomicon` (the GPT partition-type GUID → name knowledge table).
- **Panic-free** — no `unwrap`/`expect`/`panic!` in production code, enforced by the workspace's `unwrap_used`/`expect_used = deny` lints, with bounds-checked integer reads on attacker-controllable input.
- **`unsafe`-free** — `#![forbid(unsafe_code)]`.
- **Fuzzed** — a `cargo fuzz` target drives the parser; the invariant is "must not panic."
- **Validated against real disk images**, not only synthetic fixtures.

---

[Privacy Policy](https://securityronin.github.io/gpt-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/gpt-partition-forensic/terms/) · © 2026 Security Ronin Ltd
