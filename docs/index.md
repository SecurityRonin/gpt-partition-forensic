# gpt-partition-forensic

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
    println!("[{:?}] {}: {}", a.severity, a.code, a.note);
}
# Ok::<(), gpt_partition_forensic::Error>(())
```

## Two crates, one workspace

| Crate | Role | What it gives you |
| --- | --- | --- |
| [`gpt-partition-core`](https://crates.io/crates/gpt-partition-core) | **Reader** | Pure `Read + Seek` GPT decoder — header, partition entries, GUIDs, CRC32, SHA-256, and the protective/legacy MBR. No findings. |
| [`gpt-partition-forensic`](https://crates.io/crates/gpt-partition-forensic) | **Analyzer** | Runs the reader, then grades the structure into `forensicnomicon::report::Observation` findings. Re-exports the reader, so you depend on one crate. |

The reader publishes as `gpt-partition-core` (the bare `gpt-core` name is taken by a third party), but the import path is the ergonomic `use gpt::…`.

## What it detects

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
| `GPT-MBR-UNDERSIZED` | High | The protective MBR covers less than the whole disk. |
| `GPT-MBR-HYBRID-HIDDEN` | High | A hybrid-MBR entry matches no GPT partition. |

## Trust, but verify

CRC32 (ISO-HDLC) and SHA-256 (FIPS 180-4) are implemented from scratch and verified against zlib / NIST vectors; production code is panic-free (`unwrap_used`/`expect_used = deny`, bounds-checked reads), `#![forbid(unsafe_code)]` across the workspace, fuzzed over both the parser and the full `analyse` pipeline, and validated against real disk images. The zero-config `analyse()` path performs every integrity check — you cannot accidentally skip CRC validation.

See the project [README](https://github.com/SecurityRonin/gpt-partition-forensic) for the full quick start and sibling-crate map.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
