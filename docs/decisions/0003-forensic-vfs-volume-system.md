# 3. Expose GPT partitions through the `forensic-vfs` VolumeSystem contract

Date: 2026-07-24
Status: Accepted

## Context

An evidence stack composes: `E01 → GPT → NTFS`. The filesystem reader above
must open a partition as a byte window without knowing that a GPT (versus an
MBR or APM) sits beneath it — otherwise every filesystem crate would grow an
`if gpt { … } else if mbr { … }` cascade, the exact special-casing the fleet VFS
policy exists to prevent (`~/src/ronin-issen/CLAUDE.md`, *VFS & Universal
Container Abstraction*).

The fleet's `forensic-vfs` crate defines the KNOWLEDGE-leaf contract for this:
`ImageSource` (positioned byte reads) plus a `VolumeSystem` trait that yields
`VolumeDesc`s, each openable as a `SubRange` byte window. Commits `c0a94b9`
(RED) / `c7ddebc` (GREEN) added a `GptVolumes` adapter implementing it, validated
against the `mmls`/`sgdisk` oracle.

## Decision

Implement `forensic_vfs::VolumeSystem` for `GptVolumes` in `core/src/vfs.rs`.
`GptVolumes::probe` wraps a parent `ImageSource` (a raw disk, or an E01/VMDK
container that already implements the trait), decodes the GPT, and exposes each
in-use partition as a `VolumeDesc` openable as a `SubRange`. The module doc
states the intent: it "lets `E01 → GPT → NTFS` compose without the filesystem
layer knowing a partition scheme sits beneath it."

Two design points fall out of the untrusted-input posture:

- **The entry-array read is capped** at `ENTRY_ARRAY_CAP = 4 MiB`
  (`core/src/vfs.rs`) so a header claiming an absurd `num_partition_entries`
  cannot force an unbounded allocation.
- **Probing tries 512- then 4096-byte logical sectors**, because the sector size
  is not stored in the GPT itself (see also `analyse::detect_sector_size`); no
  `EFI PART` under either yields `VfsError::Unsupported`, never a bogus volume
  list.

## Consequences

- A whole stack reads as one `Arc<dyn ImageSource>` that filesystem readers
  consume uniformly; adding GPT support benefits every VFS consumer at once.
- The adapter is gated behind the optional `vfs` feature so the bare parser does
  not inherit the VFS dependency graph — see ADR 0004.
- The reader depends on `forensic-vfs` only for its contract types, keeping the
  dependency direction pointed *down* onto the KNOWLEDGE leaf.
