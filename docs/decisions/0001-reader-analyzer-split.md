# 1. Reader/analyzer split — `gpt-partition-core` + `gpt-partition-forensic`

Date: 2026-07-24
Status: Accepted

## Context

GPT support in this repository began as a single crate (`gpt-forensic`) that
both decoded the on-disk GUID Partition Table and graded it into forensic
findings. That conflates two audiences: a consumer that only wants to *read* the
table (a filesystem mounter, a container tool) is forced to pull the whole
findings model, and a consumer that wants *findings* has no way to reuse the
decoder without the grading layer.

The SecurityRonin fleet mandates a uniform "reader/analyzer split" for every
format (`~/src/ronin-issen/CLAUDE.md`, *Crate-structure standard — reader/analyzer
split (core/ + forensic/)*; reference impl `ntfs-forensic`): one workspace repo
`<x>-forensic` with two members — `core/` (the raw `Read + Seek` reader, no
findings) and `forensic/` (the anomaly auditor emitting
`forensicnomicon::report`). The split was applied here in commit `c3667e1`
("refactor: split into core (gpt-partition-core) + forensic
(gpt-partition-forensic) workspace").

## Decision

Structure the repository as one Cargo workspace (`Cargo.toml`
`members = ["core", "forensic"]`) with two crates:

1. **`core/` → `gpt-partition-core`** — a pure `Read + Seek` GPT decoder:
   header, partition entries, GUIDs, CRC32, SHA-256, and the protective/legacy
   MBR (`core/src/{header,entry,guid,crc32,sha256,mbr}.rs`). Its `lib.rs`
   documents the contract explicitly: "it carries **no forensic findings** of
   its own (no `report::Observation`, no anomaly grading)."
2. **`forensic/` → `gpt-partition-forensic`** — runs the reader, then grades the
   structure into `forensicnomicon::report::Observation` findings
   (`forensic/src/{analyse,findings,collision,entropy}.rs`). It re-exports the
   reader (`pub use gpt::{…}` in `forensic/src/lib.rs`) so a consumer that wants
   both depends on one crate.

The analyzer depends on the reader by default (`gpt = { workspace = true }` in
`forensic/Cargo.toml`), consistent with the fleet default — the reader's
`Read + Seek` surface already exposes the raw header/entry/slack bytes the audit
needs, so there is no reason to drop below `-core` here.

## Consequences

- A mounter or container tool depends on `gpt-partition-core` alone and never
  compiles the findings model (ADR 0004 makes even the VFS adapter optional).
- The two crates version and publish together from one workspace
  (`[workspace.package] version` inheritance), keeping the reader and analyzer
  in lockstep.
- The layout matches every sibling partition-scheme crate (`mbr-forensic`,
  `apm-forensic`), so `disk-forensic` can dispatch to any of them uniformly.
- Findings derivation is centralized in the analyzer: severity, code, and note
  are derived from `AnomalyKind` (`forensic/src/findings.rs`) so they cannot
  drift from the reader's structures.
