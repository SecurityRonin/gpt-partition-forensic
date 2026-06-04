# gpt-forensic — session handoff

> Untracked scratch note for continuing work in a fresh Claude Code session
> started in `~/src/gpt-forensic`. Delete or commit as you see fit.

## What this crate is

Forensic GUID Partition Table (GPT) parser — the sibling of `~/src/mbr-forensic`,
modeled on it (same anomaly model, quality bar, near-zero-dep ethos). Pure
`Read + Seek` library; no image-format decoding (compose with `ewf`/`vhd`/
`vmdk`/`qcow2`/… for E01/VHD/VMDK input).

## Current state (all local, nothing pushed)

- Branch `main`, clean. **19 tests green**, clippy clean (`--all-targets --all-features`).
- Modules: `crc32` (CRC-32/ISO-HDLC, verified vs zlib), `guid` (mixed-endian
  GUID + Display), `header` (parse + self-CRC validation), `entry` (type/unique
  GUID, UTF-16 names, array parse, `type_name()`), `analyse` (top-level: header
  & array CRC integrity, **primary↔backup divergence**, partition overlaps,
  out-of-bounds), `findings` (Severity/Anomaly/AnomalyKind/GptAnalysis/Location).
- `fuzz/` libfuzzer targets: `parse_header`, `analyse_full` (compile under
  `cargo +nightly fuzz`).
- Real-data validated: `cargo run --example …` on `~/src/dd/dd/tests/data/gpt.raw`
  → correct disk GUID, both Linux partitions, zero false-positive anomalies.

## Dependency you MUST keep in mind

`Cargo.toml` has `forensicnomicon = { path = "../forensicnomicon" }`. The GPT
type-GUID table (`forensicnomicon::gpt`, consumed by `GptEntry::type_name`) lives
on forensicnomicon branch **`disk-forensic-knowledge`** — NOT `main`. If
forensicnomicon gets switched to `main`, this crate stops building. Keep that
branch checked out, or merge the knowledge into forensicnomicon `main` first.

## How it composes with mbr-forensic

mbr-forensic auto-parses the GPT (via this crate) when an `EFI PART` header is
detected, exposing `MbrAnalysis.gpt`. **That integration lives in the
mbr-forensic repo** (worktree branch `worktree-forensic-features`), not here — a
session in this repo can't edit it. Pure gpt-forensic work is fine here.

## Conventions (carry these over)

- **Strict TDD**: separate RED commit (failing tests) then GREEN commit (impl).
- **No hallucinated facts**: every GUID/offset/constant must trace to an
  authoritative source cited in a doc comment (UEFI spec, Wikipedia GPT, util-linux,
  systemd Discoverable Partitions Spec). Validate against real images, not just
  synthetic fixtures.
- **gitsign/Sigstore is flaky**: tlog uploads intermittently fail; just retry the
  commit (loop 2–3×). Shared cred cache:
  `export GITSIGN_CREDENTIAL_CACHE="$HOME/Library/Caches/sigstore/gitsign/cache.sock"`.
- Match the house module style (heavily-documented `pub const`/structs, KAT tests).

## Remaining Tier F backlog (gpt-forensic)

- `gpt-forensic-cli` subcrate (mirror `iso9660-forensic`/`ext4fs-forensic` layout:
  workspace with lib + cli + fuzz) — `analyse`/`dump` subcommands.
- proptest invariants (parser/analyse never panic; round-trips).
- criterion benches (analyse throughput).
- README (badges, above-the-fold quickstart) + anomaly-code reference table.
- More knowledge in forensicnomicon: partition attribute-flag meanings, more
  type GUIDs as needed.
