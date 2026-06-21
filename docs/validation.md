# Validation

`gpt-partition-forensic` parses untrusted GPT partition tables from potentially
compromised disk images. This page records exactly which **independent oracles**
and **independent test corpora** back each capability, so every correctness
claim is independently re-checkable.

The honest summary up front: the **two cryptographic primitives** (CRC-32/ISO-HDLC
and SHA-256) are validated at the strongest tier — against third-party published
known-answer vectors (zlib's canonical CRC-32 check value and the NIST/FIPS 180-4
SHA-256 example vectors). The **GPT structural layer** — partition enumeration
(first/last LBA, type GUID, unique GUID, name), disk GUID, sector-size detection,
backup-GPT readability, and the clean-disk happy path — is now validated at
**Tier 1** against a **real GPT disk image** cross-decoded by two independent
tools (`sgdisk` minted it; TSK `mmls` independently re-decoded the same bytes).
The remaining **forensic detectors** — primary/backup divergence, partition-overlap
and concealment heuristics, MBR↔GPT cross-checks, entropy scoring — are still
validated only against **synthetic fixtures authored in this repo** (Tier 3),
because they require deliberately corrupted inputs that no off-the-shelf oracle
mints. Those remaining gaps are documented below.

This page cross-references, rather than duplicates, the fleet-wide machine index
`issen/docs/corpus-catalog.md`.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier | Evidence |
|---|---|---|---|---|
| **zlib / PNG CRC-32 known-answer** | Yes — the universally published CRC-32/ISO-HDLC check value `0xCBF43926` for `"123456789"`, plus reproducible single-byte values | The from-scratch CRC-32/ISO-HDLC implementation used for header and entry-array integrity fields | 1 | `forensic/tests/crc32_tests.rs:16` (`canonical_check_value`), `forensic/tests/crc32_tests.rs:21` (`single_byte_vectors`) |
| **NIST / FIPS 180-4 SHA-256 example vectors** | Yes — third-party standard test vectors (empty string, `"abc"`, the 56-byte two-block message) | The from-scratch SHA-256 implementation used for the disk evidence hash | 1 | `forensic/tests/sha256_tests.rs:7` (`empty_string_vector`), `:15` (`abc_vector`), `:24` (`two_block_vector`) |
| **The Sleuth Kit `mmls` 4.12.1** | Yes — a separate codebase from both this crate and the minter; it re-decodes the same on-disk bytes | Partition offsets and lengths (first/last LBA) of the real GPT image | 1 | `forensic/tests/real_gpt_oracle.rs` (`real_gpt_partition_layout_matches_mmls_sgdisk_oracle`) |
| **GPT fdisk `sgdisk` 1.0.10** | Yes — a separate codebase; minted the image and reports the per-partition GUID details mmls does not print | Disk GUID, per-partition type GUID + unique GUID, partition names | 1 | `forensic/tests/real_gpt_oracle.rs` (same test) |

Both crypto primitives are implemented from scratch in this repo
(`core/src/crc32.rs`, `core/src/sha256.rs`) and gated against externally-authored
answer keys, so the math is checked against a source we did not write.

The **GPT structural parse** is now backed by a real disk image (minted by
`sgdisk`, independently re-decoded by TSK `mmls`) — see "GPT structural layer
(real-data oracle)" below. The remaining **forensic detectors** (divergence,
overlap, concealment, MBR↔GPT) still rest on synthetic fixtures; see "Documented
gap".

## Independent test corpora

One real GPT disk image is committed and consumed:

| Corpus | Independent of us? | Size / MD5 | Validates | Tier | Consumed by |
|---|---|---|---|---|---|
| `tests/data/gpt_real_3part.img` | Yes — minted by `sgdisk`, re-decoded by `mmls` (both separate codebases) | 8 MiB / `cbda08767efb84203c5f02b827fc2a94` | Partition layout (first/last LBA), type/unique GUIDs, names, disk GUID, sector size, backup-GPT readability | 1 | `forensic/tests/real_gpt_oracle.rs` |

Provenance (verbatim mint commands, tool versions, captured oracle output) lives
in `tests/data/README.md`. The whole 8 MiB image is committed so both the primary
GPT (LBA 1) and the backup GPT (end of disk) are present.

Every other GPT header, partition-entry array, protective MBR, and corrupted-disk
variant consumed by the tests is constructed in-code by builder functions
(these drive the Tier-3 detector tests, which need deliberately malformed bytes):

| In-code fixture builder | Builds | Used by |
|---|---|---|
| `build_header(...)` | A single CRC-self-consistent GPT header | `forensic/tests/header_tests.rs:35` onward |
| `build_gpt_disk()` | A full primary+backup GPT disk image | `forensic/tests/analyse_tests.rs:58` |
| `build(mbr, gpt)` | A GPT disk with caller-specified MBR + GPT partitions | `forensic/tests/reconcile_tests.rs` |
| `raw_entry(...)` / `sector_with(...)` | Raw 16-byte MBR partition entries / an MBR sector | `forensic/tests/mbr_tests.rs:32` |
| `entry(...)` / array builders | GPT partition entries + array CRC | `forensic/tests/entry_tests.rs`, `type_name_tests.rs` |

The two crypto known-answer corpora (zlib's `"123456789"` and the NIST SHA-256
strings) are the only externally-authored test inputs in the repository, and they
are embedded as string literals in the test sources cited above.

## Per-capability validation

### GPT structural layer (real-data oracle) — Tier 1

`forensic/tests/real_gpt_oracle.rs` loads the real `tests/data/gpt_real_3part.img`,
runs it through `analyse()`, and asserts each partition's **first/last LBA**,
**type GUID**, **unique GUID**, and **name**, plus the **disk GUID**, the detected
**512-byte sector size**, **backup-GPT readability**, and that the clean disk is
**anomaly-free** — all against values captured from the independent oracles, not
computed by this crate. `mmls` (TSK 4.12.1) supplies the offsets/lengths; `sgdisk -i`
(GPT fdisk 1.0.10) supplies the GUID details mmls does not print. Both are
separate codebases, so their agreement on the same bytes is a genuine
cross-tool check. The resolved type names (e.g. "Microsoft Basic Data") come from
our own fleet KNOWLEDGE table and are asserted as a secondary check; the type
GUID *strings* are the independent, load-bearing assertion. Evidence:
`forensic/tests/real_gpt_oracle.rs`.

This covers the structural parse. It does **not** exercise the anomaly detectors
(divergence, overlap, concealment, MBR↔GPT) — a clean sgdisk image trips none of
them; those remain Tier 3 (see below).

### CRC-32/ISO-HDLC primitive — Tier 1

`forensic/tests/crc32_tests.rs` checks the from-scratch `crc32::checksum`
against the canonical published CRC-32/ISO-HDLC check value `0xCBF43926` for
`"123456789"` and against independently-reproducible single-byte zlib values
(`"a"` → `0xE8B7BE43`, `"abc"` → `0x352441C2`). The answer key is third-party.
Evidence: `forensic/tests/crc32_tests.rs:16`, `:21`.

### SHA-256 (FIPS 180-4) primitive — Tier 1

`forensic/tests/sha256_tests.rs` checks the from-scratch `sha256::digest`
against the NIST / FIPS 180-4 example vectors: the empty string, `"abc"`, and the
56-byte two-block message. Evidence: `forensic/tests/sha256_tests.rs:7`, `:15`,
`:24`.

### GPT header parse + self-CRC — Tier 3

`forensic/tests/header_tests.rs` parses a `build_header(...)`-constructed header,
confirms it self-validates, confirms a flipped `my_lba` byte fails the CRC, and
confirms bad-signature / too-short error paths. The header and its expected CRC
are both authored here. Evidence: `forensic/tests/header_tests.rs:49`
(`valid_self_crc_recognised`), `:59` (`corrupted_header_fails_crc`), `:67`,
`:74`.

### Partition-entry array parse + array CRC — Tier 3

`forensic/tests/entry_tests.rs` parses used/unused entries and confirms the
array CRC matches over an in-code entry array. Evidence:
`forensic/tests/entry_tests.rs:29`, `:43`, `:49`.

### `analyse()` anomaly pipeline — Tier 3

`forensic/tests/analyse_tests.rs` drives the full `analyse()` pipeline over the
synthetic `build_gpt_disk()` image and asserts that a clean disk is silent while
deliberately corrupted variants surface the expected anomalies: primary header
CRC, primary array CRC, missing backup, primary/backup divergence,
primary/backup array-content divergence, trailing-space-after-backup, header
LBA mismatch, header slack data, overlapping partitions, and the exposed GPT
evidence hash. Both the corruption and the expected anomaly code are authored
here. Evidence: `forensic/tests/analyse_tests.rs:113`–`:325`.

### Concealment / hidden-volume heuristics — Tier 3

High-entropy detection (`high_entropy_partition_flagged_as_hidden_volume`),
known-filesystem exclusion (`recognized_filesystem_not_flagged_as_encrypted`),
and the Shannon-entropy primitive itself (`forensic/tests/entropy_tests.rs`) are
validated on hand-constructed byte patterns. The entropy *primitive* has
analytically-derivable expected values (all-zero → 0 bits, two equiprobable
values → 1 bit, full 0..=255 range → 8 bits), which is a stronger check than a
chosen-output fixture, but the *partition data* it scores is synthetic.
Evidence: `forensic/tests/analyse_tests.rs:226`, `:246`;
`forensic/tests/entropy_tests.rs:7`, `:17`, `:30`.

### MBR ↔ GPT reconciliation — Tier 3

`forensic/tests/reconcile_tests.rs` and `forensic/tests/mbr_tests.rs` build a
disk with a caller-specified MBR and GPT and assert the cross-checks: proper
protective MBR is clean, missing/undersized protective MBR flagged, hybrid
hidden partition flagged, partition-before-first-usable flagged. All inputs are
in-code. Evidence: `forensic/tests/reconcile_tests.rs:94`–`:165`;
`forensic/tests/mbr_tests.rs:32`, `:56`, `:61`.

### 4K-sector handling — Tier 3

`forensic/tests/sector4k_tests.rs` confirms a forced sector size overrides
detection on a synthetic 4K-sector disk. Evidence:
`forensic/tests/sector4k_tests.rs:75`.

### Partition type-name resolution — Tier 3 (delegated to a fleet table)

`GptEntry::type_name` resolves the type GUID via `forensicnomicon::gpt::type_name`
(`core/src/entry.rs:77`). The lookup table lives in our own fleet KNOWLEDGE crate,
so this is **not** an independent oracle; the test (`type_name_tests.rs`) asserts
a known GUID resolves and an unknown one returns `None`. Evidence:
`forensic/tests/type_name_tests.rs:20`, `:29`; `core/src/entry.rs:77`.

### Duplicate / collision GUID detection — Tier 3

`forensic/tests/dup_guid_tests.rs` and `forensic/tests/collision_tests.rs`
validate duplicate-unique-GUID and cross-disk collision detection on in-code
GUID sets. Evidence: `forensic/tests/dup_guid_tests.rs:23`, `:30`;
`forensic/tests/collision_tests.rs:9`, `:18`, `:28`.

### Canonical finding conversion — Tier 3

`forensic/tests/canonical_finding_tests.rs` confirms an `Anomaly` converts to a
`forensicnomicon::report::Finding` carrying its location. Evidence:
`forensic/tests/canonical_finding_tests.rs:9`, `:22`.

## Documented gap — remaining synthetic-only claims

The **structural parse** is now Tier 1 (real image, `sgdisk` + `mmls` oracles,
`forensic/tests/real_gpt_oracle.rs`). What remains Tier 3 are the **anomaly
detectors**, because a clean off-the-shelf image trips none of them — they need
deliberately corrupted inputs that no standard tool mints:

- Primary/backup header & array divergence, missing/trailing-space backup, header
  LBA/slack checks, partition overlap and out-of-bounds extents (`analyse_tests.rs`).
- Concealment / hidden-volume entropy heuristics (`analyse_tests.rs`,
  `entropy_tests.rs`).
- MBR↔GPT reconciliation: protective-MBR sizing, hybrid-MBR hidden partitions
  (`reconcile_tests.rs`, `mbr_tests.rs`).

To raise these to Tier 1/2, the path is a real image deliberately damaged by an
independent tool (e.g. `dd`-zeroing the backup GPT, or a known-tampered DFIR CTF
image with documented ground truth), env-gated and fetched manually like the
sibling crates, with provenance recorded in `tests/data/README.md` and the fleet
`corpus-catalog.md`. Until those land, the **detector** claims rest on synthetic
fixtures and should be read as Tier 3; the **structural parse** is real-data
validated.

## Reproducing the validation

All tests are committed and always run — there are no env-gated or `#[ignore]`d
tests; the real GPT image is small (8 MiB) and committed in-repo.

```bash
# Real-data structural oracle (Tier 1 — sgdisk + mmls cross-check)
cargo test -p gpt-partition-forensic --test real_gpt_oracle

# Independent-oracle crypto known-answer tests (Tier 1)
cargo test -p gpt-partition-forensic --test crc32_tests
cargo test -p gpt-partition-forensic --test sha256_tests

# Forensic detector suite (Tier 3 synthetic fixtures)
cargo test -p gpt-partition-forensic --test analyse_tests
cargo test -p gpt-partition-forensic --test header_tests
cargo test -p gpt-partition-forensic --test entry_tests
cargo test -p gpt-partition-forensic --test reconcile_tests
cargo test -p gpt-partition-forensic --test mbr_tests

# Everything
cargo test --workspace
```

## Coverage & fuzzing as backstops

The workspace enforces panic-free production code (`unwrap_used` / `expect_used =
deny`), `#![forbid(unsafe_code)]`, and a `cargo fuzz` workspace whose invariant is
"must not panic" over both the parser and the full `analyse` pipeline. These are
regression and robustness backstops that prove behavior is exercised and the code
never panics on attacker-controllable input — they are **not** the correctness
claim. The independent correctness checks are the two Tier-1 crypto oracles and
the Tier-1 real-data structural oracle (`sgdisk` + `mmls` on a real image); the
remaining anomaly **detectors** rest on synthetic fixtures pending a
deliberately-damaged real image (see "Documented gap").
