# 6. From-scratch CRC-32 and SHA-256, validated against independent oracles

Date: 2026-07-24
Status: Accepted

## Context

The reader needs two hash primitives:

- **CRC-32/ISO-HDLC** — GPT stores it in the header and over the partition
  array; validating it is the whole point of the integrity check.
- **SHA-256** — an evidence/chain-of-custody fingerprint of the header sector
  plus entry array (`GptAnalysis.gpt_sha256`), so an analyst can prove the
  structure did not change between acquisitions.

The fleet's global rule is "never hand-roll a cryptographic primitive — use a
mature, audited crate" (`~/.claude/CLAUDE.core.md`). That rule targets crypto
used for *security decisions* (key derivation, authentication, decryption),
where a hand-rolled S-box or round function is unaudited and side-channel-unsafe.
Neither use here is a security boundary: CRC-32 is a non-cryptographic checksum,
and the SHA-256 is a tamper-evidence *fingerprint*, not a MAC or a key. Against
that, the crate advertises "dependency-light" as a trust signal for evidence
parsers, and both algorithms are small, fully specified, and cheap to verify.

## Decision

Implement both from scratch in `gpt-partition-core`, keeping the runtime
dependencies to `thiserror`, `safe-read`, and `forensicnomicon`:

- `core/src/crc32.rs` — table-free bitwise CRC-32/ISO-HDLC (poly `0xEDB88320`,
  init/final-XOR `0xFFFFFFFF`), matching zlib/PNG. Throughput is irrelevant
  because GPT integrity fields are small.
- `core/src/sha256.rs` — FIPS 180-4 SHA-256, round/init constants reproduced
  verbatim from the standard for diffability.

Correctness is established against **independent third-party oracles**, not
self-authored expectations (the anti-LZNT1-trap requirement of *Evidence-Based
Rigor*): the CRC against zlib's canonical check value
`checksum(b"123456789") == 0xCBF43926`, and SHA-256 against the NIST/FIPS 180-4
known-answer vectors (`d6c4e25`/`a59f874`). This is documented in
`docs/validation.md` and the README "Trust, but verify" section.

## Consequences

- The reader stays dependency-light and `forbid(unsafe)`, with no C-binding or
  large crypto crate in the graph — a real trust differentiator for an evidence
  parser.
- The from-scratch code is a *value-producing, oracle-checkable* path, so the
  mandatory independent oracle (zlib/NIST vectors) is present — tier-1 validation
  for these two primitives.
- Should a security-grade hash ever be needed (e.g. HMAC over evidence), this
  decision does **not** license hand-rolling it — the global rule reasserts and a
  RustCrypto crate is used.
