# 7. Paranoid Gatekeeper: `forbid(unsafe)`, panic-free lints, `safe-read` readers

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse **untrusted, attacker-controllable disk images**: a header can
claim any `header_size`, any `num_partition_entries`, any self-referencing LBA. A
naive `data[off..off+4]` on such input panics or reads out of bounds. The fleet's
*Security & Robustness Standard — Paranoid Gatekeeper* requires every `*-core` /
`*-forensic` crate to never panic, never read out of bounds, and never trust a
length field.

A recurring fleet failure is each crate hand-rolling its own `bytes.rs` of
`read_u32_le`-style helpers, which drift and can overflow `usize` in a
`get(off..off+4)`. The fleet answer is the single audited `safe-read` crate
(`no_std`, `forbid(unsafe)`, fuzzed). Commit `318e97d` adopted it (then named
`forensic-bytes`); `398ec43` renamed the dependency to `safe-read`.

## Decision

Enforce a uniform robustness posture across the workspace:

1. **`unsafe_code = "forbid"`** in `[workspace.lints.rust]` (`Cargo.toml`) — no
   `unsafe` anywhere; the reader needs no mmap, so it takes the stricter `forbid`
   rather than the `deny` + bounded-allow that mmap readers (ewf, memf) use.
2. **`unwrap_used`/`expect_used = "deny"`** in `[workspace.lints.clippy]`, with
   `correctness`/`suspicious = "deny"`. Production code carries no
   `unwrap`/`expect`/`panic!`; tests opt out via
   `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]` (both
   `lib.rs` files).
3. **All integer field reads route through `safe-read`** (`le_u32`/`le_u64` in
   `core/src/header.rs`, `entry.rs`), never a hand-rolled `bytes.rs`. Length,
   offset, and count fields from the image are range-checked before use, and
   array reads are allocation-capped (`ENTRY_ARRAY_CAP` in `core/src/vfs.rs`).
4. **Fuzzed** — a standalone `cargo fuzz` workspace (`fuzz/`) drives both the
   parser and the full `analyse` pipeline; the invariant is "must not panic"
   (README "Trust, but verify"). `0c995d4` "harden entry-array read against
   crafted overflow" is a fuzz-hardening fix.

## Consequences

- Panic-freedom is enforced statically by lint (the construction guarantee) and
  tested empirically by the fuzzer (the measured evidence) — the two are
  complementary, and the README leads with "Fuzzed" and qualifies "panic-free" as
  "enforced by the workspace's lints" rather than a bare universal claim.
- `safe-read` is the fleet's shared, audited implementation, so this crate
  inherits its fuzzing and fixes instead of maintaining a private copy
  (*Dependency Preference — prefer our own crates*).
- `forbid(unsafe)` lets the crate wear the "unsafe-free" claim honestly; no
  bounded-allow exceptions exist to audit.
