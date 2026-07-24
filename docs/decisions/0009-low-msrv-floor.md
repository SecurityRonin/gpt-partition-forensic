# 9. Low, CI-verified MSRV floor (1.85) separate from the pinned dev toolchain (1.96)

Date: 2026-07-24
Status: Accepted

## Context

The fleet policy separates two distinct numbers (`~/.claude/CLAUDE.core.md`,
*Rust MSRV & Toolchain Policy*):

- the **dev toolchain** — one pinned version every contributor and CI builds
  with, ending fmt/clippy drift; and
- the **declared MSRV** (`rust-version`) — a downstream-facing compatibility
  promise, kept **low and CI-verified** for *published libraries* because a low
  MSRV widens the crates.io audience and is a README trust signal.

This repo publishes libraries (ADR 0005), so it takes the library branch: pin the
toolchain high, promise a low floor.

## Decision

- **Pin the dev toolchain to the current fleet stable** — `rust-toolchain.toml`
  `channel = "1.96.0"` with `components = ["clippy", "rustfmt"]` (the single
  source of truth; `50d2d66` "pin toolchain to 1.96.0 (fleet toolchain policy)").
- **Declare a low MSRV of `1.85`** — `[workspace.package] rust-version = "1.85"`
  (`Cargo.toml`), inherited by both members.
- **Verify the floor in CI** — `.github/workflows/ci.yml` runs a dedicated
  `MSRV (1.85)` job on `dtolnay/rust-toolchain@1.85`, so the promise is a checked
  guarantee, not an aspiration.

## Consequences

- Downstream consumers on Rust 1.85+ can depend on `gpt-partition-core` /
  `gpt-partition-forensic`, and the MSRV badge in the README reflects a
  CI-enforced fact.
- Raising the floor is treated as a near-breaking change: only when a dependency
  or language feature genuinely requires it, deliberately, not to match the
  toolchain bump.
- **Unrecovered rationale:** the choice of `1.85` specifically (rather than a
  lower floor) is not explained in the commit history — it is most plausibly the
  effective floor of a dependency in the graph (`forensic-vfs` /
  `forensicnomicon` / `safe-read`), but that is inference. Rationale reconstructed
  from structure; original intent not recovered in available history. The
  CI-verified floor is the current, testable fact regardless.
