# 2. Crate naming: `gpt-partition-*` prefix, `gpt-core` collision, `[lib] name = "gpt"`

Date: 2026-07-24
Status: Accepted

## Context

Two naming problems had to be resolved before publishing.

1. **The repo was first named `gpt-forensic`.** Under the fleet naming grammar a
   bare `gpt-forensic` crate over-claims the whole GPT namespace, and the
   short-form prefix `gpt-` is a generic word that does not stand alone on
   crates.io. Commits `df72cba` / `25c6c18` renamed the repo and crates to the
   self-describing `gpt-partition-*` form.
2. **The natural reader name `gpt-core` is already taken** on crates.io by an
   unrelated third party (`gpt-core` 0.0.6). The fleet rule for that case
   (`~/src/ronin-issen/CLAUDE.md`, *Crate naming grammar* → "If `<x>-core`
   itself is taken … the reader publishes under the `<x>-forensic-core` form")
   yields a `gpt-partition-core` package here, while the ergonomic import path
   should stay short.

## Decision

- Publish the reader as **`gpt-partition-core`** and the analyzer as
  **`gpt-partition-forensic`** (the `core/Cargo.toml` header comment records the
  collision rationale verbatim).
- Keep the ergonomic import path **`use gpt::…`** via `[lib] name = "gpt"` in
  `core/Cargo.toml`, so consumers write `use gpt::{GptHeader, GptEntry, Guid}`
  regardless of the published package name.
- Declare the inter-crate dependency once in the workspace as
  `gpt = { path = "core", version = "0.6.0", package = "gpt-partition-core" }`
  (`Cargo.toml` `[workspace.dependencies]`), so a version bump touches one line.

## Consequences

- The published names are unambiguous on crates.io and do not fight the
  third-party `gpt-core`, while downstream code keeps the terse `gpt::` path.
- The repo, both crates, badges, and the sibling cross-links all read
  `gpt-partition-*`; the stale `gpt-forensic` name was swept from docs
  (`df72cba` "fix repository URL after gpt-forensic → gpt-partition-forensic
  rename").
- Because the bare package name changed after early publishes, the name is
  settled now; renaming again would strand the old crates.io names (the fleet's
  72h rename window has long passed).
