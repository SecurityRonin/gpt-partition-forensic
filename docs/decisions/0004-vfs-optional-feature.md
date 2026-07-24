# 4. Gate the VFS adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The `GptVolumes` VolumeSystem adapter (ADR 0003) pulls in `forensic-vfs` and its
transitive graph (`DynSource`, `SubRange`, the adapter machinery). But the
majority of `gpt-partition-core` consumers want only the bare table decoder:
`disk-forensic`'s scheme dispatch, a triage tool printing partitions, the
analyzer in `forensic/`. Forcing every one of them to compile the VFS graph
would inflate build times and dependency surface for a capability they never
call.

This is in tension with the fleet's *Batteries-Included* default (compile
everything in; do not slim with `default-features = false`). That default
governs **end-user binaries** shipped to examiners; `gpt-partition-core` is a
library whose primary consumers are other libraries, where a genuinely optional,
heavy integration subsystem is the documented exception.

## Decision

Ship the VFS adapter behind a non-default `vfs` feature:

```toml
# core/Cargo.toml
forensic-vfs = { version = "0.2", optional = true }

[features]
default = []
vfs = ["dep:forensic-vfs"]
```

The module is `#[cfg(feature = "vfs")] pub mod vfs;` (`core/src/lib.rs`). The
`core/Cargo.toml` comment records the rationale: "Behind the `vfs` feature so the
bare parser does not inherit the VFS dependency graph."

## Consequences

- The default `gpt-partition-core` build stays lean — `thiserror`, `safe-read`,
  `forensicnomicon` (its knowledge tables) only — so scheme-dispatch and triage
  consumers pay nothing for VFS.
- Consumers that compose evidence stacks opt in with
  `features = ["vfs"]`, and the fleet binaries that mount images turn the feature
  on, honoring *Batteries-Included* (the slim path is for outside/library
  consumers, never for our own tools).
- This is the sanctioned "rarely-wanted heavy subsystem" exception, not a
  capability amputation: the decode/grade path is unaffected and always on.
