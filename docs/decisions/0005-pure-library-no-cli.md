# 5. A pure data library — no bundled CLI, no text report

Date: 2026-07-24
Status: Accepted

## Context

Early versions carried their own CLI crate and a `text_report` renderer that
formatted the analysis for a terminal. That duplicated a concern the fleet
centralizes: the examiner-facing command line is the unified `disk4n6`
(`disk-forensic`), which auto-detects the partitioning scheme and dispatches to
`mbr-forensic` / `apm-forensic` / this crate. A per-scheme CLI fragments the UX
and forces this crate to own output-formatting policy that belongs at the
orchestration layer.

Two breaking commits removed the front-end:

- `e5413ca` "refactor!: drop the separate CLI crate — gpt-forensic is now a pure
  library".
- `dd94d5b` "refactor!: remove text_report — gpt-forensic is a pure data library
  (0.3.0)".

## Decision

`gpt-partition-forensic` is a **pure data library**. It exposes `analyse()` /
`analyse_with_options()` returning a `GptAnalysis` of typed structures and graded
`forensicnomicon::report` findings (`forensic/src/lib.rs`), and it renders
nothing. Presentation — text tables, JSON, colored severity — is the caller's
job, done once in `disk4n6`. The README directs users to
`cargo install disk-forensic` for a ready-made command line.

## Consequences

- Tier: **library**. This repo ships no binary an examiner runs; classifying it
  as product tier would be dishonest.
- No CLI-argument, terminal-width, or output-format code lives here, so the crate
  has no `clap`/`crossterm`-class dependencies and a small surface to fuzz and
  audit.
- Callers choose their own rendering; the machine-vs-human output policy lives in
  the front-end, not scattered across per-scheme libraries.
- The findings model is the stable contract other crates consume (ADR 0008), so
  removing the bespoke text report lost no capability — it removed a redundant
  one.
