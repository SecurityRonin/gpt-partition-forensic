# 8. Normalize findings onto `forensicnomicon::report`

Date: 2026-07-24
Status: Accepted

## Context

Each fleet analyzer used to emit its own `XxxAnalysis` type, forcing
orchestration (Issen, `disk4n6`) and any future GUI to special-case N bespoke
shapes. The fleet's reporting model (`~/src/ronin-issen/CLAUDE.md`, *The
Reporting Model — `forensicnomicon::report`*) makes every analyzer emit the one
shared `report::Finding`/`Observation` vocabulary — the union of the analyzers'
data — so consumers render findings uniformly. Commit `32bb530`
("feat(gpt-forensic)!: normalize onto forensicnomicon::report") migrated this
crate; `b94c1d0` added `Observation::evidence` so the on-disk location travels
with each finding.

## Decision

Keep the domain-specific `AnomalyKind` enum (the GPT knowledge — every code from
`GPT-HDR-CRC` to `GPT-MBR-HYBRID-HIDDEN`) in `forensic/src/findings.rs`, and
convert to canonical findings via `impl forensicnomicon::report::Observation for
Anomaly`:

- `severity()`, `code()`, `note()` are derived from `AnomalyKind` so they cannot
  drift (the module doc: "every anomaly's severity, stable code, and human note
  are derived from its `AnomalyKind`").
- `evidence()` emits `report::Evidence` carrying the field, value, and on-disk
  `Location` for each anomaly.
- The 5-level `Severity` scale is re-exported from `forensicnomicon::report`, not
  re-declared (`pub use forensicnomicon::report::Severity;`).

Per the split (ADR 0001), only the `forensic/` crate touches the reporting model;
`gpt-partition-core` stays free of `report::Observation`.

## Consequences

- `disk-forensic`, Issen, and a future GUI aggregate GPT findings into one
  `Report` alongside every other analyzer with no per-crate glue.
- The `code` values (`GPT-*`, SCREAMING-KEBAB, scheme-prefixed) are a published
  contract — stable across releases; new variants get new codes, never a rename.
- Findings are observations, never legal conclusions — MITRE/threat narration
  uses "consistent with," honoring the fleet epistemology.
- Because the migration changed the public type, it was a breaking release
  (`!` in the commit), coordinated with the `forensicnomicon` version pin in
  `[workspace.dependencies]`.
