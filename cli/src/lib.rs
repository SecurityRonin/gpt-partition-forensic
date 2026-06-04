//! Library half of the `gpt` CLI: each subcommand is a pure function returning a
//! ready-to-print `String` (or raw bytes), so it can be unit-tested against an
//! in-memory image without spawning the binary. `main.rs` is a thin clap shell.

pub mod cmd;
