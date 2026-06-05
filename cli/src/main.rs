//! Thin clap shell over [`gpt_forensic_cli::cmd`].

use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use gpt_forensic_cli::cmd;

#[derive(Parser)]
#[command(
    name = "gpt",
    about = "Forensic inspection of GUID Partition Table (GPT) disk images",
    version,
    // -h/--help and -V/--version cover everything; drop the redundant
    // auto-generated `help` subcommand from the command list.
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Full forensic analysis: header/array CRC integrity, primary/backup
    /// divergence, partition overlaps, and out-of-bounds extents
    #[command(visible_alias = "analyze")]
    Analyse { image: PathBuf },

    /// Dump one 512-byte LBA — annotated hex by default, raw bytes with --raw
    Dump {
        image: PathBuf,
        /// Logical block address to dump (default: 1, the primary GPT header)
        #[arg(long, default_value_t = 1)]
        lba: u64,
        /// Emit the raw 512-byte sector to stdout instead of annotated hex
        #[arg(long)]
        raw: bool,
    },
}

/// Open `image` for reading, returning the reader and its byte length (`0` if
/// the length cannot be determined).
fn open(image: &PathBuf) -> Result<(BufReader<File>, u64)> {
    let f = File::open(image).with_context(|| format!("cannot open {}", image.display()))?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    Ok((BufReader::new(f), size))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyse { image } => {
            let (mut reader, size) = open(&image)?;
            let name = image
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("disk.img");
            let out = cmd::analyse::run(&mut reader, size, name).context("analysis failed")?;
            print!("{out}");
        }
        Command::Dump { image, lba, raw } => {
            let (mut reader, _) = open(&image)?;
            if raw {
                let bytes = cmd::dump::run_raw(&mut reader, lba).context("dump failed")?;
                io::stdout()
                    .write_all(&bytes)
                    .context("stdout write failed")?;
            } else {
                let out = cmd::dump::run(&mut reader, lba).context("dump failed")?;
                print!("{out}");
            }
        }
    }
    Ok(())
}
