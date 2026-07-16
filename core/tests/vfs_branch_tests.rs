#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Branch coverage for the `forensic-vfs` GPT adapter's non-fixture paths:
//! the short-read/EOF tolerance, the 512→4096 sector-size fall-through, and the
//! no-GPT `Unsupported` verdict — driven by an in-memory `ImageSource` so no
//! on-disk fixture is needed. Helpers live here (an integration crate), not in
//! the library's `#[cfg(test)]` module, so they do not count toward the
//! library's own coverage denominator.

#![cfg(feature = "vfs")]

use forensic_vfs::{
    DynSource, ImageSource, VfsError, VfsResult, VolumeKind, VolumeScheme, VolumeSystem,
};
use gpt::vfs::GptVolumes;
use std::sync::Arc;

/// A minimal in-memory [`ImageSource`] over a byte vector.
struct VecSource(Vec<u8>);

impl ImageSource for VecSource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let start = offset.min(self.0.len() as u64) as usize;
        let avail = &self.0[start..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
}

fn src(bytes: Vec<u8>) -> DynSource {
    Arc::new(VecSource(bytes))
}

/// A spec-correct GPT with 4096-byte logical sectors and one partition, so
/// `open` fails the 512-byte probe and succeeds on the 4096-byte retry.
fn build_4kn_gpt() -> Vec<u8> {
    const SS: usize = 4096;
    const SECTORS: u64 = 64;
    const NUM: u32 = 128;
    const ESIZE: u32 = 128;
    const ARRAY_SECTORS: u64 = (NUM as u64 * ESIZE as u64) / SS as u64; // 4
    let linux_type: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];
    let mut disk = vec![0u8; SECTORS as usize * SS];

    let mut array = vec![0u8; (NUM as usize) * (ESIZE as usize)];
    let fu = 2 + ARRAY_SECTORS; // 6
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&linux_type);
    e[16..24].copy_from_slice(&fu.to_le_bytes());
    e[24] = 0x33;
    e[32..40].copy_from_slice(&fu.to_le_bytes());
    e[40..48].copy_from_slice(&(fu + 10).to_le_bytes());
    array[0..128].copy_from_slice(&e);
    let acrc = gpt::crc32::checksum(&array);
    let bal = SECTORS - 1 - ARRAY_SECTORS;

    let mut hdr = [0u8; 512];
    hdr[0..8].copy_from_slice(b"EFI PART");
    hdr[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    hdr[12..16].copy_from_slice(&92u32.to_le_bytes());
    hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
    hdr[32..40].copy_from_slice(&(SECTORS - 1).to_le_bytes());
    hdr[40..48].copy_from_slice(&fu.to_le_bytes());
    hdr[48..56].copy_from_slice(&(bal - 1).to_le_bytes());
    hdr[56..72].copy_from_slice(&[0x11; 16]);
    hdr[72..80].copy_from_slice(&2u64.to_le_bytes());
    hdr[80..84].copy_from_slice(&NUM.to_le_bytes());
    hdr[84..88].copy_from_slice(&ESIZE.to_le_bytes());
    hdr[88..92].copy_from_slice(&acrc.to_le_bytes());
    let hcrc = gpt::crc32::checksum(&hdr[0..92]);
    hdr[16..20].copy_from_slice(&hcrc.to_le_bytes());

    disk[SS..SS + 512].copy_from_slice(&hdr); // LBA 1 @ 4096
    let aoff = 2 * SS;
    disk[aoff..aoff + array.len()].copy_from_slice(&array);
    disk
}

#[test]
fn no_gpt_source_is_unsupported() {
    // No "EFI PART" at either sector size → falls through both probes and returns
    // VfsError::Unsupported (never a panic).
    match GptVolumes::open(src(vec![0u8; 8192])) {
        Err(VfsError::Unsupported { scheme, layer }) => {
            assert_eq!(scheme, "GPT");
            assert_eq!(layer, "GptVolumes");
        }
        Ok(_) => panic!("no GPT must not parse"),
        Err(other) => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn truncated_source_tolerates_eof() {
    // A source shorter than one 512-byte sector: `fill` hits EOF (read_at returns
    // 0) and stops with a zeroed tail; the parse then finds no GPT — no panic.
    assert!(GptVolumes::open(src(vec![0u8; 100])).is_err());
}

#[test]
fn open_falls_through_to_4kn_sector_size() {
    // 512-byte probe finds no "EFI PART" at byte 512; the 4096-byte retry succeeds
    // (the `continue` fall-through), yielding the partition.
    let Ok(vs) = GptVolumes::open(src(build_4kn_gpt())) else {
        panic!("4Kn GPT must parse on the retry");
    };
    assert_eq!(vs.scheme(), VolumeScheme::Gpt);
    let vols = vs.volumes();
    assert_eq!(vols.len(), 1, "one used partition");
    assert_eq!(vols[0].kind, VolumeKind::Partition);
    assert_eq!(vols[0].start, 6 * 4096); // first_lba (6) * 4096
}
