//! `forensic-vfs` [`VolumeSystem`] adapter for GPT, behind the `vfs` feature.
//!
//! Wraps a parent [`ImageSource`](forensic_vfs::ImageSource) (a raw disk, or an
//! E01/VMDK/… container that already implements it) and exposes the disk's GPT
//! partitions as [`VolumeDesc`]s, each openable as a [`SubRange`] byte window.
//! This is the structural bridge that lets `E01 → GPT → NTFS` compose without
//! the filesystem layer knowing a partition scheme sits beneath it (ADR 0003).

use std::sync::Arc;

use forensic_vfs::adapters::SubRange;
use forensic_vfs::{DynSource, VfsError, VfsResult, VolumeDesc, VolumeScheme, VolumeSystem};

/// A GPT partition scheme over one parent byte source.
pub struct GptVolumes {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

impl GptVolumes {
    /// Probe `parent` for a GPT and build the volume table.
    pub fn open(parent: DynSource) -> VfsResult<Self> {
        // RED: not implemented yet — no partitions parsed.
        Ok(Self {
            parent,
            volumes: Vec::new(),
        })
    }
}

impl VolumeSystem for GptVolumes {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Gpt
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let v = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "gpt volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(self.parent.clone(), v.start, v.len)))
    }
}

#[cfg(test)]
mod tests {
    use super::GptVolumes;
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{DynSource, VolumeKind, VolumeScheme, VolumeSystem};
    use std::sync::Arc;

    /// The real `sgdisk`-minted, `mmls`-verified 3-partition GPT (Tier-1 oracle;
    /// see `tests/data/README.md`). Opened via the real positioned-read
    /// `FileSource`, located by manifest dir so the working directory does not
    /// matter.
    fn real_gpt() -> DynSource {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/data/gpt_real_3part.img"
        );
        Arc::new(FileSource::open(path).expect("open real GPT fixture"))
    }

    #[test]
    fn gpt_volumes_match_mmls_sgdisk_oracle() {
        let vs = GptVolumes::open(real_gpt()).expect("real GPT must parse");
        assert_eq!(vs.scheme(), VolumeScheme::Gpt);

        let vols = vs.volumes();
        assert_eq!(vols.len(), 3, "three used partitions");

        // Answer key: mmls 4.12.1 + `sgdisk -i`, 512-byte sectors, inclusive
        // LBAs. start = first_lba*512; len = (last_lba - first_lba + 1)*512.
        // 0: BASICDATA  2048..=6143   (4096 sectors)
        assert_eq!(vols[0].kind, VolumeKind::Partition);
        assert_eq!(vols[0].start, 2048 * 512);
        assert_eq!(vols[0].len, 4096 * 512);
        assert_eq!(vols[0].label.as_deref(), Some("BASICDATA"));
        assert_eq!(
            vols[0].type_hint.as_deref(),
            Some("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
        );
        // 1: LINUXFS    6144..=10239  (4096 sectors)
        assert_eq!(vols[1].start, 6144 * 512);
        assert_eq!(vols[1].len, 4096 * 512);
        assert_eq!(vols[1].label.as_deref(), Some("LINUXFS"));
        assert_eq!(
            vols[1].type_hint.as_deref(),
            Some("0FC63DAF-8483-4772-8E79-3D69D8477DE4")
        );
        // 2: EFISYSTEM  10240..=12287 (2048 sectors)
        assert_eq!(vols[2].start, 10240 * 512);
        assert_eq!(vols[2].len, 2048 * 512);
        assert_eq!(vols[2].label.as_deref(), Some("EFISYSTEM"));
        assert_eq!(
            vols[2].type_hint.as_deref(),
            Some("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
        );
    }

    #[test]
    fn open_volume_windows_the_partition_bytes() {
        let parent = real_gpt();
        let vs = GptVolumes::open(parent.clone()).expect("parse");
        let efi = vs.open_volume(2).expect("open EFI volume");
        // The window length equals the EFI partition length.
        assert_eq!(efi.len(), 2048 * 512);
        // Byte 0 of the window equals the parent byte at the partition's start
        // offset (10240*512) — proving the SubRange addresses the right span.
        let mut win = [0u8; 32];
        assert_eq!(efi.read_at(0, &mut win).expect("read window"), 32);
        let mut par = [0u8; 32];
        parent.read_at(10240 * 512, &mut par).expect("read parent");
        assert_eq!(win, par);
    }

    #[test]
    fn open_volume_out_of_range_errors_not_panics() {
        let vs = GptVolumes::open(real_gpt()).expect("parse");
        assert!(vs.open_volume(99).is_err());
    }
}
