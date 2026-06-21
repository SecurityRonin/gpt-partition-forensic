# Test data — provenance

This directory holds real test fixtures for `gpt-partition-forensic`. It follows
the fleet one-root standard (a single `tests/data/` at the repo root); workspace
members reach it with a relative `include_bytes!("../../tests/data/<file>")`.

The fleet-wide machine index is `issen/docs/corpus-catalog.md` — this README is
the co-located human-facing detail; cross-reference, do not duplicate.

#### gpt_real_3part.img

- **Classification:** `REAL-self` — a real GPT disk image, self-minted from
  independent tool output (sgdisk), then cross-checked by a separate tool (mmls).
- **Source:** minted on this machine with **GPT fdisk (sgdisk) 1.0.10**.
  Independently re-decoded by **The Sleuth Kit `mmls` 4.12.1** (a separate
  codebase from both sgdisk and this crate) — that cross-tool agreement is what
  makes it a genuine independent oracle.
- **Size:** 8,388,608 bytes (8 MiB). The whole image is committed so both the
  primary GPT (LBA 1) and the **backup** GPT (end of disk) are present.
- **MD5:** `cbda08767efb84203c5f02b827fc2a94`
- **License:** the bytes are this repo's own trivial tool output (sgdisk itself
  is GPL, but the produced image is not a derivative work of sgdisk's source);
  committed and freely redistributable as self-minted forensic test data.
- **Consumed by:** `forensic/tests/real_gpt_oracle.rs`
  (`real_gpt_partition_layout_matches_mmls_sgdisk_oracle`).

**Verbatim generator commands** (reproducible):

```bash
dd if=/dev/zero of=gpt_real_3part.img bs=1M count=8
sgdisk --disk-guid=A1A2A3A4-B1B2-C1C2-D1D2-E1E2E3E4E5E6 \
  -n 1:2048:+2M -t 1:0700 -c 1:BASICDATA \
  -n 2:0:+2M    -t 2:8300 -c 2:LINUXFS \
  -n 3:0:+1M    -t 3:EF00 -c 3:EFISYSTEM \
  -u 1:11111111-2222-3333-4444-555555555501 \
  -u 2:11111111-2222-3333-4444-555555555502 \
  -u 3:11111111-2222-3333-4444-555555555503 \
  gpt_real_3part.img
```

**Independent oracle output captured as the answer key** (`mmls gpt_real_3part.img`,
512-byte sectors, inclusive [Start, End]):

```
004:  000   0000002048   0000006143   0000004096   BASICDATA
005:  001   0000006144   0000010239   0000004096   LINUXFS
006:  002   0000010240   0000012287   0000002048   EFISYSTEM
```

GUID details (`sgdisk -i N`, which mmls does not print):

| # | type GUID | unique GUID | type name |
|---|---|---|---|
| 1 | `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` | `…555555555501` | Microsoft basic data |
| 2 | `0FC63DAF-8483-4772-8E79-3D69D8477DE4` | `…555555555502` | Linux filesystem |
| 3 | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | `…555555555503` | EFI system partition |

Disk GUID (`sgdisk -p`): `A1A2A3A4-B1B2-C1C2-D1D2-E1E2E3E4E5E6`.
