// Copyright 2026 John "topjohnwu" Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helper functions for inspecting Samsung's Data Dynamic Partition (DDP) header
//! in Android Logical Partition (`super.img`) images.

const SPARSE_HEADER_MAGIC: u32 = 0xed26_ff3a;
const CHUNK_RAW: u16 = 0xcac1;
const CHUNK_FILL: u16 = 0xcac2;

const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616c_4467; // "gDla"

const DDP_SUPER_USED_SIZE_OFFSET: usize = 0x400;
const LP_GEOMETRY_OFFSET: usize = 0x1000;
const REQUIRED_LOGICAL_SIZE: usize = LP_GEOMETRY_OFFSET + 4;

/// Number of bytes at the start of a (possibly sparse) super image that are needed
/// to read its DDP header and verify its LP geometry magic.
pub(crate) const SUPER_METADATA_PREFIX_SIZE: usize = 16 * 1024;

/// Inspects the raw or sparse bytes at the start of a `super.img` and extracts
/// Samsung's non-standard DDP `super_used_size` (in 512-byte sectors), if present.
pub(crate) fn inspect_super_bytes(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if magic == SPARSE_HEADER_MAGIC {
        let logical_data = unsparse_prefix(data, REQUIRED_LOGICAL_SIZE)?;
        parse_super_used_size(&logical_data)
    } else {
        parse_super_used_size(data)
    }
}

/// Unsparses only the prefix of a sparse image up to `target_size` bytes.
fn unsparse_prefix(data: &[u8], target_size: usize) -> Option<Vec<u8>> {
    if data.len() < 28 {
        return None;
    }

    let file_hdr_sz = u16::from_le_bytes(data[8..10].try_into().ok()?) as usize;
    let chunk_hdr_sz = u16::from_le_bytes(data[10..12].try_into().ok()?) as usize;
    let blk_sz = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;

    if blk_sz == 0 || chunk_hdr_sz < 12 || file_hdr_sz < 28 || data.len() < file_hdr_sz {
        return None;
    }

    let mut logical_buf = vec![0u8; target_size];
    let mut logical_pos = 0;
    let mut offset = file_hdr_sz;

    while offset + chunk_hdr_sz <= data.len() && logical_pos < target_size {
        let chunk_type = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
        let chunk_sz_blocks =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().ok()?) as usize;
        let total_sz = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().ok()?) as usize;

        if total_sz < chunk_hdr_sz {
            return None;
        }

        let chunk_bytes = chunk_sz_blocks.checked_mul(blk_sz)?;
        let data_offset = offset + chunk_hdr_sz;

        if chunk_type == CHUNK_RAW {
            let data_sz = total_sz - chunk_hdr_sz;
            let avail = data.len().saturating_sub(data_offset).min(data_sz);
            let to_copy = avail.min(target_size - logical_pos);
            logical_buf[logical_pos..logical_pos + to_copy]
                .copy_from_slice(&data[data_offset..data_offset + to_copy]);
        } else if chunk_type == CHUNK_FILL && data_offset + 4 <= data.len() {
            let fill_val = &data[data_offset..data_offset + 4];
            let to_fill = chunk_bytes.min(target_size - logical_pos);
            for i in 0..to_fill {
                logical_buf[logical_pos + i] = fill_val[i % 4];
            }
        }
        // CHUNK_DONT_CARE leaves zeroes intact

        logical_pos = logical_pos.saturating_add(chunk_bytes);
        offset = offset.checked_add(total_sz)?;
    }

    Some(logical_buf)
}

/// Verifies the `liblp` geometry magic at `0x1000` and reads Samsung's DDP
/// `super_used_size` field at `0x400`.
///
/// Upstream `liblp` reserves the first 4096 bytes (`0x0000..0x0fff`) of `super` as zeroes.
/// On devices with Data Dynamic Partition (DDP), Samsung writes `super_used_size` (in
/// 512-byte sectors) as a little-endian `u32` at offset `0x400`, which the bootloader's
/// `GetSuperUsedSizeFromImage` reads during flashing. Non-DDP Samsung images and standard
/// `lpmake` images leave offset `0x400` as `0`.
fn parse_super_used_size(raw: &[u8]) -> Option<u32> {
    if raw.len() < REQUIRED_LOGICAL_SIZE {
        return None;
    }

    // Verify geometry header magic
    let geom_magic = u32::from_le_bytes(
        raw[LP_GEOMETRY_OFFSET..LP_GEOMETRY_OFFSET + 4]
            .try_into()
            .ok()?,
    );
    if geom_magic != LP_METADATA_GEOMETRY_MAGIC {
        return None;
    }

    let used_size = u32::from_le_bytes(
        raw[DDP_SUPER_USED_SIZE_OFFSET..DDP_SUPER_USED_SIZE_OFFSET + 4]
            .try_into()
            .ok()?,
    );

    (used_size > 0).then_some(used_size)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn build_test_raw_image(super_used_size: u32) -> Vec<u8> {
        let mut raw = vec![0u8; 8 * 1024];

        // Samsung DDP super_used_size at 0x400
        raw[DDP_SUPER_USED_SIZE_OFFSET..DDP_SUPER_USED_SIZE_OFFSET + 4]
            .copy_from_slice(&super_used_size.to_le_bytes());

        // Geometry at 0x1000
        raw[LP_GEOMETRY_OFFSET..LP_GEOMETRY_OFFSET + 4]
            .copy_from_slice(&LP_METADATA_GEOMETRY_MAGIC.to_le_bytes());

        raw
    }

    fn build_test_sparse_image(raw_payload: &[u8]) -> Vec<u8> {
        let blk_sz = 4096usize;
        let chunks: Vec<&[u8]> = raw_payload.chunks(blk_sz).collect();
        let total_blks = chunks.len() as u32;
        let mut sparse = Vec::new();

        // Sparse header (28 bytes)
        sparse.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes()); // magic
        sparse.extend_from_slice(&1u16.to_le_bytes()); // major
        sparse.extend_from_slice(&0u16.to_le_bytes()); // minor
        sparse.extend_from_slice(&28u16.to_le_bytes()); // file_hdr_sz
        sparse.extend_from_slice(&12u16.to_le_bytes()); // chunk_hdr_sz
        sparse.extend_from_slice(&(blk_sz as u32).to_le_bytes()); // blk_sz
        sparse.extend_from_slice(&total_blks.to_le_bytes()); // total_blks
        sparse.extend_from_slice(&(chunks.len() as u32).to_le_bytes()); // total_chunks
        sparse.extend_from_slice(&0u32.to_le_bytes()); // image_checksum

        // Emit one 4 KiB RAW chunk per block, matching Samsung's super.img layout
        // where chunk 0 holds 0x0000..0x0fff and chunk 1 starts at 0x1000.
        for chunk in chunks {
            sparse.extend_from_slice(&CHUNK_RAW.to_le_bytes());
            sparse.extend_from_slice(&0u16.to_le_bytes());
            sparse.extend_from_slice(&1u32.to_le_bytes());
            let total_sz = 12 + chunk.len() as u32;
            sparse.extend_from_slice(&total_sz.to_le_bytes());
            sparse.extend_from_slice(chunk);
        }

        sparse
    }

    #[test]
    fn test_inspect_super_used_size() {
        // DDP super.img (e.g. SM-F968B) has non-zero super_used_size at 0x400
        let ddp_raw = build_test_raw_image(26_779_384);
        assert_eq!(inspect_super_bytes(&ddp_raw), Some(26_779_384));

        let ddp_sparse = build_test_sparse_image(&ddp_raw);
        assert_eq!(inspect_super_bytes(&ddp_sparse), Some(26_779_384));

        // Non-DDP super.img (e.g. SM-P610 or AOSP lpmake) has 0 at 0x400
        let non_ddp_raw = build_test_raw_image(0);
        assert_eq!(inspect_super_bytes(&non_ddp_raw), None);

        let non_ddp_sparse = build_test_sparse_image(&non_ddp_raw);
        assert_eq!(inspect_super_bytes(&non_ddp_sparse), None);
    }
}
