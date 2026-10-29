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

//! LZ4 frames: header parsing and streaming of compressed or decompressed blocks.

use futures::io::{AsyncRead, AsyncReadExt};
use futures::stream::{self, Stream};
use std::borrow::Cow;
use std::io;

// Lz4FrameHeader asserts the content size is present, so the header size is always 15
const LZ4_HEADER_SIZE: usize = 15;

/// Header containing metadata parsed from an LZ4 frame.
#[derive(Clone, Debug)]
pub(crate) struct Lz4FrameHeader {
    /// Total size of the decompressed content in bytes.
    pub(crate) content_size: u64,
    /// Maximum size of a block in bytes.
    pub(crate) block_max_size: u64,
}

impl Lz4FrameHeader {
    /// Parses the LZ4 frame header from an async reader.
    pub(crate) async fn parse<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<Self> {
        let mut header = [0u8; LZ4_HEADER_SIZE];
        reader.read_exact(&mut header).await?;
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());

        if magic != 0x184D2204 {
            // We only support the standard LZ4 frame magic in this context,
            // not the skippable frames (0x184D2A50 - 0x184D2A5F)
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Not a valid LZ4 frame. Magic: 0x{:08X}", magic),
            ));
        }

        let flg = header[4];

        let version = (flg >> 6) & 0x03;
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported LZ4 version: {}", version),
            ));
        }

        let block_independence = ((flg >> 5) & 0x01) == 1;
        let block_checksum = ((flg >> 4) & 0x01) == 1;
        let content_size_flag = ((flg >> 3) & 0x01) == 1;
        let dict_id_flag = (flg & 0x01) == 1;

        if !content_size_flag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 content size must be enabled",
            ));
        }
        if block_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 block checksum must be disabled",
            ));
        }
        if !block_independence {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 block independence must be enabled",
            ));
        }
        if dict_id_flag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 dictionary ID must be disabled",
            ));
        }

        let bd = header[5];

        let block_max_size_code = (bd >> 4) & 0x07;
        let block_max_size = match block_max_size_code {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => 4 * 1024 * 1024,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid block max size code: {}", block_max_size_code),
                ));
            }
        };

        let content_size = u64::from_le_bytes(header[6..14].try_into().unwrap());

        Ok(Self {
            content_size,
            block_max_size,
        })
    }
}

/// Streams an LZ4 frame from `reader` as slices of whole compressed blocks, each
/// paired with its decompressed size. A slice holds as many blocks as fit in
/// `slice_max_bytes` of decompressed data, and at least one.
pub(super) fn compressed_slices<'r, R: AsyncRead + Unpin>(
    reader: &'r mut R,
    header: Option<&Lz4FrameHeader>,
    slice_max_bytes: usize,
) -> impl Stream<Item = io::Result<(usize, Vec<u8>)>> + 'r {
    let (block_max_size, remaining_decompressed) =
        header.map_or((0, 0), |h| (h.block_max_size as usize, h.content_size));
    let max_blocks = slice_max_bytes
        .checked_div(block_max_size)
        .map_or(0, |n| n.max(1));
    let iter = Lz4SliceIterator {
        reader,
        block_max_size,
        max_blocks,
        remaining_decompressed,
        started: false,
        finished: block_max_size == 0,
    };
    stream::unfold(iter, |mut it| async move {
        it.next_slice().await.map(|item| (item, it))
    })
}

/// Streams the decompressed contents of an LZ4 frame from `reader` in slices of at
/// most `slice_max_bytes`.
pub(super) fn decompressed_slices<'r, R: AsyncRead + Unpin>(
    reader: &'r mut R,
    header: Option<&Lz4FrameHeader>,
    slice_max_bytes: usize,
) -> impl Stream<Item = io::Result<Vec<u8>>> + 'r {
    let block_max_size = header.map_or(0, |h| h.block_max_size as usize);
    let iter = Lz4DecompressedSliceIterator {
        reader,
        block_max_size,
        slice_max_bytes,
        leftover: Vec::new(),
        started: false,
        finished: block_max_size == 0,
    };
    stream::unfold(iter, |mut it| async move {
        it.next_slice().await.map(|item| (item, it))
    })
}

struct Lz4SliceIterator<'r, R> {
    reader: &'r mut R,
    block_max_size: usize,
    max_blocks: usize,
    remaining_decompressed: u64,
    started: bool,
    finished: bool,
}

impl<'r, R: AsyncRead + Unpin> Lz4SliceIterator<'r, R> {
    async fn next_slice(&mut self) -> Option<io::Result<(usize, Vec<u8>)>> {
        match self.try_next_slice().await {
            Ok(Some(slice)) => Some(Ok(slice)),
            Ok(None) => None,
            Err(e) => {
                self.finished = true;
                Some(Err(e))
            }
        }
    }

    async fn try_next_slice(&mut self) -> io::Result<Option<(usize, Vec<u8>)>> {
        if self.finished {
            return Ok(None);
        }
        if !self.started {
            let mut header = [0u8; LZ4_HEADER_SIZE];
            self.reader.read_exact(&mut header).await?;
            self.started = true;
        }

        let mut buffer = Vec::new();
        let mut num_blocks = 0;

        while num_blocks < self.max_blocks {
            let mut size_bytes = [0u8; 4];
            self.reader.read_exact(&mut size_bytes).await?;

            let block_size = u32::from_le_bytes(size_bytes);
            if block_size == 0 {
                self.finished = true;
                break;
            }

            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            if data_size > self.block_max_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "LZ4 block size {} exceeds max block size {}",
                        data_size, self.block_max_size
                    ),
                ));
            }
            let start = buffer.len();
            buffer.resize(start + 4 + data_size, 0);
            buffer[start..start + 4].copy_from_slice(&size_bytes);
            self.reader.read_exact(&mut buffer[start + 4..]).await?;

            num_blocks += 1;
        }

        if buffer.is_empty() {
            return Ok(None);
        }

        let decompressed_size = std::cmp::min(
            self.remaining_decompressed,
            (num_blocks as u64) * (self.block_max_size as u64),
        ) as usize;
        self.remaining_decompressed -= decompressed_size as u64;

        Ok(Some((decompressed_size, buffer)))
    }
}

/// Reader state that produces decompressed byte chunks from an LZ4 stream.
struct Lz4DecompressedSliceIterator<'r, R> {
    reader: &'r mut R,
    block_max_size: usize,
    slice_max_bytes: usize,
    leftover: Vec<u8>,
    started: bool,
    finished: bool,
}

impl<'r, R: AsyncRead + Unpin> Lz4DecompressedSliceIterator<'r, R> {
    async fn next_slice(&mut self) -> Option<io::Result<Vec<u8>>> {
        match self.try_next_slice().await {
            Ok(Some(slice)) => Some(Ok(slice)),
            Ok(None) => None,
            Err(e) => {
                self.finished = true;
                self.leftover.clear();
                Some(Err(e))
            }
        }
    }

    async fn try_next_slice(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.finished && self.leftover.is_empty() {
            return Ok(None);
        }
        if !self.started {
            let mut header = [0u8; LZ4_HEADER_SIZE];
            self.reader.read_exact(&mut header).await?;
            self.started = true;
        }

        let mut buffer = Vec::with_capacity(self.slice_max_bytes);

        // Drain any leftover decompressed bytes from a previous block
        let take = self.slice_max_bytes.min(self.leftover.len());
        buffer.extend(self.leftover.drain(..take));

        let mut block_buf = Vec::new();

        while buffer.len() < self.slice_max_bytes && !self.finished {
            let mut size_bytes = [0u8; 4];
            self.reader.read_exact(&mut size_bytes).await?;

            let block_size = u32::from_le_bytes(size_bytes);
            if block_size == 0 {
                // EndMark reached
                self.finished = true;
                break;
            }

            let is_uncompressed = (block_size & 0x8000_0000) != 0;
            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            if data_size > self.block_max_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "LZ4 block size {} exceeds max block size {}",
                        data_size, self.block_max_size
                    ),
                ));
            }
            block_buf.resize(data_size, 0);
            self.reader.read_exact(&mut block_buf).await?;

            let decomp = if is_uncompressed {
                Cow::Borrowed(&block_buf[..])
            } else {
                let decomp = lz4_flex::block::decompress(&block_buf, self.block_max_size)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Cow::Owned(decomp)
            };

            let needed = self.slice_max_bytes - buffer.len();
            if decomp.len() <= needed {
                buffer.extend_from_slice(&decomp);
            } else {
                buffer.extend_from_slice(&decomp[..needed]);
                self.leftover.extend_from_slice(&decomp[needed..]);
                break;
            }
        }

        if buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(buffer))
        }
    }
}
