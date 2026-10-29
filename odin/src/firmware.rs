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

use crate::FlashError;
use crate::progress::{self, FlashEvent};
use crate::tar::TarArchive;
use fast_md5::Md5;
use futures::StreamExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, Cursor};
use futures::stream::{self, Stream};
use samloader_pit::PitEntry;
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A file inside a TAR package.
#[derive(Clone, Debug)]
pub(crate) struct PackageEntry {
    /// Path of the file inside the archive.
    pub(crate) original_name: String,
    /// File name with any directory and `.lz4` suffix stripped.
    pub(crate) normalized_name: String,
    /// Index of the containing package.
    pub(crate) package_index: usize,
    /// Byte offset of the file's data within the package.
    pub(crate) offset: u64,
    /// Size of the file's data in bytes.
    pub(crate) size: u64,
    /// Whether the file name has a `.lz4` suffix.
    pub(crate) is_lz4: bool,
}

/// The flashable contents of a set of TAR packages, honoring `download-list.txt`.
pub(crate) struct PackageIndex {
    /// Files to consider for flashing, in package order. Metadata and PIT files
    /// are excluded.
    pub(crate) entries: Vec<PackageEntry>,
    /// Whether any package contained a `download-list.txt`.
    pub(crate) has_download_list: bool,
    /// Value of `super_used_size.txt`, if present.
    pub(crate) super_used_size: Option<u32>,
    /// The first PIT file found, if requested.
    pub(crate) pit_bytes: Option<Vec<u8>>,
}

impl PackageIndex {
    /// Indexes the files in `packages`. Readers are only accessed through
    /// absolute seeks. If `want_pit` is set, the first PIT file found is read.
    pub(crate) async fn scan<R: AsyncRead + AsyncSeek + Unpin>(
        packages: &mut [(String, R)],
        want_pit: bool,
    ) -> Result<Self, FlashError> {
        if packages.is_empty() {
            return Ok(Self {
                entries: Vec::new(),
                has_download_list: false,
                super_used_size: None,
                pit_bytes: None,
            });
        }

        let mut archives_download_lists: Vec<HashSet<String>> = Vec::new();
        let mut all_packages_entries: Vec<Vec<PackageEntry>> = Vec::new();
        let mut pit_from_tar: Option<Vec<u8>> = None;
        let mut has_download_list = false;
        let mut super_used_size = None;

        for (package_index, (pkg_name, reader)) in packages.iter_mut().enumerate() {
            let mut archive = TarArchive::new(&mut *reader);
            let mut package_entries = Vec::new();

            while let Some(mut entry) = archive
                .next_entry()
                .await
                .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?
            {
                let entry_path = entry.path().to_string();
                let offset = entry.raw_file_position();
                let size = entry.size();

                let (normalized_name, is_lz4) = normalize_basename(&entry_path);

                if normalized_name == "download-list.txt" {
                    let mut content = String::new();
                    entry
                        .read_to_string(&mut content)
                        .await
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?;

                    has_download_list = true;
                    let download_list = content
                        .lines()
                        .filter_map(|s| {
                            let s = s.trim();
                            if s.is_empty() {
                                None
                            } else {
                                Some(s.to_string())
                            }
                        })
                        .collect();
                    archives_download_lists.push(download_list);
                } else if normalized_name == "super_used_size.txt" {
                    let mut content = String::new();
                    entry
                        .read_to_string(&mut content)
                        .await
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?;
                    let val = content.trim().parse::<u32>().map_err(|e| {
                        FlashError::ArchiveCorrupted(
                            pkg_name.clone(),
                            io::Error::new(io::ErrorKind::InvalidData, e),
                        )
                    })?;
                    super_used_size = Some(val);
                } else if normalized_name.ends_with(".pit") {
                    if want_pit && pit_from_tar.is_none() {
                        let mut bytes = Vec::new();
                        entry
                            .read_to_end(&mut bytes)
                            .await
                            .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?;
                        pit_from_tar = Some(bytes);
                    }
                } else {
                    package_entries.push(PackageEntry {
                        original_name: entry_path,
                        normalized_name,
                        package_index,
                        offset,
                        size,
                        is_lz4,
                    });
                }
            }

            all_packages_entries.push(package_entries);
        }

        // If any package contained a manifest, we use it as our global download allowlist
        let download_allowlist = if let Some((first, rest)) = archives_download_lists.split_first()
        {
            if !rest.iter().all(|m| m == first) {
                return Err(FlashError::CrossArchiveInconsistency);
            }
            Some(first)
        } else {
            None
        };

        let mut resolved_entries: Vec<PackageEntry> = Vec::new();

        // Apply manifest filtering and positional precedence (last-writer-wins)
        for package_entries in all_packages_entries {
            for entry in package_entries {
                if let Some(allowlist) = download_allowlist {
                    if allowlist.contains(&entry.normalized_name) {
                        resolved_entries.push(entry);
                    } else {
                        progress::println(&format!(
                            "Skipping {} (not in download-list.txt)",
                            entry.original_name
                        ));
                    }
                } else {
                    resolved_entries.push(entry);
                }
            }
        }

        Ok(Self {
            entries: resolved_entries,
            has_download_list,
            super_used_size,
            pit_bytes: pit_from_tar,
        })
    }
}

/// Strips the directory and `.lz4` suffix from a file name, also returning
/// whether the suffix was present.
pub(crate) fn normalize_basename(path_str: &str) -> (String, bool) {
    let mut filename = Path::new(path_str)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    if filename.to_lowercase().ends_with(".lz4") {
        filename.truncate(filename.len() - 4);
        (filename, true)
    } else {
        (filename, false)
    }
}

// This is asserted by Lz4FrameHeader so the header size is always 15
const LZ4_HEADER_SIZE: usize = 15;

/// Verifies the trailing MD5 checksum appended to `.tar.md5` package files.
pub async fn verify_md5_footer<R: AsyncRead + AsyncSeek + Unpin>(
    mut reader: R,
    name: &str,
) -> io::Result<()> {
    let file_size = reader.seek(SeekFrom::End(0)).await?;

    if file_size < 34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File is too small to contain a valid MD5 footer",
        ));
    }

    // Read the last 512 bytes of the file. Since the TAR file must end with at least
    // two blocks of zeroes, the last null byte (0x00) marks the exact boundary
    // between the TAR payload and the appended plain-text MD5 footer.
    let seek_pos = file_size.saturating_sub(512);
    reader.seek(SeekFrom::Start(seek_pos)).await?;
    let mut last_bytes = vec![0u8; (file_size - seek_pos) as usize];
    reader.read_exact(&mut last_bytes).await?;

    // Find the last null byte (0x00)
    let mut last_null_idx = None;
    for i in (0..last_bytes.len()).rev() {
        if last_bytes[i] == 0 {
            last_null_idx = Some(i);
            break;
        }
    }

    let Some(null_idx) = last_null_idx else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid null separator for the MD5 footer",
        ));
    };

    let footer_start = null_idx + 1;
    let footer_bytes = &last_bytes[footer_start..];
    let footer_str = String::from_utf8_lossy(footer_bytes);
    let footer_line = footer_str.lines().last().unwrap_or_default();

    if footer_line.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid MD5 checksum at the end of the file",
        ));
    }

    let expected_hex = &footer_line[..32];
    let mut expected_bytes = [0u8; 16];
    for i in 0..16 {
        let hex_byte = &expected_hex[i * 2..i * 2 + 2];
        expected_bytes[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    // The payload size is the exact position up to the MD5 footer text
    let payload_size = file_size - footer_line.len() as u64 - 1;

    crate::progress::on_event(FlashEvent::Md5Start {
        name,
        size: payload_size,
    });

    let res: io::Result<()> = async {
        // Reset file pointer and compute MD5 over the payload only
        reader.seek(SeekFrom::Start(0)).await?;
        let mut hasher = Md5::new();
        let mut buffer = [0u8; 128 * 1024];
        let mut remaining = payload_size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..to_read]).await?;
            hasher.update(&buffer[..to_read]);
            crate::progress::inc(to_read as u64);
            remaining -= to_read as u64;
        }

        let calculated_digest = hasher.finalize();
        if calculated_digest != expected_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MD5 verification failed! File is corrupted or modified.",
            ));
        }

        Ok(())
    }
    .await;

    if res.is_err() {
        crate::progress::on_event(FlashEvent::Md5Fail(name));
    } else {
        crate::progress::on_event(FlashEvent::Md5End(name));
    }

    res
}

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

/// Backing byte source for a planned partition payload.
///
/// Rather than owning or holding a mutable borrow of a reader directly, `Package` and
/// `Image` store indices into [`FlashConfig`](crate::FlashConfig)'s `packages` and
/// `partitions` lists. Multiple planned partitions typically originate from the same
/// TAR archive, and reading requires `&mut R`, so Rust's borrow rules prevent multiple
/// [`FirmwarePartitionPayload`] items from simultaneously holding `&mut R` references to
/// the same underlying archive reader. Storing the index allows
/// [`FirmwarePartitionSource::open_reader`] to borrow and seek the appropriate reader on
/// demand one partition at a time.
#[derive(Clone)]
pub(crate) enum FirmwarePartitionSource {
    /// Entry inside a TAR package archive.
    Package {
        /// Index into `FlashConfig::packages`.
        index: usize,
        /// Byte offset where the entry's payload starts within the TAR archive.
        offset: u64,
        /// Raw byte length of the entry in the TAR archive.
        size: u64,
    },
    /// Standalone partition image.
    Image {
        /// Index into `FlashConfig::partitions`.
        index: usize,
        /// Total byte length of the standalone partition image.
        size: u64,
    },
    /// In-memory byte buffer (e.g. rewritten vbmeta image).
    Memory(Vec<u8>),
}

impl FirmwarePartitionSource {
    /// Returns the raw byte length of the payload in its backing source.
    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::Package { size, .. } | Self::Image { size, .. } => *size,
            Self::Memory(data) => data.len() as u64,
        }
    }

    /// Positions and returns a size-bounded reader at the start of this partition's payload.
    pub(crate) async fn open_reader<
        'a,
        P: AsyncRead + AsyncSeek + Unpin,
        I: AsyncRead + AsyncSeek + Unpin,
    >(
        &'a self,
        packages: &'a mut [(String, P)],
        partitions: &'a mut [(Option<String>, String, I)],
    ) -> io::Result<impl AsyncRead + Unpin + 'a> {
        let reader = match self {
            Self::Package { index, offset, .. } => {
                let reader = &mut packages[*index].1;
                reader.seek(SeekFrom::Start(*offset)).await?;
                SourceReader::Package(reader)
            }
            Self::Image { index, .. } => {
                let reader = &mut partitions[*index].2;
                reader.seek(SeekFrom::Start(0)).await?;
                SourceReader::Image(reader)
            }
            Self::Memory(data) => SourceReader::Memory(Cursor::new(data.as_slice())),
        };
        Ok(reader.take(self.size()))
    }
}

enum SourceReader<'a, P, I> {
    Package(&'a mut P),
    Image(&'a mut I),
    Memory(Cursor<&'a [u8]>),
}

impl<P: AsyncRead + Unpin, I: AsyncRead + Unpin> AsyncRead for SourceReader<'_, P, I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Package(r) => Pin::new(r).poll_read(cx, buf),
            Self::Image(r) => Pin::new(r).poll_read(cx, buf),
            Self::Memory(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

/// A partition image resolved to the PIT entry it will be flashed to.
pub(crate) struct FirmwarePartitionPayload<'a> {
    /// PIT partition entry associated with this payload.
    pub(crate) pit_entry: &'a PitEntry,
    /// The image to flash.
    pub(crate) image: FirmwareImage,
}

/// The bytes of a partition image and how they are encoded, independent of any PIT.
#[derive(Clone)]
pub(crate) struct FirmwareImage {
    /// Backing source for the image bytes.
    pub(crate) source: FirmwarePartitionSource,
    /// Metadata header of the LZ4 frame if the image is LZ4-compressed.
    pub(crate) lz4_header: Option<Lz4FrameHeader>,
}

impl FirmwareImage {
    /// Inspects the image stored in `source`, parsing its LZ4 frame header if
    /// `is_lz4` is set.
    pub(crate) async fn inspect<P, I>(
        source: FirmwarePartitionSource,
        is_lz4: bool,
        packages: &mut [(String, P)],
        partitions: &mut [(Option<String>, String, I)],
    ) -> io::Result<Self>
    where
        P: AsyncRead + AsyncSeek + Unpin,
        I: AsyncRead + AsyncSeek + Unpin,
    {
        let lz4_header = if is_lz4 {
            let reader = source.open_reader(packages, partitions).await?;
            Some(Lz4FrameHeader::parse(reader).await?)
        } else {
            None
        };
        Ok(Self { source, lz4_header })
    }

    /// Total raw size of the payload in bytes in its backing source.
    pub(crate) fn size(&self) -> u64 {
        self.source.size()
    }

    /// Total uncompressed size of the payload in bytes.
    pub(crate) fn uncompressed_size(&self) -> u64 {
        self.lz4_header
            .as_ref()
            .map_or_else(|| self.size(), |h| h.content_size)
    }

    /// Streams raw slices of an uncompressed partition payload.
    pub(crate) fn slices<'r, R: AsyncRead + Unpin>(
        &self,
        reader: &'r mut R,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<Vec<u8>>> + 'r {
        stream::unfold(
            (reader, self.size()),
            move |(reader, mut remaining)| async move {
                if remaining == 0 {
                    return None;
                }
                let to_read = remaining.min(slice_max_bytes as u64) as usize;
                let mut buffer = vec![0u8; to_read];
                if let Err(e) = reader.read_exact(&mut buffer).await {
                    return Some((Err(e), (reader, 0)));
                }
                remaining -= to_read as u64;
                Some((Ok(buffer), (reader, remaining)))
            },
        )
    }

    /// Streams LZ4-compressed block slices along with their uncompressed byte sizes.
    pub(crate) fn compressed_slices<'r, R: AsyncRead + Unpin>(
        &self,
        reader: &'r mut R,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<(usize, Vec<u8>)>> + 'r {
        let (block_max_size, remaining_decompressed) = self
            .lz4_header
            .as_ref()
            .map_or((0, 0), |h| (h.block_max_size as usize, h.content_size));
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

    /// Streams decompressed byte slices from an LZ4-compressed partition payload.
    pub(crate) fn decompressed_slices<'r, R: AsyncRead + Unpin>(
        &self,
        reader: &'r mut R,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<Vec<u8>>> + 'r {
        let block_max_size = self
            .lz4_header
            .as_ref()
            .map_or(0, |h| h.block_max_size as usize);
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

    /// Reads the entire payload content, decompressing it if needed.
    pub(crate) async fn read_all<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> io::Result<Vec<u8>> {
        if let Some(header) = &self.lz4_header {
            let mut data = Vec::new();
            let content_size = header.content_size;
            let slice_size = (header.block_max_size as usize).max(64 * 1024);
            let mut slices = std::pin::pin!(self.decompressed_slices(reader, slice_size));
            while let Some(slice) = slices.next().await {
                data.extend_from_slice(&slice?);
            }
            if data.len() as u64 != content_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "LZ4 content size mismatch: expected {}, got {}",
                        content_size,
                        data.len()
                    ),
                ));
            }
            Ok(data)
        } else {
            let size = self.size();
            let mut data = Vec::new();
            reader.take(size).read_to_end(&mut data).await?;
            if data.len() as u64 != size {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading partition payload",
                ));
            }
            Ok(data)
        }
    }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::FlashProgress;
    use fast_md5::Md5;
    use futures::io::Cursor;
    use std::fmt::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    #[derive(Clone)]
    struct TestProgress {
        started_total: Arc<AtomicU64>,
        inc_bytes: Arc<AtomicU64>,
        ended: Arc<AtomicBool>,
        failed: Arc<AtomicBool>,
    }

    impl TestProgress {
        fn new() -> Self {
            Self {
                started_total: Arc::new(AtomicU64::new(0)),
                inc_bytes: Arc::new(AtomicU64::new(0)),
                ended: Arc::new(AtomicBool::new(false)),
                failed: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl FlashProgress for TestProgress {
        fn set_length(&self, _len: u64) {}

        fn inc(&self, bytes: u64) {
            self.inc_bytes.fetch_add(bytes, Ordering::Relaxed);
        }

        fn on_event(&self, event: FlashEvent<'_>) {
            match event {
                FlashEvent::Md5Start {
                    size: total_bytes, ..
                } => {
                    self.started_total.store(total_bytes, Ordering::Relaxed);
                }
                FlashEvent::Md5End(_) => {
                    self.ended.store(true, Ordering::Relaxed);
                }
                FlashEvent::Md5Fail(_) => {
                    self.failed.store(true, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_verify_md5_footer_success() {
        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Construct a synthetic TAR payload with zeroes padding and MD5 footer
        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        // Null byte separating payload from MD5 footer text
        data.push(0);

        let mut hasher = Md5::new();
        hasher.update(&data);
        let digest = hasher.finalize();

        let hex_str = digest.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        });
        let footer = format!("{}  test.tar\n", hex_str);
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        crate::progress::set_progress(progress.clone());
        let res = futures::executor::block_on(verify_md5_footer(Cursor::new(&data), "test.tar"));
        crate::progress::clear_progress();

        assert!(res.is_ok());
        let expected_total = (payload.len() + 1) as u64;
        assert_eq!(
            progress.started_total.load(Ordering::Relaxed),
            expected_total
        );
        assert_eq!(progress.inc_bytes.load(Ordering::Relaxed), expected_total);
        assert!(progress.ended.load(Ordering::Relaxed));
        assert!(!progress.failed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_verify_md5_footer_corruption() {
        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        data.push(0);

        // Intentionally wrong hash
        let footer = "0123456789abcdef0123456789abcdef  test.tar\n";
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        crate::progress::set_progress(progress.clone());
        let res = futures::executor::block_on(verify_md5_footer(Cursor::new(&data), "test.tar"));
        crate::progress::clear_progress();

        assert!(res.is_err());
        assert!(progress.failed.load(Ordering::Relaxed));
        assert!(!progress.ended.load(Ordering::Relaxed));
    }

    #[test]
    fn test_lz4_decompressed_slices_reseek_and_truncation() {
        use futures::StreamExt;
        use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
        use std::io::Write;

        // 150 KB payload spanning 3 independent 64 KB LZ4 blocks (64K + 64K + 22K)
        let original: Vec<u8> = (0..150 * 1024).map(|i| (i % 251) as u8).collect();

        let mut frame_info = FrameInfo::new();
        frame_info.block_mode = BlockMode::Independent;
        frame_info.block_size = BlockSize::Max64KB;
        frame_info.content_size = Some(original.len() as u64);

        let mut encoder = FrameEncoder::with_frame_info(frame_info, Vec::new());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        futures::executor::block_on(async {
            let mut cursor = futures::io::Cursor::new(compressed.as_slice());
            let header = Lz4FrameHeader::parse(&mut cursor).await.unwrap();
            assert_eq!(header.content_size, original.len() as u64);
            assert_eq!(header.block_max_size, 64 * 1024);

            let image = FirmwareImage {
                source: FirmwarePartitionSource::Image {
                    index: 0,
                    size: compressed.len() as u64,
                },
                lz4_header: Some(header),
            };
            let mut packages: [(String, Cursor<&[u8]>); 0] = [];
            let mut partitions = [(None, "test.img.lz4".to_string(), cursor)];

            // 1. Read a partial prefix and drop the stream (simulating inspect_super_partition)
            {
                let mut reader = image
                    .source
                    .open_reader(&mut packages, &mut partitions)
                    .await
                    .unwrap();
                let prefix = std::pin::pin!(image.decompressed_slices(&mut reader, 10 * 1024))
                    .next()
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(prefix, &original[..10 * 1024]);
            }

            // 2. Consume full stream with a 50 KB slice limit (unaligned with 64 KB blocks,
            // exercising both open_reader rewind and leftover buffering)
            let mut reassembled = Vec::new();
            {
                let mut reader = image
                    .source
                    .open_reader(&mut packages, &mut partitions)
                    .await
                    .unwrap();
                let mut slices = std::pin::pin!(image.decompressed_slices(&mut reader, 50 * 1024));
                while let Some(res) = slices.next().await {
                    let slice = res.unwrap();
                    assert!(slice.len() <= 50 * 1024);
                    reassembled.extend_from_slice(&slice);
                }
            }
            assert_eq!(reassembled, original);

            // 3. Truncated LZ4 stream must yield Err rather than silently ending with Ok
            let truncated = &compressed[..compressed.len() - 10];
            let mut truncated_reader = futures::io::Cursor::new(truncated);
            let results: Vec<io::Result<Vec<u8>>> = image
                .decompressed_slices(&mut truncated_reader, 50 * 1024)
                .collect()
                .await;
            assert!(results.iter().any(|r| r.is_err()));
        });
    }

    pub(crate) fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for &(path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, content).unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn test_package_index_metadata_and_manifest() {
        let tar_bytes = build_tar(&[
            ("meta-data/super_used_size.txt", b"27276104\n"),
            ("meta-data/download-list.txt", b"boot.img\n"),
            ("boot.img", b"DUMMY BOOT IMAGE DATA"),
        ]);

        futures::executor::block_on(async {
            let mut packages = [(
                "test_package.tar".to_string(),
                Cursor::new(tar_bytes.as_slice()),
            )];
            let index = PackageIndex::scan(&mut packages, true).await.unwrap();

            assert_eq!(index.super_used_size, Some(27276104));
            assert!(index.has_download_list);
            assert_eq!(index.entries.len(), 1);
            assert_eq!(index.entries[0].normalized_name, "boot.img");
        });
    }

    #[test]
    fn test_package_index_corrupt_manifest_fails() {
        let tar_bytes = build_tar(&[("meta-data/download-list.txt", &[0xFF, 0xFE, 0xFD])]);

        futures::executor::block_on(async {
            let mut packages = [(
                "corrupt_manifest.tar".to_string(),
                Cursor::new(tar_bytes.as_slice()),
            )];
            let result = PackageIndex::scan(&mut packages, true).await;

            assert!(matches!(result, Err(FlashError::ArchiveCorrupted(_, _))));
        });
    }

    #[test]
    fn test_package_index_filtering_and_truncation() {
        let pit_bytes = b"PIT DATA";
        let tar_bytes = build_tar(&[
            ("meta-data/download-list.txt", b"boot.img\nsuper.img\n"),
            ("meta-data/super_used_size.txt", b"12345\n"),
            ("device.pit", pit_bytes),
            ("boot.img.lz4", b"BOOT DATA"),
            ("recovery.img.lz4", b"RECOVERY DATA"),
        ]);

        futures::executor::block_on(async {
            let mut packages = [("AP.tar".to_string(), Cursor::new(tar_bytes.as_slice()))];
            let index = PackageIndex::scan(&mut packages, true).await.unwrap();
            // recovery.img is omitted (not in download-list), metadata & pit are omitted
            let names: Vec<_> = index.entries.iter().map(|e| &e.normalized_name).collect();
            assert_eq!(names, ["boot.img"]);
            assert!(index.entries[0].is_lz4);
            assert_eq!(index.super_used_size, Some(12345));
            assert_eq!(index.pit_bytes.as_deref(), Some(&pit_bytes[..]));

            // The PIT is only read when requested
            let index = PackageIndex::scan(&mut packages, false).await.unwrap();
            assert_eq!(index.pit_bytes, None);

            // Truncated package errors on scan
            let truncated = &tar_bytes[..tar_bytes.len() - 600];
            let mut bad_packages = [("AP.tar".to_string(), Cursor::new(truncated))];
            let res = PackageIndex::scan(&mut bad_packages, true).await;
            assert!(matches!(res, Err(FlashError::ArchiveCorrupted(pkg, _)) if pkg == "AP.tar"));
        });
    }
}
