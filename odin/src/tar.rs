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

use futures::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use std::borrow::Cow;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

const TAR_BLOCK_SIZE: u64 = 512;

/// An asynchronous reader for scanning entries in a TAR archive using `Seek` to
/// skip unread entry payloads.
pub(crate) struct TarArchive<R> {
    reader: R,
    /// Total length of the archive, determined on the first `next_entry` call.
    len: Option<u64>,
    next_header_pos: u64,
    done: bool,
}

/// A single entry in a [`TarArchive`].
pub(crate) struct TarEntry<'a, R> {
    reader: futures::io::Take<&'a mut R>,
    path: String,
    offset: u64,
    size: u64,
}

impl<R: AsyncRead + Unpin> TarEntry<'_, R> {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn raw_file_position(&self) -> u64 {
        self.offset
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TarEntry<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.reader).poll_read(cx, buf) {
            Poll::Ready(Ok(0)) if !buf.is_empty() && self.reader.limit() > 0 => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading entry",
                )))
            }
            other => other,
        }
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> TarArchive<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            len: None,
            next_header_pos: 0,
            done: false,
        }
    }

    pub(crate) async fn next_entry(&mut self) -> io::Result<Option<TarEntry<'_, R>>> {
        if self.done {
            return Ok(None);
        }

        match self.try_next_entry().await {
            Ok(Some((path, offset, size))) => Ok(Some(TarEntry {
                reader: (&mut self.reader).take(size),
                path,
                offset,
                size,
            })),
            Ok(None) => {
                self.done = true;
                Ok(None)
            }
            Err(e) => {
                self.done = true;
                Err(e)
            }
        }
    }

    async fn try_next_entry(&mut self) -> io::Result<Option<(String, u64, u64)>> {
        let mut gnu_longname: Option<Vec<u8>> = None;
        let mut gnu_longlink = false;
        let mut pax_extensions: Option<Vec<u8>> = None;
        let mut processed = 0;

        loop {
            processed += 1;
            let (header, file_pos, size) =
                match self.next_entry_raw(pax_extensions.as_deref()).await? {
                    Some(raw) => raw,
                    None if processed > 1 => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "members found describing a future member but no future member found",
                        ));
                    }
                    None => return Ok(None),
                };

            let is_recognized_header = header.as_gnu().is_some() || header.as_ustar().is_some();
            let entry_type = header.entry_type();

            if is_recognized_header && entry_type.is_gnu_longname() {
                if gnu_longname.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "two long name entries describing the same member",
                    ));
                }
                gnu_longname = Some(self.read_extension_data(size).await?);
                continue;
            }

            if is_recognized_header && entry_type.is_gnu_longlink() {
                if gnu_longlink {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "two long link entries describing the same member",
                    ));
                }
                gnu_longlink = true;
                continue;
            }

            if is_recognized_header && entry_type.is_pax_local_extensions() {
                if pax_extensions.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "two pax extensions entries describing the same member",
                    ));
                }
                pax_extensions = Some(self.read_extension_data(size).await?);
                continue;
            }

            if entry_type.is_gnu_sparse() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GNU sparse entries are not supported",
                ));
            }

            let path_bytes: Cow<'_, [u8]> = if let Some(ref bytes) = gnu_longname {
                Cow::Borrowed(bytes.strip_suffix(&[0]).unwrap_or(bytes))
            } else if let Some(path) = pax_extensions.as_deref().and_then(pax_path_value) {
                Cow::Borrowed(path)
            } else {
                header.path_bytes()
            };

            let path = String::from_utf8_lossy(&path_bytes).into_owned();
            return Ok(Some((path, file_pos, size)));
        }
    }

    async fn read_extension_data(&mut self, size: u64) -> io::Result<Vec<u8>> {
        let cap = size.min(64 * 1024) as usize;
        let mut buf = Vec::with_capacity(cap);
        (&mut self.reader).take(size).read_to_end(&mut buf).await?;
        if buf.len() as u64 != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading extension header",
            ));
        }
        Ok(buf)
    }

    async fn next_entry_raw(
        &mut self,
        pax_extensions: Option<&[u8]>,
    ) -> io::Result<Option<(::tar::Header, u64, u64)>> {
        let mut header = ::tar::Header::new_old();

        let len = match self.len {
            Some(len) => len,
            None => *self.len.insert(self.reader.seek(SeekFrom::End(0)).await?),
        };

        self.reader
            .seek(SeekFrom::Start(self.next_header_pos))
            .await?;

        if !try_read_all(&mut self.reader, header.as_mut_bytes()).await? {
            // A complete archive ends with zero blocks, so EOF here means the file
            // was cut exactly at an entry boundary and later entries are missing.
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "archive is missing its end-of-archive marker (truncated?)",
            ));
        }

        if header.as_bytes().iter().all(|&b| b == 0) {
            return Ok(None);
        }

        self.next_header_pos = self
            .next_header_pos
            .checked_add(TAR_BLOCK_SIZE)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "size overflow"))?;

        // Verify the header checksum (bytes 148..156 are treated as ASCII spaces)
        let sum = header.as_bytes()[..148]
            .iter()
            .chain(&header.as_bytes()[156..])
            .fold(0u32, |a, &b| a + (b as u32))
            + 8 * 32;
        let cksum = header.cksum()?;
        if sum != cksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive header checksum mismatch",
            ));
        }

        let entry_type = header.entry_type();
        let is_extension_header = entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_pax_global_extensions();

        let file_pos = self.next_header_pos;
        let mut size = header.entry_size()?;

        if let Some(pax_bytes) = pax_extensions.filter(|_| !is_extension_header)
            && let Some(pax_size) = pax_size_value(pax_bytes)
        {
            size = pax_size;
        }

        // Seeking past EOF succeeds, so a truncated archive would otherwise look like
        // a clean end and silently drop the remaining entries.
        if file_pos.checked_add(size).is_none_or(|end| end > len) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "entry extends past the end of the archive",
            ));
        }

        let padded_size = size
            .checked_add(TAR_BLOCK_SIZE - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "size overflow"))?
            & !(TAR_BLOCK_SIZE - 1);
        self.next_header_pos = file_pos
            .checked_add(padded_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "size overflow"))?;

        Ok(Some((header, file_pos, size)))
    }
}

async fn try_read_all<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut read = 0;
    while read < buf.len() {
        match reader.read(&mut buf[read..]).await? {
            0 if read == 0 => return Ok(false),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to read entire block",
                ));
            }
            n => read += n,
        }
    }
    Ok(true)
}

fn pax_size_value(a: &[u8]) -> Option<u64> {
    // Mirrors tar::pax_extensions_value: a malformed record ends the lookup
    for ext in ::tar::PaxExtensions::new(a) {
        let ext = ext.ok()?;
        if ext.key_bytes() == b"size" {
            return ext.value().ok()?.parse().ok();
        }
    }
    None
}

fn pax_path_value(a: &[u8]) -> Option<&[u8]> {
    ::tar::PaxExtensions::new(a)
        .filter_map(|f| f.ok())
        .find(|f| f.key_bytes() == b"path")
        .map(|f| f.value_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    #[test]
    fn test_tar_archive_async_entries_and_extensions() {
        let mut builder = ::tar::Builder::new(Vec::new());

        // 1. Standard entry (skipped without reading payload)
        let mut header = ::tar::Header::new_gnu();
        let boot_data = vec![0xABu8; 1025];
        header.set_size(boot_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "boot.img.lz4", &boot_data[..])
            .unwrap();

        // 2. GNU long-name entry (> 100 bytes)
        let long_path = format!("{}/download-list.txt", "nested_dir".repeat(12));
        let manifest_data = b"boot.img\nsuper.img\n";
        let mut header = ::tar::Header::new_gnu();
        header.set_size(manifest_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, &long_path, &manifest_data[..])
            .unwrap();

        // 3. PAX extended header overriding path
        builder
            .append_pax_extensions([("path", b"meta-data/super_used_size.txt" as &[u8])])
            .unwrap();
        let super_size_data = b"27276104\n";
        let mut header = ::tar::Header::new_ustar();
        header.set_path("placeholder.txt").unwrap();
        header.set_size(super_size_data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &super_size_data[..]).unwrap();

        let mut tar_bytes = builder.into_inner().unwrap();
        // Append a simulated .tar.md5 footer after the archive's trailing zero blocks
        tar_bytes.extend_from_slice(b"0123456789abcdef0123456789abcdef  AP.tar\n");

        futures::executor::block_on(async {
            let mut cursor = Cursor::new(tar_bytes.as_slice());
            // Start from a non-zero cursor position to verify TarArchive rewinds to 0
            cursor.seek(SeekFrom::End(0)).await.unwrap();

            let mut archive = TarArchive::new(cursor);

            // Entry 1: boot.img.lz4 (not read, skipped via seek on next_entry)
            let entry1 = archive.next_entry().await.unwrap().unwrap();
            assert_eq!(entry1.path(), "boot.img.lz4");
            assert_eq!(entry1.raw_file_position(), 512);
            assert_eq!(entry1.size(), 1025);

            // Entry 2: GNU long name (read content)
            let mut entry2 = archive.next_entry().await.unwrap().unwrap();
            assert_eq!(entry2.path(), long_path);
            assert_eq!(entry2.size(), manifest_data.len() as u64);
            let mut content2 = String::new();
            entry2.read_to_string(&mut content2).await.unwrap();
            assert_eq!(content2, "boot.img\nsuper.img\n");

            // Entry 3: PAX extended path (read content)
            let mut entry3 = archive.next_entry().await.unwrap().unwrap();
            assert_eq!(entry3.path(), "meta-data/super_used_size.txt");
            let mut content3 = String::new();
            entry3.read_to_string(&mut content3).await.unwrap();
            assert_eq!(content3, "27276104\n");

            // End of archive (stops at zero block before MD5 footer)
            assert!(archive.next_entry().await.unwrap().is_none());

            // Corrupt header checksum must fail with InvalidData
            let mut corrupted = tar_bytes.clone();
            corrupted[0] ^= 0xFF;
            let mut bad_archive = TarArchive::new(Cursor::new(corrupted.as_slice()));
            assert_eq!(
                bad_archive.next_entry().await.err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );

            // Truncated entry payload must fail with UnexpectedEof on next_entry
            let mut truncated_archive = TarArchive::new(Cursor::new(&tar_bytes[..600]));
            let err = truncated_archive.next_entry().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(err.to_string(), "entry extends past the end of the archive");

            // Cut inside a later unread entry: earlier entries return, then UnexpectedEof
            let cut_offset = 2048 + 512 + 5;
            let mut cut_archive = TarArchive::new(Cursor::new(&tar_bytes[..cut_offset]));
            let entry1 = cut_archive.next_entry().await.unwrap().unwrap();
            assert_eq!(entry1.path(), "boot.img.lz4");
            let err = cut_archive.next_entry().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(err.to_string(), "entry extends past the end of the archive");

            // Cut exactly at an entry boundary (no zero blocks)
            let mut cut_boundary_archive = TarArchive::new(Cursor::new(&tar_bytes[..2048]));
            let entry1 = cut_boundary_archive.next_entry().await.unwrap().unwrap();
            assert_eq!(entry1.path(), "boot.img.lz4");
            let err = cut_boundary_archive.next_entry().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(
                err.to_string(),
                "archive is missing its end-of-archive marker (truncated?)"
            );

            // A single trailing zero block is accepted
            let mut single_zero_tar = tar_bytes[..2048].to_vec();
            single_zero_tar.extend_from_slice(&[0u8; 512]);
            let mut archive = TarArchive::new(Cursor::new(single_zero_tar.as_slice()));
            assert!(archive.next_entry().await.unwrap().is_some());
            assert!(archive.next_entry().await.unwrap().is_none());

            // A single trailing zero block with .tar.md5 footer is accepted
            single_zero_tar.extend_from_slice(b"0123456789abcdef0123456789abcdef  AP.tar\n");
            let mut archive = TarArchive::new(Cursor::new(single_zero_tar.as_slice()));
            assert!(archive.next_entry().await.unwrap().is_some());
            assert!(archive.next_entry().await.unwrap().is_none());

            // 0-byte input gives an error
            let mut empty_archive = TarArchive::new(Cursor::new(&[][..]));
            let err = empty_archive.next_entry().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(
                err.to_string(),
                "archive is missing its end-of-archive marker (truncated?)"
            );

            // Base-256 size of 2^63 gives an error
            let mut base256_header = ::tar::Header::new_gnu();
            base256_header.set_path("huge.bin").unwrap();
            let header_bytes = base256_header.as_mut_bytes();
            header_bytes[124] = 0x80;
            header_bytes[128] = 0x80;
            base256_header.set_cksum();
            let mut tar = base256_header.as_bytes().to_vec();
            tar.extend_from_slice(&[0u8; 1024]);
            let mut archive = TarArchive::new(Cursor::new(tar.as_slice()));
            let err = archive.next_entry().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(err.to_string(), "entry extends past the end of the archive");
        });
    }

    #[test]
    fn test_pax_size_value() {
        // Malformed record "5 a=b\n" stops the lookup, returning None (so header size is kept)
        assert_eq!(pax_size_value(b"5 a=b\n13 size=1024\n"), None);
        // Well-formed records parse size
        assert_eq!(pax_size_value(b"6 a=b\n13 size=1024\n"), Some(1024));
    }

    #[test]
    fn test_gnu_sparse_rejected() {
        futures::executor::block_on(async {
            let mut header = ::tar::Header::new_gnu();
            header.set_path("sparse.img").unwrap();
            header.set_entry_type(::tar::EntryType::new(b'S'));
            header.set_size(0);
            header.set_cksum();
            let mut tar = header.as_bytes().to_vec();
            tar.extend_from_slice(&[0u8; 1024]);
            let mut archive = TarArchive::new(Cursor::new(tar.as_slice()));
            let err = archive.next_entry().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(err.to_string(), "GNU sparse entries are not supported");
        });
    }
}
