// Copyright 2026 John "topjohnwu" Wu
// Copyright 2021-2024 Henrik Grimler
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
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
use crate::avb;
use crate::firmware::{
    FirmwarePartitionPayload, FirmwarePartitionSource, Lz4FrameHeader, verify_md5_footer,
};
use crate::lp::inspect_super_partition;
use crate::odin::OdinSession;
use crate::progress::{self, FlashEvent};
use crate::tar::TarArchive;
use futures::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, Cursor};
use samloader_pit::{PitData, PitEntry};
use std::collections::HashSet;
use std::io::{self, SeekFrom};
use std::path::Path;

#[derive(Clone, Debug)]
struct IndexedEntry {
    original_name: String,
    normalized_name: String,
    package_index: usize,
    offset: u64,
    size: u64,
    is_lz4: bool,
}

/// Result of indexing TAR packages.
struct PackageScan {
    entries: Vec<IndexedEntry>,
    has_download_list: bool,
    super_used_size: Option<u32>,
    pit_bytes: Option<Vec<u8>>,
}

async fn scan_packages<R: AsyncRead + AsyncSeek + Unpin>(
    packages: &mut [(String, R)],
    want_pit: bool,
) -> Result<PackageScan, FlashError> {
    if packages.is_empty() {
        return Ok(PackageScan {
            entries: Vec::new(),
            has_download_list: false,
            super_used_size: None,
            pit_bytes: None,
        });
    }

    let mut archives_download_lists: Vec<HashSet<String>> = Vec::new();
    let mut all_packages_entries: Vec<Vec<IndexedEntry>> = Vec::new();
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
                package_entries.push(IndexedEntry {
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
    let download_allowlist = if let Some((first, rest)) = archives_download_lists.split_first() {
        if !rest.iter().all(|m| m == first) {
            return Err(FlashError::CrossArchiveInconsistency);
        }
        Some(first)
    } else {
        None
    };

    let mut resolved_entries: Vec<IndexedEntry> = Vec::new();

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

    Ok(PackageScan {
        entries: resolved_entries,
        has_download_list,
        super_used_size,
        pit_bytes: pit_from_tar,
    })
}

/// Lists the file names (directory and `.lz4` suffix stripped) that would be
/// considered for flashing from `packages`, honoring `download-list.txt`.
/// Metadata files and PIT files are excluded. Useful for confirmation prompts
/// before connecting to a device.
///
/// Readers are only accessed through absolute seeks, so they can be passed to
/// [`FlashManager::packages`] afterwards without rewinding.
pub async fn package_flash_files<R: AsyncRead + AsyncSeek + Unpin>(
    packages: &mut [(String, R)],
) -> Result<Vec<String>, FlashError> {
    let scan = scan_packages(packages, false).await?;
    Ok(scan
        .entries
        .into_iter()
        .map(|e| e.normalized_name)
        .collect())
}

/// Returns whether flashing `names` would write the userdata partition, which
/// wipes the device's data.
///
/// Each name is either a file name, such as those returned by
/// [`package_flash_files`], or a partition name. Directories and `.lz4` suffixes
/// are stripped. `skip` takes the same targets as [`FlashManager::skip`].
///
/// As the device's PIT is not consulted, this is a name-based check meant for
/// confirmation prompts before connecting to a device. Partitions given by
/// numeric ID cannot be resolved.
pub fn flashes_userdata(names: &[impl AsRef<str>], skip: &[impl AsRef<str>]) -> bool {
    let is_skipped = |name: &str| {
        skip.iter().any(|target| {
            let target = target.as_ref().trim();
            target.eq_ignore_ascii_case("USERDATA")
                || normalize_basename(target).0.eq_ignore_ascii_case(name)
        })
    };

    names.iter().any(|name| {
        let (name, _) = normalize_basename(name.as_ref());
        name.to_ascii_lowercase().starts_with("userdata") && !is_skipped(&name)
    })
}

fn normalize_basename(path_str: &str) -> (String, bool) {
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

fn find_pit_entry_by_filename<'a>(pit_data: &'a PitData, filename: &str) -> Option<&'a PitEntry> {
    pit_data.entries.iter().find(|e| {
        let flash_fn = e.flash_filename.to_string_lossy();
        flash_fn.eq_ignore_ascii_case(filename)
    })
}

fn is_super_entry(entry: &PitEntry) -> bool {
    entry.partition_name == "SUPER"
        || entry
            .flash_filename
            .to_string_lossy()
            .eq_ignore_ascii_case("super.img")
}

// Mirrors fastboot, where partitions with a prefix (e.g. guest_vbmeta_a) also count
fn is_vbmeta_entry(entry: &PitEntry) -> bool {
    let name = entry.partition_name.to_string_lossy().to_ascii_uppercase();
    ["VBMETA", "VBMETA_A", "VBMETA_B"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn is_top_level_vbmeta_entry(entry: &PitEntry) -> bool {
    let name = entry.partition_name.to_string_lossy();
    ["VBMETA", "VBMETA_A", "VBMETA_B"]
        .iter()
        .any(|vbmeta| name.eq_ignore_ascii_case(vbmeta))
}

fn is_boot_entry(entry: &PitEntry) -> bool {
    let name = entry.partition_name.to_string_lossy();
    ["BOOT", "BOOT_A", "BOOT_B"]
        .iter()
        .any(|boot| name.eq_ignore_ascii_case(boot))
}

// A skip target matches either the flash filename or the partition name of a PIT
// entry. Partition names also match their _A and _B slots on A/B devices.
fn is_skip_target(entry: &PitEntry, target: &str) -> bool {
    let (filename, _) = normalize_basename(target);
    if entry
        .flash_filename
        .to_string_lossy()
        .eq_ignore_ascii_case(&filename)
    {
        return true;
    }

    let name = entry.partition_name.to_string_lossy();
    ["", "_A", "_B"]
        .iter()
        .any(|slot| name.eq_ignore_ascii_case(&format!("{}{}", target, slot)))
}

/// Specifies the device reboot behavior after a flash session concludes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum RebootMode {
    /// Do not reboot the device; end the session and remain in download mode.
    #[default]
    None,
    /// Reboot the device normally out of Download Mode.
    Normal,
    /// Reboot the device back into Download Mode.
    Download,
}

/// Orchestrates the flashing pipeline, processing package and partition sources
/// and executing the Loke flash protocol.
pub struct FlashManager<'a, P = Cursor<&'static [u8]>, I = Cursor<&'static [u8]>> {
    session: &'a mut OdinSession,
    pit_file_bytes: Option<Vec<u8>>,

    reboot_mode: RebootMode,
    skip_size_check: bool,
    skip_md5: bool,
    packages: Vec<(String, P)>,
    partitions: Vec<(Option<String>, String, I)>,
    super_used_size: Option<u32>,
    has_download_list: bool,
    sales_code: Option<&'a str>,
    erase: bool,
    skip: Vec<String>,
    vbmeta_flags: u32,
}

impl<'a> FlashManager<'a> {
    /// Creates a new `FlashManager` associated with an active `OdinSession`.
    pub fn new(session: &'a mut OdinSession) -> Self {
        Self {
            session,
            pit_file_bytes: None,
            reboot_mode: RebootMode::None,
            skip_size_check: false,
            skip_md5: false,
            packages: Vec::new(),
            partitions: Vec::new(),
            super_used_size: None,
            has_download_list: false,
            sales_code: None,
            erase: false,
            skip: Vec::new(),
            vbmeta_flags: 0,
        }
    }
}

impl<'a, P, I> FlashManager<'a, P, I> {
    /// Sets whether to perform a low-level NAND hardware erase on the `USERDATA` partition
    /// prior to flashing or as a standalone wipe operation.
    pub fn erase(mut self, enabled: bool) -> Self {
        self.erase = enabled;
        self
    }

    /// Sets an optional 3-letter CSC / Sales Code to configure on the device.
    pub fn sales_code(mut self, sales_code: Option<&'a str>) -> Self {
        self.sales_code = sales_code;
        self
    }

    /// Sets the reboot mode to perform after flashing completes.
    pub fn reboot_mode(mut self, mode: RebootMode) -> Self {
        self.reboot_mode = mode;
        self
    }

    /// Sets whether to automatically reboot normally out of Download Mode after flashing.
    pub fn auto_reboot(mut self, enabled: bool) -> Self {
        self.reboot_mode = if enabled {
            RebootMode::Normal
        } else {
            RebootMode::None
        };
        self
    }

    /// Sets whether to reboot the device back into Download Mode after flashing.
    pub fn redownload(mut self, enabled: bool) -> Self {
        if enabled {
            self.reboot_mode = RebootMode::Download;
        }
        self
    }

    /// Sets whether to skip partition size checks.
    pub fn skip_size_check(mut self, enabled: bool) -> Self {
        self.skip_size_check = enabled;
        self
    }

    /// Sets whether to skip MD5 package verification.
    pub fn skip_md5(mut self, enabled: bool) -> Self {
        self.skip_md5 = enabled;
        self
    }

    /// Sets an explicit PIT payload.
    pub fn pit(mut self, pit_bytes: impl Into<Vec<u8>>) -> Self {
        self.pit_file_bytes = Some(pit_bytes.into());
        self
    }

    /// Sets the list of TAR packages `(name, reader)` to flash.
    pub fn packages<S: Into<String>, R>(
        self,
        packages: impl IntoIterator<Item = (S, R)>,
    ) -> FlashManager<'a, R, I> {
        FlashManager {
            session: self.session,
            pit_file_bytes: self.pit_file_bytes,
            reboot_mode: self.reboot_mode,
            skip_size_check: self.skip_size_check,
            skip_md5: self.skip_md5,
            packages: packages
                .into_iter()
                .map(|(name, reader)| (name.into(), reader))
                .collect(),
            partitions: self.partitions,
            super_used_size: self.super_used_size,
            has_download_list: self.has_download_list,
            sales_code: self.sales_code,
            erase: self.erase,
            skip: self.skip,
            vbmeta_flags: self.vbmeta_flags,
        }
    }

    /// Sets the list of individual partition inputs `(target_partition, filename, reader)` to flash.
    pub fn partitions<S: Into<String>, R>(
        self,
        partitions: impl IntoIterator<Item = (Option<String>, S, R)>,
    ) -> FlashManager<'a, P, R> {
        FlashManager {
            session: self.session,
            pit_file_bytes: self.pit_file_bytes,
            reboot_mode: self.reboot_mode,
            skip_size_check: self.skip_size_check,
            skip_md5: self.skip_md5,
            packages: self.packages,
            partitions: partitions
                .into_iter()
                .map(|(part, name, reader)| (part, name.into(), reader))
                .collect(),
            super_used_size: self.super_used_size,
            has_download_list: self.has_download_list,
            sales_code: self.sales_code,
            erase: self.erase,
            skip: self.skip,
            vbmeta_flags: self.vbmeta_flags,
        }
    }

    /// Sets the partitions to exclude from flashing. Each target is either a file name
    /// or a partition name in the PIT. Partition names also exclude their `_A` and `_B`
    /// slots.
    pub fn skip(mut self, targets: &[impl AsRef<str>]) -> Self {
        self.skip = targets
            .iter()
            .map(|t| t.as_ref().trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        self
    }

    /// Sets whether to disable dm-verity in the flashed vbmeta images, like fastboot's
    /// `--disable-verity`. Every partition named `VBMETA`, `VBMETA_A` or `VBMETA_B`
    /// (optionally with a prefix) is rewritten, and LZ4 compressed images are sent
    /// decompressed. Devices without a vbmeta partition have `BOOT` rewritten instead.
    pub fn disable_verity(mut self, enabled: bool) -> Self {
        self.set_vbmeta_flag(avb::AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED, enabled);
        self
    }

    /// Sets whether to disable AVB verification in the flashed vbmeta images, like
    /// fastboot's `--disable-verification`. The same images as with
    /// [`disable_verity`](Self::disable_verity) are rewritten.
    pub fn disable_verification(mut self, enabled: bool) -> Self {
        self.set_vbmeta_flag(avb::AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED, enabled);
        self
    }

    fn set_vbmeta_flag(&mut self, flag: u32, enabled: bool) {
        if enabled {
            self.vbmeta_flags |= flag;
        } else {
            self.vbmeta_flags &= !flag;
        }
    }
}

impl<'a, P: AsyncRead + AsyncSeek + Unpin, I: AsyncRead + AsyncSeek + Unpin>
    FlashManager<'a, P, I>
{
    /// Executes the flashing pipeline sequence.
    pub async fn execute(&mut self) -> Result<(), FlashError> {
        // Step 0: Set device sales code if configured
        if let Some(sales_code) = self.sales_code {
            progress::println(&format!("Setting device sales code to {}...", sales_code));
            self.session.set_sales_code(sales_code).await?;
        }

        // If no packages, partitions, or explicit PIT are specified, complete session and return
        if self.packages.is_empty() && self.partitions.is_empty() && self.pit_file_bytes.is_none() {
            if !self.skip.is_empty() {
                progress::println("Warning: --skip ignored when no partitions are flashed");
            }
            if self.vbmeta_flags & avb::AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED != 0 {
                progress::println(
                    "Warning: --disable-verity ignored when no partitions are flashed",
                );
            }
            if self.vbmeta_flags & avb::AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED != 0 {
                progress::println(
                    "Warning: --disable-verification ignored when no partitions are flashed",
                );
            }
            if self.erase {
                self.session.nand_erase().await?;
            }
            match self.reboot_mode {
                RebootMode::Normal => self.session.reboot_device().await?,
                RebootMode::Download => self.session.reboot_to_download().await?,
                RebootMode::None => self.session.end_session().await?,
            }
            return Ok(());
        }

        // Step 1: Verify MD5 footers and scan TAR containers to index entries
        self.verify_packages().await?;
        let entries = self.scan_tar_packages().await?;

        // Step 2: Plan against a PIT before anything destructive happens on the device.
        // With a local PIT, the plan is checked against it, then rebuilt against the
        // PIT read back from the device after flashing. Otherwise the device PIT is
        // read before the NAND erase, which does not modify it.
        let flashes_pit = self.pit_file_bytes.is_some();
        let planning_pit;
        let mut flashed_pit = None;

        let planned_partitions = if flashes_pit {
            planning_pit = self.parse_local_pit()?;
            self.plan_partitions(&planning_pit, &entries, false).await?;

            if self.erase {
                self.session.nand_erase().await?;
            }

            let pit_bytes = self.pit_file_bytes.as_ref().unwrap();
            progress::println("Flashing PIT");
            self.session.send_pit_info(pit_bytes).await?;
            progress::println("PIT flash successful\n");

            let downloaded = self.download_pit().await?;
            let pit_ref = flashed_pit.insert(downloaded);
            self.plan_partitions(pit_ref, &entries, true).await?
        } else {
            let downloaded = self.download_pit().await?;
            let pit_ref = flashed_pit.insert(downloaded);
            let planned = self.plan_partitions(pit_ref, &entries, true).await?;

            if self.erase {
                self.session.nand_erase().await?;
            }
            planned
        };

        // Auto-detect super_used_size if not specified in TAR metadata
        if self.super_used_size.is_none()
            && let Some(super_part) = planned_partitions
                .iter()
                .find(|p| is_super_entry(p.pit_entry))
            && let Ok(mut reader) = super_part
                .source
                .open_reader(&mut self.packages, &mut self.partitions)
                .await
        {
            self.super_used_size = inspect_super_partition(super_part, &mut reader).await;
        }

        // Step 3: Flash payloads to the device
        self.flash_partitions(planned_partitions, self.reboot_mode)
            .await?;

        Ok(())
    }

    // Helper 1: Optionally verify MD5 footers on TAR packages
    async fn verify_packages(&mut self) -> Result<(), FlashError> {
        if self.skip_md5 {
            return Ok(());
        }

        for (name, reader) in &mut self.packages {
            if name.to_lowercase().ends_with(".md5") {
                verify_md5_footer(&mut *reader, name)
                    .await
                    .map_err(|e| FlashError::Md5VerificationFailed(name.clone(), e))?;
            }
        }

        Ok(())
    }

    // Helper 2: Scan TAR packages to find resolved entries and pull package PIT if needed
    async fn scan_tar_packages(&mut self) -> Result<Vec<IndexedEntry>, FlashError> {
        let want_pit = self.pit_file_bytes.is_none();
        let scan = scan_packages(&mut self.packages, want_pit).await?;
        if scan.has_download_list {
            self.has_download_list = true;
        }
        if self.super_used_size.is_none() {
            self.super_used_size = scan.super_used_size;
        }
        if self.pit_file_bytes.is_none() {
            self.pit_file_bytes = scan.pit_bytes;
        }
        Ok(scan.entries)
    }

    // Helper 3: Parse local PIT file bytes
    fn parse_local_pit(&self) -> Result<PitData, FlashError> {
        let pit_bytes = self.pit_file_bytes.as_ref().unwrap();
        PitData::new(pit_bytes).map_err(FlashError::PitUnpackFailed)
    }

    // Helper 4: Download active PIT data from device
    async fn download_pit(&mut self) -> Result<PitData, FlashError> {
        progress::println("Downloading device's PIT file");
        let pit_buffer = self.session.receive_pit_info().await?;
        let pit_data = PitData::new(&pit_buffer).map_err(FlashError::PitUnpackFailed)?;
        Ok(pit_data)
    }

    // Helper 5: Plan partitions against a given PIT
    async fn plan_partitions<'c>(
        &mut self,
        pit_data: &'c PitData,
        entries: &[IndexedEntry],
        report: bool,
    ) -> Result<Vec<FirmwarePartitionPayload<'c>>, FlashError> {
        let skipped_ids = self.resolve_skipped_partitions(pit_data)?;

        // The super size check is meaningless when super is not flashed
        if pit_data
            .entries
            .iter()
            .any(|e| skipped_ids.contains(&e.partition_id) && is_super_entry(e))
        {
            self.super_used_size = None;
        }

        let mut planned_partitions = self
            .build_partition_infos(pit_data, entries, &skipped_ids, report)
            .await?;

        self.rewrite_vbmeta_payloads(pit_data, &mut planned_partitions, report)
            .await?;

        Ok(planned_partitions)
    }

    // Helper 6: Resolve skip targets into the IDs of the PIT entries they match
    fn resolve_skipped_partitions(&self, pit_data: &PitData) -> Result<HashSet<u32>, FlashError> {
        let mut skipped_ids = HashSet::new();
        for target in &self.skip {
            let mut matched = false;
            for entry in &pit_data.entries {
                if is_skip_target(entry, target) {
                    skipped_ids.insert(entry.partition_id);
                    matched = true;
                }
            }
            if !matched {
                return Err(FlashError::SkipTargetNotFound(target.clone()));
            }
        }
        Ok(skipped_ids)
    }

    // Helper 7: Resolve package entries and standalone files into FirmwarePartitionPayload items
    async fn build_partition_infos<'c>(
        &mut self,
        pit_data: &'c PitData,
        resolved_entries: &[IndexedEntry],
        skipped_ids: &HashSet<u32>,
        report: bool,
    ) -> Result<Vec<FirmwarePartitionPayload<'c>>, FlashError> {
        enum CandidateSource {
            Archive(IndexedEntry),
            Standalone { index: usize, is_lz4: bool },
        }

        struct Candidate<'pit> {
            pit_entry: &'pit PitEntry,
            source: CandidateSource,
        }

        let mut candidates = Vec::new();

        // 1. Collect candidate entries from TAR packages
        for entry in resolved_entries {
            let Some(pit_entry) = find_pit_entry_by_filename(pit_data, &entry.normalized_name)
            else {
                if report {
                    progress::println(&format!(
                        "Skipping orphan file \"{}\" (no matching partition in PIT)",
                        entry.original_name
                    ));
                }
                continue;
            };

            candidates.push(Candidate {
                pit_entry,
                source: CandidateSource::Archive(entry.clone()),
            });
        }

        // 2. Collect candidate individual files
        for (index, (part_name, part_filename, _)) in self.partitions.iter().enumerate() {
            let (filename, is_lz4_suffix) = normalize_basename(part_filename);
            let entry = match part_name {
                None => {
                    let Some(entry) = find_pit_entry_by_filename(pit_data, &filename) else {
                        return Err(FlashError::PartitionNotFound(part_filename.clone()));
                    };
                    entry
                }
                Some(name) => {
                    if let Ok(id) = name.parse::<u32>() {
                        let Some(entry) = pit_data.find_entry_by_id(id) else {
                            return Err(FlashError::PartitionIdNotFound(id));
                        };
                        entry
                    } else {
                        let Some(entry) = pit_data.find_entry_by_name(name) else {
                            return Err(FlashError::PartitionNotFound(name.clone()));
                        };
                        entry
                    }
                }
            };

            candidates.push(Candidate {
                pit_entry: entry,
                source: CandidateSource::Standalone {
                    index,
                    is_lz4: is_lz4_suffix,
                },
            });
        }

        // 3. Partition deduplication: last writer wins
        let mut mapped_partition_ids = HashSet::new();
        let mut unique_candidates = Vec::new();
        for candidate in candidates.into_iter().rev() {
            if mapped_partition_ids.insert(candidate.pit_entry.partition_id) {
                unique_candidates.push(candidate);
            }
        }
        unique_candidates.reverse();

        // 4. Drop partitions excluded with skip targets
        unique_candidates.retain(|candidate| {
            if skipped_ids.contains(&candidate.pit_entry.partition_id) {
                if report {
                    progress::println(&format!(
                        "Skipping {} (excluded with --skip)",
                        candidate.pit_entry.partition_name.to_string_lossy()
                    ));
                }
                false
            } else {
                true
            }
        });

        // 5. Inspect headers and validate sizes only for unique planned partitions
        let mut planned_partitions = Vec::with_capacity(unique_candidates.len());
        for candidate in unique_candidates {
            let (source, is_lz4, display_name) = match candidate.source {
                CandidateSource::Archive(entry) => (
                    FirmwarePartitionSource::Package {
                        index: entry.package_index,
                        offset: entry.offset,
                        size: entry.size,
                    },
                    entry.is_lz4,
                    entry.original_name,
                ),
                CandidateSource::Standalone { index, is_lz4 } => {
                    let (_, name, reader) = &mut self.partitions[index];
                    let display_name = name.clone();
                    let size = reader
                        .seek(SeekFrom::End(0))
                        .await
                        .map_err(|e| FlashError::FileReadFailed(display_name.clone(), e))?;
                    (
                        FirmwarePartitionSource::Image { index, size },
                        is_lz4,
                        display_name,
                    )
                }
            };

            let lz4_header = if is_lz4 {
                let mut reader = source
                    .open_reader(&mut self.packages, &mut self.partitions)
                    .await
                    .map_err(|e| FlashError::Lz4Header(display_name.clone(), e))?;
                let fh = Lz4FrameHeader::parse(&mut reader)
                    .await
                    .map_err(|e| FlashError::Lz4Header(display_name, e))?;
                Some(fh)
            } else {
                None
            };

            let planned = FirmwarePartitionPayload {
                pit_entry: candidate.pit_entry,
                source,
                lz4_header,
            };

            if !self.skip_size_check {
                let partition_size = planned.pit_entry.partition_size();
                if partition_size > 0 && planned.uncompressed_size() > partition_size {
                    return Err(FlashError::PartitionTooSmall(
                        planned
                            .pit_entry
                            .partition_name
                            .to_string_lossy()
                            .into_owned(),
                    ));
                }
            }

            planned_partitions.push(planned);
        }

        Ok(planned_partitions)
    }

    // Helper 8: Set the requested AVB flags in vbmeta payloads. Like fastboot, the
    // top-level vbmeta is looked up in boot on devices without a vbmeta partition.
    async fn rewrite_vbmeta_payloads(
        &mut self,
        pit_data: &PitData,
        planned_partitions: &mut [FirmwarePartitionPayload<'_>],
        report: bool,
    ) -> Result<(), FlashError> {
        if self.vbmeta_flags == 0 {
            return Ok(());
        }

        let has_vbmeta_partition = pit_data.entries.iter().any(is_top_level_vbmeta_entry);
        let mut rewritten = false;
        for planned in planned_partitions.iter_mut() {
            let pit_entry = planned.pit_entry;
            let in_footer = if is_vbmeta_entry(pit_entry) {
                false
            } else if !has_vbmeta_partition && is_boot_entry(pit_entry) {
                true
            } else {
                continue;
            };

            let name = pit_entry.partition_name.to_string_lossy();
            let rewrite_err = |e| FlashError::VbmetaRewriteFailed(name.to_string(), e);

            // The patched image is sent uncompressed, bypassing LZ4 passthrough
            let mut data = {
                let mut reader = planned
                    .source
                    .open_reader(&mut self.packages, &mut self.partitions)
                    .await
                    .map_err(rewrite_err)?;
                planned.read_all(&mut reader).await.map_err(rewrite_err)?
            };

            let Some(offset) = avb::rewrite_vbmeta(&mut data, self.vbmeta_flags, in_footer)
                .map_err(rewrite_err)?
            else {
                if report {
                    progress::println(&format!(
                        "Warning: {} is smaller than a vbmeta header, AVB flags left unchanged",
                        name
                    ));
                }
                rewritten = true;
                continue;
            };

            if report {
                progress::println(&format!(
                    "Rewriting {} vbmeta struct at offset: {}",
                    name, offset
                ));
            }
            planned.lz4_header = None;
            planned.source = FirmwarePartitionSource::Memory(data);
            rewritten = true;
        }

        if !rewritten && report {
            progress::println(
                "Warning: no vbmeta image is being flashed, AVB flags left unchanged",
            );
        }

        Ok(())
    }

    // Helper 9: Flash deduplicated partition payloads to the device
    async fn flash_partitions(
        &mut self,
        planned_partitions: Vec<FirmwarePartitionPayload<'_>>,
        reboot_mode: RebootMode,
    ) -> Result<(), FlashError> {
        let total_bytes: u64 = planned_partitions
            .iter()
            .map(FirmwarePartitionPayload::uncompressed_size)
            .sum();

        self.session.set_total_bytes(total_bytes).await?;

        if let Some(super_used_size) = self.super_used_size
            && super_used_size > 0
            && self.session.bootloader_protocol_version() >= 3
        {
            let check_size = if self.has_download_list || self.packages.is_empty() {
                super_used_size
            } else {
                0
            };
            progress::println("Checking available super partition size...");
            self.session
                .check_super_size(check_size)
                .await
                .map_err(FlashError::SuperSizeCheckFailed)?;
        }

        for planned in planned_partitions {
            let name = planned.pit_entry.partition_name.to_string_lossy();
            let partition_size = planned.uncompressed_size();

            progress::on_event(FlashEvent::PartitionStart {
                name: &name,
                size: partition_size,
            });

            let res = async {
                let mut reader = planned
                    .source
                    .open_reader(&mut self.packages, &mut self.partitions)
                    .await?;
                self.session.send_partition(&planned, &mut reader).await
            }
            .await;

            if let Err(e) = res {
                progress::on_event(FlashEvent::PartitionFail(&name));
                return Err(FlashError::Odin(e));
            }

            progress::on_event(FlashEvent::PartitionEnd(&name));
        }

        self.session.end_session().await?;

        match reboot_mode {
            RebootMode::Normal => {
                self.session.reboot_device().await?;
            }
            RebootMode::Download => {
                self.session.reboot_to_download().await?;
            }
            RebootMode::None => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::odin::OdinConnection;
    use crate::usb::{MockBackend, MockEvent};

    #[test]
    fn test_flashes_userdata() {
        let none: &[&str] = &[];

        // File names, ignoring directories and the .lz4 suffix, and partition names
        assert!(flashes_userdata(&["boot.img", "userdata.img"], none));
        assert!(flashes_userdata(&["dir/userdata.img.lz4"], none));
        assert!(flashes_userdata(&["USERDATA"], none));
        assert!(!flashes_userdata(&["boot.img", "super.img"], none));
        assert!(!flashes_userdata(none, none));

        // Skipped by partition name in any case, or by file name
        assert!(!flashes_userdata(&["userdata.img"], &["userdata"]));
        assert!(!flashes_userdata(&["USERDATA"], &[" USERDATA "]));
        assert!(!flashes_userdata(
            &["userdata.img"],
            &["out/userdata.img.lz4"]
        ));

        // Skipping other partitions does not exclude userdata
        assert!(flashes_userdata(&["userdata.img"], &["boot", "super.img"]));
    }

    fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
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
    fn test_scan_tar_packages_metadata_and_manifest() {
        let tar_bytes = build_tar(&[
            ("meta-data/super_used_size.txt", b"27276104\n"),
            ("meta-data/download-list.txt", b"boot.img\n"),
            ("boot.img", b"DUMMY BOOT IMAGE DATA"),
        ]);

        futures::executor::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session)
                .packages([("test_package.tar", Cursor::new(tar_bytes.as_slice()))]);
            let resolved = manager.scan_tar_packages().await.unwrap();

            assert_eq!(manager.super_used_size, Some(27276104));
            assert!(manager.has_download_list);
            assert_eq!(resolved.len(), 1);
            assert_eq!(resolved[0].normalized_name, "boot.img");
        });
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_success() {
        futures::executor::block_on(async {
            let backend = Box::new(MockBackend::new().with_protocol_version(3));
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session);
            manager.super_used_size = Some(27276104);
            manager.has_download_list = true;

            assert!(
                manager
                    .flash_partitions(Vec::new(), RebootMode::None)
                    .await
                    .is_ok()
            );
        });
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_rejection() {
        futures::executor::block_on(async {
            let backend = Box::new(
                MockBackend::new()
                    .with_protocol_version(3)
                    .with_fail_check_super_size(-1),
            );
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session);
            manager.super_used_size = Some(27276104);
            manager.has_download_list = true;

            let res = manager.flash_partitions(Vec::new(), RebootMode::None).await;
            assert!(matches!(res, Err(FlashError::SuperSizeCheckFailed(_))));
        });
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_skipped_on_legacy_protocol() {
        futures::executor::block_on(async {
            // Even if fail_check_super_size is set, legacy protocol version 2 must skip opcode 0x6a
            let backend = Box::new(
                MockBackend::new()
                    .with_protocol_version(2)
                    .with_fail_check_super_size(-1),
            );
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session);
            manager.super_used_size = Some(27276104);
            manager.has_download_list = true;

            assert!(
                manager
                    .flash_partitions(Vec::new(), RebootMode::None)
                    .await
                    .is_ok()
            );
        });
    }

    #[test]
    fn test_scan_tar_packages_corrupt_manifest_fails() {
        let tar_bytes = build_tar(&[("meta-data/download-list.txt", &[0xFF, 0xFE, 0xFD])]);

        futures::executor::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session)
                .packages([("corrupt_manifest.tar", Cursor::new(tar_bytes.as_slice()))]);
            let result = manager.scan_tar_packages().await;

            assert!(matches!(result, Err(FlashError::ArchiveCorrupted(_, _))));
        });
    }

    #[test]
    fn test_download_and_parse_pit_flashes_available_pit() {
        futures::executor::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let pit_bytes = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/M3_EUR_OPEN_4G.pit"
            ));
            let mut manager = FlashManager::new(&mut session).pit(&pit_bytes[..]);

            let local_pit = manager.parse_local_pit().unwrap();
            assert_eq!(local_pit.cpu_bl_id.to_string_lossy(), "Mx-MDM");

            manager.session.send_pit_info(pit_bytes).await.unwrap();
            let pit_data = manager.download_pit().await.unwrap();
            // M3_EUR_OPEN_4G.pit has Mx-MDM, verifying PIT was sent and updated device state
            assert_eq!(pit_data.cpu_bl_id.to_string_lossy(), "Mx-MDM");
        });
    }

    fn ab_pit_data() -> PitData {
        PitData::new(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/Q7MQ_EUR_OPENX.pit"
        )))
        .unwrap()
    }

    fn skipped_names(targets: &[&str]) -> Result<Vec<String>, FlashError> {
        futures::executor::block_on(async {
            let pit_data = ab_pit_data();
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let manager = FlashManager::new(&mut session).skip(targets);
            let skipped_ids = manager.resolve_skipped_partitions(&pit_data)?;
            let mut names: Vec<String> = pit_data
                .entries
                .iter()
                .filter(|e| skipped_ids.contains(&e.partition_id))
                .map(|e| e.partition_name.to_string_lossy().into_owned())
                .collect();
            names.sort();
            Ok(names)
        })
    }

    #[test]
    fn test_skip_partition_name_covers_ab_slots() {
        assert_eq!(skipped_names(&["BOOT"]).unwrap(), ["BOOT_A", "BOOT_B"]);
        assert_eq!(
            skipped_names(&["vbmeta"]).unwrap(),
            ["VBMETA_A", "VBMETA_B"]
        );
        assert_eq!(skipped_names(&["boot_b"]).unwrap(), ["BOOT_B"]);
        assert_eq!(skipped_names(&["SUPER"]).unwrap(), ["SUPER"]);
    }

    #[test]
    fn test_skip_file_name_covers_all_matching_partitions() {
        assert_eq!(skipped_names(&["boot.img"]).unwrap(), ["BOOT_A", "BOOT_B"]);
        assert_eq!(
            skipped_names(&["AP/vbmeta.img.lz4"]).unwrap(),
            ["VBMETA_A", "VBMETA_B"]
        );
        assert_eq!(
            skipped_names(&["init_boot.img", "DTBO", " "]).unwrap(),
            ["DTBO_A", "DTBO_B", "INIT_BOOT_A", "INIT_BOOT_B"]
        );
    }

    #[test]
    fn test_skip_unknown_target_fails() {
        assert!(matches!(
            skipped_names(&["BOOT", "nonexistent.img"]),
            Err(FlashError::SkipTargetNotFound(t)) if t == "nonexistent.img"
        ));
    }

    #[test]
    fn test_build_partition_infos_drops_skipped_partitions() {
        let partitions = vec![
            (None, "boot.img", Cursor::new(&b"DUMMY IMAGE DATA"[..])),
            (None, "vbmeta.img", Cursor::new(&b"DUMMY IMAGE DATA"[..])),
            (None, "dtbo.img", Cursor::new(&b"DUMMY IMAGE DATA"[..])),
            (
                Some("VBMETA_B".to_string()),
                "vbmeta.img",
                Cursor::new(&b"DUMMY IMAGE DATA"[..]),
            ),
        ];

        futures::executor::block_on(async {
            let pit_data = ab_pit_data();
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let mut manager = FlashManager::new(&mut session)
                .partitions(partitions)
                .skip(&["boot.img", "VBMETA"]);
            let skipped_ids = manager.resolve_skipped_partitions(&pit_data).unwrap();
            let infos = manager
                .build_partition_infos(&pit_data, &[], &skipped_ids, true)
                .await
                .unwrap();

            let names: Vec<String> = infos
                .iter()
                .map(|p| p.pit_entry.partition_name.to_string_lossy().into_owned())
                .collect();
            assert_eq!(names, ["DTBO_A"]);
        });
    }

    #[test]
    fn test_execute_skipping_super_skips_super_size_check() {
        let tar_bytes = build_tar(&[
            ("meta-data/super_used_size.txt", b"27276104\n"),
            ("meta-data/download-list.txt", b"boot.img\nsuper.img\n"),
            ("boot.img", b"DUMMY BOOT IMAGE DATA"),
            ("super.img", b"DUMMY SUPER IMAGE DATA"),
        ]);

        let run = |skip: &[&str]| {
            futures::executor::block_on(async {
                let backend = Box::new(
                    MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b())
                        .with_protocol_version(3)
                        .with_fail_check_super_size(-1),
                );
                let mut connection = OdinConnection::new(backend);
                connection.init().await.unwrap();
                let mut session = connection.begin_session().await.unwrap();
                FlashManager::new(&mut session)
                    .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                    .skip(skip)
                    .execute()
                    .await
            })
        };

        assert!(matches!(run(&[]), Err(FlashError::SuperSizeCheckFailed(_))));
        assert!(run(&["super.img"]).is_ok());
    }

    fn lz4_compress(data: &[u8]) -> (Vec<u8>, Lz4FrameHeader) {
        use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
        use std::io::Write;

        let info = FrameInfo::new()
            .content_size(Some(data.len() as u64))
            .block_size(BlockSize::Max1MB)
            .block_mode(BlockMode::Independent);
        let mut encoder = FrameEncoder::with_frame_info(info, Vec::new());
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();
        let header =
            futures::executor::block_on(Lz4FrameHeader::parse(Cursor::new(&compressed[..])))
                .unwrap();
        (compressed, header)
    }

    fn find_entry<'p>(pit_data: &'p PitData, name: &str) -> &'p PitEntry {
        pit_data.find_entry_by_name(name).unwrap()
    }

    fn rewrite_vbmeta(
        pit_data: &PitData,
        partitions: Vec<Cursor<Vec<u8>>>,
        planned: &mut [FirmwarePartitionPayload<'_>],
        verity: bool,
        verification: bool,
    ) -> Result<(), FlashError> {
        futures::executor::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            FlashManager::new(&mut session)
                .partitions(partitions.into_iter().map(|r| (None, "part", r)))
                .disable_verity(verity)
                .disable_verification(verification)
                .rewrite_vbmeta_payloads(pit_data, planned, true)
                .await
        })
    }

    fn planned_bytes(
        planned: &FirmwarePartitionPayload<'_>,
        partitions: &[Cursor<Vec<u8>>],
    ) -> Vec<u8> {
        assert!(planned.lz4_header.is_none());
        match &planned.source {
            FirmwarePartitionSource::Memory(data) => data.clone(),
            FirmwarePartitionSource::Image { index, .. } => partitions[*index].get_ref().clone(),
            FirmwarePartitionSource::Package { .. } => unreachable!(),
        }
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_patches_all_vbmeta() {
        use crate::avb::tests::{vbmeta_flags, vbmeta_image};

        let pit_data = ab_pit_data();
        let image = vbmeta_image(0);
        let size = image.len() as u64;
        let (lz4_bytes, header) = lz4_compress(&image);
        let lz4_size = lz4_bytes.len() as u64;
        let backing = || {
            vec![
                Cursor::new(image.clone()),
                Cursor::new(lz4_bytes.clone()),
                Cursor::new(image.clone()),
                Cursor::new(image.clone()),
            ]
        };
        let mut planned = vec![
            FirmwarePartitionPayload {
                pit_entry: find_entry(&pit_data, "VBMETA_A"),
                source: FirmwarePartitionSource::Image { index: 0, size },
                lz4_header: None,
            },
            FirmwarePartitionPayload {
                pit_entry: find_entry(&pit_data, "VBMETA_B"),
                source: FirmwarePartitionSource::Image {
                    index: 1,
                    size: lz4_size,
                },
                lz4_header: Some(header),
            },
            FirmwarePartitionPayload {
                pit_entry: find_entry(&pit_data, "VBMETA_SYSTEM_A"),
                source: FirmwarePartitionSource::Image { index: 2, size },
                lz4_header: None,
            },
            FirmwarePartitionPayload {
                pit_entry: find_entry(&pit_data, "BOOT_A"),
                source: FirmwarePartitionSource::Image { index: 3, size },
                lz4_header: None,
            },
        ];

        rewrite_vbmeta(&pit_data, backing(), &mut planned, true, false).unwrap();
        assert_eq!(
            vbmeta_flags(&planned_bytes(&planned[0], &backing()), 0),
            0x1
        );
        assert_eq!(
            vbmeta_flags(&planned_bytes(&planned[1], &backing()), 0),
            0x1
        );

        // Rewriting again accumulates flags, and LZ4 passthrough stays disabled
        rewrite_vbmeta(&pit_data, backing(), &mut planned, false, true).unwrap();
        for p in &planned[..2] {
            let data = planned_bytes(p, &backing());
            assert_eq!(data.len(), image.len());
            assert_eq!(vbmeta_flags(&data, 0), 0x3);
        }

        // Like fastboot, only top-level vbmeta partitions are rewritten
        assert_eq!(planned_bytes(&planned[2], &backing()), image);
        assert_eq!(planned_bytes(&planned[3], &backing()), image);
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_disabled_keeps_payloads() {
        let pit_data = ab_pit_data();
        let (lz4_bytes, header) = lz4_compress(&crate::avb::tests::vbmeta_image(0));
        let size = lz4_bytes.len() as u64;
        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "VBMETA_A"),
            source: FirmwarePartitionSource::Image { index: 0, size },
            lz4_header: Some(header),
        }];

        rewrite_vbmeta(
            &pit_data,
            vec![Cursor::new(lz4_bytes)],
            &mut planned,
            false,
            false,
        )
        .unwrap();
        assert!(planned[0].lz4_header.is_some());
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_invalid_vbmeta_fails() {
        let pit_data = ab_pit_data();
        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "VBMETA_A"),
            source: FirmwarePartitionSource::Image {
                index: 0,
                size: 4096,
            },
            lz4_header: None,
        }];

        assert!(matches!(
            rewrite_vbmeta(
                &pit_data,
                vec![Cursor::new(vec![0u8; 4096])],
                &mut planned,
                true,
                true,
            ),
            Err(FlashError::VbmetaRewriteFailed(name, _)) if name == "VBMETA_A"
        ));
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_boot_without_vbmeta_partition() {
        use crate::avb::tests::vbmeta_flags;

        // M3_EUR_OPEN_4G.pit has no vbmeta partition, so the vbmeta in boot's footer
        // is rewritten. A boot image without an AVB footer is rejected.
        let pit_data = PitData::new(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/M3_EUR_OPEN_4G.pit"
        )))
        .unwrap();

        let mut boot = vec![0u8; 16 * 1024];
        boot[0x1000..0x1004].copy_from_slice(b"AVB0");
        let footer = boot.len() - 64;
        boot[footer..footer + 4].copy_from_slice(b"AVBf");
        boot[footer + 20..footer + 28].copy_from_slice(&0x1000u64.to_be_bytes());

        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "BOOT"),
            source: FirmwarePartitionSource::Image {
                index: 0,
                size: boot.len() as u64,
            },
            lz4_header: None,
        }];
        rewrite_vbmeta(&pit_data, vec![Cursor::new(boot)], &mut planned, true, true).unwrap();
        assert_eq!(vbmeta_flags(&planned_bytes(&planned[0], &[]), 0x1000), 0x3);

        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "BOOT"),
            source: FirmwarePartitionSource::Image {
                index: 0,
                size: 4096,
            },
            lz4_header: None,
        }];
        assert!(matches!(
            rewrite_vbmeta(
                &pit_data,
                vec![Cursor::new(vec![0u8; 4096])],
                &mut planned,
                true,
                false,
            ),
            Err(FlashError::VbmetaRewriteFailed(_, _))
        ));
    }

    #[test]
    fn test_execute_disable_verity_with_lz4_vbmeta() {
        use std::io::Write;

        let build_package = |vbmeta: &[u8]| {
            let mut encoder = lz4_flex::frame::FrameEncoder::with_frame_info(
                lz4_flex::frame::FrameInfo::new()
                    .content_size(Some(vbmeta.len() as u64))
                    .block_size(lz4_flex::frame::BlockSize::Max1MB)
                    .block_mode(lz4_flex::frame::BlockMode::Independent),
                Vec::new(),
            );
            encoder.write_all(vbmeta).unwrap();
            let vbmeta_lz4 = encoder.finish().unwrap();

            build_tar(&[
                ("vbmeta.img.lz4", &vbmeta_lz4),
                ("boot.img", b"DUMMY BOOT IMAGE DATA"),
            ])
        };
        let valid = build_package(&crate::avb::tests::vbmeta_image(0));
        let invalid = build_package(&[0u8; 4096]);

        let run = |name: &str, tar_bytes: &[u8], verity: bool| {
            futures::executor::block_on(async {
                let backend = Box::new(MockBackend::with_profile(
                    crate::usb::DeviceProfile::sm_f968b(),
                ));
                let mut connection = OdinConnection::new(backend);
                connection.init().await.unwrap();
                let mut session = connection.begin_session().await.unwrap();
                assert!(session.is_lz4_supported());
                FlashManager::new(&mut session)
                    .packages([(name, Cursor::new(tar_bytes))])
                    .disable_verity(verity)
                    .execute()
                    .await
            })
        };

        assert!(run("valid.tar", &valid, false).is_ok());
        assert!(run("valid.tar", &valid, true).is_ok());
        // The vbmeta in the package is only parsed when a rewrite is requested
        assert!(run("invalid.tar", &invalid, false).is_ok());
        assert!(matches!(
            run("invalid.tar", &invalid, true),
            Err(FlashError::VbmetaRewriteFailed(name, _)) if name == "VBMETA_A"
        ));
    }

    #[test]
    fn test_execute_truncated_package_fails_before_device() {
        let tar_bytes = build_tar(&[("boot.img", &[0xABu8; 1024])]);
        let truncated = &tar_bytes[..600];

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let res = FlashManager::new(&mut session)
                .erase(true)
                .packages([("AP.tar", Cursor::new(truncated))])
                .execute()
                .await;

            assert!(matches!(res, Err(FlashError::ArchiveCorrupted(pkg, _)) if pkg == "AP.tar"));
            let logged = events.lock().unwrap();
            assert!(
                !logged.contains(&MockEvent::NandErase)
                    && !logged.contains(&MockEvent::PitFlash)
                    && !logged.iter().any(|e| matches!(e, MockEvent::Slice { .. })),
                "no destructive operations should have occurred, got: {:?}",
                *logged
            );
        });
    }

    #[test]
    fn test_execute_bad_skip_target_does_not_erase() {
        let tar_bytes = build_tar(&[("boot.img", b"DUMMY BOOT IMAGE DATA")]);

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let res = FlashManager::new(&mut session)
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .skip(&["nonexistent_partition"])
                .execute()
                .await;

            assert!(
                matches!(res, Err(FlashError::SkipTargetNotFound(target)) if target == "nonexistent_partition")
            );
            let logged = events.lock().unwrap();
            assert!(
                !logged.contains(&MockEvent::NandErase),
                "NandErase should not have occurred, got: {:?}",
                *logged
            );
        });
    }

    #[test]
    fn test_execute_invalid_vbmeta_does_not_flash_pit() {
        let tar_bytes = build_tar(&[("vbmeta.img", &[0xFFu8; 512])]);
        let pit_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/Q7MQ_EUR_OPENX.pit"
        ));

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let res = FlashManager::new(&mut session)
                .pit(&pit_bytes[..])
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .disable_verity(true)
                .execute()
                .await;

            assert!(
                matches!(res, Err(FlashError::VbmetaRewriteFailed(name, _)) if name == "VBMETA_A")
            );
            let logged = events.lock().unwrap();
            assert!(
                !logged.contains(&MockEvent::PitFlash) && !logged.contains(&MockEvent::NandErase),
                "PitFlash/NandErase should not have occurred, got: {:?}",
                *logged
            );
        });
    }

    #[test]
    fn test_execute_order_with_local_pit() {
        let tar_bytes = build_tar(&[("boot.img", b"DUMMY BOOT IMAGE DATA")]);
        let pit_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/Q7MQ_EUR_OPENX.pit"
        ));

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            FlashManager::new(&mut session)
                .pit(&pit_bytes[..])
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .execute()
                .await
                .unwrap();

            let logged = events.lock().unwrap().clone();
            assert!(logged.len() >= 4);
            assert_eq!(logged[0], MockEvent::NandErase);
            assert_eq!(logged[1], MockEvent::PitFlash);
            assert_eq!(logged[2], MockEvent::PitDump);
            assert!(matches!(logged[3], MockEvent::Slice { .. }));
        });
    }

    #[test]
    fn test_execute_order_without_local_pit() {
        let tar_bytes = build_tar(&[("boot.img", b"DUMMY BOOT IMAGE DATA")]);

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            FlashManager::new(&mut session)
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .execute()
                .await
                .unwrap();

            let logged = events.lock().unwrap().clone();
            assert!(logged.len() >= 3);
            assert_eq!(logged[0], MockEvent::PitDump);
            assert_eq!(logged[1], MockEvent::NandErase);
            assert!(matches!(logged[2], MockEvent::Slice { .. }));
        });
    }

    #[test]
    fn test_execute_invalid_local_pit_rejected_early() {
        let tar_bytes = build_tar(&[("boot.img", b"DUMMY BOOT IMAGE DATA")]);

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            let res = FlashManager::new(&mut session)
                .pit(b"invalid_pit_bytes")
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .execute()
                .await;

            assert!(matches!(res, Err(FlashError::PitUnpackFailed(_))));
            let logged = events.lock().unwrap();
            assert!(
                logged.is_empty(),
                "no operations should have occurred on invalid local pit, got: {:?}",
                *logged
            );
        });
    }

    #[test]
    fn test_execute_vbmeta_payload_flags() {
        use std::io::Write;

        let raw_vbmeta = crate::avb::tests::vbmeta_image(0);
        let mut encoder = lz4_flex::frame::FrameEncoder::with_frame_info(
            lz4_flex::frame::FrameInfo::new()
                .content_size(Some(raw_vbmeta.len() as u64))
                .block_size(lz4_flex::frame::BlockSize::Max1MB)
                .block_mode(lz4_flex::frame::BlockMode::Independent),
            Vec::new(),
        );
        encoder.write_all(&raw_vbmeta).unwrap();
        let vbmeta_lz4 = encoder.finish().unwrap();

        let tar_bytes = build_tar(&[("vbmeta.img.lz4", &vbmeta_lz4)]);

        // 1. With --disable-verity and --disable-verification: sent raw, byte 123 is 0x03
        futures::executor::block_on(async {
            let backend = MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b());
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            FlashManager::new(&mut session)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .disable_verity(true)
                .disable_verification(true)
                .execute()
                .await
                .unwrap();

            let logged = events.lock().unwrap().clone();
            let slice = logged
                .iter()
                .find_map(|e| match e {
                    MockEvent::Slice { lz4, data, .. } => Some((*lz4, data)),
                    _ => None,
                })
                .expect("vbmeta slice");

            assert!(!slice.0, "rewritten vbmeta must be sent raw (uncompressed)");
            // Only the flags field (big endian u32 at offset 120) changes
            let mut expected = raw_vbmeta.clone();
            expected[123] = 0x03;
            assert_eq!(slice.1, &expected);
        });

        // 2. Without flags: payload matches input exactly for raw, and lz4 passthrough is preserved for lz4
        futures::executor::block_on(async {
            let raw_tar = build_tar(&[("vbmeta.img", &raw_vbmeta)]);
            let backend = MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b());
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            FlashManager::new(&mut session)
                .packages([("AP.tar", Cursor::new(raw_tar.as_slice()))])
                .execute()
                .await
                .unwrap();

            let logged = events.lock().unwrap().clone();
            let slice = logged
                .iter()
                .find_map(|e| match e {
                    MockEvent::Slice { lz4, data, .. } => Some((*lz4, data)),
                    _ => None,
                })
                .expect("vbmeta slice");

            assert!(!slice.0);
            assert_eq!(slice.1, &raw_vbmeta);
        });

        // 3. Without flags on LZ4 input: lz4 passthrough is preserved
        futures::executor::block_on(async {
            let backend = MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b());
            let events = backend.event_log();
            let mut connection = OdinConnection::new(Box::new(backend));
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            FlashManager::new(&mut session)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .execute()
                .await
                .unwrap();

            let logged = events.lock().unwrap().clone();
            let slice = logged
                .iter()
                .find_map(|e| match e {
                    MockEvent::Slice { lz4, data, .. } => Some((*lz4, data)),
                    _ => None,
                })
                .expect("vbmeta slice");

            assert!(slice.0, "unmodified vbmeta must preserve LZ4 passthrough");
            // Passthrough sends the LZ4 blocks between the 15 byte frame header and the EndMark
            assert_eq!(slice.1, &vbmeta_lz4[15..vbmeta_lz4.len() - 4]);
        });
    }

    #[test]
    fn test_package_flash_files_filtering_and_truncation() {
        let manifest = b"boot.img\nsuper.img\n";
        let pit_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/M3_EUR_OPEN_4G.pit"
        ));
        let tar_bytes = build_tar(&[
            ("meta-data/download-list.txt", manifest),
            ("meta-data/super_used_size.txt", b"12345\n"),
            ("device.pit", pit_bytes),
            ("boot.img.lz4", b"BOOT DATA"),
            ("recovery.img.lz4", b"RECOVERY DATA"),
        ]);

        futures::executor::block_on(async {
            let mut packages = vec![("AP.tar".to_string(), Cursor::new(tar_bytes.as_slice()))];
            let files = package_flash_files(&mut packages).await.unwrap();
            // recovery.img is omitted (not in download-list), metadata & pit are omitted
            assert_eq!(files, ["boot.img"]);

            // Truncated package errors on scan
            let truncated = &tar_bytes[..tar_bytes.len() - 600];
            let mut bad_packages = vec![("AP.tar".to_string(), Cursor::new(truncated))];
            let res = package_flash_files(&mut bad_packages).await;
            assert!(matches!(res, Err(FlashError::ArchiveCorrupted(pkg, _)) if pkg == "AP.tar"));
        });
    }

    #[test]
    fn test_execute_with_local_pit_reports_once() {
        #[derive(Clone, Default)]
        struct Collector(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

        impl crate::FlashProgress for Collector {
            fn println(&self, msg: &str) {
                self.0.lock().unwrap().push(msg.to_string());
            }
        }

        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tar_bytes = build_tar(&[
            ("boot.img", b"DUMMY BOOT IMAGE DATA"),
            ("dtbo.img", b"DUMMY DTBO IMAGE DATA"),
        ]);
        let pit_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/Q7MQ_EUR_OPENX.pit"
        ));

        let collector = Collector::default();
        crate::progress::set_progress(collector.clone());
        let res = futures::executor::block_on(async {
            let backend = Box::new(MockBackend::new());
            let mut connection = OdinConnection::new(backend);
            connection.init().await.unwrap();
            let mut session = connection.begin_session().await.unwrap();

            // The plan is checked against the local PIT and then rebuilt against the
            // flashed PIT, but informational messages must only be printed once
            FlashManager::new(&mut session)
                .pit(&pit_bytes[..])
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .skip(&["DTBO"])
                .execute()
                .await
        });
        crate::progress::clear_progress();
        res.unwrap();

        let messages = collector.0.lock().unwrap();
        let count = messages
            .iter()
            .filter(|m| m.as_str() == "Skipping DTBO_A (excluded with --skip)")
            .count();
        assert_eq!(count, 1, "messages: {:?}", *messages);
    }
}
