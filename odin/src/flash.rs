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
use crate::firmware::avb;
use crate::firmware::{
    FirmwareImage, FirmwarePartitionPayload, FirmwareReaders, ImageSource, PackageIndex,
    normalize_basename, verify_md5_footer,
};
use crate::odin::{OdinSession, parse_sales_code};
use crate::progress::{self, FlashEvent};
use futures::io::{AsyncRead, AsyncSeek, AsyncSeekExt, Cursor};
use samloader_pit::PitData;
use std::collections::HashSet;
use std::io::SeekFrom;

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

/// Options carried from a [`FlashConfig`] into execution.
#[derive(Default)]
struct FlashOptions {
    reboot_mode: RebootMode,
    skip_size_check: bool,
    skip_md5: bool,
    sales_code: Option<String>,
    erase: bool,
    skip: Vec<String>,
    vbmeta_flags: u32,
}

impl FlashOptions {
    /// Resolves the skip targets into the IDs of the PIT entries they match. A target
    /// matches the flash file name or the partition name of an entry. Partition names
    /// also match their `_A` and `_B` slots on A/B devices.
    fn skipped_partition_ids(&self, pit_data: &PitData) -> Result<HashSet<u32>, FlashError> {
        let mut skipped_ids = HashSet::new();
        for target in &self.skip {
            let (filename, _) = normalize_basename(target);
            let names = ["", "_A", "_B"].map(|slot| format!("{target}{slot}"));
            let mut matched = false;
            for entry in &pit_data.entries {
                let partition_name = entry.partition_name.to_string_lossy();
                if entry
                    .flash_filename
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&filename)
                    || names.iter().any(|n| partition_name.eq_ignore_ascii_case(n))
                {
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

    /// Warns about options that only apply when partitions are flashed.
    fn warn_unused(&self) {
        if !self.skip.is_empty() {
            progress::println("Warning: --skip ignored when no partitions are flashed");
        }
        if self.vbmeta_flags & avb::AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED != 0 {
            progress::println("Warning: --disable-verity ignored when no partitions are flashed");
        }
        if self.vbmeta_flags & avb::AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED != 0 {
            progress::println(
                "Warning: --disable-verification ignored when no partitions are flashed",
            );
        }
    }
}

/// Configures a flash operation. Building it performs no I/O.
///
/// Call [`preplan`](Self::preplan) to read and validate the inputs, then
/// [`FlashBlueprint::execute`] to flash a device.
pub struct FlashConfig<P = Cursor<&'static [u8]>, I = Cursor<&'static [u8]>> {
    options: FlashOptions,
    pit: Option<Vec<u8>>,
    readers: FirmwareReaders<P, I>,
}

impl FlashConfig {
    /// Creates a new `FlashConfig` with default options and no inputs.
    pub fn new() -> Self {
        Self {
            options: FlashOptions::default(),
            pit: None,
            readers: FirmwareReaders::default(),
        }
    }
}

impl Default for FlashConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl<P, I> FlashConfig<P, I> {
    /// Sets whether to perform a low-level NAND hardware erase on the `USERDATA` partition
    /// prior to flashing or as a standalone wipe operation.
    pub fn erase(mut self, enabled: bool) -> Self {
        self.options.erase = enabled;
        self
    }

    /// Sets an optional 3-letter CSC / Sales Code to configure on the device.
    pub fn sales_code(mut self, sales_code: Option<&str>) -> Self {
        self.options.sales_code = sales_code.map(str::to_owned);
        self
    }

    /// Sets the reboot mode to perform after flashing completes.
    pub fn reboot_mode(mut self, mode: RebootMode) -> Self {
        self.options.reboot_mode = mode;
        self
    }

    /// Sets whether to skip partition size checks.
    pub fn skip_size_check(mut self, enabled: bool) -> Self {
        self.options.skip_size_check = enabled;
        self
    }

    /// Sets whether to skip MD5 package verification.
    pub fn skip_md5(mut self, enabled: bool) -> Self {
        self.options.skip_md5 = enabled;
        self
    }

    /// Sets an explicit PIT payload to flash. Without one, a PIT found in a
    /// package is flashed.
    pub fn pit(mut self, pit_bytes: impl Into<Vec<u8>>) -> Self {
        self.pit = Some(pit_bytes.into());
        self
    }

    /// Sets the list of TAR packages `(name, reader)` to flash.
    pub fn packages<S: Into<String>, R>(
        self,
        packages: impl IntoIterator<Item = (S, R)>,
    ) -> FlashConfig<R, I> {
        FlashConfig {
            options: self.options,
            pit: self.pit,
            readers: FirmwareReaders {
                packages: packages
                    .into_iter()
                    .map(|(name, reader)| (name.into(), reader))
                    .collect(),
                partitions: self.readers.partitions,
            },
        }
    }

    /// Sets the list of individual partition inputs `(target_partition, filename, reader)` to flash.
    pub fn partitions<S: Into<String>, R>(
        self,
        partitions: impl IntoIterator<Item = (Option<String>, S, R)>,
    ) -> FlashConfig<P, R> {
        FlashConfig {
            options: self.options,
            pit: self.pit,
            readers: FirmwareReaders {
                packages: self.readers.packages,
                partitions: partitions
                    .into_iter()
                    .map(|(part, name, reader)| (part, name.into(), reader))
                    .collect(),
            },
        }
    }

    /// Sets the partitions to exclude from flashing. Each target is either a file name
    /// or a partition name in the PIT. Partition names also exclude their `_A` and `_B`
    /// slots.
    pub fn skip(mut self, targets: &[impl AsRef<str>]) -> Self {
        self.options.skip = targets
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
            self.options.vbmeta_flags |= flag;
        } else {
            self.options.vbmeta_flags &= !flag;
        }
    }
}

impl<P: AsyncRead + AsyncSeek + Unpin, I: AsyncRead + AsyncSeek + Unpin> FlashConfig<P, I> {
    /// Reads and validates all inputs without a device or PIT.
    ///
    /// This verifies MD5 footers, indexes the packages, parses the LZ4 header of
    /// every LZ4 compressed image, and inspects super images. A local PIT is
    /// checked to be valid, but not used. The result only depends on the inputs
    /// and options, as matching images to partitions, including skips, needs the
    /// device's PIT and happens in [`FlashBlueprint::execute`].
    pub async fn preplan(self) -> Result<FlashBlueprint<P, I>, FlashError> {
        let Self {
            options,
            pit,
            mut readers,
        } = self;

        if let Some(sales_code) = &options.sales_code {
            parse_sales_code(sales_code)?;
        }

        if readers.is_empty() && pit.is_none() {
            options.warn_unused();
            return Ok(FlashBlueprint {
                options,
                pit,
                readers,
                images: Vec::new(),
                super_used_size: None,
                has_download_list: false,
            });
        }

        if !options.skip_md5 {
            for (name, reader) in &mut readers.packages {
                if name.to_lowercase().ends_with(".md5") {
                    verify_md5_footer(&mut *reader, name)
                        .await
                        .map_err(|e| FlashError::Md5VerificationFailed(name.clone(), e))?;
                }
            }
        }

        let index = PackageIndex::scan(&mut readers.packages, pit.is_none()).await?;
        let pit = pit.or(index.pit_bytes);
        if let Some(pit_bytes) = &pit {
            PitData::new(pit_bytes).map_err(FlashError::PitUnpackFailed)?;
        }

        let mut images = Vec::with_capacity(index.entries.len() + readers.partitions.len());
        for entry in index.entries {
            let source = ImageSource::Package {
                index: entry.package_index,
                offset: entry.offset,
                size: entry.size,
            };
            let image = FirmwareImage::inspect(source, entry.is_lz4, &mut readers)
                .await
                .map_err(|e| FlashError::Lz4Header(entry.original_name.clone(), e))?;
            images.push(PlannedImage {
                target: Target::File(entry.normalized_name),
                display_name: entry.original_name,
                image,
                super_used_size: None,
            });
        }

        for index in 0..readers.partitions.len() {
            let (part_name, filename, reader) = &mut readers.partitions[index];
            let (normalized_name, is_lz4) = normalize_basename(filename);
            let target = match part_name {
                None => Target::File(normalized_name),
                Some(name) => match name.parse::<u32>() {
                    Ok(id) => Target::PartitionId(id),
                    Err(_) => Target::Partition(name.clone()),
                },
            };
            let display_name = filename.clone();
            let size = reader
                .seek(SeekFrom::End(0))
                .await
                .map_err(|e| FlashError::FileReadFailed(display_name.clone(), e))?;
            let source = ImageSource::Image { index, size };
            let image = FirmwareImage::inspect(source, is_lz4, &mut readers)
                .await
                .map_err(|e| FlashError::Lz4Header(display_name.clone(), e))?;
            images.push(PlannedImage {
                target,
                display_name,
                image,
                super_used_size: None,
            });
        }

        if index.super_used_size.is_none() {
            for planned in images.iter_mut().filter(|i| i.target.is_super()) {
                planned.super_used_size = planned.image.super_used_size(&mut readers).await;
            }
        }

        Ok(FlashBlueprint {
            options,
            pit,
            readers,
            images,
            super_used_size: index.super_used_size,
            has_download_list: index.has_download_list,
        })
    }
}

/// How an image is matched to a PIT entry during execution.
#[derive(Debug, PartialEq)]
enum Target {
    /// Flash file name in the PIT, with any directory and `.lz4` suffix stripped.
    File(String),
    /// Explicit partition name, e.g. `-p BOOT boot.img`.
    Partition(String),
    /// Explicit partition ID, e.g. `-p 12 boot.img`.
    PartitionId(u32),
}

impl Target {
    /// Whether the target is known to be the super partition without a PIT.
    fn is_super(&self) -> bool {
        match self {
            Self::File(name) => name.eq_ignore_ascii_case("super.img"),
            Self::Partition(name) => name.eq_ignore_ascii_case("SUPER"),
            Self::PartitionId(_) => false,
        }
    }
}

/// An input image collected without a PIT.
struct PlannedImage {
    target: Target,
    display_name: String,
    image: FirmwareImage,
    /// LP metadata size of the image, if it targets the super partition.
    super_used_size: Option<u32>,
}

impl PlannedImage {
    /// Whether the image is a standalone file rather than a package entry.
    fn is_standalone(&self) -> bool {
        matches!(self.image.source, ImageSource::Image { .. })
    }
}

/// A flash prepared from a [`FlashConfig`], holding everything that can be
/// determined without a device or PIT. Created by [`FlashConfig::preplan`].
pub struct FlashBlueprint<P = Cursor<&'static [u8]>, I = Cursor<&'static [u8]>> {
    options: FlashOptions,
    /// PIT to flash, given explicitly or found in a package.
    pit: Option<Vec<u8>>,
    readers: FirmwareReaders<P, I>,
    /// Package entries in order, followed by standalone files.
    images: Vec<PlannedImage>,
    /// Value of `super_used_size.txt`, if present.
    super_used_size: Option<u32>,
    has_download_list: bool,
}

impl<P, I> FlashBlueprint<P, I> {
    /// Returns whether the flash writes the userdata partition, which wipes the
    /// device's data. As the device's PIT is not consulted, this is a name-based
    /// check meant for confirmation prompts before connecting to a device, which
    /// honors the configured skip targets. Partitions given by numeric ID cannot
    /// be resolved.
    pub fn flashes_userdata(&self) -> bool {
        // Skip targets are file names or partition names, like in `skipped_partition_ids`
        let is_skipped = |name: &str| {
            self.options.skip.iter().any(|target| {
                target.eq_ignore_ascii_case("USERDATA")
                    || normalize_basename(target).0.eq_ignore_ascii_case(name)
            })
        };

        self.images.iter().any(|planned| match &planned.target {
            Target::File(name) | Target::Partition(name) => {
                name.to_ascii_lowercase().starts_with("userdata") && !is_skipped(name)
            }
            Target::PartitionId(_) => false,
        })
    }

    fn is_empty(&self) -> bool {
        self.readers.is_empty() && self.pit.is_none()
    }
}

/// A blueprint resolved against a PIT.
#[derive(Default)]
struct Resolved<'p> {
    payloads: Vec<FirmwarePartitionPayload<'p>>,
    /// Index into `FlashBlueprint::images` of each payload.
    image_indices: Vec<usize>,
    /// Whether a super partition is excluded with a skip target.
    super_skipped: bool,
}

impl<P: AsyncRead + AsyncSeek + Unpin, I: AsyncRead + AsyncSeek + Unpin> FlashBlueprint<P, I> {
    /// Resolves the blueprint against the device's PIT, then flashes the device
    /// behind `session`.
    ///
    /// With a local PIT, the blueprint is first resolved against it to catch
    /// errors before the PIT is flashed. Nothing is written to the device, not
    /// even the CSC, before the blueprint has been resolved.
    pub async fn execute(mut self, session: &mut OdinSession) -> Result<(), FlashError> {
        if self.is_empty() {
            self.prepare_device(session).await?;
            match self.options.reboot_mode {
                RebootMode::Normal => session.reboot_device().await?,
                RebootMode::Download => session.reboot_to_download().await?,
                RebootMode::None => session.end_session().await?,
            }
            return Ok(());
        }

        // With a local PIT, the CSC is set and the device erased right before the PIT is
        // flashed, after resolving against the local PIT. Otherwise, this happens after
        // resolving against the device's PIT.
        let local_pit = self.pit.take();
        if let Some(pit_bytes) = &local_pit {
            let pit_data = PitData::new(pit_bytes).map_err(FlashError::PitUnpackFailed)?;
            self.resolve(&pit_data, false).await?;
            self.prepare_device(session).await?;

            progress::println("Flashing PIT");
            session.send_pit_info(pit_bytes).await?;
            progress::println("PIT flash successful\n");
        }

        progress::println("Downloading device's PIT file");
        let pit_buffer = session.receive_pit_info().await?;
        let device_pit = PitData::new(&pit_buffer).map_err(FlashError::PitUnpackFailed)?;
        let resolved = self.resolve(&device_pit, true).await?;
        if local_pit.is_none() {
            self.prepare_device(session).await?;
        }

        let super_used_size = self.super_used_size(&resolved).await;
        self.flash(session, resolved, super_used_size).await
    }

    /// Sets the CSC and erases the device as configured. These are the first writes
    /// to the device.
    async fn prepare_device(&self, session: &mut OdinSession) -> Result<(), FlashError> {
        if let Some(sales_code) = &self.options.sales_code {
            progress::println(&format!("Setting device sales code to {}...", sales_code));
            session.set_sales_code(sales_code).await?;
        }
        if self.options.erase {
            session.nand_erase().await?;
        }
        Ok(())
    }

    /// Matches images to the entries of `pit_data`, applies overrides, skips and
    /// size checks, and rewrites vbmeta images. Reading vbmeta images is the only
    /// input I/O.
    async fn resolve<'p>(
        &mut self,
        pit_data: &'p PitData,
        report: bool,
    ) -> Result<Resolved<'p>, FlashError> {
        let skipped_ids = self.options.skipped_partition_ids(pit_data)?;

        // 1. Match each image to a PIT entry
        let mut candidates = Vec::with_capacity(self.images.len());
        for (index, planned) in self.images.iter().enumerate() {
            let pit_entry = match &planned.target {
                Target::File(name) => match pit_data.find_entry_by_flash_filename(name) {
                    Some(entry) => entry,
                    None if planned.is_standalone() => {
                        return Err(FlashError::PartitionNotFound(planned.display_name.clone()));
                    }
                    None => {
                        if report {
                            progress::println(&format!(
                                "Skipping orphan file \"{}\" (no matching partition in PIT)",
                                planned.display_name
                            ));
                        }
                        continue;
                    }
                },
                Target::Partition(name) => pit_data
                    .find_entry_by_name(name)
                    .ok_or_else(|| FlashError::PartitionNotFound(name.clone()))?,
                Target::PartitionId(id) => pit_data
                    .find_entry_by_id(*id)
                    .ok_or(FlashError::PartitionIdNotFound(*id))?,
            };
            candidates.push((pit_entry, index));
        }

        // 2. Partition deduplication: last writer wins
        let mut mapped_partition_ids = HashSet::new();
        let mut unique_candidates = Vec::new();
        for candidate in candidates.into_iter().rev() {
            if mapped_partition_ids.insert(candidate.0.partition_id) {
                unique_candidates.push(candidate);
            }
        }
        unique_candidates.reverse();

        // 3. Drop partitions excluded with skip targets
        unique_candidates.retain(|(pit_entry, _)| {
            if skipped_ids.contains(&pit_entry.partition_id) {
                if report {
                    progress::println(&format!(
                        "Skipping {} (excluded with --skip)",
                        pit_entry.partition_name.to_string_lossy()
                    ));
                }
                false
            } else {
                true
            }
        });

        // 4. Validate sizes
        let mut resolved = Resolved {
            super_skipped: pit_data
                .entries
                .iter()
                .any(|e| skipped_ids.contains(&e.partition_id) && e.is_super()),
            ..Default::default()
        };
        for (pit_entry, index) in unique_candidates {
            let image = self.images[index].image.clone();
            if !self.options.skip_size_check {
                let partition_size = pit_entry.partition_size();
                if partition_size > 0 && image.uncompressed_size() > partition_size {
                    return Err(FlashError::PartitionTooSmall(
                        pit_entry.partition_name.to_string_lossy().into_owned(),
                    ));
                }
            }
            resolved
                .payloads
                .push(FirmwarePartitionPayload { pit_entry, image });
            resolved.image_indices.push(index);
        }

        self.rewrite_vbmeta_payloads(pit_data, &mut resolved.payloads, report)
            .await?;

        Ok(resolved)
    }

    // Set the requested AVB flags in vbmeta payloads. Like fastboot, the top-level
    // vbmeta is looked up in boot on devices without a vbmeta partition.
    async fn rewrite_vbmeta_payloads(
        &mut self,
        pit_data: &PitData,
        planned_partitions: &mut [FirmwarePartitionPayload<'_>],
        report: bool,
    ) -> Result<(), FlashError> {
        let vbmeta_flags = self.options.vbmeta_flags;
        if vbmeta_flags == 0 {
            return Ok(());
        }

        let has_vbmeta_partition = pit_data.entries.iter().any(|e| e.is_top_level_vbmeta());
        let mut rewritten = false;
        for planned in planned_partitions.iter_mut() {
            let pit_entry = planned.pit_entry;
            let in_footer = if pit_entry.is_vbmeta() {
                false
            } else if !has_vbmeta_partition && pit_entry.is_boot() {
                true
            } else {
                continue;
            };

            let name = pit_entry.partition_name.to_string_lossy();
            let rewrite_err = |e| FlashError::VbmetaRewriteFailed(name.to_string(), e);

            // The patched image is sent uncompressed, bypassing LZ4 passthrough
            let mut data = planned
                .image
                .read_all(&mut self.readers)
                .await
                .map_err(rewrite_err)?;

            let Some(offset) =
                avb::rewrite_vbmeta(&mut data, vbmeta_flags, in_footer).map_err(rewrite_err)?
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
            planned.image = FirmwareImage {
                source: ImageSource::Memory(data),
                lz4_header: None,
            };
            rewritten = true;
        }

        if !rewritten && report {
            progress::println(
                "Warning: no vbmeta image is being flashed, AVB flags left unchanged",
            );
        }

        Ok(())
    }

    /// Determines the super partition size to check against the device. The value
    /// from `super_used_size.txt` takes precedence over inspecting the super image.
    async fn super_used_size(&mut self, resolved: &Resolved<'_>) -> Option<u32> {
        if resolved.super_skipped {
            return None;
        }
        if self.super_used_size.is_some() {
            return self.super_used_size;
        }

        let (payload, &index) = resolved
            .payloads
            .iter()
            .zip(&resolved.image_indices)
            .find(|(payload, _)| payload.pit_entry.is_super())?;
        let planned = &self.images[index];
        if planned.target.is_super() {
            // Already inspected while pre-planning
            return planned.super_used_size;
        }
        payload.image.super_used_size(&mut self.readers).await
    }

    /// Flashes resolved payloads to the device, then ends the session and reboots
    /// as configured.
    async fn flash(
        &mut self,
        session: &mut OdinSession,
        resolved: Resolved<'_>,
        super_used_size: Option<u32>,
    ) -> Result<(), FlashError> {
        let total_bytes: u64 = resolved
            .payloads
            .iter()
            .map(|p| p.image.uncompressed_size())
            .sum();

        session.set_total_bytes(total_bytes).await?;

        if let Some(super_used_size) = super_used_size
            && super_used_size > 0
            && session.bootloader_protocol_version() >= 3
        {
            let check_size = if self.has_download_list || self.readers.packages.is_empty() {
                super_used_size
            } else {
                0
            };
            progress::println("Checking available super partition size...");
            session
                .check_super_size(check_size)
                .await
                .map_err(FlashError::SuperSizeCheckFailed)?;
        }

        for planned in resolved.payloads {
            let name = planned.pit_entry.partition_name.to_string_lossy();
            let partition_size = planned.image.uncompressed_size();

            progress::on_event(FlashEvent::PartitionStart {
                name: &name,
                size: partition_size,
            });

            let res = async {
                let mut reader = planned.image.open(&mut self.readers).await?;
                session.send_partition(&planned, &mut reader).await
            }
            .await;

            if let Err(e) = res {
                progress::on_event(FlashEvent::PartitionFail(&name));
                return Err(FlashError::Odin(e));
            }

            progress::on_event(FlashEvent::PartitionEnd(&name));
        }

        session.end_session().await?;

        match self.options.reboot_mode {
            RebootMode::Normal => {
                session.reboot_device().await?;
            }
            RebootMode::Download => {
                session.reboot_to_download().await?;
            }
            RebootMode::None => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
