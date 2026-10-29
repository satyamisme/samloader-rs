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
mod tests {
    use super::*;
    use crate::OdinError;
    use crate::test_util::{
        M3_PIT, Q7MQ_PIT, ab_pit_data, build_tar, find_entry, lz4_compress, mock_session,
    };
    use crate::usb::{MockBackend, MockEvent};

    impl<P: AsyncRead + AsyncSeek + Unpin, I: AsyncRead + AsyncSeek + Unpin> FlashConfig<P, I> {
        /// Pre-plans and executes the flash.
        async fn run(self, session: &mut OdinSession) -> Result<(), FlashError> {
            self.preplan().await?.execute(session).await
        }
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_success() {
        futures::executor::block_on(async {
            let mut session = mock_session(MockBackend::new().with_protocol_version(3)).await;

            let mut blueprint = FlashConfig::new().preplan().await.unwrap();
            blueprint.has_download_list = true;

            assert!(
                blueprint
                    .flash(&mut session, Resolved::default(), Some(27276104))
                    .await
                    .is_ok()
            );
        });
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_rejection() {
        futures::executor::block_on(async {
            let mut session = mock_session(
                MockBackend::new()
                    .with_protocol_version(3)
                    .with_fail_check_super_size(-1),
            )
            .await;

            let mut blueprint = FlashConfig::new().preplan().await.unwrap();
            blueprint.has_download_list = true;

            let res = blueprint
                .flash(&mut session, Resolved::default(), Some(27276104))
                .await;
            assert!(matches!(res, Err(FlashError::SuperSizeCheckFailed(_))));
        });
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_skipped_on_legacy_protocol() {
        futures::executor::block_on(async {
            // Even if fail_check_super_size is set, legacy protocol version 2 must skip opcode 0x6a
            let mut session = mock_session(
                MockBackend::new()
                    .with_protocol_version(2)
                    .with_fail_check_super_size(-1),
            )
            .await;

            let mut blueprint = FlashConfig::new().preplan().await.unwrap();
            blueprint.has_download_list = true;

            assert!(
                blueprint
                    .flash(&mut session, Resolved::default(), Some(27276104))
                    .await
                    .is_ok()
            );
        });
    }

    #[test]
    fn test_download_and_parse_pit_flashes_available_pit() {
        futures::executor::block_on(async {
            let mut session = mock_session(MockBackend::new()).await;

            let local_pit = PitData::new(M3_PIT).unwrap();
            assert_eq!(local_pit.cpu_bl_id.to_string_lossy(), "Mx-MDM");

            session.send_pit_info(M3_PIT).await.unwrap();
            let pit_buffer = session.receive_pit_info().await.unwrap();
            let pit_data = PitData::new(&pit_buffer).unwrap();
            // M3_EUR_OPEN_4G.pit has Mx-MDM, verifying PIT was sent and updated device state
            assert_eq!(pit_data.cpu_bl_id.to_string_lossy(), "Mx-MDM");
        });
    }

    fn skipped_names(targets: &[&str]) -> Result<Vec<String>, FlashError> {
        let pit_data = ab_pit_data();
        let config = FlashConfig::new().skip(targets);
        let skipped_ids = config.options.skipped_partition_ids(&pit_data)?;
        let mut names: Vec<String> = pit_data
            .entries
            .iter()
            .filter(|e| skipped_ids.contains(&e.partition_id))
            .map(|e| e.partition_name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        Ok(names)
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
    fn test_resolve_drops_skipped_partitions() {
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
            let mut blueprint = FlashConfig::new()
                .partitions(partitions)
                .skip(&["boot.img", "VBMETA"])
                .preplan()
                .await
                .unwrap();
            let resolved = blueprint.resolve(&pit_data, true).await.unwrap();

            let names: Vec<String> = resolved
                .payloads
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
                let mut session = mock_session(
                    MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b())
                        .with_protocol_version(3)
                        .with_fail_check_super_size(-1),
                )
                .await;
                FlashConfig::new()
                    .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                    .skip(skip)
                    .run(&mut session)
                    .await
            })
        };

        assert!(matches!(run(&[]), Err(FlashError::SuperSizeCheckFailed(_))));
        assert!(run(&["super.img"]).is_ok());
    }

    fn rewrite_vbmeta(
        pit_data: &PitData,
        partitions: Vec<Cursor<Vec<u8>>>,
        planned: &mut [FirmwarePartitionPayload<'_>],
        verity: bool,
        verification: bool,
    ) -> Result<(), FlashError> {
        futures::executor::block_on(async {
            let mut blueprint = FlashConfig::new()
                .partitions(partitions.into_iter().map(|r| (None, "part", r)))
                .disable_verity(verity)
                .disable_verification(verification)
                .preplan()
                .await
                .unwrap();
            blueprint
                .rewrite_vbmeta_payloads(pit_data, planned, true)
                .await
        })
    }

    fn planned_bytes(
        planned: &FirmwarePartitionPayload<'_>,
        partitions: &[Cursor<Vec<u8>>],
    ) -> Vec<u8> {
        assert!(planned.image.lz4_header.is_none());
        match &planned.image.source {
            ImageSource::Memory(data) => data.clone(),
            ImageSource::Image { index, .. } => partitions[*index].get_ref().clone(),
            ImageSource::Package { .. } => unreachable!(),
        }
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_patches_all_vbmeta() {
        use crate::firmware::avb::tests::{vbmeta_flags, vbmeta_image};

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
                image: FirmwareImage {
                    source: ImageSource::Image { index: 0, size },
                    lz4_header: None,
                },
            },
            FirmwarePartitionPayload {
                pit_entry: find_entry(&pit_data, "VBMETA_B"),
                image: FirmwareImage {
                    source: ImageSource::Image {
                        index: 1,
                        size: lz4_size,
                    },
                    lz4_header: Some(header),
                },
            },
            FirmwarePartitionPayload {
                pit_entry: find_entry(&pit_data, "VBMETA_SYSTEM_A"),
                image: FirmwareImage {
                    source: ImageSource::Image { index: 2, size },
                    lz4_header: None,
                },
            },
            FirmwarePartitionPayload {
                pit_entry: find_entry(&pit_data, "BOOT_A"),
                image: FirmwareImage {
                    source: ImageSource::Image { index: 3, size },
                    lz4_header: None,
                },
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
        let (lz4_bytes, header) = lz4_compress(&crate::firmware::avb::tests::vbmeta_image(0));
        let size = lz4_bytes.len() as u64;
        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "VBMETA_A"),
            image: FirmwareImage {
                source: ImageSource::Image { index: 0, size },
                lz4_header: Some(header),
            },
        }];

        rewrite_vbmeta(
            &pit_data,
            vec![Cursor::new(lz4_bytes)],
            &mut planned,
            false,
            false,
        )
        .unwrap();
        assert!(planned[0].image.lz4_header.is_some());
    }

    #[test]
    fn test_rewrite_vbmeta_payloads_invalid_vbmeta_fails() {
        let pit_data = ab_pit_data();
        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "VBMETA_A"),
            image: FirmwareImage {
                source: ImageSource::Image {
                    index: 0,
                    size: 4096,
                },
                lz4_header: None,
            },
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
        use crate::firmware::avb::tests::vbmeta_flags;

        // M3_EUR_OPEN_4G.pit has no vbmeta partition, so the vbmeta in boot's footer
        // is rewritten. A boot image without an AVB footer is rejected.
        let pit_data = PitData::new(M3_PIT).unwrap();

        let mut boot = vec![0u8; 16 * 1024];
        boot[0x1000..0x1004].copy_from_slice(b"AVB0");
        let footer = boot.len() - 64;
        boot[footer..footer + 4].copy_from_slice(b"AVBf");
        boot[footer + 20..footer + 28].copy_from_slice(&0x1000u64.to_be_bytes());

        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "BOOT"),
            image: FirmwareImage {
                source: ImageSource::Image {
                    index: 0,
                    size: boot.len() as u64,
                },
                lz4_header: None,
            },
        }];
        rewrite_vbmeta(&pit_data, vec![Cursor::new(boot)], &mut planned, true, true).unwrap();
        assert_eq!(vbmeta_flags(&planned_bytes(&planned[0], &[]), 0x1000), 0x3);

        let mut planned = vec![FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "BOOT"),
            image: FirmwareImage {
                source: ImageSource::Image {
                    index: 0,
                    size: 4096,
                },
                lz4_header: None,
            },
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
        let build_package = |vbmeta: &[u8]| {
            let (vbmeta_lz4, _) = lz4_compress(vbmeta);

            build_tar(&[
                ("vbmeta.img.lz4", &vbmeta_lz4),
                ("boot.img", b"DUMMY BOOT IMAGE DATA"),
            ])
        };
        let valid = build_package(&crate::firmware::avb::tests::vbmeta_image(0));
        let invalid = build_package(&[0u8; 4096]);

        let run = |name: &str, tar_bytes: &[u8], verity: bool| {
            futures::executor::block_on(async {
                let mut session = mock_session(MockBackend::with_profile(
                    crate::usb::DeviceProfile::sm_f968b(),
                ))
                .await;
                assert!(session.is_lz4_supported());
                FlashConfig::new()
                    .packages([(name, Cursor::new(tar_bytes))])
                    .disable_verity(verity)
                    .run(&mut session)
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
            let mut session = mock_session(backend).await;

            let res = FlashConfig::new()
                .erase(true)
                .packages([("AP.tar", Cursor::new(truncated))])
                .run(&mut session)
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
            let mut session = mock_session(backend).await;

            let res = FlashConfig::new()
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .skip(&["nonexistent_partition"])
                .run(&mut session)
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

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            let res = FlashConfig::new()
                .pit(Q7MQ_PIT)
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .disable_verity(true)
                .run(&mut session)
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

        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            FlashConfig::new()
                .pit(Q7MQ_PIT)
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .run(&mut session)
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
            let mut session = mock_session(backend).await;

            FlashConfig::new()
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .run(&mut session)
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
            let mut session = mock_session(backend).await;

            let res = FlashConfig::new()
                .pit(b"invalid_pit_bytes")
                .erase(true)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .run(&mut session)
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
        let raw_vbmeta = crate::firmware::avb::tests::vbmeta_image(0);
        let (vbmeta_lz4, _) = lz4_compress(&raw_vbmeta);

        let tar_bytes = build_tar(&[("vbmeta.img.lz4", &vbmeta_lz4)]);

        // 1. With --disable-verity and --disable-verification: sent raw, byte 123 is 0x03
        futures::executor::block_on(async {
            let backend = MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b());
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            FlashConfig::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .disable_verity(true)
                .disable_verification(true)
                .run(&mut session)
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
            let mut session = mock_session(backend).await;

            FlashConfig::new()
                .packages([("AP.tar", Cursor::new(raw_tar.as_slice()))])
                .run(&mut session)
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
            let mut session = mock_session(backend).await;

            FlashConfig::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .run(&mut session)
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

        let collector = Collector::default();
        crate::progress::set_progress(collector.clone());
        let res = futures::executor::block_on(async {
            let mut session = mock_session(MockBackend::new()).await;

            // The plan is checked against the local PIT and then rebuilt against the
            // flashed PIT, but informational messages must only be printed once
            FlashConfig::new()
                .pit(Q7MQ_PIT)
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .skip(&["DTBO"])
                .run(&mut session)
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

    /// Summarizes the images of a blueprint for comparisons.
    fn image_summary<P, I>(
        blueprint: &FlashBlueprint<P, I>,
    ) -> Vec<(String, u64, Option<u64>, Option<u32>)> {
        blueprint
            .images
            .iter()
            .map(|planned| {
                (
                    format!("{:?}", planned.target),
                    planned.image.size(),
                    planned.image.lz4_header.as_ref().map(|h| h.content_size),
                    planned.super_used_size,
                )
            })
            .collect()
    }

    #[test]
    fn test_preplan_is_deterministic_without_device() {
        let (vendor_lz4, _) = lz4_compress(&[0xAB; 4096]);
        let tar_bytes = build_tar(&[("boot.img", b"BOOT"), ("vendor.img.lz4", &vendor_lz4)]);

        let preplan = || {
            futures::executor::block_on(
                FlashConfig::new()
                    .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                    .partitions([
                        (Some("12".to_string()), "a.img", Cursor::new(&b"A"[..])),
                        (Some("BOOT".to_string()), "b.img", Cursor::new(&b"BB"[..])),
                    ])
                    // Skip targets are only resolved against a PIT during execution
                    .skip(&["nonexistent"])
                    .preplan(),
            )
            .unwrap()
        };

        let summary = image_summary(&preplan());
        assert_eq!(summary, image_summary(&preplan()));
        assert_eq!(
            summary,
            [
                ("File(\"boot.img\")".to_string(), 4, None, None),
                (
                    "File(\"vendor.img\")".to_string(),
                    vendor_lz4.len() as u64,
                    Some(4096),
                    None
                ),
                ("PartitionId(12)".to_string(), 1, None, None),
                ("Partition(\"BOOT\")".to_string(), 2, None, None),
            ]
        );
    }

    #[test]
    fn test_preplan_rejects_corrupt_lz4_regardless_of_skip() {
        let tar_bytes = build_tar(&[("boot.img.lz4", &[0xFF; 64]), ("orphan.img.lz4", b"")]);
        let skips: [&[&str]; 3] = [&[], &["boot.img", "orphan.img"], &["BOOT"]];
        for skip in skips {
            let res = futures::executor::block_on(
                FlashConfig::new()
                    .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                    .skip(skip)
                    .preplan(),
            );
            assert!(matches!(res, Err(FlashError::Lz4Header(name, _)) if name == "boot.img.lz4"));
        }

        // A corrupt image is rejected even if it would be overridden by a later one
        let res = futures::executor::block_on(
            FlashConfig::new()
                .partitions([
                    (None, "boot.img.lz4", Cursor::new(&[0xFFu8; 64][..])),
                    (
                        Some("BOOT".to_string()),
                        "boot.img",
                        Cursor::new(&b"BOOT"[..]),
                    ),
                ])
                .preplan(),
        );
        assert!(matches!(res, Err(FlashError::Lz4Header(name, _)) if name == "boot.img.lz4"));
    }

    #[test]
    fn test_preplan_rejects_invalid_inputs() {
        let tar_bytes = build_tar(&[("boot.img", b"BOOT")]);
        let preplan = |config: FlashConfig<Cursor<&[u8]>>| {
            futures::executor::block_on(config.preplan()).map(|_| ())
        };

        let res = preplan(FlashConfig::new().sales_code(Some("TOOLONG")));
        assert!(
            matches!(res, Err(FlashError::Odin(OdinError::InvalidSalesCode(code))) if code == "TOOLONG")
        );

        let res = preplan(
            FlashConfig::new()
                .pit(&b"invalid"[..])
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))]),
        );
        assert!(matches!(res, Err(FlashError::PitUnpackFailed(_))));

        let pit_tar = build_tar(&[("boot.img", b"BOOT"), ("device.pit", b"invalid")]);
        let res =
            preplan(FlashConfig::new().packages([("CSC.tar", Cursor::new(pit_tar.as_slice()))]));
        assert!(matches!(res, Err(FlashError::PitUnpackFailed(_))));

        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut md5_tar = tar_bytes.clone();
        md5_tar.extend_from_slice(b"0123456789abcdef0123456789abcdef  AP.tar\n");
        let res =
            preplan(FlashConfig::new().packages([("AP.tar.md5", Cursor::new(md5_tar.as_slice()))]));
        assert!(
            matches!(res, Err(FlashError::Md5VerificationFailed(name, _)) if name == "AP.tar.md5")
        );
    }

    #[test]
    fn test_preplan_inspects_super_images() {
        let super_img = crate::firmware::lp::tests::build_test_raw_image(&[(2048, 0, 4096)]);
        let expected = crate::firmware::lp::inspect_super_bytes(&super_img);
        assert!(expected.is_some());

        let tar_bytes = build_tar(&[("super.img", &super_img)]);
        let blueprint = futures::executor::block_on(
            FlashConfig::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .partitions([
                    (
                        Some("SUPER".to_string()),
                        "a.img",
                        Cursor::new(&super_img[..]),
                    ),
                    (Some("7".to_string()), "b.img", Cursor::new(&super_img[..])),
                ])
                .preplan(),
        )
        .unwrap();
        let sizes: Vec<_> = blueprint.images.iter().map(|i| i.super_used_size).collect();
        // Partition IDs cannot be identified as super without a PIT
        assert_eq!(sizes, [expected, expected, None]);

        // super_used_size.txt takes precedence over inspecting images
        let tar_bytes = build_tar(&[
            ("meta-data/super_used_size.txt", b"123\n"),
            ("super.img", &super_img),
        ]);
        let blueprint = futures::executor::block_on(
            FlashConfig::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .preplan(),
        )
        .unwrap();
        assert_eq!(blueprint.super_used_size, Some(123));
        assert_eq!(blueprint.images[0].super_used_size, None);
    }

    #[test]
    fn test_super_used_size_inspects_partition_id_targets() {
        let super_img = crate::firmware::lp::tests::build_test_raw_image(&[(2048, 0, 4096)]);
        let pit_data = ab_pit_data();
        let super_id = find_entry(&pit_data, "SUPER").partition_id;

        futures::executor::block_on(async {
            let mut blueprint = FlashConfig::new()
                .partitions([(
                    Some(super_id.to_string()),
                    "super.img",
                    Cursor::new(&super_img[..]),
                )])
                .preplan()
                .await
                .unwrap();
            assert_eq!(blueprint.images[0].super_used_size, None);

            let resolved = blueprint.resolve(&pit_data, true).await.unwrap();
            assert_eq!(
                blueprint.super_used_size(&resolved).await,
                crate::firmware::lp::inspect_super_bytes(&super_img)
            );
        });
    }

    #[test]
    fn test_blueprint_flashes_userdata() {
        let tar_bytes = build_tar(&[("boot.img", b"BOOT"), ("AP/userdata.img", b"DATA")]);
        let listed_tar = build_tar(&[
            ("meta-data/download-list.txt", b"boot.img\n"),
            ("boot.img", b"BOOT"),
            ("userdata.img", b"DATA"),
        ]);
        let boot_tar = build_tar(&[("boot.img", b"BOOT")]);
        let (userdata_lz4, _) = lz4_compress(b"DATA");
        let lz4_tar = build_tar(&[("AP/userdata.img.lz4", &userdata_lz4)]);

        type Partitions<'a> = Vec<(Option<String>, &'a str, Cursor<&'a [u8]>)>;
        let flashes_userdata = |tar: &[u8], partitions: Partitions, skip: &[&str]| {
            futures::executor::block_on(
                FlashConfig::new()
                    .packages([("AP.tar", Cursor::new(tar))])
                    .partitions(partitions)
                    .skip(skip)
                    .preplan(),
            )
            .unwrap()
            .flashes_userdata()
        };
        let data = || Cursor::new(&b"DATA"[..]);

        assert!(flashes_userdata(&tar_bytes, vec![], &[]));
        assert!(!flashes_userdata(&tar_bytes, vec![], &["userdata"]));
        assert!(!flashes_userdata(&tar_bytes, vec![], &[" USERDATA "]));
        assert!(!flashes_userdata(
            &tar_bytes,
            vec![],
            &["out/userdata.img.lz4"]
        ));
        assert!(flashes_userdata(&tar_bytes, vec![], &["boot", "super.img"]));
        assert!(flashes_userdata(&lz4_tar, vec![], &[]));
        assert!(!flashes_userdata(&lz4_tar, vec![], &["userdata.img"]));
        assert!(!flashes_userdata(&listed_tar, vec![], &[]));
        assert!(!flashes_userdata(&boot_tar, vec![], &[]));
        assert!(flashes_userdata(
            &boot_tar,
            vec![(None, "userdata.img", data())],
            &[]
        ));
        assert!(flashes_userdata(
            &boot_tar,
            vec![(Some("USERDATA".to_string()), "data.img", data())],
            &[]
        ));
        assert!(!flashes_userdata(
            &boot_tar,
            vec![(Some("USERDATA".to_string()), "data.img", data())],
            &["userdata"]
        ));
        // Partition IDs cannot be resolved without a PIT
        assert!(!flashes_userdata(
            &boot_tar,
            vec![(Some("42".to_string()), "userdata.img", data())],
            &[]
        ));
    }

    #[test]
    fn test_resolve_last_writer_wins() {
        let bl_tar = build_tar(&[("boot.img", b"FIRST")]);
        let ap_tar = build_tar(&[("boot.img", b"SECOND")]);
        let pit_data = ab_pit_data();
        let boot_name = pit_data
            .find_entry_by_flash_filename("boot.img")
            .unwrap()
            .partition_name
            .to_string_lossy()
            .into_owned();

        futures::executor::block_on(async {
            let packages = || {
                [
                    ("BL.tar", Cursor::new(bl_tar.as_slice())),
                    ("AP.tar", Cursor::new(ap_tar.as_slice())),
                ]
            };

            let mut blueprint = FlashConfig::new()
                .packages(packages())
                .preplan()
                .await
                .unwrap();
            let resolved = blueprint.resolve(&pit_data, true).await.unwrap();
            assert_eq!(resolved.payloads.len(), 1);
            assert!(matches!(
                resolved.payloads[0].image.source,
                ImageSource::Package { index: 1, .. }
            ));

            // Explicit partitions come after packages, so they win
            let mut blueprint = FlashConfig::new()
                .packages(packages())
                .partitions([(
                    Some(boot_name.clone()),
                    "my_boot.img",
                    Cursor::new(&b"MINE"[..]),
                )])
                .preplan()
                .await
                .unwrap();
            let resolved = blueprint.resolve(&pit_data, true).await.unwrap();
            assert_eq!(resolved.payloads.len(), 1);
            assert!(matches!(
                resolved.payloads[0].image.source,
                ImageSource::Image { index: 0, .. }
            ));
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_phase_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}

        let preplan = FlashConfig::new()
            .packages([("AP.tar", Cursor::new(&b""[..]))])
            .preplan();
        assert_send(&preplan);
        let _ = |blueprint: FlashBlueprint, session: &mut OdinSession| {
            assert_send(&blueprint.execute(session));
        };
    }

    #[test]
    fn test_execute_sets_sales_code_after_resolving() {
        let tar_bytes = build_tar(&[("boot.img", b"DUMMY BOOT IMAGE DATA")]);
        let csc = || MockEvent::SalesCode("XAA".to_string());

        let run = |pit: Option<&[u8]>, packages: bool, skip: &[&str]| {
            futures::executor::block_on(async {
                let backend = MockBackend::new();
                let events = backend.event_log();
                let mut session = mock_session(backend).await;

                let mut config = FlashConfig::new()
                    .sales_code(Some("XAA"))
                    .erase(true)
                    .skip(skip);
                if let Some(pit) = pit {
                    config = config.pit(pit);
                }
                let packages = packages.then(|| ("AP.tar", Cursor::new(tar_bytes.as_slice())));
                let res = config.packages(packages).run(&mut session).await;
                let logged = events.lock().unwrap().clone();
                (res, logged)
            })
        };

        // Without a local PIT: after the device PIT is read and resolved
        let (res, logged) = run(None, true, &[]);
        assert!(res.is_ok());
        assert_eq!(
            logged[..3],
            [MockEvent::PitDump, csc(), MockEvent::NandErase]
        );

        // With a local PIT: after the dry run, before anything is written
        let (res, logged) = run(Some(Q7MQ_PIT), true, &[]);
        assert!(res.is_ok());
        assert_eq!(
            logged[..4],
            [
                csc(),
                MockEvent::NandErase,
                MockEvent::PitFlash,
                MockEvent::PitDump
            ]
        );

        // Nothing to flash: first
        let (res, logged) = run(None, false, &[]);
        assert!(res.is_ok());
        assert_eq!(logged, [csc(), MockEvent::NandErase]);

        // Resolving fails: never set
        let (res, logged) = run(None, true, &["nonexistent"]);
        assert!(matches!(res, Err(FlashError::SkipTargetNotFound(_))));
        assert_eq!(logged, [MockEvent::PitDump]);
    }
}
