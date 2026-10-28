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

use crate::PartitionArg;
use crate::print_error;
use indicatif::{ProgressBar, ProgressStyle};
use samloader_odin::{
    FlashEvent, FlashManager, FlashProgress, OdinConnection, RebootMode, UsbBackendOption,
    create_backend,
    futures::{executor::block_on, io::AllowStdIo},
    package_flash_files, set_progress,
};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "{msg}\n[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

pub(crate) struct CliProgress {
    progress_bar: std::sync::Mutex<Option<ProgressBar>>,
    verbose: bool,
}

impl CliProgress {
    pub(crate) fn new(verbose: bool) -> Self {
        Self {
            progress_bar: std::sync::Mutex::new(None),
            verbose,
        }
    }
}

impl FlashProgress for CliProgress {
    fn set_length(&self, len: u64) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.set_length(len);
        }
    }

    fn inc(&self, bytes: u64) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.inc(bytes);
        }
    }

    fn println(&self, msg: &str) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.println(msg);
        } else {
            println!("{}", msg);
        }
    }

    fn println_verbose(&self, msg: &str) {
        if self.verbose {
            self.println(msg);
        }
    }

    fn is_verbose(&self) -> bool {
        self.verbose
    }

    fn eprintln_verbose(&self, msg: &str) {
        if !self.verbose {
            return;
        }
        match &*self.progress_bar.lock().unwrap() {
            Some(pb) => pb.suspend(|| eprintln!("{}", msg)),
            None => eprintln!("{}", msg),
        }
    }

    fn on_event(&self, event: FlashEvent<'_>) {
        match event {
            FlashEvent::PartitionStart { name, size } => {
                let pb = ProgressBar::no_length()
                    .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
                pb.enable_steady_tick(Duration::from_secs(1));
                pb.set_message(format!("Flashing {}", name));
                if size > 0 {
                    pb.set_length(size);
                }
                *self.progress_bar.lock().unwrap() = Some(pb);
            }
            FlashEvent::PartitionEnd(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.set_message(format!("{} flash successful", name));
                    pb.finish();
                    println!();
                }
            }
            FlashEvent::PartitionFail(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.abandon_with_message(format!("{} flash failed", name));
                }
            }
            FlashEvent::Md5Start {
                name,
                size: total_bytes,
            } => {
                let pb = ProgressBar::no_length()
                    .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
                pb.enable_steady_tick(Duration::from_secs(1));
                pb.set_message(format!("Verifying MD5 checksum for {}", name));
                if total_bytes > 0 {
                    pb.set_length(total_bytes);
                }
                *self.progress_bar.lock().unwrap() = Some(pb);
            }
            FlashEvent::Md5End(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.set_message(format!("{} MD5 verification successful", name));
                    pb.finish();
                    println!();
                }
            }
            FlashEvent::Md5Fail(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.abandon_with_message(format!("{} MD5 verification failed", name));
                }
            }
        }
    }
}

// Strips any directory and .lz4 suffix, like the partition matching done when flashing
fn normalize_basename(path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.len().checked_sub(4) {
        Some(stem) if name[stem..].eq_ignore_ascii_case(".lz4") => name[..stem].to_string(),
        _ => name,
    }
}

// Checks whether userdata is flashed before talking to the device, so without its PIT.
// Packages and auto-matched files are checked by file name, and explicit partitions by
// partition name. Partitions given by numeric ID cannot be resolved and are not checked.
fn flashes_userdata(
    package_files: &[String],
    partitions: &[PartitionArg],
    skip: &[String],
) -> bool {
    let is_skipped = |name: &str| {
        skip.iter().any(|target| {
            let target = target.trim();
            target.eq_ignore_ascii_case("USERDATA")
                || normalize_basename(target).eq_ignore_ascii_case(name)
        })
    };

    let mut names = package_files.to_vec();
    for part in partitions {
        names.push(match &part.name {
            Some(name) => name.clone(),
            None => normalize_basename(&part.filename),
        });
    }
    names
        .iter()
        .any(|name| name.to_ascii_lowercase().starts_with("userdata") && !is_skipped(name))
}

// Asks a y/n question on the terminal, declining when stdin is closed
fn confirm(question: &str) -> bool {
    let mut stdin = io::stdin().lock();
    loop {
        print!("{} [y/n] ", question);
        let _ = io::stdout().flush();

        let mut answer = String::new();
        if stdin.read_line(&mut answer).unwrap_or(0) == 0 {
            println!();
            return false;
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => {}
        }
    }
}

pub(crate) struct FlashArgs {
    /// The USB backend used to communicate with the device
    pub(crate) usb_backend: UsbBackendOption,

    /// Whether to enable verbose output
    pub(crate) verbose: bool,

    /// How the device reboots after flashing
    pub(crate) reboot_mode: RebootMode,

    /// Wait until a compatible device is connected
    pub(crate) wait: bool,

    /// Do not verify that files fit in their partitions
    pub(crate) skip_size_check: bool,

    /// Skip MD5 checksum verification of packages
    pub(crate) skip_md5: bool,

    /// Optional: the PIT file to flash to the device
    pub(crate) pit: Option<String>,

    /// TAR packages to flash
    pub(crate) packages: Vec<String>,

    /// Individual partition images to flash
    pub(crate) partitions: Vec<PartitionArg>,

    /// File or partition names to exclude from flashing
    pub(crate) skip: Vec<String>,

    /// Set disable-verity when flashing vbmeta
    pub(crate) disable_verity: bool,

    /// Set disable-verification when flashing vbmeta
    pub(crate) disable_verification: bool,

    /// Optional: CSC code to set on the device
    pub(crate) csc_code: Option<String>,

    /// Perform a NAND erase on USERDATA before flashing
    pub(crate) erase: bool,

    /// Flash userdata without asking for confirmation
    pub(crate) force: bool,
}

pub(crate) fn action_flash(args: FlashArgs) -> i32 {
    match flash(args) {
        Ok(()) => 0,
        Err(e) => {
            print_error!("{}", e);
            1
        }
    }
}

fn flash(args: FlashArgs) -> Result<(), Box<dyn Error>> {
    let FlashArgs {
        usb_backend,
        verbose,
        reboot_mode,
        wait,
        skip_size_check,
        skip_md5,
        pit,
        packages,
        partitions,
        skip,
        disable_verity,
        disable_verification,
        csc_code,
        erase,
        force,
    } = args;

    if !force {
        let mut check_packages = Vec::with_capacity(packages.len());
        for pkg in &packages {
            let file =
                File::open(pkg).map_err(|e| format!("Failed to open file \"{}\": {}", pkg, e))?;
            check_packages.push((pkg.clone(), AllowStdIo::new(file)));
        }

        let package_files = block_on(package_flash_files(&mut check_packages))?;

        if flashes_userdata(&package_files, &partitions, &skip) {
            if !io::stdin().is_terminal() {
                return Err(
                    "Flash list contains userdata, which will wipe the device's data. \
                            Pass --force to flash it without a terminal."
                        .into(),
                );
            }
            if !confirm("Flash list contains userdata. This will wipe the device's data. Continue?")
            {
                return Err("Flashing aborted by user.".into());
            }
        }
    }

    let mut opened_packages = Vec::with_capacity(packages.len());
    for pkg in &packages {
        let file =
            File::open(pkg).map_err(|e| format!("Failed to open file \"{}\": {}", pkg, e))?;
        opened_packages.push((pkg.as_str(), AllowStdIo::new(file)));
    }

    let mut opened_partitions = Vec::with_capacity(partitions.len());
    for p in &partitions {
        let file = File::open(&p.filename)
            .map_err(|e| format!("Failed to open file \"{}\": {}", p.filename, e))?;
        opened_partitions.push((p.name.clone(), p.filename.as_str(), AllowStdIo::new(file)));
    }

    let pit_bytes = match pit {
        Some(pit_path) => Some(
            std::fs::read(&pit_path)
                .map_err(|e| format!("Failed to read file \"{}\": {}", pit_path, e))?,
        ),
        None => None,
    };

    set_progress(CliProgress::new(verbose));

    block_on(async {
        let usb = create_backend(usb_backend, wait).await?;
        let mut connection = OdinConnection::new(usb);
        connection.init().await?;
        let mut session = connection.begin_session().await?;

        let mut flash_manager = FlashManager::new(&mut session)
            .reboot_mode(reboot_mode)
            .skip_size_check(skip_size_check)
            .skip_md5(skip_md5)
            .erase(erase)
            .packages(opened_packages)
            .partitions(opened_partitions)
            .skip(&skip)
            .disable_verity(disable_verity)
            .disable_verification(disable_verification)
            .sales_code(csc_code.as_deref());

        if let Some(buffer) = pit_bytes {
            flash_manager = flash_manager.pit(buffer);
        }

        flash_manager.execute().await?;
        Ok(())
    })
}
