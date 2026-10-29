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
    FlashConfig, FlashEvent, FlashProgress, OdinConnection, RebootMode, UsbBackendOption,
    create_backend, flashes_userdata,
    futures::{executor::block_on, io::AllowStdIo},
    package_flash_files, set_progress,
};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Write};
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

// Opens a file for reading by the async flashing pipeline
fn open(path: &str) -> Result<AllowStdIo<File>, String> {
    File::open(path)
        .map(AllowStdIo::new)
        .map_err(|e| format!("Failed to open file \"{}\": {}", path, e))
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

    let mut opened_packages = packages
        .iter()
        .map(|pkg| Ok((pkg.clone(), open(pkg)?)))
        .collect::<Result<Vec<_>, String>>()?;

    if !force {
        let package_files = block_on(package_flash_files(&mut opened_packages))?;

        let names: Vec<&str> = package_files
            .iter()
            .map(String::as_str)
            .chain(
                partitions
                    .iter()
                    .map(|p| p.name.as_deref().unwrap_or(&p.filename)),
            )
            .collect();

        if flashes_userdata(&names, &skip) {
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

    let opened_partitions = partitions
        .iter()
        .map(|p| Ok((p.name.clone(), p.filename.as_str(), open(&p.filename)?)))
        .collect::<Result<Vec<_>, String>>()?;

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

        let mut config = FlashConfig::new()
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
            config = config.pit(buffer);
        }

        config.preplan().await?.execute(&mut session).await?;
        Ok(())
    })
}
