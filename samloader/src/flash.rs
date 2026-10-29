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
use crate::progress::CliProgress;
use crate::session::connect;
use samloader_odin::{
    FlashConfig, RebootMode, UsbBackendOption,
    futures::{executor::block_on, io::AllowStdIo},
    set_progress,
};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Write};

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

    let opened_packages = packages
        .iter()
        .map(|pkg| Ok((pkg.clone(), open(pkg)?)))
        .collect::<Result<Vec<_>, String>>()?;

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

    // Validate and index the inputs before connecting to the device
    set_progress(CliProgress::new(verbose));
    let blueprint = block_on(config.preplan())?;

    if !force && blueprint.flashes_userdata() {
        if !io::stdin().is_terminal() {
            return Err(
                "Flash list contains userdata, which will wipe the device's data. \
                        Pass --force to flash it without a terminal."
                    .into(),
            );
        }
        if !confirm("Flash list contains userdata. This will wipe the device's data. Continue?") {
            return Err("Flashing aborted by user.".into());
        }
    }

    block_on(async {
        let mut session = connect(usb_backend, wait).await?;
        blueprint.execute(&mut session).await?;
        Ok(())
    })
}
