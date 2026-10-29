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

#[cfg(not(any(feature = "rusb", feature = "nusb", feature = "serialport")))]
compile_error!("At least one USB backend must be enabled!");

mod actions;
mod cli;
mod download;
mod flash;
mod progress;
mod session;

use clap::Parser;
use cli::{CheckUpdateArgs, Cli, Command};
use samloader_fus::{FusClient, fetch_version_xml};
use std::error::Error;

#[macro_export]
macro_rules! print_error {
    ($($arg:tt)*) => {
        eprint!("ERROR: ");
        eprintln!($($arg)*);
    };
}

/// An error that has already been reported to the user, so that only the
/// exit status remains to be set.
#[derive(Debug)]
pub(crate) struct AlreadyReported;

impl std::fmt::Display for AlreadyReported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("errors were reported above")
    }
}

impl std::error::Error for AlreadyReported {}

fn check_update(args: CheckUpdateArgs) -> Result<(), Box<dyn Error>> {
    let info = FusClient::new()
        .and_then(|client| client.fetch_history(&args.fus.model, &args.fus.region))
        .or_else(|_| fetch_version_xml(&args.fus.model, &args.fus.region))
        .expect("Failed to fetch version info");

    if args.all {
        println!("Latest Stable Version:");
        println!("{}", info.latest);

        if !info.previous.is_empty() {
            println!();
            println!("Previous Stable Versions (sorted from new to old):");
            for v in &info.previous {
                println!("{}", v);
            }
        }

        if !info.beta.is_empty() {
            println!();
            println!("Beta Versions (sorted from new to old):");
            for v in &info.beta {
                println!("{}", v);
            }
        }
    } else {
        println!("{}", info.latest);
    }
    Ok(())
}

fn main() {
    let Cli {
        verbose,
        usb_backend,
        command,
    } = Cli::parse();

    let result = match command {
        Command::Download(args) => download::action_download(args, verbose),
        Command::CheckUpdate(args) => check_update(args),
        Command::Detect(args) => actions::action_detect(usb_backend, args.wait, args.json),
        Command::DumpPit(args) => actions::action_dump_pit(
            usb_backend,
            &args.output,
            verbose,
            args.odin.reboot_mode(),
            args.odin.wait,
        ),
        Command::PrintPit(args) => actions::action_print_pit(
            usb_backend,
            args.file.as_deref().unwrap_or(""),
            verbose,
            args.odin.reboot_mode(),
            args.odin.wait,
        ),
        Command::Flash(args) => flash::action_flash(args, usb_backend, verbose),
        Command::VerifyMd5(args) => actions::action_verify_md5(&args.files),
        Command::RebootDownload => actions::action_reboot_download(usb_backend, verbose),
        #[cfg(target_os = "linux")]
        Command::FixUsb => actions::action_fix_usb(),
    };

    if let Err(e) = result {
        if !e.is::<AlreadyReported>() {
            print_error!("{}", e);
        }
        std::process::exit(1);
    }
}
