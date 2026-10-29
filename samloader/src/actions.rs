// Copyright 2026 John "topjohnwu" Wu
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

use crate::progress::CliProgress;
use crate::session::{connect, finish};
use crate::{AlreadyReported, print_error};
use samloader_odin::{
    RebootMode, UsbBackendOption, detect_device,
    futures::{executor::block_on, io::AllowStdIo},
    query_device_info, set_progress, verify_md5_footer,
};
use samloader_pit::PitData;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};

pub(crate) fn action_detect(
    usb_backend: UsbBackendOption,
    wait: bool,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    if !json {
        set_progress(CliProgress::new(false));
    }
    block_on(async {
        if !detect_device(usb_backend, wait).await {
            return Err("Failed to detect compatible download-mode device.".into());
        }

        match query_device_info(usb_backend, false).await {
            Ok(info) => {
                if json {
                    println!("{}", info.to_json());
                } else {
                    println!("Device detected (Download mode)");
                    print!("{}", info);
                }
            }
            Err(_) => {
                if json {
                    println!("{{\"modelName\":\"\",\"serialNumber\":\"\"}}");
                } else {
                    println!("Device detected (Download mode)");
                }
            }
        }
        Ok(())
    })
}

pub(crate) fn action_dump_pit(
    usb_backend: UsbBackendOption,
    output: &str,
    verbose: bool,
    reboot_mode: RebootMode,
    wait: bool,
) -> Result<(), Box<dyn Error>> {
    if output.is_empty() {
        println!("Output file was not specified.\n");
        return Ok(());
    }

    let mut output_file =
        File::create(output).map_err(|_| format!("Failed to open output file \"{}\"", output))?;

    set_progress(CliProgress::new(verbose));

    block_on(async {
        let mut session = connect(usb_backend, wait).await?;

        println!("Downloading device's PIT file");
        let dumped: Result<(), Box<dyn Error>> = async {
            let pit_buffer = session.receive_pit_info().await?;
            output_file
                .write_all(&pit_buffer)
                .map_err(|e| format!("Failed to write PIT data to output file: {}", e))?;
            Ok(())
        }
        .await;

        // End the session and reboot even if the PIT could not be dumped
        let finished = finish(&mut session, reboot_mode).await;
        dumped?;
        Ok(finished?)
    })
}

pub(crate) fn action_print_pit(
    usb_backend: UsbBackendOption,
    file: &str,
    verbose: bool,
    reboot_mode: RebootMode,
    wait: bool,
) -> Result<(), Box<dyn Error>> {
    if !file.is_empty() {
        let mut f = File::open(file).map_err(|_| format!("Failed to open file \"{}\"", file))?;

        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)
            .map_err(|_| format!("Failed to read file \"{}\"", file))?;

        let pit_data = PitData::new(&buffer).map_err(|_| "Failed to unpack PIT file!")?;
        println!("{}", pit_data);
        return Ok(());
    }

    set_progress(CliProgress::new(verbose));

    block_on(async {
        let mut session = connect(usb_backend, wait).await?;

        println!("Downloading device's PIT file");
        let printed: Result<(), Box<dyn Error>> = async {
            let device_pit = session.receive_pit_info().await?;
            let pit_data =
                PitData::new(&device_pit).map_err(|_| "Failed to unpack device's PIT file!")?;
            println!("{}", pit_data);
            Ok(())
        }
        .await;

        // End the session and reboot even if the PIT could not be printed
        let finished = finish(&mut session, reboot_mode).await;
        printed?;
        Ok(finished?)
    })
}

pub(crate) fn action_reboot_download(
    usb_backend: UsbBackendOption,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    set_progress(CliProgress::new(verbose));
    Ok(block_on(samloader_odin::reboot_download(usb_backend))?)
}

pub(crate) fn action_verify_md5(files: &[String]) -> Result<(), Box<dyn Error>> {
    let mut success = true;
    set_progress(CliProgress::new(false));
    block_on(async {
        // Verify every file, reporting each failure as it is found
        for file_path in files {
            let file = match File::open(file_path) {
                Ok(f) => f,
                Err(e) => {
                    print_error!("Failed to open file \"{}\": {}", file_path, e);
                    success = false;
                    continue;
                }
            };

            if let Err(e) = verify_md5_footer(AllowStdIo::new(&file), file_path).await {
                print_error!("MD5 verification failed for \"{}\": {}", file_path, e);
                success = false;
            }
        }
    });
    if success {
        Ok(())
    } else {
        Err(AlreadyReported.into())
    }
}

#[cfg(target_os = "linux")]
const UDEV_RULES_PATH: &str = "/etc/udev/rules.d/60-samloader.rules";

#[cfg(target_os = "linux")]
pub(crate) fn action_fix_usb() -> Result<(), Box<dyn Error>> {
    if unsafe { libc::geteuid() != 0 } {
        return Err("This command must be run as root (e.g., using sudo).".into());
    }

    println!("Writing udev rule to {}...", UDEV_RULES_PATH);
    let rule = "SUBSYSTEM==\"usb\", ATTR{idVendor}==\"04e8\", TAG+=\"uaccess\"\n";
    std::fs::write(UDEV_RULES_PATH, rule)
        .map_err(|e| format!("Failed to write udev rules file: {}", e))?;

    println!("Reloading and triggering udev rules...");
    let status = std::process::Command::new("udevadm")
        .arg("control")
        .arg("--reload-rules")
        .status();
    if !status.is_ok_and(|s| s.success()) {
        return Err("Failed to reload udev rules via udevadm.".into());
    }

    let status = std::process::Command::new("udevadm")
        .arg("trigger")
        .status();
    if !status.is_ok_and(|s| s.success()) {
        return Err("Failed to trigger udev rules via udevadm.".into());
    }

    println!("SUCCESS: USB udev rules successfully configured and reloaded.");
    Ok(())
}
