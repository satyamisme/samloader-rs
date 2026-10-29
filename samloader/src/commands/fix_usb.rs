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

use std::error::Error;

const UDEV_RULES_PATH: &str = "/etc/udev/rules.d/60-samloader.rules";

/// Installs a udev rule that grants users access to Samsung USB devices.
pub(crate) fn run() -> Result<(), Box<dyn Error>> {
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
