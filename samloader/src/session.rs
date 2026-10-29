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

use samloader_odin::{
    OdinConnection, OdinError, OdinSession, RebootMode, UsbBackendOption, create_backend,
};

/// Connects to a device in Download Mode and begins an Odin session.
pub(crate) async fn connect(
    usb_backend: UsbBackendOption,
    wait: bool,
) -> Result<OdinSession, OdinError> {
    let usb = create_backend(usb_backend, wait).await?;
    let mut connection = OdinConnection::new(usb);
    connection.init().await?;
    connection.begin_session().await
}

/// Ends the session and reboots the device as requested.
///
/// The reboot is attempted even if ending the session fails, and the first
/// error is returned.
pub(crate) async fn finish(
    session: &mut OdinSession,
    reboot_mode: RebootMode,
) -> Result<(), OdinError> {
    let ended = session.end_session().await;
    let rebooted = match reboot_mode {
        RebootMode::Normal => session.reboot_device().await,
        RebootMode::Download => session.reboot_to_download().await,
        RebootMode::None => Ok(()),
    };
    ended.and(rebooted)
}
