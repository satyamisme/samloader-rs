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

#[cfg(not(any(real_backend, mock_backend)))]
compile_error!("At least one USB backend must be enabled!");

use crate::error::OdinError;
use std::time::Duration;

#[cfg(feature = "rusb")]
use ::rusb::{Context, DeviceHandle, UsbContext};

#[cfg(feature = "serialport")]
use std::io::{Read, Write};

#[allow(unused_macros)]
macro_rules! print_warning {
    ($($arg:tt)*) => {
        crate::progress::eprintln_verbose(&format!("WARNING: {}", format_args!($($arg)*)));
    };
}

#[allow(unused_macros)]
macro_rules! print_verbose {
    ($($arg:tt)*) => {
        crate::progress::eprintln_verbose(&format!($($arg)*));
    };
}

const VID_SAMSUNG: u16 = 0x04E8;
const PID_GALAXY_S: u16 = 0x6601;
const PID_GALAXY_S2: u16 = 0x685D;
const PID_DROID_CHARGE: u16 = 0x68C3;

const SUPPORTED_DEVICES: &[(u16, u16)] = &[
    (VID_SAMSUNG, PID_GALAXY_S),
    (VID_SAMSUNG, PID_GALAXY_S2),
    (VID_SAMSUNG, PID_DROID_CHARGE),
];

#[cfg(any(feature = "nusb", feature = "rusb"))]
const USB_CLASS_CDC_DATA: u8 = 0x0A;

/// Returns whether the VID/PID belongs to a Samsung device that is not in Download Mode.
#[cfg(real_backend)]
fn is_normal_mode_device(vid: u16, pid: u16) -> bool {
    vid == VID_SAMSUNG && !SUPPORTED_DEVICES.contains(&(vid, pid))
}

/// Opens the first device matching `predicate` that the backend can initialize.
///
/// Unlike [`UsbBackend::find_device`], which returns only the first match, this
/// moves on to the next match when a device fails to open, e.g. an unrelated
/// device from the same vendor without a usable CDC data interface.
#[cfg(real_backend)]
async fn open_first_usable<B, P>(predicate: P) -> Result<B, OdinError>
where
    B: UsbBackend,
    P: Fn(u16, u16) -> bool + Sync,
{
    // Errors that only indicate an unsuitable device are replaced by more
    // meaningful errors (e.g. permission denied) from later candidates.
    let mut error = OdinError::DeviceNotFound;
    let mut skip = 0usize;
    loop {
        // `find_device` returns only the first match, so devices are re-enumerated
        // on every attempt and the first `skip` matches are passed over. This
        // assumes a stable enumeration order; hotplug events between attempts
        // can at worst cause a device to be retried or skipped.
        let mut seen = 0usize;
        let mut id = (0u16, 0u16);
        let device = B::find_device(|vid, pid| {
            if predicate(vid, pid) {
                seen += 1;
                if seen > skip {
                    id = (vid, pid);
                    return true;
                }
            }
            false
        })
        .await;

        let device = match device {
            Ok(device) => device,
            Err(OdinError::DeviceNotFound) => return Err(error),
            Err(e) => return Err(e),
        };

        match B::new(device).await {
            Ok(backend) => return Ok(backend),
            Err(e) => {
                print_verbose!("Skipping device {:04X}:{:04X}: {}", id.0, id.1, e);
                if matches!(
                    error,
                    OdinError::DeviceNotFound
                        | OdinError::InterfaceConfigurationNotFound
                        | OdinError::ConfigDescriptorRetrieval
                ) {
                    error = e;
                }
            }
        }
        skip += 1;
    }
}

/// Opens the first usable Samsung device that is not in Download Mode.
#[cfg(real_backend)]
async fn open_normal_mode_device<B: UsbBackend>() -> Result<B, OdinError> {
    match open_first_usable(is_normal_mode_device).await {
        Err(OdinError::DeviceNotFound) => Err(OdinError::NormalModeDeviceNotFound),
        res => res,
    }
}

/// Helper trait representing `Send` on non-WASM targets and unbounded on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

/// Helper trait representing `Send` on non-WASM targets and unbounded on WASM.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// Trait representing a duplex data transport layer for USB or serial communication.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait UsbTransfer: MaybeSend {
    /// Resets the transport connection state and buffers.
    async fn reset(&mut self);
    /// Sends a buffer of data across the transport with a timeout.
    async fn send_data(&mut self, data: &[u8], timeout: i32) -> bool;
    /// Receives data from the transport into a buffer, returning the number of bytes read.
    async fn receive_data(&mut self, data: &mut [u8], timeout: i32) -> i32;
    /// Returns the USB Product descriptor string if available.
    fn product_name(&self) -> Option<&str> {
        None
    }
}

/// Trait representing a backend factory and device locator for USB or serial transports.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait UsbBackend: Sized + UsbTransfer {
    /// The associated device type identifier.
    type UsbDevice: MaybeSend;

    /// Instantiates a new backend session wrapper for a given device.
    async fn new(device: Self::UsbDevice) -> Result<Self, OdinError>;
    /// Searches for a matching connected device based on a predicate.
    async fn find_device<'a, F>(predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a;

    /// Searches for a connected device in Download Mode.
    async fn find_download_device() -> Result<Self::UsbDevice, OdinError> {
        Self::find_device(|vid, pid| SUPPORTED_DEVICES.contains(&(vid, pid))).await
    }
}

#[cfg(feature = "rusb")]
pub use rusb::RusbBackend;

#[cfg(feature = "rusb")]
mod rusb;

#[cfg(feature = "serialport")]
pub use serial::SerialBackend;

#[cfg(feature = "serialport")]
mod serial;

#[cfg(feature = "nusb")]
pub use nusb::NusbBackend;

#[cfg(feature = "nusb")]
mod nusb;

#[cfg(mock_backend)]
#[allow(unused_imports)]
pub use mock::{DeviceProfile, DeviceProfileBuilder, MockBackend, MockEvent};

#[cfg(mock_backend)]
mod mock;

/// Supported USB backend options.
#[derive(Debug, Clone, Copy)]
pub enum UsbBackendOption {
    /// libusb (rusb) backend.
    #[cfg(feature = "rusb")]
    Libusb,
    /// Virtual COM port (serialport) backend.
    #[cfg(feature = "serialport")]
    Vcom,
    /// nusb backend.
    #[cfg(feature = "nusb")]
    Nusb,
    /// Mock backend.
    #[cfg(mock_backend)]
    Mock,
}

impl TryFrom<&str> for UsbBackendOption {
    type Error = OdinError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "rusb")]
            "libusb" => Ok(UsbBackendOption::Libusb),
            #[cfg(feature = "serialport")]
            "vcom" => Ok(UsbBackendOption::Vcom),
            #[cfg(feature = "nusb")]
            "nusb" => Ok(UsbBackendOption::Nusb),
            #[cfg(mock_backend)]
            "mock" => Ok(UsbBackendOption::Mock),
            _ => Err(OdinError::ParseError(format!("Unknown USB backend: {s}"))),
        }
    }
}

impl std::str::FromStr for UsbBackendOption {
    type Err = OdinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl UsbBackendOption {
    /// Returns the string representation of the backend option.
    pub const fn to_str(self) -> &'static str {
        match self {
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => "libusb",
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => "vcom",
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => "nusb",
            #[cfg(mock_backend)]
            UsbBackendOption::Mock => "mock",
        }
    }

    pub(crate) async fn check_device(self) -> Result<(), OdinError> {
        match self {
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => {
                SerialBackend::find_download_device().await?;
                Ok(())
            }
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => {
                NusbBackend::find_download_device().await?;
                Ok(())
            }
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => {
                RusbBackend::find_download_device().await?;
                Ok(())
            }
            #[cfg(mock_backend)]
            UsbBackendOption::Mock => Ok(()),
        }
    }

    async fn create_transfer(self) -> Result<Box<dyn UsbTransfer>, OdinError> {
        match self {
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => {
                let device = SerialBackend::find_download_device().await?;
                let backend = SerialBackend::new(device).await?;
                Ok(Box::new(backend))
            }
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => {
                let device = NusbBackend::find_download_device().await?;
                let backend = NusbBackend::new(device).await?;
                Ok(Box::new(backend))
            }
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => {
                let device = RusbBackend::find_download_device().await?;
                let backend = RusbBackend::new(device).await?;
                Ok(Box::new(backend))
            }
            #[cfg(mock_backend)]
            UsbBackendOption::Mock => {
                let backend = MockBackend::new();
                Ok(Box::new(backend))
            }
        }
    }

    /// Opens a Samsung device that is not in Download Mode, skipping devices
    /// that do not expose a usable interface.
    pub(crate) async fn create_normal_mode_transfer(
        self,
    ) -> Result<Box<dyn UsbTransfer>, OdinError> {
        match self {
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => {
                let backend: SerialBackend = open_normal_mode_device().await?;
                Ok(Box::new(backend))
            }
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => {
                let backend: NusbBackend = open_normal_mode_device().await?;
                Ok(Box::new(backend))
            }
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => {
                let backend: RusbBackend = open_normal_mode_device().await?;
                Ok(Box::new(backend))
            }
            #[cfg(mock_backend)]
            UsbBackendOption::Mock => {
                let backend = MockBackend::new();
                Ok(Box::new(backend))
            }
        }
    }
}

impl std::fmt::Display for UsbBackendOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

async fn poll_device<T, F, Fut>(wait: bool, mut f: F) -> Result<T, OdinError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OdinError>>,
{
    let mut print_wait = false;
    loop {
        match f().await {
            Ok(val) => return Ok(val),
            Err(OdinError::DeviceNotFound) if wait => {
                if !print_wait {
                    crate::progress::println("Waiting for device...");
                    print_wait = true;
                }
                futures_timer::Delay::new(Duration::from_secs(1)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Creates and initializes the requested USB/VCOM communication backend interface.
pub async fn create_backend(
    usb_backend: UsbBackendOption,
    wait: bool,
) -> Result<Box<dyn UsbTransfer>, OdinError> {
    poll_device(wait, || usb_backend.create_transfer()).await
}

/// Helper function to detect a compatible download-mode device on a given backend.
pub async fn detect_device(usb_backend: UsbBackendOption, wait: bool) -> bool {
    poll_device(wait, || usb_backend.check_device())
        .await
        .is_ok()
}

/// Helper function to prompt user pairing for a compatible download-mode device on WASM.
#[cfg(target_arch = "wasm32")]
pub async fn request_device(usb_backend: UsbBackendOption) -> Result<(), OdinError> {
    match usb_backend {
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb => {
            let selectors: Vec<::nusb::DeviceSelector> = SUPPORTED_DEVICES
                .iter()
                .map(|&(vid, pid)| ::nusb::DeviceSelector::all().with_vid_pid(vid, pid))
                .collect();

            ::nusb::request_device(&selectors)
                .await
                .map_err(|e| OdinError::DeviceAccess(Box::new(e)))?
                .ok_or(OdinError::DeviceNotFound)?;
            Ok(())
        }
        #[cfg(mock_backend)]
        UsbBackendOption::Mock => Ok(()),
    }
}

/// Helper function to prompt user pairing for a Samsung device in normal mode
/// on WASM, which is required before calling [`reboot_download`](crate::reboot_download).
///
/// Once the device reboots, it re-enumerates with a Download Mode product ID
/// and must be paired again with [`request_device`].
#[cfg(target_arch = "wasm32")]
pub async fn request_reboot_device(usb_backend: UsbBackendOption) -> Result<(), OdinError> {
    match usb_backend {
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb => {
            // WebUSB matches the class code against both the device class and
            // its interface classes, so this matches the modem interface.
            let selectors = [::nusb::DeviceSelector::all()
                .with_vid(VID_SAMSUNG)
                .with_class(USB_CLASS_CDC_DATA)];

            ::nusb::request_device(&selectors)
                .await
                .map_err(|e| OdinError::DeviceAccess(Box::new(e)))?
                .ok_or(OdinError::DeviceNotFound)?;
            Ok(())
        }
        #[cfg(mock_backend)]
        UsbBackendOption::Mock => Ok(()),
    }
}

#[cfg(all(test, real_backend))]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const PID_NORMAL: u16 = 0x6860;
    const PID_PORTABLE_SSD: u16 = 0x61F5;

    #[derive(Clone, Copy)]
    enum Open {
        Ok,
        NoInterface,
        ClaimFailed,
    }

    type FakeDevice = (u16, u16, Open);

    thread_local! {
        static DEVICES: RefCell<Vec<FakeDevice>> = const { RefCell::new(Vec::new()) };
    }

    struct FakeBackend {
        pid: u16,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl UsbTransfer for FakeBackend {
        async fn reset(&mut self) {}
        async fn send_data(&mut self, _data: &[u8], _timeout: i32) -> bool {
            true
        }
        async fn receive_data(&mut self, _data: &mut [u8], _timeout: i32) -> i32 {
            0
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl UsbBackend for FakeBackend {
        type UsbDevice = FakeDevice;

        async fn new(device: Self::UsbDevice) -> Result<Self, OdinError> {
            match device.2 {
                Open::Ok => Ok(Self { pid: device.1 }),
                Open::NoInterface => Err(OdinError::InterfaceConfigurationNotFound),
                Open::ClaimFailed => Err(OdinError::InterfaceClaimFailed),
            }
        }

        async fn find_device<'a, F>(mut predicate: F) -> Result<Self::UsbDevice, OdinError>
        where
            F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
        {
            DEVICES
                .with_borrow(|d| d.iter().copied().find(|&(vid, pid, _)| predicate(vid, pid)))
                .ok_or(OdinError::DeviceNotFound)
        }
    }

    fn open_normal_mode(devices: &[FakeDevice]) -> Result<FakeBackend, OdinError> {
        DEVICES.set(devices.to_vec());
        futures::executor::block_on(open_normal_mode_device())
    }

    #[test]
    fn test_normal_mode_skips_download_mode_and_unusable_devices() {
        let backend = open_normal_mode(&[
            (VID_SAMSUNG, PID_GALAXY_S2, Open::Ok),
            (VID_SAMSUNG, PID_PORTABLE_SSD, Open::NoInterface),
            (0x18D1, 0x4EE7, Open::Ok),
            (VID_SAMSUNG, PID_NORMAL, Open::Ok),
        ])
        .unwrap();
        assert_eq!(backend.pid, PID_NORMAL);
    }

    #[test]
    fn test_normal_mode_tries_devices_sharing_vid_pid() {
        let backend = open_normal_mode(&[
            (VID_SAMSUNG, PID_NORMAL, Open::NoInterface),
            (VID_SAMSUNG, PID_NORMAL, Open::Ok),
        ])
        .unwrap();
        assert_eq!(backend.pid, PID_NORMAL);
    }

    #[test]
    fn test_normal_mode_not_found() {
        let res = open_normal_mode(&[(VID_SAMSUNG, PID_GALAXY_S2, Open::Ok)]);
        assert!(matches!(res, Err(OdinError::NormalModeDeviceNotFound)));
    }

    #[test]
    fn test_normal_mode_prefers_meaningful_error() {
        let res = open_normal_mode(&[
            (VID_SAMSUNG, PID_NORMAL, Open::ClaimFailed),
            (VID_SAMSUNG, PID_PORTABLE_SSD, Open::NoInterface),
        ]);
        assert!(matches!(res, Err(OdinError::InterfaceClaimFailed)));

        let res = open_normal_mode(&[(VID_SAMSUNG, PID_PORTABLE_SSD, Open::NoInterface)]);
        assert!(matches!(
            res,
            Err(OdinError::InterfaceConfigurationNotFound)
        ));
    }
}
