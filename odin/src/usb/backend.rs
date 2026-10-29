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

//! Selection of the USB backend implementation at runtime.

use super::transport::{UsbBackend, UsbTransfer};
use crate::error::OdinError;

/// Runs `$body` with `$b` bound to the backend type selected by `$option`.
///
/// This is the only place that maps [`UsbBackendOption`] variants to backend
/// types. Prefer passing `$b` to generic functions over calling its methods
/// directly, since inherent methods (e.g. `MockBackend::new`) take precedence
/// over trait methods of the same name.
macro_rules! with_backend {
    ($option:expr, |$b:ident| $body:expr) => {
        match $option {
            #[cfg(feature = "nusb")]
            UsbBackendOption::Nusb => {
                type $b = super::NusbBackend;
                $body
            }
            #[cfg(feature = "rusb")]
            UsbBackendOption::Libusb => {
                type $b = super::RusbBackend;
                $body
            }
            #[cfg(feature = "serialport")]
            UsbBackendOption::Vcom => {
                type $b = super::SerialBackend;
                $body
            }
            #[cfg(mock_backend)]
            UsbBackendOption::Mock => {
                type $b = super::MockBackend;
                $body
            }
        }
    };
}

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
    /// All backend options enabled in this build, in order of preference.
    pub const ALL: &'static [UsbBackendOption] = &[
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb,
        #[cfg(feature = "rusb")]
        UsbBackendOption::Libusb,
        #[cfg(feature = "serialport")]
        UsbBackendOption::Vcom,
        #[cfg(mock_backend)]
        UsbBackendOption::Mock,
    ];

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

    /// Checks whether a device in Download Mode is connected.
    pub(crate) async fn check_device(self) -> Result<(), OdinError> {
        with_backend!(self, |B| B::find_download_device().await.map(drop))
    }

    /// Opens the device in Download Mode.
    pub(crate) async fn create_transfer(self) -> Result<Box<dyn UsbTransfer>, OdinError> {
        with_backend!(self, |B| Ok(Box::new(
            super::open_download_device::<B>().await?
        )))
    }

    /// Opens a Samsung device that is not in Download Mode, skipping devices
    /// that do not expose a usable interface.
    pub(crate) async fn create_normal_mode_transfer(
        self,
    ) -> Result<Box<dyn UsbTransfer>, OdinError> {
        with_backend!(self, |B| Ok(Box::new(
            super::open_normal_mode_device::<B>().await?
        )))
    }
}

impl std::fmt::Display for UsbBackendOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_backends_round_trip() {
        assert!(!UsbBackendOption::ALL.is_empty());
        for backend in UsbBackendOption::ALL {
            let parsed = UsbBackendOption::try_from(backend.to_str()).unwrap();
            assert_eq!(parsed.to_str(), backend.to_str());
        }
    }
}
