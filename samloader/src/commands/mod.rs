// Copyright 2026 John "topjohnwu" Wu
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

//! The implementation of each subcommand.

pub(crate) mod check_update;
pub(crate) mod detect;
pub(crate) mod download;
#[cfg(target_os = "linux")]
pub(crate) mod fix_usb;
pub(crate) mod flash;
pub(crate) mod md5;
pub(crate) mod pit;
pub(crate) mod reboot;

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
