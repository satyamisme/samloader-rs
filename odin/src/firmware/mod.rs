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

//! Parsing and reading of firmware packages and the images inside them.

mod image;
mod lz4;
mod package;

pub(crate) use image::{FirmwareImage, FirmwarePartitionPayload, FirmwareReaders, ImageSource};
#[cfg(test)]
pub(crate) use lz4::Lz4FrameHeader;
pub use package::verify_md5_footer;
pub(crate) use package::{PackageIndex, normalize_basename};

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for &(path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, content).unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }
}
