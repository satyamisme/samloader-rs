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

use std::env;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    // `PROFILE` is "debug" for the dev profile and any profile inheriting from it.
    // Cargo discourages it in favor of e.g. `CARGO_CFG_DEBUG_ASSERTIONS`, but
    // the mock backend is intentionally tied to the profile, not its settings.
    let debug_build = env::var("PROFILE").is_ok_and(|p| p == "debug");
    let mock_feature = env::var_os("CARGO_FEATURE_MOCK").is_some();

    // The mock backend is always available in debug builds. Must match the
    // definition in samloader-odin's build script.
    println!("cargo::rustc-check-cfg=cfg(mock_backend)");
    if mock_feature || debug_build {
        println!("cargo::rustc-cfg=mock_backend");
    }
}
