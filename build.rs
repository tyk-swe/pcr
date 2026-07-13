// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=PACKETCRAFTR_BUILD_TARGET={target}");
    }
}
