// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Selection reads Cargo's target metadata; it never inspects the build host.

use std::env;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let linux = os == "linux";
    let capabilities = [
        ("packetcraftr_test_procfs", linux),
        ("packetcraftr_test_util_linux", linux),
        ("packetcraftr_test_dev_full", linux),
        ("packetcraftr_test_non_utf8_paths", linux),
    ];
    for (name, enabled) in capabilities {
        println!("cargo::rustc-check-cfg=cfg({name})");
        if enabled {
            println!("cargo::rustc-cfg={name}");
        }
    }
}
