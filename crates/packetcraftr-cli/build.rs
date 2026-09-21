// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Names the target facilities the process-level test contracts exercise, so
//! each test gates on the capability it needs instead of a bare target OS.
//! Selection reads Cargo's target metadata; it never inspects the build host.

use std::env;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Process tests require target facilities: procfs/signals for cancellation,
    // util-linux `script` for PTYs, and `/dev/full` for write failures. Enable
    // capability cfgs here; enabled tests require the facility at runtime.
    let linux = os == "linux";
    let capabilities = [
        ("packetcraftr_test_procfs", linux),
        ("packetcraftr_test_util_linux", linux),
        ("packetcraftr_test_dev_full", linux),
    ];
    for (name, enabled) in capabilities {
        println!("cargo::rustc-check-cfg=cfg({name})");
        if enabled {
            println!("cargo::rustc-cfg={name}");
        }
    }
}
