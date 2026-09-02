// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Names the native capabilities this build can back, so the crate tests one
//! predicate per capability instead of repeating feature-by-target tables.

use std::env;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let feature = |name: &str| env::var_os(format!("CARGO_FEATURE_{name}")).is_some();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let abi = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    let unix_backend = matches!(os.as_str(), "linux" | "macos");
    let windows = os == "windows";
    let native_route = feature("NATIVE_ROUTE") && (unix_backend || windows);
    let pcap_backend = feature("NATIVE_LAYER2") && unix_backend;
    let npcap_backend = feature("NATIVE_LAYER2") && windows && arch == "x86_64" && abi == "msvc";
    let native_layer2 = pcap_backend || npcap_backend;
    let native_layer3 = feature("NATIVE_LAYER3") && (unix_backend || windows);

    let capabilities = [
        ("native_route", native_route),
        ("native_layer2", native_layer2),
        ("native_layer3", native_layer3),
        ("native_send", native_layer2 || native_layer3),
        ("pcap_backend", pcap_backend),
        ("npcap_backend", npcap_backend),
        (
            "worker_reaper",
            (native_route && os == "linux") || native_layer2,
        ),
    ];
    for (name, enabled) in capabilities {
        println!("cargo::rustc-check-cfg=cfg({name})");
        if enabled {
            println!("cargo::rustc-cfg={name}");
        }
    }
}
