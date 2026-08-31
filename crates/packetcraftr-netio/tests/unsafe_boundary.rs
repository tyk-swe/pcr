// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes paths and counts by hand; the fail-closed lints are for
// library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Enforces the workspace's central safety claim: the workspace lint denies
//! `unsafe_code` everywhere, and the only files permitted to opt out of that
//! denial are the native-API wrappers under
//! `crates/packetcraftr-netio/src/platform/`.
//!
//! Without this test the rule lives only in AGENTS.md and in a comment at this
//! crate's root, so a new opt-out anywhere else would compile silently.
//!
//! This file is scanned along with every other source file, so the attribute
//! spellings it looks for are assembled from fragments rather than written out.

use std::fs;
use std::path::{Path, PathBuf};

/// The one directory whose files may opt out of the `unsafe_code` denial.
const SANCTIONED_DIRECTORY: &str = "crates/packetcraftr-netio/src/platform";

/// The two whitespace-free attribute spellings that re-enable `unsafe`,
/// assembled from fragments so this file does not itself contain either one.
const COMPACT_OPT_OUTS: [&str; 2] = [
    concat!("allow(", "unsafe_code)"),
    concat!("expect(", "unsafe_code"),
];

/// The workspace root, two levels above this crate's manifest.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("crate manifest must sit two levels below the workspace root")
        .to_path_buf()
}

/// Every `.rs` file under `crates/`, as a workspace-relative path.
fn rust_sources() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut pending = vec![root.join("crates")];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("crate directory must be readable") {
            let path = entry.expect("directory entry must be readable").path();
            if path.is_dir() {
                // `target/` holds build output, not sources under review.
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path
                    .strip_prefix(&root)
                    .expect("source must live under the workspace root")
                    .to_path_buf();
                sources.push(relative);
            }
        }
    }
    sources.sort();
    assert!(
        sources.len() > 100,
        "the source walk found only {} files, so it is not seeing the workspace",
        sources.len()
    );
    sources
}

/// Whether a workspace-relative path is one of the sanctioned wrappers.
fn is_sanctioned(path: &Path) -> bool {
    path.starts_with(SANCTIONED_DIRECTORY)
}

/// Whether a source line contains an unsafe opt-out, ignoring Rust whitespace.
fn contains_unsafe_opt_out(line: &str) -> bool {
    let compact: String = line
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    COMPACT_OPT_OUTS
        .iter()
        .any(|opt_out| compact.contains(opt_out))
}

#[test]
fn only_the_platform_wrappers_opt_out_of_the_unsafe_denial() {
    let mut offenders = Vec::new();
    let mut sanctioned = 0usize;
    for path in rust_sources() {
        let contents =
            fs::read_to_string(workspace_root().join(&path)).expect("source must be readable");
        for (index, line) in contents.lines().enumerate() {
            // Prose about the rule is not the rule; only attributes count.
            if line.trim_start().starts_with("//") {
                continue;
            }
            // Catches the inner and outer attribute forms, and any `cfg_attr`
            // that reaches either through a platform predicate.
            if !contains_unsafe_opt_out(line) {
                continue;
            }
            if is_sanctioned(&path) {
                sanctioned += 1;
            } else {
                offenders.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "`unsafe_code` may only be re-enabled under {SANCTIONED_DIRECTORY}, but found:\n{}",
        offenders.join("\n")
    );
    assert!(
        sanctioned > 0,
        "no sanctioned opt-out was found, so this test is no longer checking anything"
    );
}

#[test]
fn unsafe_opt_out_detection_ignores_attribute_whitespace() {
    let opt_out = concat!("#![", "allow", " (", "unsafe_code)]");
    assert!(contains_unsafe_opt_out(opt_out));
}

#[test]
fn the_native_io_crate_denies_unsafe_code_at_its_root() {
    let root = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("crate root must be readable");
    assert!(
        root.contains("#![deny(unsafe_code)]"),
        "the crate root must keep the denial the platform wrappers opt out of"
    );
}
