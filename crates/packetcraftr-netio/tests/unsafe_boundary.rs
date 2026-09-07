// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Other crates forbid unsafe in the compiler. Netio must allow it in native
//! wrappers, so check only that this exception stays inside `src/platform`.

use std::fs;
use std::path::PathBuf;

#[test]
fn unsafe_exceptions_stay_in_native_wrappers() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path == root.join("platform") {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path).unwrap();
                let attributes: String = source
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .flat_map(str::chars)
                    .filter(|character| !character.is_whitespace())
                    .collect();
                for exception in ["allow(unsafe_code", "expect(unsafe_code"] {
                    assert!(
                        !attributes.contains(exception),
                        "{}: unsafe exception outside platform",
                        path.display()
                    );
                }
            }
        }
    }
}
