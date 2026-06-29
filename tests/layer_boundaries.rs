// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};

const LOWER_LAYER_ROOTS: &[&str] = &[
    "src/domain",
    "src/network",
    "src/output",
    "src/rules",
    "src/tools",
];

const REMOVED_ENGINE_CONTRACT_SHIMS: &[&str] = &[
    "src/engine/command.rs",
    "src/engine/event.rs",
    "src/engine/policy.rs",
    "src/engine/request.rs",
    "src/engine/spec.rs",
];

#[test]
fn lower_layers_do_not_import_engine() {
    let mut violations = Vec::new();

    for root in LOWER_LAYER_ROOTS {
        collect_matching_lines(Path::new(root), &mut violations, &|line| {
            line.contains("crate::engine")
        });
    }

    assert!(
        violations.is_empty(),
        "lower layers must not import crate::engine:\n{}",
        violations.join("\n")
    );
}

#[test]
fn engine_does_not_reintroduce_domain_contract_shims() {
    let present = REMOVED_ENGINE_CONTRACT_SHIMS
        .iter()
        .filter(|path| Path::new(path).exists())
        .copied()
        .collect::<Vec<_>>();

    assert!(
        present.is_empty(),
        "engine must not re-export moved domain contracts through shim modules:\n{}",
        present.join("\n")
    );
}

#[test]
fn engine_layer_does_not_re_export_names() {
    let mut violations = Vec::new();
    collect_matching_lines(Path::new("src/engine"), &mut violations, &|line| {
        line.trim_start().starts_with("pub use ")
    });

    assert!(
        violations.is_empty(),
        "engine must expose names from their owning modules instead of re-exporting:\n{}",
        violations.join("\n")
    );
}

fn collect_matching_lines(
    path: &Path,
    violations: &mut Vec<String>,
    is_violation: &impl Fn(&str) -> bool,
) {
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", path.display());
        }) {
            let entry = entry.unwrap_or_else(|err| {
                panic!(
                    "failed to read directory entry under {}: {err}",
                    path.display()
                );
            });
            collect_matching_lines(&entry.path(), violations, is_violation);
        }
        return;
    }

    if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
        return;
    }

    let source = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });

    for (line_index, line) in source.lines().enumerate() {
        if is_violation(line) {
            violations.push(format!(
                "{}:{}: {}",
                display_path(path),
                line_index + 1,
                line.trim()
            ));
        }
    }
}

fn display_path(path: &Path) -> String {
    PathBuf::from(path).display().to_string()
}
