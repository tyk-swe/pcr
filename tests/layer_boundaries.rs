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

const DOMAIN_FORBIDDEN_IMPORTS: &[&str] = &[
    "crate::engine",
    "crate::network",
    "crate::output",
    "crate::rules",
    "crate::tools",
    "crate::util",
    "pnet",
    "trust_dns_proto",
    "tokio",
];

const ENGINE_FORBIDDEN_IMPORTS: &[&str] = &[
    "crate::network",
    "crate::output",
    "crate::tools",
    "crate::util",
];

const CLI_FORBIDDEN_IMPORTS: &[&str] = &[
    "crate::engine",
    "crate::output",
    "crate::network",
    "crate::tools",
    "crate::util",
];

const INFRASTRUCTURE_ROOTS: &[&str] = &["src/network", "src/output", "src/rules", "src/tools"];

const INFRASTRUCTURE_FORBIDDEN_IMPORTS: &[&str] = &["crate::engine", "crate::app", "crate::cli"];

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
fn domain_does_not_import_concrete_layers_or_runtime_crates() {
    assert_no_forbidden_imports("src/domain", DOMAIN_FORBIDDEN_IMPORTS);
}

#[test]
fn engine_does_not_import_concrete_infrastructure() {
    assert_no_forbidden_imports("src/engine", ENGINE_FORBIDDEN_IMPORTS);
}

#[test]
fn cli_does_not_import_application_or_infrastructure_layers() {
    assert_no_forbidden_imports("src/cli", CLI_FORBIDDEN_IMPORTS);
}

#[test]
fn infrastructure_layers_do_not_import_orchestration_layers() {
    for root in INFRASTRUCTURE_ROOTS {
        assert_no_forbidden_imports(root, INFRASTRUCTURE_FORBIDDEN_IMPORTS);
    }
}

#[test]
fn library_public_surface_is_deliberately_small() {
    let source = fs::read_to_string("src/lib.rs").expect("failed to read src/lib.rs");
    let public_modules = source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("pub mod ")
                .and_then(|rest| rest.strip_suffix(';'))
        })
        .collect::<Vec<_>>();
    let public_uses = source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("pub use ")
                .and_then(|rest| rest.strip_suffix(';'))
        })
        .collect::<Vec<_>>();

    assert_eq!(public_modules, ["domain", "rules"]);
    assert_eq!(public_uses, ["app::run_cli"]);
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

fn assert_no_forbidden_imports(root: &str, forbidden: &[&str]) {
    let mut violations = Vec::new();
    collect_matching_lines(Path::new(root), &mut violations, &|line| {
        let trimmed = line.trim_start();
        forbidden.iter().any(|needle| {
            trimmed.contains(needle)
                && (trimmed.starts_with("use ")
                    || trimmed.starts_with("pub use ")
                    || trimmed.contains(needle))
        })
    });

    assert!(
        violations.is_empty(),
        "{root} contains forbidden imports:\n{}",
        violations.join("\n")
    );
}

fn display_path(path: &Path) -> String {
    PathBuf::from(path).display().to_string()
}
