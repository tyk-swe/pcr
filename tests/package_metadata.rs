// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cargo_metadata(root: &Path) -> Value {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root)
        .output()
        .expect("cargo metadata should start");

    assert!(
        output.status.success(),
        "cargo metadata failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata should emit JSON")
}

#[test]
fn metadata_reports_one_package_and_no_internal_path_dependencies() {
    let metadata = cargo_metadata(&repository_root());
    let packages = metadata["packages"]
        .as_array()
        .expect("metadata packages should be an array");
    let members = metadata["workspace_members"]
        .as_array()
        .expect("metadata workspace_members should be an array");

    assert_eq!(packages.len(), 1, "the repository must contain one package");
    assert_eq!(members.len(), 1, "the repository must contain one member");

    let package = &packages[0];
    assert_eq!(package["name"], "packetcraftr");
    assert_eq!(package["version"], "0.3.0");
    assert_eq!(package["license"], "AGPL-3.0-only");
    assert_eq!(package["rust_version"], "1.96");
    assert_eq!(package["readme"], "README.md");
    assert!(package["publish"].is_null());
    assert_eq!(
        package["features"]["default"],
        serde_json::json!(["native"])
    );
    assert_eq!(
        package["features"]["native"],
        serde_json::json!(["native-route", "native-layer2", "native-layer3"])
    );
    assert_eq!(members[0], package["id"]);

    let path_dependencies: Vec<_> = package["dependencies"]
        .as_array()
        .expect("package dependencies should be an array")
        .iter()
        .filter(|dependency| !dependency["path"].is_null())
        .map(|dependency| {
            dependency["name"]
                .as_str()
                .unwrap_or("<unnamed dependency>")
        })
        .collect();
    assert!(
        path_dependencies.is_empty(),
        "internal path dependencies remain: {path_dependencies:?}"
    );

    let targets = package["targets"]
        .as_array()
        .expect("package targets should be an array");
    for kind in ["lib", "bin"] {
        assert!(
            targets.iter().any(|target| {
                target["name"] == "packetcraftr"
                    && target["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|value| value == kind))
            }),
            "the package must provide its packetcraftr {kind} target"
        );
    }
}

#[test]
fn release_documents_and_immutable_schemas_are_packaged() {
    let root = repository_root();
    for path in [
        "README.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/operator-library-manual.md",
        "docs/migration-output-v1-v2.md",
        "docs/RELEASING.md",
        "schemas/packetcraftr.packet.v1.schema.json",
        "schemas/packetcraftr.output.v2.schema.json",
    ] {
        assert!(
            root.join(path).is_file(),
            "required release file is missing: {path}"
        );
    }
    assert!(
        !root
            .join("schemas/packetcraftr.output.v1.schema.json")
            .exists(),
        "output-v1 schema must not remain in the 0.3 package"
    );
    let schema = std::fs::read_to_string(root.join("schemas/packetcraftr.output.v2.schema.json"))
        .expect("output-v2 schema should be readable");
    assert!(schema.contains("/v0.3.0/schemas/packetcraftr.output.v2.schema.json"));
}

#[test]
fn manifest_and_lockfile_describe_a_single_local_package() {
    let root = repository_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .expect("the root Cargo.toml should be readable");
    assert!(
        manifest.lines().any(|line| line.trim() == "[package]"),
        "the root manifest must be a package manifest"
    );
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim().starts_with("[workspace")),
        "an explicit workspace manifest must not remain"
    );
    for required in [
        "unsafe_op_in_unsafe_fn = \"deny\"",
        "[profile.release]",
        "overflow-checks = true",
    ] {
        assert!(
            manifest.lines().any(|line| line.trim() == required),
            "Cargo.toml must retain the hardening setting {required}"
        );
    }

    let lockfile =
        std::fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock should be readable");
    let local_packages: Vec<_> = lockfile
        .split("[[package]]")
        .filter(|block| block.lines().any(|line| line.starts_with("name = ")))
        .filter(|block| !block.lines().any(|line| line.starts_with("source = ")))
        .collect();
    assert_eq!(
        local_packages.len(),
        1,
        "Cargo.lock must contain exactly one local package"
    );
    assert!(
        local_packages[0]
            .lines()
            .any(|line| line == "name = \"packetcraftr\""),
        "the local lockfile package must be packetcraftr"
    );
}
