// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path};

const SOURCE_SIZE_LIMIT_BYTES: u64 = 20 * 1024;
const SOURCE_ROOTS: &[&str] = &["src", "tests", "benches", "fuzz"];
const BASELINE_FILE: &str = "tests/source_size_baseline.txt";
const EXCLUDED_DIRECTORY_NAMES: &[&str] = &[
    ".git",
    "generated",
    "vendor",
    "vendored",
    "third_party",
    "third-party",
];
const EXCLUDED_DIRECTORY_PATHS: &[&str] = &["fuzz/target"];

fn normalize_relative_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|error| {
        format!(
            "failed to make {} relative to {}: {error}",
            path.display(),
            root.display()
        )
    })?;
    let mut segments = Vec::new();

    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(format!(
                "source path contains a non-normal component: {}",
                relative.display()
            ));
        };
        let segment = segment.to_str().ok_or_else(|| {
            format!(
                "source path is not valid UTF-8 and cannot be baselined: {}",
                relative.display()
            )
        })?;
        segments.push(segment);
    }

    Ok(segments.join("/"))
}

fn has_git_marker(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path.join(".git")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "failed to inspect Git metadata under {}: {error}",
            path.display()
        )),
    }
}

fn is_excluded_directory(relative: &str, path: &Path) -> Result<bool, String> {
    let excluded_by_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| EXCLUDED_DIRECTORY_NAMES.contains(&name));
    let excluded_by_path = EXCLUDED_DIRECTORY_PATHS.contains(&relative);

    Ok(excluded_by_name || excluded_by_path || has_git_marker(path)?)
}

fn normalized_source_size(bytes: &[u8]) -> u64 {
    let crlf_count = bytes.windows(2).filter(|pair| *pair == b"\r\n").count();
    u64::try_from(bytes.len() - crlf_count).expect("source size should fit in u64")
}

fn visit_directory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    let relative = normalize_relative_path(root, directory)?;
    if is_excluded_directory(&relative, directory)? {
        return Ok(());
    }

    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("failed to read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "failed to read an entry in {}: {error}",
                directory.display()
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            visit_directory(root, &path, files)?;
            continue;
        }
        if !file_type.is_file() || path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }

        let relative = normalize_relative_path(root, &path)?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let size = normalized_source_size(&bytes);
        if files.insert(relative.clone(), size).is_some() {
            return Err(format!("source path was visited twice: {relative}"));
        }
    }

    Ok(())
}

fn repository_rust_sources(root: &Path) -> Result<BTreeMap<String, u64>, String> {
    let mut files = BTreeMap::new();

    for source_root in SOURCE_ROOTS {
        let directory = root.join(source_root);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "failed to inspect source root {}: {error}",
                    directory.display()
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if !metadata.is_dir() {
            return Err(format!(
                "configured source root is not a directory: {}",
                directory.display()
            ));
        }
        visit_directory(root, &directory, &mut files)?;
    }

    Ok(files)
}

fn validate_baseline_path(path: &str, line_number: usize) -> Result<(), String> {
    if path.contains('\\')
        || path.contains(':')
        || !path.ends_with(".rs")
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!(
            "{BASELINE_FILE}:{line_number}: path must be a normalized, repository-relative \
             Rust path using `/`: {path:?}"
        ));
    }
    if !SOURCE_ROOTS.iter().any(|root| {
        path.strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
    }) {
        return Err(format!(
            "{BASELINE_FILE}:{line_number}: path is outside guarded source roots: {path}"
        ));
    }

    Ok(())
}

fn source_size_baseline(root: &Path) -> Result<BTreeMap<String, u64>, String> {
    let baseline_path = root.join(BASELINE_FILE);
    let contents = fs::read_to_string(&baseline_path)
        .map_err(|error| format!("failed to read {}: {error}", baseline_path.display()))?;
    let mut baseline = BTreeMap::new();
    let mut previous_path: Option<&str> = None;

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (path, permitted) = line.split_once('\t').ok_or_else(|| {
            format!("{BASELINE_FILE}:{line_number}: expected `<path><TAB><maximum-bytes>`")
        })?;
        if permitted.contains('\t') {
            return Err(format!(
                "{BASELINE_FILE}:{line_number}: expected exactly two tab-separated fields"
            ));
        }
        validate_baseline_path(path, line_number)?;

        if previous_path.is_some_and(|previous| previous >= path) {
            return Err(format!(
                "{BASELINE_FILE}:{line_number}: entries must be unique and sorted by path"
            ));
        }
        previous_path = Some(path);

        let permitted = permitted.parse::<u64>().map_err(|error| {
            format!(
                "{BASELINE_FILE}:{line_number}: invalid maximum byte count {permitted:?}: {error}"
            )
        })?;
        if permitted <= SOURCE_SIZE_LIMIT_BYTES {
            return Err(format!(
                "{BASELINE_FILE}:{line_number}: baseline size {permitted} must exceed the \
                 {SOURCE_SIZE_LIMIT_BYTES}-byte source limit; remove this unnecessary exception"
            ));
        }
        baseline.insert(path.to_owned(), permitted);
    }

    Ok(baseline)
}

fn source_size_violations(
    baseline: &BTreeMap<String, u64>,
    sources: &BTreeMap<String, u64>,
) -> BTreeMap<String, String> {
    let mut violations = BTreeMap::new();

    for (path, permitted) in baseline {
        let Some(current) = sources.get(path) else {
            violations.insert(
                path.clone(),
                format!(
                    "- {path}: allowlisted file no longer exists or is excluded; remove its \
                     obsolete entry from {BASELINE_FILE}"
                ),
            );
            continue;
        };

        if *current <= SOURCE_SIZE_LIMIT_BYTES {
            violations.insert(
                path.clone(),
                format!(
                    "- {path}: current size is {current} bytes; normal permitted size is \
                     {SOURCE_SIZE_LIMIT_BYTES} bytes, so remove its obsolete entry from \
                     {BASELINE_FILE}"
                ),
            );
        } else if current != permitted {
            let guidance = if current < permitted {
                format!("lower its stale baseline entry in {BASELINE_FILE} to {current} bytes")
            } else {
                format!(
                    "split the file or obtain repository lead approval before raising its \
                     {BASELINE_FILE} entry"
                )
            };
            violations.insert(
                path.clone(),
                format!(
                    "- {path}: current size is {current} bytes; recorded baseline size is \
                     {permitted} bytes; {guidance}"
                ),
            );
        }
    }

    for (path, current) in sources {
        if !baseline.contains_key(path) && *current > SOURCE_SIZE_LIMIT_BYTES {
            violations.insert(
                path.clone(),
                format!(
                    "- {path}: current size is {current} bytes; permitted size is \
                     {SOURCE_SIZE_LIMIT_BYTES} bytes (20 KiB)"
                ),
            );
        }
    }

    violations
}

#[test]
fn rust_source_files_respect_size_guard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let baseline = source_size_baseline(root)
        .unwrap_or_else(|error| panic!("invalid Rust source-size baseline: {error}"));
    let sources = repository_rust_sources(root)
        .unwrap_or_else(|error| panic!("failed to scan Rust sources: {error}"));
    let violations = source_size_violations(&baseline, &sources);

    assert!(
        violations.is_empty(),
        "Rust source-size guard failed (CRLF is normalized to LF):\n{}\n\n\
         Split each file into focused, canonically named modules. New or increased exceptions \
         require repository lead approval and a manual edit to {BASELINE_FILE}; the test never \
         regenerates it. See `CONTRIBUTING.md` under `Rust source size guard`.",
        violations.into_values().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn files_at_or_below_normal_limit_cannot_keep_baseline_exceptions() {
    let path = "src/example.rs".to_owned();
    let baseline = BTreeMap::from([(path.clone(), SOURCE_SIZE_LIMIT_BYTES + 100)]);

    for current in [SOURCE_SIZE_LIMIT_BYTES - 1, SOURCE_SIZE_LIMIT_BYTES] {
        let sources = BTreeMap::from([(path.clone(), current)]);
        let violations = source_size_violations(&baseline, &sources);
        let violation = violations
            .get(&path)
            .expect("an obsolete baseline entry should be rejected");

        assert!(violation.contains(&format!("current size is {current} bytes")));
        assert!(violation.contains("remove its obsolete entry"));
    }
}

#[test]
fn shrinking_oversized_file_requires_matching_baseline_reduction() {
    let path = "src/example.rs".to_owned();
    let permitted = SOURCE_SIZE_LIMIT_BYTES + 100;
    let current = permitted - 1;
    let baseline = BTreeMap::from([(path.clone(), permitted)]);
    let sources = BTreeMap::from([(path.clone(), current)]);
    let violations = source_size_violations(&baseline, &sources);
    let violation = violations
        .get(&path)
        .expect("a stale oversized-file baseline should be rejected");

    assert!(violation.contains(&format!("current size is {current} bytes")));
    assert!(violation.contains(&format!("recorded baseline size is {permitted} bytes")));
    assert!(violation.contains(&format!("to {current} bytes")));
}

#[test]
fn source_size_normalization_is_platform_stable() {
    assert_eq!(
        normalized_source_size(b"fn main() {\n}\n"),
        normalized_source_size(b"fn main() {\r\n}\r\n")
    );
    assert_eq!(normalized_source_size(b"standalone\rcarriage"), 19);
}
