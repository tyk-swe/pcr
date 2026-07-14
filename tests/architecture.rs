// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

const DOMAINS: &[(&str, &[&str])] = &[
    ("error", &[]),
    ("capture", &["error"]),
    ("packet", &["capture"]),
    ("protocol", &["packet", "capture"]),
    ("session", &[]),
    ("net", &["packet", "capture", "error"]),
    ("client", &["packet", "protocol", "capture", "net", "error"]),
    (
        "workflow",
        &[
            "client", "packet", "protocol", "capture", "session", "net", "error",
        ],
    ),
    (
        "output",
        &[
            "workflow", "client", "packet", "protocol", "capture", "session", "net", "error",
        ],
    ),
];

const LIBRARY_ROOT_ITEMS: &[&str] = &[
    "pub mod capture;",
    "pub mod client;",
    "pub mod error;",
    "pub mod net;",
    "pub mod output;",
    "pub mod packet;",
    "pub mod protocol;",
    "pub mod session;",
    "pub mod workflow;",
];

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs")
            && path.file_stem().is_none_or(|stem| stem != "tests")
        {
            files.push(path.to_owned());
        }
        return;
    }
    if !path.is_dir() {
        return;
    }

    let mut entries: Vec<_> = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| entry.expect("source entry should be readable").path())
        .collect();
    entries.sort();
    for entry in entries {
        rust_files(&entry, files);
    }
}

fn domain_files(root: &Path, domain: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    rust_files(&root.join("src").join(format!("{domain}.rs")), &mut files);
    rust_files(&root.join("src").join(domain), &mut files);
    files
}

fn mentions_domain(source: &str, domain: &str) -> bool {
    ["crate::", "packetcraftr::", "super::"]
        .iter()
        .any(|prefix| {
            let marker = format!("{prefix}{domain}");
            source.match_indices(&marker).any(|(index, _)| {
                source[index + marker.len()..]
                    .chars()
                    .next()
                    .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
            }) || source
                .match_indices(&format!("{prefix}{{"))
                .any(|(index, marker)| {
                    let group = &source[index + marker.len()..];
                    let mut depth = 0_usize;
                    let mut entry_start = 0_usize;

                    for (offset, character) in group.char_indices() {
                        match character {
                            '{' => depth += 1,
                            '}' if depth == 0 => {
                                return group[entry_start..offset]
                                    .trim_start()
                                    .strip_prefix(domain)
                                    .is_some_and(|suffix| {
                                        suffix.chars().next().is_none_or(|character| {
                                            !character.is_ascii_alphanumeric() && character != '_'
                                        })
                                    });
                            }
                            '}' => depth -= 1,
                            ',' if depth == 0 => {
                                let entry = group[entry_start..offset].trim_start();
                                if entry.strip_prefix(domain).is_some_and(|suffix| {
                                    suffix.chars().next().is_none_or(|character| {
                                        !character.is_ascii_alphanumeric() && character != '_'
                                    })
                                }) {
                                    return true;
                                }
                                entry_start = offset + character.len_utf8();
                            }
                            _ => {}
                        }
                    }
                    false
                })
        })
}

#[test]
fn grouped_imports_mention_their_top_level_domains() {
    assert!(mentions_domain(
        "use crate::{packet, output::Report};",
        "output"
    ));
    assert!(mentions_domain(
        "use packetcraftr::{\n    output as report,\n    packet,\n};",
        "output"
    ));
    assert!(mentions_domain("use super::{output, packet};", "output"));
    assert!(!mentions_domain(
        "use crate::{packet::{output, Packet}};",
        "output"
    ));
    assert!(!mentions_domain(
        "use crate::{output_format, packet};",
        "output"
    ));
}

#[test]
fn production_domains_follow_the_dependency_direction() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    for (domain, allowed) in DOMAINS {
        for file in domain_files(root, domain) {
            let source = std::fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
            let production = source
                .split_once("\n#[cfg(test)]\nmod tests")
                .map_or(source.as_str(), |(production, _)| production);

            for (dependency, _) in DOMAINS {
                if dependency != domain
                    && !allowed.contains(dependency)
                    && mentions_domain(production, dependency)
                {
                    violations.push(format!(
                        "{domain} -> {dependency} in {}",
                        file.strip_prefix(root).unwrap_or(&file).display()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden production domain dependencies:\n{}",
        violations.join("\n")
    );
}

#[test]
fn library_root_contains_only_canonical_modules() {
    let items: Vec<_> = include_str!("../src/lib.rs")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with("#!"))
        .collect();

    assert_eq!(
        items, LIBRARY_ROOT_ITEMS,
        "the library root must expose only the canonical modules; CLI code, removed facades, and \
         flat reexports belong outside it"
    );
}
