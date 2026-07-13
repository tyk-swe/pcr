// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
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

const REMOVED_OR_BINARY_ROOTS: &[&str] = &["cli", "core", "io", "protocols", "tools"];

#[derive(Clone, Debug)]
struct Token {
    text: String,
    start: usize,
    end: usize,
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_owned());
        }
        return;
    }
    if !path.is_dir() {
        return;
    }

    let mut entries: Vec<_> = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| {
            entry
                .expect("source directory entry should be readable")
                .path()
        })
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
    files.sort();
    files.dedup();
    assert!(!files.is_empty(), "domain {domain} has no Rust source");
    files
}

fn skip_quoted(bytes: &[u8], mut index: usize, quote: u8) -> usize {
    index += 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = (index + 2).min(bytes.len()),
            byte if byte == quote => return index + 1,
            _ => index += 1,
        }
    }
    index
}

fn raw_string_end(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = index;
    if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hash_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'\"') {
        return None;
    }
    let hashes = cursor - hash_start;
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\"'
            && bytes
                .get(cursor + 1..cursor + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn rust_tokens(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            index += 2;
            let mut depth = 1_usize;
            while index < bytes.len() && depth > 0 {
                if bytes.get(index..index + 2) == Some(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes.get(index..index + 2) == Some(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            continue;
        }
        if let Some(end) = raw_string_end(bytes, index) {
            index = end;
            continue;
        }
        if bytes[index] == b'\"' {
            index = skip_quoted(bytes, index, b'\"');
            continue;
        }
        if bytes[index] == b'\'' {
            let looks_like_character =
                bytes.get(index + 1) == Some(&b'\\') || bytes.get(index + 2) == Some(&b'\'');
            if looks_like_character {
                index = skip_quoted(bytes, index, b'\'');
                continue;
            }
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(Token {
                text: source[start..index].to_owned(),
                start,
                end: index,
            });
            continue;
        }

        let start = index;
        if bytes.get(index..index + 2) == Some(b"::") {
            index += 2;
        } else {
            index += 1;
        }
        tokens.push(Token {
            text: source[start..index].to_owned(),
            start,
            end: index,
        });
    }
    tokens
}

fn matching_delimiter(tokens: &[Token], open: usize, left: &str, right: &str) -> Option<usize> {
    let mut depth = 0_usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if token.text == left {
            depth += 1;
        } else if token.text == right {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn exact_test_attribute(tokens: &[Token], index: usize) -> Option<usize> {
    let expected = ["#", "[", "cfg", "(", "test", ")", "]"];
    tokens
        .get(index..index + expected.len())?
        .iter()
        .map(|token| token.text.as_str())
        .eq(expected)
        .then_some(index + expected.len() - 1)
}

fn test_only_ranges(tokens: &[Token]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let Some(attribute_end) = exact_test_attribute(tokens, index) else {
            index += 1;
            continue;
        };

        let start = tokens[index].start;
        let mut item_start = attribute_end + 1;
        while tokens
            .get(item_start)
            .is_some_and(|token| token.text == "#")
            && tokens
                .get(item_start + 1)
                .is_some_and(|token| token.text == "[")
        {
            item_start = matching_delimiter(tokens, item_start + 1, "[", "]")
                .expect("attribute brackets should balance")
                + 1;
        }

        let mut item_end = None;
        for cursor in item_start..tokens.len() {
            match tokens[cursor].text.as_str() {
                ";" => {
                    item_end = Some(cursor);
                    break;
                }
                "{" => {
                    item_end = matching_delimiter(tokens, cursor, "{", "}");
                    break;
                }
                _ => {}
            }
        }
        let item_end = item_end.expect("a cfg(test) item should have a terminator");
        ranges.push((start, tokens[item_end].end));
        index = item_end + 1;
    }
    ranges
}

fn is_test_only(token: &Token, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| token.start >= *start && token.start < *end)
}

fn is_tracked_root(name: &str) -> bool {
    DOMAINS.iter().any(|(domain, _)| *domain == name) || REMOVED_OR_BINARY_ROOTS.contains(&name)
}

fn dependencies(source: &str) -> BTreeSet<String> {
    let tokens = rust_tokens(source);
    let test_ranges = test_only_ranges(&tokens);
    let tokens: Vec<_> = tokens
        .iter()
        .filter(|token| !is_test_only(token, &test_ranges))
        .collect();
    let mut dependencies = BTreeSet::new();

    for index in 0..tokens.len().saturating_sub(2) {
        if !matches!(tokens[index].text.as_str(), "crate" | "packetcraftr")
            || tokens[index + 1].text != "::"
        {
            continue;
        }

        if tokens[index + 2].text != "{" {
            let root = tokens[index + 2].text.as_str();
            if is_tracked_root(root) {
                dependencies.insert(root.to_owned());
            }
            continue;
        }

        let mut depth = 1_usize;
        let mut expects_root = true;
        for token in tokens.iter().skip(index + 3) {
            match token.text.as_str() {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                "," if depth == 1 => expects_root = true,
                root if depth == 1 && expects_root => {
                    if is_tracked_root(root) {
                        dependencies.insert(root.to_owned());
                    }
                    expects_root = false;
                }
                _ => {}
            }
        }
    }

    // Also catch relative escapes such as `super::super::output` and
    // absolute-root paths such as `::output`; otherwise a forbidden edge
    // could evade the canonical `crate::domain` spelling without changing
    // what it depends on.
    for index in 0..tokens.len() {
        if tokens[index].text == "super" {
            let mut cursor = index;
            while tokens
                .get(cursor)
                .is_some_and(|token| token.text == "super")
                && tokens
                    .get(cursor + 1)
                    .is_some_and(|token| token.text == "::")
            {
                cursor += 2;
            }
            if let Some(root) = tokens.get(cursor).map(|token| token.text.as_str())
                && is_tracked_root(root)
            {
                dependencies.insert(root.to_owned());
            }
        } else if tokens[index].text == "::"
            && tokens.get(index.wrapping_sub(1)).is_none_or(|previous| {
                !previous
                    .text
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            })
            && let Some(root) = tokens.get(index + 1).map(|token| token.text.as_str())
            && is_tracked_root(root)
        {
            dependencies.insert(root.to_owned());
        }
    }
    dependencies
}

#[test]
fn production_domains_follow_the_dependency_direction() {
    let root = repository_root();
    let mut violations = Vec::new();

    for (domain, allowed) in DOMAINS {
        for file in domain_files(&root, domain) {
            let source = std::fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
            for dependency in dependencies(&source) {
                if dependency != *domain && !allowed.contains(&dependency.as_str()) {
                    let relative = file.strip_prefix(&root).unwrap_or(&file);
                    violations.push(format!(
                        "{domain} -> {dependency} in {}",
                        relative.display()
                    ));
                }
            }
        }
    }

    violations.sort();
    violations.dedup();
    assert!(
        violations.is_empty(),
        "forbidden production domain dependencies:\n{}",
        violations.join("\n")
    );
}

#[test]
fn library_root_excludes_cli_and_removed_facades() {
    let root = repository_root();
    let source =
        std::fs::read_to_string(root.join("src/lib.rs")).expect("src/lib.rs should be readable");
    let tokens = rust_tokens(&source);
    let test_ranges = test_only_ranges(&tokens);
    let tokens: Vec<_> = tokens
        .iter()
        .filter(|token| !is_test_only(token, &test_ranges))
        .collect();

    let declared_forbidden: BTreeSet<_> = tokens
        .windows(2)
        .filter(|window| window[0].text == "mod")
        .map(|window| window[1].text.as_str())
        .filter(|module| REMOVED_OR_BINARY_ROOTS.contains(module))
        .collect();
    assert!(
        declared_forbidden.is_empty(),
        "the library root must not own CLI or removed facade modules: {declared_forbidden:?}"
    );
    assert!(
        !tokens
            .iter()
            .any(|token| token.text == "run_cli_entrypoint"),
        "the CLI entry point must be owned by the binary"
    );

    let public_modules: BTreeSet<_> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub mod "))
        .filter_map(|line| line.strip_suffix(';'))
        .collect();
    let expected: BTreeSet<_> = DOMAINS.iter().map(|(domain, _)| *domain).collect();
    assert_eq!(
        public_modules, expected,
        "the library root must expose exactly the canonical domain modules"
    );
    assert!(
        !source
            .lines()
            .any(|line| line.trim().starts_with("pub use ")),
        "flat root reexports are forbidden"
    );
}
