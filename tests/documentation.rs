// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug, PartialEq, Eq)]
struct MissingLink {
    source: PathBuf,
    target: String,
    resolved: PathBuf,
}

#[test]
fn repository_relative_markdown_links_resolve() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let documents = repository_markdown_documents(root).unwrap();
    let missing = missing_links(&documents).unwrap();

    assert!(
        missing.is_empty(),
        "missing relative Markdown links:\n{}",
        format_missing_links(root, &missing)
    );
}

#[test]
fn validator_reports_the_source_document_and_missing_target() {
    let temporary = TemporaryDirectory::new("missing-link");
    let docs = temporary.path().join("docs");
    fs::create_dir_all(&docs).unwrap();
    let source = docs.join("guide.md");
    fs::write(&source, "[missing](fixtures/absent.md#example)\n").unwrap();

    let missing = missing_links(&[source]).unwrap();
    let report = format_missing_links(temporary.path(), &missing);

    assert_eq!(missing.len(), 1);
    assert!(report.contains("docs/guide.md"), "{report}");
    assert!(report.contains("fixtures/absent.md#example"), "{report}");
}

fn repository_markdown_documents(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut documents = Vec::new();

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file() && is_markdown(&path) {
            documents.push(path);
        }
    }

    for directory in ["docs", ".github"] {
        collect_markdown_documents(&root.join(directory), &mut documents)?;
    }

    documents.sort();
    documents.dedup();
    Ok(documents)
}

fn collect_markdown_documents(directory: &Path, documents: &mut Vec<PathBuf>) -> io::Result<()> {
    if !directory.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_markdown_documents(&path, documents)?;
        } else if file_type.is_file() && is_markdown(&path) {
            documents.push(path);
        }
    }
    Ok(())
}

fn is_markdown(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
}

fn missing_links(documents: &[PathBuf]) -> io::Result<Vec<MissingLink>> {
    let mut missing = Vec::new();
    for source in documents {
        let markdown = fs::read_to_string(source)?;
        for target in markdown_link_targets(&markdown) {
            let Some(relative) = local_relative_path(&target) else {
                continue;
            };
            let resolved = source
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(relative);
            if !resolved.exists() {
                missing.push(MissingLink {
                    source: source.clone(),
                    target,
                    resolved,
                });
            }
        }
    }
    missing.sort_by(|left, right| {
        (&left.source, &left.target, &left.resolved).cmp(&(
            &right.source,
            &right.target,
            &right.resolved,
        ))
    });
    Ok(missing)
}

fn markdown_link_targets(markdown: &str) -> Vec<String> {
    let mut targets = inline_link_targets(markdown);
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        let Some(label_end) = trimmed.find("]:") else {
            continue;
        };
        if !trimmed.starts_with('[') || trimmed.starts_with("[^") {
            continue;
        }
        let destination = trimmed[label_end + 2..].trim_start();
        if let Some(target) = destination_token(destination) {
            targets.push(target);
        }
    }
    targets
}

fn inline_link_targets(markdown: &str) -> Vec<String> {
    let bytes = markdown.as_bytes();
    let mut targets = Vec::new();
    let mut cursor = 0;

    while cursor + 1 < bytes.len() {
        let Some(offset) = markdown[cursor..].find("](") else {
            break;
        };
        let destination_start = cursor + offset + 2;
        if let Some(target) = destination_token(&markdown[destination_start..]) {
            targets.push(target);
        }
        cursor = destination_start;
    }

    targets
}

fn destination_token(destination: &str) -> Option<String> {
    let destination = destination.trim_start();
    if destination.is_empty() {
        return None;
    }

    if let Some(angle_destination) = destination.strip_prefix('<') {
        let end = angle_destination.find('>')?;
        return Some(unescape_markdown(&angle_destination[..end]));
    }

    let bytes = destination.as_bytes();
    let mut escaped = false;
    let mut nested_parentheses = 0_u32;
    let mut end = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            end = index + 1;
            continue;
        }
        match byte {
            b'\\' => {
                escaped = true;
                end = index + 1;
            }
            b'(' => {
                nested_parentheses += 1;
                end = index + 1;
            }
            b')' if nested_parentheses == 0 => break,
            b')' => {
                nested_parentheses -= 1;
                end = index + 1;
            }
            byte if byte.is_ascii_whitespace() && nested_parentheses == 0 => break,
            _ => end = index + 1,
        }
    }

    (end > 0).then(|| unescape_markdown(&destination[..end]))
}

fn unescape_markdown(value: &str) -> String {
    let mut unescaped = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            if let Some(escaped) = characters.next() {
                unescaped.push(escaped);
            }
        } else {
            unescaped.push(character);
        }
    }
    unescaped
}

fn local_relative_path(target: &str) -> Option<PathBuf> {
    let target = target.trim();
    if target.is_empty()
        || target.starts_with('#')
        || target.starts_with('/')
        || target.starts_with("//")
        || has_uri_scheme(target)
    {
        return None;
    }

    let path_end = target
        .char_indices()
        .find_map(|(index, character)| matches!(character, '#' | '?').then_some(index))
        .unwrap_or(target.len());
    let path = &target[..path_end];
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(percent_decode(path)))
}

fn has_uri_scheme(target: &str) -> bool {
    let Some(colon) = target.find(':') else {
        return false;
    };
    let scheme = &target[..colon];
    !scheme.is_empty()
        && scheme.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')))
        })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn format_missing_links(root: &Path, missing: &[MissingLink]) -> String {
    missing
        .iter()
        .map(|link| {
            let source = link.source.strip_prefix(root).unwrap_or(&link.source);
            let resolved = link.resolved.strip_prefix(root).unwrap_or(&link.resolved);
            format!(
                "{} -> {} (resolved as {})",
                source.display(),
                link.target,
                resolved.display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let identifier = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "packetcraftr-documentation-{label}-{}-{identifier}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
