// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fs;
use std::io::Write;
use std::path::Path;

mod support;
use support::{path_text, run};

#[derive(Debug)]
struct Snippet {
    lang: String,
    content: String,
    negative_code: Option<String>,
}

fn extract_snippets(doc: &str) -> Vec<Snippet> {
    let mut snippets = Vec::new();
    let mut pending_comment: Option<String> = None;
    let mut in_block = false;
    let mut block_lang = String::new();
    let mut block_lines: Vec<&str> = Vec::new();

    for line in doc.lines() {
        let trimmed = line.trim();
        if !in_block {
            if trimmed.starts_with("<!--") && trimmed.contains("negative") {
                pending_comment = Some(trimmed.to_string());
            } else if trimmed.starts_with("```") {
                let lang = trimmed.trim_start_matches('`').trim();
                in_block = true;
                block_lang = lang.to_string();
                block_lines.clear();
            } else if !trimmed.is_empty() {
                pending_comment = None;
            }
        } else if trimmed.starts_with("```") {
            in_block = false;
            let content = block_lines.join("\n");
            let is_v2_schema = is_packet_v2_block(&block_lines);
            if is_v2_schema {
                let negative_code = pending_comment.as_ref().and_then(|c| {
                    if let Some(pos) = c.find("negative:") {
                        let rest = &c[pos + "negative:".len()..];
                        let code = rest.trim().trim_end_matches("-->").trim();
                        if !code.is_empty() {
                            return Some(code.to_string());
                        }
                    }
                    if c.contains("negative") {
                        return Some(String::new());
                    }
                    None
                });
                snippets.push(Snippet {
                    lang: block_lang.clone(),
                    content,
                    negative_code,
                });
            }
            pending_comment = None;
        } else {
            block_lines.push(line);
        }
    }
    snippets
}

fn is_packet_v2_block(lines: &[&str]) -> bool {
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "{" {
            continue;
        }
        if trimmed.starts_with("schema: packetcraftr.packet/v2")
            || trimmed.starts_with("schema: \"packetcraftr.packet/v2\"")
            || trimmed.starts_with("\"schema\": \"packetcraftr.packet/v2\"")
            || trimmed.starts_with("'schema': 'packetcraftr.packet/v2'")
        {
            return true;
        }
        return false;
    }
    false
}

#[test]
fn packet_v2_doc_snippets_build() {
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/packet-v2.md");
    let doc = fs::read_to_string(&doc_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", doc_path.display()));
    let snippets = extract_snippets(&doc);

    assert!(
        !snippets.is_empty(),
        "docs/packet-v2.md must contain packet/v2 snippets to test"
    );

    for (index, snippet) in snippets.iter().enumerate() {
        let suffix = if snippet.lang.eq_ignore_ascii_case("json") {
            ".json"
        } else {
            ".yaml"
        };
        let mut temp_file = tempfile::Builder::new()
            .prefix(&format!("doc_snippet_{index}_"))
            .suffix(suffix)
            .tempfile()
            .expect("temporary file must open");
        temp_file
            .write_all(snippet.content.as_bytes())
            .expect("snippet must write");
        temp_file.flush().expect("snippet must flush");

        let output = run(&[
            "build",
            "--packet-file",
            path_text(temp_file.path()),
            "--output",
            "hex",
        ]);

        if let Some(expected_code) = &snippet.negative_code {
            assert!(
                !output.status.success(),
                "snippet #{} expected to fail but succeeded: stdout={}",
                index,
                String::from_utf8_lossy(&output.stdout)
            );
            if !expected_code.is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stderr.contains(expected_code) || stdout.contains(expected_code),
                    "snippet #{} failed but expected code '{}' was not in output. stderr:\n{}\nstdout:\n{}",
                    index,
                    expected_code,
                    stderr,
                    stdout
                );
            }
        } else {
            assert!(
                output.status.success(),
                "snippet #{} failed: stderr={}\ncontent:\n{}",
                index,
                String::from_utf8_lossy(&output.stderr),
                snippet.content
            );
        }
    }
}
