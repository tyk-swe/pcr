// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use packetcraftr_core::error::Kind;

use super::bounded::{InputKind, read_bounded_file_allow_empty, read_stdin_bounded_allow_empty};
use crate::errors::CliError;

pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_MANIFEST_LINES: usize = 4_096;
pub(crate) const MAX_DECLARATION_BYTES: usize = 512;

const MANIFEST_KIND: InputKind = InputKind::Manifest;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ManifestBounds {
    pub(crate) max_bytes: usize,
    pub(crate) max_lines: usize,
}

impl Default for ManifestBounds {
    fn default() -> Self {
        Self {
            max_bytes: MAX_MANIFEST_BYTES,
            max_lines: MAX_MANIFEST_LINES,
        }
    }
}

impl ManifestBounds {
    pub(crate) fn new(max_bytes: usize, max_lines: usize) -> Result<Self, CliError> {
        if !(1..=MAX_MANIFEST_BYTES).contains(&max_bytes) {
            return Err(CliError::new(
                Kind::Usage,
                format!(
                    "--max-manifest-bytes must be in 1..={MAX_MANIFEST_BYTES}, got {max_bytes}"
                ),
            ));
        }
        if !(1..=MAX_MANIFEST_LINES).contains(&max_lines) {
            return Err(CliError::new(
                Kind::Usage,
                format!(
                    "--max-manifest-lines must be in 1..={MAX_MANIFEST_LINES}, got {max_lines}"
                ),
            ));
        }
        Ok(Self {
            max_bytes,
            max_lines,
        })
    }
}

pub(crate) fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == "-"
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Declaration {
    pub(crate) token: String,
    pub(crate) source: DeclarationSource,
    pub(crate) line: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeclarationSource {
    Argument { position: usize },
    File { path: PathBuf },
    Stdin,
}

impl DeclarationSource {
    pub(crate) fn describe(&self) -> (String, Option<u32>) {
        match self {
            Self::Argument { position } => (format!("argument {position}"), None),
            Self::File { path } => (path.display().to_string(), None),
            Self::Stdin => ("stdin".to_owned(), None),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ManifestSource {
    File(PathBuf),
    Stdin,
}

impl ManifestSource {
    pub(crate) fn open(path: &Path) -> Self {
        if is_stdin(path) {
            Self::Stdin
        } else {
            Self::File(path.to_path_buf())
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Stdin => "stdin".to_owned(),
        }
    }
}

pub(crate) struct ManifestBudget {
    remaining_bytes: usize,
    remaining_lines: usize,
    stdin_used: bool,
}

impl ManifestBounds {
    pub(crate) fn budget(&self) -> ManifestBudget {
        ManifestBudget {
            remaining_bytes: self.max_bytes,
            remaining_lines: self.max_lines,
            stdin_used: false,
        }
    }
}

#[cfg(test)]
pub(crate) fn read(
    sources: &[ManifestSource],
    bounds: ManifestBounds,
) -> Result<Vec<Declaration>, CliError> {
    read_with_budget(sources, &mut bounds.budget())
}

pub(crate) fn read_with_budget(
    sources: &[ManifestSource],
    budget: &mut ManifestBudget,
) -> Result<Vec<Declaration>, CliError> {
    let mut declarations = Vec::new();
    let mut stdin_sources = 0_usize;
    for source in sources {
        if matches!(source, ManifestSource::Stdin) {
            stdin_sources += 1;
        }
    }
    if stdin_sources > 1 {
        return Err(CliError::new(
            Kind::Usage,
            "stdin (`-`) can supply at most one manifest in a group",
        ));
    }
    for source in sources {
        let label = source.describe();
        let bytes = match source {
            ManifestSource::File(path) => {
                read_bounded_file_allow_empty(path, budget.remaining_bytes, MANIFEST_KIND)?
            }
            ManifestSource::Stdin => {
                if budget.stdin_used {
                    return Err(manifest_error(
                        &label,
                        "standard input was already consumed by an earlier manifest",
                        None,
                    ));
                }
                budget.stdin_used = true;
                read_stdin_bounded_allow_empty(budget.remaining_bytes, MANIFEST_KIND)?
            }
        };
        budget.remaining_bytes = budget
            .remaining_bytes
            .checked_sub(bytes.len())
            .ok_or_else(|| manifest_error(&label, "combined manifest byte limit exceeded", None))?;
        let remaining_lines = &mut budget.remaining_lines;
        let text = String::from_utf8(bytes)
            .map_err(|_| manifest_error(&label, "manifest must be UTF-8 text", None))?;
        for (offset, physical) in text.lines().enumerate() {
            if *remaining_lines == 0 {
                return Err(manifest_error(
                    &label,
                    "combined manifest line limit exceeded",
                    None,
                ));
            }
            *remaining_lines -= 1;
            let line = offset as u32 + 1;
            let token = match physical.split_once('#') {
                Some((token, _)) => token,
                None => physical,
            }
            .trim();
            if token.is_empty() {
                continue;
            }
            if token.len() > MAX_DECLARATION_BYTES {
                return Err(manifest_error(
                    &label,
                    &format!("declaration exceeds the {MAX_DECLARATION_BYTES}-byte limit"),
                    Some(line),
                ));
            }
            if token.split_whitespace().nth(1).is_some() {
                return Err(manifest_error(
                    &label,
                    "one declaration per line; extra tokens are rejected",
                    Some(line),
                ));
            }
            let source = match source {
                ManifestSource::File(path) => DeclarationSource::File { path: path.clone() },
                ManifestSource::Stdin => DeclarationSource::Stdin,
            };
            declarations.push(Declaration {
                token: token.to_owned(),
                source,
                line: Some(line),
            });
        }
    }
    Ok(declarations)
}

fn manifest_error(source: &str, message: &str, line: Option<u32>) -> CliError {
    let message = match line {
        Some(line) => format!("{source}:{line}: {message}"),
        None => format!("{source}: {message}"),
    };
    CliError::new(Kind::Usage, message)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write_manifest(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp manifest");
        file.write_all(bytes).expect("write");
        file
    }

    fn read_sources(
        includes: &[&[u8]],
        excludes: &[&[u8]],
        max_bytes: usize,
        max_lines: usize,
    ) -> Result<Vec<Declaration>, CliError> {
        let bounds = ManifestBounds::new(max_bytes, max_lines).expect("bounds");
        let mut budget = bounds.budget();
        let mut files = Vec::new();
        let read_group = |contents: &[&[u8]],
                          files: &mut Vec<tempfile::NamedTempFile>,
                          budget: &mut ManifestBudget| {
            let sources: Vec<ManifestSource> = contents
                .iter()
                .map(|bytes| {
                    files.push(write_manifest(bytes));
                    ManifestSource::File(files.last().expect("manifest").path().to_path_buf())
                })
                .collect();
            read_with_budget(&sources, budget)
        };
        read_group(includes, &mut files, &mut budget)?;
        let declarations = read_group(excludes, &mut files, &mut budget)?;
        Ok(declarations)
    }

    fn read_bytes(bytes: &[u8]) -> Result<Vec<Declaration>, CliError> {
        let file = write_manifest(bytes);
        read(
            &[ManifestSource::File(file.path().to_path_buf())],
            ManifestBounds::default(),
        )
    }

    #[test]
    fn manifests_skip_comments_blanks_and_crlf() {
        let declarations = read_bytes(
            b"# leading comment\r\n192.0.2.1 # trailing comment\n\n\r\n  10.0.0.0/24\t\n",
        )
        .expect("parsed");
        assert_eq!(
            declarations
                .iter()
                .map(|declaration| declaration.token.as_str())
                .collect::<Vec<_>>(),
            ["192.0.2.1", "10.0.0.0/24"]
        );
        assert_eq!(declarations[0].line, Some(2));
        assert_eq!(declarations[1].line, Some(5));
    }

    #[test]
    fn empty_and_comment_only_manifests_yield_no_declarations() {
        for bytes in [b"".as_slice(), b"\n\n# only comments\n".as_slice()] {
            assert!(read_bytes(bytes).expect("empty").is_empty());
        }
    }

    #[test]
    fn non_utf8_manifests_are_rejected() {
        let error = read_bytes(b"192.0.2.1\n\xff\xfe").expect_err("invalid utf-8");
        assert!(error.to_string().contains("UTF-8"));
    }

    #[test]
    fn extra_tokens_on_one_line_are_rejected() {
        let error = read_bytes(b"192.0.2.1 10.0.0.1\n").expect_err("two tokens");
        assert!(error.to_string().contains("extra tokens"), "{error}");
        assert!(error.to_string().contains(":1:"), "{error}");
    }

    #[test]
    fn declarations_over_512_bytes_are_rejected() {
        let long = "a".repeat(513);
        let error = read_bytes(format!("{long}\n").as_bytes()).expect_err("oversized");
        assert!(error.to_string().contains("512"), "{error}");
        let ok = "a".repeat(512);
        assert_eq!(
            read_bytes(format!("{ok}\n").as_bytes())
                .expect("limit")
                .len(),
            1
        );
    }

    #[test]
    fn the_combined_byte_limit_counts_every_manifest() {
        let first = write_manifest(b"a\n");
        let second = write_manifest(b"b\n");
        let bounds = ManifestBounds::new(2, MAX_MANIFEST_LINES).expect("bounds");
        let error = read(
            &[
                ManifestSource::File(first.path().to_path_buf()),
                ManifestSource::File(second.path().to_path_buf()),
            ],
            bounds,
        )
        .expect_err("second file crosses the shared budget");
        assert!(error.to_string().contains("byte limit"), "{error}");
    }

    #[test]
    fn physical_lines_count_blanks_and_comments_toward_the_limit() {
        let bytes = b"#c\n\nx\n".repeat(2);
        let error = {
            let file = write_manifest(&bytes);
            read(
                &[ManifestSource::File(file.path().to_path_buf())],
                ManifestBounds::new(MAX_MANIFEST_BYTES, 5).expect("bounds"),
            )
            .expect_err("six physical lines over the budget of five")
        };
        assert!(error.to_string().contains("line limit"), "{error}");
        let file = write_manifest(&bytes);
        let declarations = read(
            &[ManifestSource::File(file.path().to_path_buf())],
            ManifestBounds::new(MAX_MANIFEST_BYTES, 6).expect("bounds"),
        )
        .expect("exactly the limit");
        assert_eq!(declarations.len(), 2);
    }

    #[test]
    fn bounds_never_exceed_the_hard_ceilings() {
        assert!(ManifestBounds::new(0, 1).is_err());
        assert!(ManifestBounds::new(MAX_MANIFEST_BYTES + 1, 1).is_err());
        assert!(ManifestBounds::new(1, 0).is_err());
        assert!(ManifestBounds::new(1, MAX_MANIFEST_LINES + 1).is_err());
        assert!(ManifestBounds::new(MAX_MANIFEST_BYTES, MAX_MANIFEST_LINES).is_ok());
    }

    #[test]
    fn stdin_paths_are_detected() {
        assert!(is_stdin(Path::new("-")));
        assert!(!is_stdin(Path::new("targets.txt")));
        assert!(matches!(
            ManifestSource::open(Path::new("-")),
            ManifestSource::Stdin
        ));
    }

    #[test]
    fn include_and_exclude_groups_share_one_combined_budget() {
        let group = b"#c\nx\n";
        let error = read_sources(&[group, group], &[group, group], MAX_MANIFEST_BYTES, 7)
            .expect_err("the two groups must share one line budget");
        assert!(error.to_string().contains("line limit"), "{error}");
        let bytes = vec![b'x'; 200];
        let err = read_sources(
            &[&bytes, &bytes],
            &[&bytes, &bytes],
            300,
            MAX_MANIFEST_LINES,
        )
        .expect_err("the two groups must share one byte budget");
        assert!(err.to_string().contains("byte limit"), "{err}");
    }

    #[test]
    fn a_repeated_stdin_in_one_group_is_rejected_before_any_source_opens() {
        let bogus = Path::new("/definitely/missing/manifest.txt");
        let error = read_with_budget(
            &[
                ManifestSource::Stdin,
                ManifestSource::File(bogus.to_path_buf()),
                ManifestSource::Stdin,
            ],
            &mut ManifestBounds::default().budget(),
        )
        .expect_err("two `-` consumers");
        assert!(error.to_string().contains("stdin"), "{error}");
    }

    #[test]
    fn an_empty_manifest_yields_no_declarations() {
        let declarations = read_bytes(b"").expect("empty manifest");
        assert!(declarations.is_empty());
        let declarations = read_bytes(b"\n\n# only comments\n  \n").expect("blank");
        assert!(declarations.is_empty());
    }

    #[test]
    fn malformed_declarations_fail_with_the_physical_line() {
        let error = read_bytes(b"\xff\xfe").expect_err("invalid UTF-8");
        assert!(error.to_string().contains("UTF-8"), "{error}");
        let error = read_bytes(b"one two").expect_err("two tokens");
        assert!(error.to_string().contains("extra tokens"), "{error}");
        let long = vec![b'x'; MAX_DECLARATION_BYTES + 1];
        let error = read_bytes(&long).expect_err("oversized declaration");
        assert!(error.to_string().contains("declaration"), "{error}");
    }
}
