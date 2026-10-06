// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::path::{Path, PathBuf};

use packetcraftr_core::error::Kind;

use super::bounded::{InputKind, read_file_capped, read_stdin_capped};
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

    pub(crate) fn budget(self) -> ManifestBudget {
        ManifestBudget {
            bounds: self,
            remaining_bytes: self.max_bytes,
            remaining_lines: self.max_lines,
            stdin_used: false,
        }
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

/// Renders the declaration's position, `source` or `source:line`.
impl fmt::Display for Declaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(formatter, "{}:{line}", self.source),
            None => self.source.fmt(formatter),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeclarationSource {
    Argument { position: usize },
    File { path: PathBuf },
    Stdin,
}

impl fmt::Display for DeclarationSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument { position } => write!(formatter, "argument {position}"),
            Self::File { path } => path.display().fmt(formatter),
            Self::Stdin => formatter.write_str("stdin"),
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

    fn declaration_source(&self) -> DeclarationSource {
        match self {
            Self::File(path) => DeclarationSource::File { path: path.clone() },
            Self::Stdin => DeclarationSource::Stdin,
        }
    }
}

/// The byte and physical-line allowance every manifest of one operation draws from.
pub(crate) struct ManifestBudget {
    bounds: ManifestBounds,
    remaining_bytes: usize,
    remaining_lines: usize,
    stdin_used: bool,
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
    let stdin_sources = sources
        .iter()
        .filter(|source| matches!(source, ManifestSource::Stdin))
        .count();
    if stdin_sources > 1 {
        return Err(CliError::new(
            Kind::Usage,
            "stdin (`-`) can supply at most one manifest in a group",
        ));
    }
    let mut declarations = Vec::new();
    for source in sources {
        let source_name = source.declaration_source();
        let bytes = match source {
            ManifestSource::File(path) => {
                read_file_capped(path, budget.remaining_bytes, MANIFEST_KIND)?
            }
            ManifestSource::Stdin => {
                if budget.stdin_used {
                    return Err(manifest_error(
                        &source_name,
                        None,
                        "standard input was already consumed by an earlier manifest",
                    ));
                }
                budget.stdin_used = true;
                read_stdin_capped(budget.remaining_bytes, MANIFEST_KIND)?
            }
        };
        if bytes.len() > budget.remaining_bytes {
            return Err(manifest_error(
                &source_name,
                Some(line_at(&bytes, budget.remaining_bytes)),
                &format!(
                    "combined manifest byte limit of {} exceeded",
                    budget.bounds.max_bytes
                ),
            ));
        }
        budget.remaining_bytes -= bytes.len();
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            manifest_error(
                &source_name,
                Some(line_at(&bytes, error.valid_up_to())),
                "manifest must be UTF-8 text",
            )
        })?;
        for (line, physical) in (1_u32..).zip(text.lines()) {
            if budget.remaining_lines == 0 {
                return Err(manifest_error(
                    &source_name,
                    Some(line),
                    &format!(
                        "combined manifest line limit of {} exceeded",
                        budget.bounds.max_lines
                    ),
                ));
            }
            budget.remaining_lines -= 1;
            let token = physical
                .split_once('#')
                .map_or(physical, |(token, _)| token)
                .trim();
            if token.is_empty() {
                continue;
            }
            if token.len() > MAX_DECLARATION_BYTES {
                return Err(manifest_error(
                    &source_name,
                    Some(line),
                    &format!("declaration exceeds the {MAX_DECLARATION_BYTES}-byte limit"),
                ));
            }
            if token.split_whitespace().nth(1).is_some() {
                return Err(manifest_error(
                    &source_name,
                    Some(line),
                    "one declaration per line; extra tokens are rejected",
                ));
            }
            declarations.push(Declaration {
                token: token.to_owned(),
                source: source_name.clone(),
                line: Some(line),
            });
        }
    }
    Ok(declarations)
}

/// The 1-based physical line holding byte `offset`.
fn line_at(bytes: &[u8], offset: usize) -> u32 {
    let newlines = bytes[..offset.min(bytes.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count();
    // The byte budget (at most 1 MiB) bounds the line count well inside u32.
    u32::try_from(newlines).map_or(u32::MAX, |newlines| newlines.saturating_add(1))
}

fn manifest_error(source: &DeclarationSource, line: Option<u32>, message: &str) -> CliError {
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

    fn source(file: &tempfile::NamedTempFile) -> ManifestSource {
        ManifestSource::File(file.path().to_path_buf())
    }

    fn read_bytes(bytes: &[u8], bounds: ManifestBounds) -> Result<Vec<Declaration>, CliError> {
        let file = write_manifest(bytes);
        read(&[source(&file)], bounds)
    }

    fn rejection(bytes: &[u8], bounds: ManifestBounds) -> (String, String) {
        let file = write_manifest(bytes);
        let error = read(&[source(&file)], bounds).expect_err("rejected manifest");
        (file.path().display().to_string(), error.message)
    }

    #[test]
    fn manifests_skip_comments_blanks_and_crlf() {
        let declarations = read_bytes(
            b"# leading comment\r\n192.0.2.1 # trailing comment\n\n\r\n  10.0.0.0/24\t\n",
            ManifestBounds::default(),
        )
        .expect("parsed");
        assert_eq!(
            declarations
                .iter()
                .map(|declaration| (declaration.token.as_str(), declaration.line))
                .collect::<Vec<_>>(),
            [("192.0.2.1", Some(2)), ("10.0.0.0/24", Some(5))]
        );
    }

    #[test]
    fn empty_and_comment_only_manifests_yield_no_declarations() {
        for bytes in [b"".as_slice(), b"\n\n# only comments\n  \n".as_slice()] {
            assert!(
                read_bytes(bytes, ManifestBounds::default())
                    .expect("empty")
                    .is_empty()
            );
        }
    }

    #[test]
    fn malformed_declarations_name_their_source_and_line() {
        let oversized = format!("192.0.2.1\n\n{}\n", "a".repeat(MAX_DECLARATION_BYTES + 1));
        let cases: [(&[u8], &str, &str); 3] = [
            (b"192.0.2.1\n\xff\xfe", ":2:", "UTF-8"),
            (b"# header\n192.0.2.1 10.0.0.1\n", ":2:", "extra tokens"),
            (oversized.as_bytes(), ":3:", "512-byte"),
        ];
        for (bytes, line, reason) in cases {
            let (path, message) = rejection(bytes, ManifestBounds::default());
            assert!(message.starts_with(&format!("{path}{line} ")), "{message}");
            assert!(message.contains(reason), "{message}");
        }
        let exact = "a".repeat(MAX_DECLARATION_BYTES);
        assert_eq!(
            read_bytes(exact.as_bytes(), ManifestBounds::default())
                .expect("a declaration at the bound")
                .len(),
            1
        );
    }

    #[test]
    fn oversized_input_names_the_line_that_crosses_the_byte_limit() {
        let bounds = ManifestBounds::new(12, MAX_MANIFEST_LINES).expect("bounds");
        let (path, message) = rejection(b"192.0.2.1\n192.0.2.2\n", bounds);
        assert_eq!(
            message,
            format!("{path}:2: combined manifest byte limit of 12 exceeded")
        );
        assert_eq!(
            read_bytes(b"192.0.2.1\n12", bounds)
                .expect("exactly the limit")
                .len(),
            2
        );
    }

    #[test]
    fn physical_lines_count_blanks_and_comments_toward_the_limit() {
        let bytes = b"#c\n\nx\n".repeat(2);
        let bounds = |lines| ManifestBounds::new(MAX_MANIFEST_BYTES, lines).expect("bounds");
        let (path, message) = rejection(&bytes, bounds(5));
        assert_eq!(
            message,
            format!("{path}:6: combined manifest line limit of 5 exceeded")
        );
        assert_eq!(
            read_bytes(&bytes, bounds(6))
                .expect("exactly the limit")
                .len(),
            2
        );
    }

    #[test]
    fn every_manifest_draws_from_one_shared_budget() {
        let first = write_manifest(b"a\n");
        let second = write_manifest(b"b\n");
        let bounds = ManifestBounds::new(3, MAX_MANIFEST_LINES).expect("bounds");
        let error = read(&[source(&first), source(&second)], bounds)
            .expect_err("the second file crosses the shared byte budget");
        assert_eq!(
            error.message,
            format!(
                "{}:1: combined manifest byte limit of 3 exceeded",
                second.path().display()
            )
        );

        let group = [write_manifest(b"#c\nx\n"), write_manifest(b"#c\nx\n")];
        let sources = group.iter().map(source).collect::<Vec<_>>();
        let mut budget = ManifestBounds::new(MAX_MANIFEST_BYTES, 7)
            .expect("bounds")
            .budget();
        assert_eq!(
            read_with_budget(&sources, &mut budget)
                .expect("includes")
                .len(),
            2
        );
        let error = read_with_budget(&sources, &mut budget)
            .expect_err("the exclusion group shares the line budget");
        assert!(
            error.message.contains("line limit of 7"),
            "{}",
            error.message
        );
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
        assert!(error.message.contains("stdin"), "{}", error.message);
    }

    #[test]
    fn declarations_render_their_source_and_line() {
        let declaration = |source, line| Declaration {
            token: "192.0.2.1".to_owned(),
            source,
            line,
        };
        assert_eq!(
            declaration(DeclarationSource::Argument { position: 3 }, None).to_string(),
            "argument 3"
        );
        assert_eq!(
            declaration(
                DeclarationSource::File {
                    path: PathBuf::from("targets.txt")
                },
                Some(4)
            )
            .to_string(),
            "targets.txt:4"
        );
        assert_eq!(
            declaration(DeclarationSource::Stdin, Some(1)).to_string(),
            "stdin:1"
        );
    }
}
