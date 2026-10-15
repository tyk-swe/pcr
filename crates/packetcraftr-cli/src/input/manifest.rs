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
