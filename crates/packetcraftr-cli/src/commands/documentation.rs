// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `documentation`: writes shell completions and man pages for the finalized
//! command tree. It publishes no contract output, so startup runs it outside
//! the output pipeline and reports failures on stderr.

pub(crate) mod arguments;
mod rendering;

use std::path::Path;

use packetcraftr_core::error::{Classification, Kind};

use self::arguments::Args;
use crate::errors::CliError;

/// Generates shell completions and man pages from the finalized command tree,
/// so the shipped documentation always describes the binary that produced it.
/// One file lands per supported shell and per command under the directory.
pub(crate) fn run(arguments: &Args) -> Result<(), CliError> {
    let completions = arguments.directory.join("completions");
    let man = arguments.directory.join("man");
    for directory in [&completions, &man] {
        std::fs::create_dir_all(directory).map_err(|error| io_error(directory, error))?;
    }
    rendering::write_completions(&completions).map_err(|error| io_error(&completions, error))?;
    rendering::write_man_pages(&man).map_err(|error| io_error(&man, error))?;
    Ok(())
}

fn io_error(directory: &Path, error: std::io::Error) -> CliError {
    let causes = std::iter::once(error.to_string())
        .chain(packetcraftr_core::error::source_chain(&error))
        .collect();
    CliError::from_classification(
        Classification::new(
            "io.documentation",
            Kind::Io,
            Some("choose a writable documentation directory"),
        ),
        format!(
            "cannot write generated documentation under {}: {error}",
            directory.display()
        ),
        causes,
    )
}
