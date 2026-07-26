// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Packaging-artifact generation arguments.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Args)]
pub(crate) struct GenerateArgs {
    #[command(subcommand)]
    pub(crate) target: GenerateTarget,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GenerateTarget {
    /// Write a completion script for one shell to standard output.
    Completions {
        #[arg(value_enum)]
        shell: CliShell,
    },
    /// Write one man page per command into a directory.
    Man {
        #[arg(value_name = "DIR")]
        directory: PathBuf,
    },
}

/// Shells this build can emit completion scripts for.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliShell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}
