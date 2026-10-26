// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{CommandFactory, ValueEnum};
use clap_complete::{Generator, Shell};
use packetcraftr_core::error::{Classification, Kind};

use crate::app::cli::Cli;
use crate::errors::CliError;
use crate::invocation::Invocation;
use crate::output::contract::Format;
use crate::output::envelope::source_causes;
use crate::staged_output::StagedFile;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Write `completions/` and `man/` trees under this directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) directory: PathBuf,
}

impl crate::commands::Generate for Args {
    fn generate(self, invocation: &Invocation, format: Format) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::from_classification(
                Classification::new("cli.output_format", Kind::Usage, Some("choose text output")),
                format!("reference documentation does not support {format} output; choose text"),
                Vec::new(),
            ));
        }
        run_with(&self, invocation, render, |_, _| Ok(()))
    }
}

type Rendered = Vec<(PathBuf, Vec<u8>)>;

fn run_with(
    arguments: &Args,
    invocation: &Invocation,
    render: impl FnOnce(&Path) -> Result<Rendered, CliError>,
    mut before: impl FnMut(&'static str, &Path) -> io::Result<()>,
) -> Result<(), CliError> {
    invocation
        .check()
        .map_err(|error| at_operation("render", &arguments.directory, error, &[]))?;
    // Finish all rendering before touching the filesystem.
    let rendered = render(&arguments.directory)?;
    let mut staged = Vec::with_capacity(rendered.len());
    for (destination, bytes) in rendered {
        invocation
            .check()
            .map_err(|error| at_operation("stage", &destination, error, &[]))?;
        let parent = destination
            .parent()
            .expect("generated destination has parent");
        std::fs::create_dir_all(parent)
            .map_err(|error| io_error("create directory", parent, error))?;
        before("stage", &destination).map_err(|error| io_error("stage", &destination, error))?;
        let mut file = StagedFile::stage_replacement(invocation, &destination)
            .map_err(|error| at_operation("stage", &destination, error, &[]))?;
        before("write", &destination).map_err(|error| io_error("write", &destination, error))?;
        file.as_file_mut()
            .write_all(&bytes)
            .map_err(|error| io_error("write", &destination, error))?;
        before("sync", &destination).map_err(|error| io_error("sync", &destination, error))?;
        file.sync()
            .map_err(|error| at_operation("sync", &destination, error, &[]))?;
        staged.push((destination, file));
    }
    // Every file is staged and synced before the first atomic replacement.
    let mut published = Vec::new();
    for (destination, file) in staged {
        before("publish", &destination).map_err(|error| {
            contextual_error(io_error("publish", &destination, error), &published)
        })?;
        let result = file
            .persist()
            .map_err(|error| at_operation("publish", &destination, error, &published))?;
        published.push(result.destination().to_owned());
    }
    Ok(())
}

fn render(directory: &Path) -> Result<Rendered, CliError> {
    let mut rendered = Vec::new();
    for shell in Shell::value_variants() {
        let destination = directory
            .join("completions")
            .join(shell.file_name("packetcraftr"));
        let mut command = Cli::command();
        command.set_bin_name("packetcraftr");
        command.build();
        // Some completion generators panic on writer errors: render to memory.
        let mut bytes = Vec::new();
        shell
            .try_generate(&command, &mut bytes)
            .map_err(|error| io_error("render completion", &destination, error))?;
        rendered.push((destination, bytes));
    }
    let mut command = Cli::command();
    command.build();
    render_man_pages(&command, &directory.join("man"), &mut rendered)?;
    Ok(rendered)
}

/// Render the grouped command tree without clap's synthetic help command tree.
fn render_man_pages(
    command: &clap::Command,
    directory: &Path,
    rendered: &mut Rendered,
) -> Result<(), CliError> {
    let manual = clap_mangen::Man::new(
        command
            .clone()
            .hide(false)
            .disable_help_subcommand(true)
            .mut_args(|arg| arg.hide_short_help(false)),
    );
    let destination = directory.join(manual.get_filename());
    let mut bytes = Vec::new();
    manual
        .render(&mut bytes)
        .map_err(|error| io_error("render manual", &destination, error))?;
    rendered.push((destination, bytes));
    for command in command
        .get_subcommands()
        .filter(|command| command.get_name() != "help")
    {
        render_man_pages(command, directory, rendered)?;
    }
    Ok(())
}

fn io_error(operation: &'static str, destination: &Path, error: io::Error) -> CliError {
    CliError::from_classification(
        Classification::new(
            "io.documentation",
            Kind::Io,
            Some("choose a writable documentation directory"),
        ),
        format!(
            "cannot {operation} generated documentation {}",
            destination.display()
        ),
        source_causes(&error),
    )
}

fn contextual_error(mut error: CliError, published: &[PathBuf]) -> CliError {
    error.classification = Classification::new(
        "io.documentation",
        error.classification.kind,
        Some("choose a writable documentation directory"),
    );
    if !published.is_empty() {
        error.message.push_str("; already published: ");
        error.message.push_str(
            &published
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    error
}

fn at_operation(
    operation: &'static str,
    destination: &Path,
    mut error: CliError,
    published: &[PathBuf],
) -> CliError {
    error.message = format!(
        "cannot {operation} generated documentation {}: {}",
        destination.display(),
        error.message
    );
    contextual_error(error, published)
}

#[cfg(test)]
mod tests;
