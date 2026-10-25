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
mod tests {
    use super::*;
    use crate::commands::{Command, Generate};
    use crate::output::stream::StreamEncoder;
    use packetcraftr_core::budget::Cancellation;

    fn invocation() -> Invocation {
        Invocation::new(
            Format::Text,
            StreamEncoder::new(Command::Read, io::sink()).into(),
            None,
            Cancellation::default(),
            None,
        )
    }

    fn files(directory: &Path) -> Result<Rendered, CliError> {
        Ok(vec![
            (directory.join("man/first.1"), b"first".to_vec()),
            (directory.join("man/second.1"), b"second".to_vec()),
        ])
    }

    #[cfg(unix)]
    #[test]
    fn new_documentation_uses_normal_creation_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let reference = temporary.path().join("ordinary-file");
        std::fs::write(&reference, b"reference").unwrap();
        let expected = std::fs::metadata(&reference).unwrap().permissions().mode() & 0o777;
        let arguments = Args {
            directory: temporary.path().into(),
        };
        run_with(&arguments, &invocation(), files, |_, _| Ok(())).unwrap();

        for (path, contents) in files(temporary.path()).unwrap() {
            assert_eq!(std::fs::read(&path).unwrap(), contents);
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                expected,
                "{} should have ordinary file creation permissions",
                path.display()
            );
        }
    }

    #[test]
    fn regeneration_atomically_replaces_existing_regular_files() {
        let temporary = tempfile::tempdir().unwrap();
        let arguments = Args {
            directory: temporary.path().into(),
        };
        run_with(&arguments, &invocation(), files, |_, _| Ok(())).unwrap();
        let first = temporary.path().join("man/first.1");
        let second = temporary.path().join("man/second.1");
        std::fs::write(&first, b"old").unwrap();
        std::fs::write(&second, b"old second").unwrap();
        #[cfg(unix)]
        let expected_permissions = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o4640)).unwrap();
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o7777
        };
        run_with(&arguments, &invocation(), files, |_, _| Ok(())).unwrap();
        assert_eq!(std::fs::read(&first).unwrap(), b"first");
        assert_eq!(std::fs::read(&second).unwrap(), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&first).unwrap().permissions().mode() & 0o7777,
                expected_permissions
            );
        }
    }

    #[test]
    fn render_failure_and_unsupported_formats_do_not_create_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("absent");
        let error = run_with(
            &Args {
                directory: destination.clone(),
            },
            &invocation(),
            |directory| {
                Err(io_error(
                    "render manual",
                    &directory.join("man/test.1"),
                    io::Error::other("render failure"),
                ))
            },
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert!(error.message.contains("render manual"));
        assert!(error.message.contains("man/test.1"));
        for format in [
            Format::Json,
            Format::Csv,
            Format::Ndjson,
            Format::Hex,
            Format::Raw,
            Format::Pcap,
            Format::PcapNg,
        ] {
            assert!(
                Args {
                    directory: destination.clone()
                }
                .generate(&invocation(), format)
                .is_err()
            );
        }
        assert!(!destination.exists());
    }

    #[test]
    fn write_and_sync_failures_leave_all_originals_intact() {
        for failed_operation in ["stage", "write", "sync"] {
            let temporary = tempfile::tempdir().unwrap();
            std::fs::create_dir(temporary.path().join("man")).unwrap();
            let first = temporary.path().join("man/first.1");
            let second = temporary.path().join("man/second.1");
            std::fs::write(&first, b"old first").unwrap();
            std::fs::write(&second, b"old second").unwrap();
            let error = run_with(
                &Args {
                    directory: temporary.path().into(),
                },
                &invocation(),
                files,
                |operation, path| {
                    if operation == failed_operation && path == second {
                        Err(io::Error::other("injected failure"))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
            assert!(error.message.contains(failed_operation));
            assert!(error.message.contains(second.to_str().unwrap()));
            assert_eq!(std::fs::read(&first).unwrap(), b"old first");
            assert_eq!(std::fs::read(&second).unwrap(), b"old second");
            assert_eq!(
                std::fs::read_dir(temporary.path().join("man"))
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect::<std::collections::BTreeSet<_>>(),
                [first, second].into_iter().collect()
            );
        }
    }

    #[test]
    fn publication_failure_reports_the_published_prefix_and_destination() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("man/first.1");
        let second = temporary.path().join("man/second.1");
        let error = run_with(
            &Args {
                directory: temporary.path().into(),
            },
            &invocation(),
            files,
            |operation, path| {
                if operation == "publish" && path == second {
                    std::fs::create_dir(path)?;
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.message.contains("inspect replacement destination"));
        assert!(error.message.contains(second.to_str().unwrap()));
        assert!(
            error
                .message
                .contains(&format!("already published: {}", first.display()))
        );
        assert_eq!(std::fs::read(first).unwrap(), b"first");
        assert!(second.is_dir());
    }

    #[test]
    fn cancellation_at_publication_reports_destination_and_published_prefix() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("man/first.1");
        let second = temporary.path().join("man/second.1");
        let invocation = invocation();
        let error = run_with(
            &Args {
                directory: temporary.path().into(),
            },
            &invocation,
            files,
            |operation, path| {
                if operation == "publish" && path == second {
                    invocation.cancellation.cancel();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.message.contains(&format!(
            "cannot publish generated documentation {}",
            second.display()
        )));
        assert!(
            error
                .message
                .contains(&format!("already published: {}", first.display()))
        );
        assert_eq!(std::fs::read(first).unwrap(), b"first");
        assert!(!second.exists());
    }

    #[test]
    fn actual_render_includes_completions_and_grouped_manuals() {
        let files = render(Path::new("docs")).unwrap();
        for shell in Shell::value_variants() {
            let destination = Path::new("docs/completions").join(shell.file_name("packetcraftr"));
            let (_, bytes) = files.iter().find(|(path, _)| *path == destination).unwrap();
            let completion = std::str::from_utf8(bytes).unwrap();
            for command in ["packetcraftr", "dissect", "documentation"] {
                assert!(
                    completion.contains(command),
                    "{} is missing {command}",
                    destination.display()
                );
            }
        }
        let mut command = Cli::command();
        command.build();
        let manuals = std::iter::once(&command)
            .chain(
                crate::commands::registry::GROUPS
                    .iter()
                    .map(|(group, _)| command.find_subcommand(group).unwrap()),
            )
            .chain(crate::commands::registry::INVENTORY.iter().map(|entry| {
                command
                    .find_subcommand(entry.group)
                    .unwrap()
                    .find_subcommand(entry.name)
                    .unwrap()
            }));
        for definition in manuals {
            let destination = Path::new("docs/man")
                .join(clap_mangen::Man::new(definition.clone()).get_filename());
            let (_, bytes) = files.iter().find(|(path, _)| *path == destination).unwrap();
            let manual = std::str::from_utf8(bytes).unwrap();
            if let Some(about) = definition.get_about() {
                for word in about
                    .to_string()
                    .split_whitespace()
                    .filter(|word| word.len() >= 4 && word.chars().all(char::is_alphanumeric))
                {
                    assert!(
                        manual.contains(word),
                        "{} is missing {word}",
                        destination.display()
                    );
                }
            }
        }
        let unique: std::collections::BTreeSet<_> = files.iter().map(|(path, _)| path).collect();
        assert_eq!(unique.len(), files.len());
    }

    #[test]
    fn replacement_rejects_directory_and_symlink_destinations() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("destination");
        std::fs::create_dir(&destination).unwrap();
        let retained = destination.join("retained");
        std::fs::write(&retained, b"preserved").unwrap();
        assert!(StagedFile::stage_replacement(&invocation(), &destination).is_err());
        assert_eq!(std::fs::read(&retained).unwrap(), b"preserved");
        #[cfg(unix)]
        {
            let link = temporary.path().join("link");
            std::os::unix::fs::symlink(&destination, &link).unwrap();
            assert!(StagedFile::stage_replacement(&invocation(), &link).is_err());
            assert_eq!(std::fs::read_link(&link).unwrap(), destination);
            assert_eq!(std::fs::read(&retained).unwrap(), b"preserved");
            let socket = temporary.path().join("socket");
            let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            assert!(StagedFile::stage_replacement(&invocation(), &socket).is_err());
        }
        let regular = temporary.path().join("regular");
        std::fs::write(&regular, b"old").unwrap();
        assert!(StagedFile::stage(&invocation(), &regular).is_err());
        assert_eq!(std::fs::read(&regular).unwrap(), b"old");
        for name in ["invalid\0destination", "missing/", "missing/."] {
            let invalid = temporary.path().join(name);
            assert!(StagedFile::stage(&invocation(), &invalid).is_err());
            assert!(StagedFile::stage_replacement(&invocation(), &invalid).is_err());
        }
        let short = temporary.path().join("x");
        let mut staged = StagedFile::stage(&invocation(), &short).unwrap();
        staged.as_file_mut().write_all(b"short file name").unwrap();
        staged.sync().unwrap();
        staged.persist().unwrap();
        assert_eq!(std::fs::read(short).unwrap(), b"short file name");
    }

    #[cfg(unix)]
    #[test]
    fn publication_rejects_a_replaced_parent_and_preserves_both_directories() {
        for replacement in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let parent = temporary.path().join("parent");
            let retired = temporary.path().join("retired");
            std::fs::create_dir(&parent).unwrap();
            let destination = parent.join("report");
            if replacement {
                std::fs::write(&destination, b"original report").unwrap();
            }
            let mut staged = if replacement {
                StagedFile::stage_replacement(&invocation(), &destination)
            } else {
                StagedFile::stage(&invocation(), &destination)
            }
            .unwrap();
            staged.as_file_mut().write_all(b"new report").unwrap();
            staged.sync().unwrap();
            std::fs::rename(&parent, &retired).unwrap();
            std::fs::create_dir(&parent).unwrap();
            std::fs::write(&destination, b"replacement report").unwrap();
            let unrelated = parent.join("unrelated");
            std::fs::write(&unrelated, b"untouched").unwrap();

            let error = staged.persist().unwrap_err();
            assert_eq!(error.classification.code, "io.output_file");
            assert_eq!(error.classification.kind, Kind::Io);
            assert!(error.message.contains("changed since staging"));
            assert!(error.message.contains(destination.to_str().unwrap()));
            assert_eq!(std::fs::read(&destination).unwrap(), b"replacement report");
            assert_eq!(std::fs::read(&unrelated).unwrap(), b"untouched");
            let original = retired.join("report");
            if replacement {
                assert_eq!(std::fs::read(original).unwrap(), b"original report");
            } else {
                assert!(!original.exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_publication_stays_private_with_a_permissive_umask() {
        crate::cancellation::tests::isolated(
            "commands::reference::documentation::tests::ordinary_publication_stays_private_with_a_permissive_umask",
            || {
                use nix::sys::stat::{Mode, umask};
                use std::os::unix::fs::PermissionsExt;

                umask(Mode::empty());
                let temporary = tempfile::tempdir().unwrap();
                let destination = temporary.path().join("report");
                let mut staged = StagedFile::stage(&invocation(), &destination).unwrap();
                staged.as_file_mut().write_all(b"private report").unwrap();
                staged.sync().unwrap();
                staged.persist().unwrap();
                assert_eq!(std::fs::read(&destination).unwrap(), b"private report");
                let permissions =
                    u64::from(std::fs::metadata(destination).unwrap().permissions().mode());
                let owner = u64::from((Mode::S_IRUSR | Mode::S_IWUSR).bits());
                let others = u64::from((Mode::S_IRWXG | Mode::S_IRWXO).bits());
                assert_eq!(permissions & owner, owner);
                assert_eq!(permissions & others, 0);
            },
        );
    }
}
