// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
    Args {
        directory: temporary.path().into(),
    }
    .generate(&invocation(), Format::Text)
    .unwrap();

    for directory in ["completions", "man"] {
        for entry in std::fs::read_dir(temporary.path().join(directory)).unwrap() {
            let path = entry.unwrap().path();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                expected,
                "{} should have ordinary file creation permissions",
                path.display()
            );
        }
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
    std::fs::write(&first, b"old").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o4640)).unwrap();
    }
    run_with(&arguments, &invocation(), files, |_, _| Ok(())).unwrap();
    assert_eq!(std::fs::read(&first).unwrap(), b"first");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o7777,
            0o4640
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
        assert_eq!(std::fs::read(first).unwrap(), b"old first");
        assert_eq!(std::fs::read(second).unwrap(), b"old second");
        assert_eq!(
            std::fs::read_dir(temporary.path().join("man"))
                .unwrap()
                .count(),
            2
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
    assert!(files.iter().any(|(path, bytes)| path
        == Path::new("docs/completions/packetcraftr.bash")
        && !bytes.is_empty()));
    assert!(
        files
            .iter()
            .any(|(path, bytes)| path == Path::new("docs/man/packetcraftr.1") && !bytes.is_empty())
    );
    assert!(files.len() > 10);
    let unique: std::collections::BTreeSet<_> = files.iter().map(|(path, _)| path).collect();
    assert_eq!(unique.len(), files.len());
}

#[test]
fn replacement_rejects_directory_and_symlink_destinations() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("destination");
    std::fs::create_dir(&destination).unwrap();
    assert!(StagedFile::stage_replacement(&invocation(), &destination).is_err());
    #[cfg(unix)]
    {
        let link = temporary.path().join("link");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        assert!(StagedFile::stage_replacement(&invocation(), &link).is_err());
        let socket = temporary.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(StagedFile::stage_replacement(&invocation(), &socket).is_err());
    }
    let regular = temporary.path().join("regular");
    std::fs::write(&regular, b"old").unwrap();
    assert!(StagedFile::stage(&invocation(), &regular).is_err());
}
