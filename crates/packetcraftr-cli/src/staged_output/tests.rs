// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use packetcraftr_core::budget::Cancellation;

use super::*;
use crate::commands::Command;
use crate::invocation::Invocation;
use crate::output::contract::Format;
use crate::output::stream::StreamEncoder;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strategy {
    #[cfg(packetcraftr_proc_fd_paths)]
    Anchored,
    Named,
}

const STRATEGIES: &[Strategy] = &[
    #[cfg(packetcraftr_proc_fd_paths)]
    Strategy::Anchored,
    Strategy::Named,
];

type Stage = fn(&Invocation, &Path) -> Result<StagedFile, CliError>;

const MODES: [Stage; 2] = [StagedFile::stage, StagedFile::stage_replacement];

fn invocation() -> Invocation {
    Invocation::new(
        Format::Text,
        StreamEncoder::new(Command::Read, std::io::sink()).into(),
        None,
        Cancellation::default(),
        None,
    )
}

fn with_strategy<T>(strategy: Strategy, run: impl FnOnce() -> T) -> T {
    #[cfg(packetcraftr_proc_fd_paths)]
    FORCE_NAMED.set(strategy == Strategy::Named);
    #[cfg(not(packetcraftr_proc_fd_paths))]
    let _ = strategy;
    let result = run();
    #[cfg(packetcraftr_proc_fd_paths)]
    FORCE_NAMED.set(false);
    result
}

fn before_publish(hook: impl FnOnce() + 'static) {
    BEFORE_PUBLISH.set(Some(Box::new(hook)));
}

fn staged(stage: Stage, invocation: &Invocation, destination: &Path, bytes: &[u8]) -> StagedFile {
    let mut file = stage(invocation, destination).unwrap();
    file.as_file_mut().write_all(bytes).unwrap();
    file.sync().unwrap();
    file
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn staged_identity(file: &mut StagedFile) -> (u64, u64) {
    identity(&file.as_file_mut().metadata().unwrap())
}

fn entries(directory: &Path) -> BTreeSet<OsString> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

fn names(names: &[&str]) -> BTreeSet<OsString> {
    names.iter().map(OsString::from).collect()
}

fn replace_directory(directory: &Path, moved_to: &Path) {
    std::fs::rename(directory, moved_to).unwrap();
    std::fs::create_dir(directory).unwrap();
}

/// Replaces the only staging entry beside `destination` with other content.
fn substitute_staging(directory: &Path, destination: &Path) -> PathBuf {
    let staging: Vec<PathBuf> = entries(directory)
        .into_iter()
        .map(|name| directory.join(name))
        .filter(|path| path != destination)
        .collect();
    let [staging] = &staging[..] else {
        panic!("named staging creates exactly one entry: {staging:?}");
    };
    std::fs::remove_file(staging).unwrap();
    std::fs::write(staging, b"substituted").unwrap();
    staging.clone()
}

#[test]
fn publication_rejects_replaced_parent() {
    for &strategy in STRATEGIES {
        for stage in MODES {
            with_strategy(strategy, || {
                let temporary = tempfile::tempdir().unwrap();
                let directory = temporary.path().join("out");
                let moved = temporary.path().join("out.old");
                std::fs::create_dir(&directory).unwrap();
                let destination = directory.join("capture.pcap");
                let mut file = staged(stage, &invocation(), &destination, b"staged bytes");
                #[cfg(packetcraftr_proc_fd_paths)]
                if strategy == Strategy::Anchored {
                    assert!(
                        entries(&directory).is_empty(),
                        "anchored staging is unnamed"
                    );
                }
                let expected = staged_identity(&mut file);
                let (hook_directory, hook_moved) = (directory.clone(), moved.clone());
                before_publish(move || replace_directory(&hook_directory, &hook_moved));

                let published = file.persist().unwrap();

                assert_eq!(published.destination(), destination);
                let output = moved.join("capture.pcap");
                assert_eq!(std::fs::read(&output).unwrap(), b"staged bytes");
                assert_eq!(
                    identity(&std::fs::symlink_metadata(&output).unwrap()),
                    expected
                );
                assert_eq!(entries(&moved), names(&["capture.pcap"]), "{strategy:?}");
                assert!(entries(&directory).is_empty(), "{strategy:?}");
            });
        }
    }
}

#[test]
fn publication_rejects_previously_substituted_entry() {
    for stage in MODES {
        with_strategy(Strategy::Named, || {
            let temporary = tempfile::tempdir().unwrap();
            let destination = temporary.path().join("capture.pcap");
            let file = staged(stage, &invocation(), &destination, b"staged bytes");
            let staging = substitute_staging(temporary.path(), &destination);

            let error = file.persist().unwrap_err();

            assert!(error.message.contains(destination.to_str().unwrap()));
            assert!(!destination.exists());
            assert_eq!(std::fs::read(&staging).unwrap(), b"substituted");
        });
    }
}

#[test]
fn publication_removes_concurrently_substituted_entry() {
    with_strategy(Strategy::Named, || {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("capture.pcap");
        let file = staged(
            StagedFile::stage,
            &invocation(),
            &destination,
            b"staged bytes",
        );
        let (directory, hook_destination) = (temporary.path().to_owned(), destination.clone());
        before_publish(move || {
            substitute_staging(&directory, &hook_destination);
        });

        let error = file.persist().unwrap_err();

        assert!(error.message.contains(destination.to_str().unwrap()));
        assert!(!destination.exists());
        assert!(
            entries(temporary.path())
                .iter()
                .all(|name| std::fs::read(temporary.path().join(name)).unwrap() != b"staged bytes"),
            "the staged bytes are never published under another name"
        );
    });
}

#[test]
fn replacement_rejects_substituted_entry() {
    with_strategy(Strategy::Named, || {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("manual.1");
        std::fs::write(&destination, b"old").unwrap();
        let file = staged(
            StagedFile::stage_replacement,
            &invocation(),
            &destination,
            b"new",
        );
        let (directory, hook_destination) = (temporary.path().to_owned(), destination.clone());
        before_publish(move || {
            substitute_staging(&directory, &hook_destination);
        });

        let error = file.persist().unwrap_err();

        assert!(error.message.contains(destination.to_str().unwrap()));
        assert!(
            error
                .causes
                .iter()
                .any(|cause| cause.contains("not the staged file")),
            "{error:?}"
        );
    });
}

#[test]
fn no_clobber_preserves_concurrent_destination() {
    for &strategy in STRATEGIES {
        with_strategy(strategy, || {
            let temporary = tempfile::tempdir().unwrap();
            let destination = temporary.path().join("capture.pcap");
            let file = staged(
                StagedFile::stage,
                &invocation(),
                &destination,
                b"staged bytes",
            );
            let hook_destination = destination.clone();
            before_publish(move || std::fs::write(hook_destination, b"original").unwrap());

            let error = file.persist().unwrap_err();

            assert!(error.message.contains(destination.to_str().unwrap()));
            assert_eq!(std::fs::read(&destination).unwrap(), b"original");
            assert_eq!(
                entries(temporary.path()),
                names(&["capture.pcap"]),
                "{strategy:?}"
            );
        });
    }
}

#[test]
fn replacement_preserves_destination_permissions() {
    for &strategy in STRATEGIES {
        with_strategy(strategy, || {
            let temporary = tempfile::tempdir().unwrap();
            let destination = temporary.path().join("manual.1");
            std::fs::write(&destination, b"old").unwrap();
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o640)).unwrap();

            let error = StagedFile::stage(&invocation(), &destination).unwrap_err();
            assert!(error.message.contains("already exists"));

            staged(
                StagedFile::stage_replacement,
                &invocation(),
                &destination,
                b"regenerated",
            )
            .persist()
            .unwrap();

            assert_eq!(std::fs::read(&destination).unwrap(), b"regenerated");
            let metadata = std::fs::metadata(&destination).unwrap();
            assert_eq!(
                metadata.permissions().mode() & 0o7777,
                0o640,
                "{strategy:?}"
            );
            assert_eq!(
                entries(temporary.path()),
                names(&["manual.1"]),
                "{strategy:?}"
            );
        });
    }
}

#[test]
fn parent_is_bound_when_staging_starts() {
    for &strategy in STRATEGIES {
        with_strategy(strategy, || {
            let temporary = tempfile::tempdir().unwrap();
            let directory = temporary.path().join("out");
            let earlier = temporary.path().join("out.earlier");
            let later = temporary.path().join("out.later");
            std::fs::create_dir(&directory).unwrap();
            replace_directory(&directory, &earlier);
            let destination = directory.join("capture.pcap");
            let mut file = StagedFile::stage(&invocation(), &destination).unwrap();
            replace_directory(&directory, &later);
            file.as_file_mut().write_all(b"staged bytes").unwrap();
            file.sync().unwrap();

            file.persist().unwrap();

            assert_eq!(
                std::fs::read(later.join("capture.pcap")).unwrap(),
                b"staged bytes"
            );
            assert!(entries(&earlier).is_empty(), "{strategy:?}");
            assert!(entries(&directory).is_empty(), "{strategy:?}");
        });
    }
}

#[test]
fn directory_destination_is_rejected() {
    for suffix in ["", "."] {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("out");
        std::fs::create_dir(&directory).unwrap();
        let destination = PathBuf::from(format!("{}/{suffix}", directory.display()));
        let error = StagedFile::stage(&invocation(), &destination).unwrap_err();
        assert!(
            error.message.contains("requires a file name"),
            "{destination:?}: {error:?}"
        );
    }
}

#[test]
fn trailing_dot_destination_publishes() {
    for &strategy in STRATEGIES {
        with_strategy(strategy, || {
            let temporary = tempfile::tempdir().unwrap();
            let destination = temporary.path().join("capture.");
            staged(StagedFile::stage, &invocation(), &destination, b"bytes")
                .persist()
                .unwrap();
            assert_eq!(std::fs::read(&destination).unwrap(), b"bytes");
        });
    }
}

#[test]
fn ordinary_output_is_staged_private() {
    for &strategy in STRATEGIES {
        with_strategy(strategy, || {
            let temporary = tempfile::tempdir().unwrap();
            let destination = temporary.path().join("capture.pcap");
            let mut file = StagedFile::stage(&invocation(), &destination).unwrap();
            let mode = file.as_file_mut().metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{strategy:?}");
        });
    }
}

#[test]
fn staging_rejects_nondirectory_parent() {
    let temporary = tempfile::tempdir().unwrap();
    let file_path = temporary.path().join("regular");
    std::fs::write(&file_path, b"").unwrap();
    let error = StagedFile::stage(&invocation(), &file_path.join("child")).unwrap_err();
    assert!(error.message.starts_with("stage output"), "{error:?}");
}

#[test]
fn publication_errors_identify_action() {
    for (action, stage) in [("publish output", MODES[0]), ("replace output", MODES[1])] {
        with_strategy(Strategy::Named, || {
            let temporary = tempfile::tempdir().unwrap();
            let destination = temporary.path().join("capture.pcap");
            let file = staged(stage, &invocation(), &destination, b"staged bytes");
            let (directory, hook_destination) = (temporary.path().to_owned(), destination.clone());
            before_publish(move || {
                substitute_staging(&directory, &hook_destination);
            });
            let error = file.persist().unwrap_err();
            assert!(error.message.starts_with(action), "{action:?}: {error:?}");
        });
    }
}

#[test]
fn abandoned_staging_cleans_up_entries() {
    for &strategy in STRATEGIES {
        with_strategy(strategy, || {
            let temporary = tempfile::tempdir().unwrap();
            let destination = temporary.path().join("capture.pcap");

            drop(staged(
                StagedFile::stage,
                &invocation(),
                &destination,
                b"abandoned",
            ));
            assert!(entries(temporary.path()).is_empty(), "{strategy:?}");

            let cancelled = invocation();
            let file = staged(StagedFile::stage, &cancelled, &destination, b"cancelled");
            cancelled.control.cancellation.cancel();
            assert!(file.persist().is_err());
            assert!(entries(temporary.path()).is_empty(), "{strategy:?}");

            let file = staged(
                StagedFile::stage_replacement,
                &invocation(),
                &destination,
                b"blocked",
            );
            let hook_destination = destination.clone();
            before_publish(move || std::fs::create_dir(hook_destination).unwrap());
            assert!(file.persist().is_err());
            assert_eq!(
                entries(temporary.path()),
                names(&["capture.pcap"]),
                "{strategy:?}"
            );
            assert!(destination.is_dir());
        });
    }
}

#[test]
fn persist_open_and_output_directory_keep_bound_directory_and_inode() {
    use std::io::Seek;

    for &strategy in STRATEGIES {
        with_strategy(strategy, || {
            let temporary = tempfile::tempdir().unwrap();
            let directory = temporary.path().join("out");
            let moved = temporary.path().join("out.old");
            std::fs::create_dir(&directory).unwrap();
            let bound = OutputDirectory::open(&directory).unwrap();
            replace_directory(&directory, &moved);

            let error = bound
                .stage(&invocation(), std::ffi::OsStr::new("nested/a.pcap"))
                .unwrap_err();
            assert!(error.message.contains("single file name"));

            let mut file = bound
                .stage(&invocation(), std::ffi::OsStr::new("slot.pcap"))
                .unwrap();
            file.as_file_mut().write_all(b"initial").unwrap();
            let expected = staged_identity(&mut file);
            let (published, mut handle) = file.persist_open().unwrap();
            assert_eq!(published.destination(), directory.join("slot.pcap"));
            assert_eq!(identity(&handle.metadata().unwrap()), expected);
            handle.set_len(0).unwrap();
            handle.rewind().unwrap();
            handle.write_all(b"reused").unwrap();
            handle.sync_all().unwrap();

            let actual = moved.join("slot.pcap");
            assert_eq!(std::fs::read(&actual).unwrap(), b"reused");
            assert_eq!(
                identity(&std::fs::symlink_metadata(&actual).unwrap()),
                expected
            );
            assert!(entries(&directory).is_empty(), "{strategy:?}");
        });
    }
}

#[test]
fn publish_staged_syncs_all_before_persisting_and_reports_partial_publication() {
    let temporary = tempfile::tempdir().unwrap();
    let first = temporary.path().join("first.bin");
    let second = temporary.path().join("second.bin");

    let inv_ok = invocation();
    let inv_cancelled = invocation();
    let mut f1 = StagedFile::stage(&inv_ok, &first).unwrap();
    f1.as_file_mut().write_all(b"one").unwrap();
    let mut f2 = StagedFile::stage(&inv_cancelled, &second).unwrap();
    f2.as_file_mut().write_all(b"two").unwrap();
    inv_cancelled.control.cancellation.cancel();

    let mut error_callback_ran = false;
    let err = publish_staged(
        vec![("first", f1), ("second", f2)],
        |label, file| (label, file.destination().to_owned()),
        |err, _| {
            error_callback_ran = true;
            err
        },
    )
    .unwrap_err();
    assert_eq!(
        err.classification,
        inv_cancelled.check().unwrap_err().classification
    );
    assert!(
        !error_callback_ran,
        "sync failure must abort before persist"
    );
    assert!(
        !first.exists(),
        "first file must not publish when second fails sync"
    );
    assert!(!second.exists());

    let mut f1 = StagedFile::stage(&inv_ok, &first).unwrap();
    f1.as_file_mut().write_all(b"one").unwrap();
    let mut f2 = StagedFile::stage(&inv_ok, &second).unwrap();
    f2.as_file_mut().write_all(b"two").unwrap();
    let results = publish_staged(
        vec![("first", f1), ("second", f2)],
        |label, file| (label, file.destination().to_owned()),
        |err, _| err,
    )
    .unwrap();
    assert_eq!(
        results,
        vec![("first", first.clone()), ("second", second.clone())]
    );
    assert_eq!(std::fs::read(&first).unwrap(), b"one");
    assert_eq!(std::fs::read(&second).unwrap(), b"two");

    let third = temporary.path().join("third.bin");
    let fourth = temporary.path().join("fourth.bin");
    let mut f3 = StagedFile::stage(&inv_ok, &third).unwrap();
    f3.as_file_mut().write_all(b"three").unwrap();
    let mut f4 = StagedFile::stage(&inv_ok, &fourth).unwrap();
    f4.as_file_mut().write_all(b"four").unwrap();
    std::fs::write(&fourth, b"conflict").unwrap();

    let mut reported = Vec::new();
    let _ = publish_staged(
        vec![("third", f3), ("fourth", f4)],
        |_, _| (),
        |err, published| {
            reported = published.to_vec();
            err
        },
    )
    .unwrap_err();
    assert_eq!(reported, vec![third.display().to_string()]);
    assert_eq!(std::fs::read(&third).unwrap(), b"three");
    assert_eq!(std::fs::read(&fourth).unwrap(), b"conflict");
}
