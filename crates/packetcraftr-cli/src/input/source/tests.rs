// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Interrupted};

use super::{Source, classify, duplicate, open, test_invocation};
use crate::invocation::Invocation;

const PROMPTLY: Duration = Duration::from_secs(5);
const LATER: Duration = Duration::from_millis(100);

fn polled_pipe(invocation: &Invocation) -> (Source, io::PipeWriter) {
    let (reader, writer) = io::pipe().unwrap();
    let source = classify(invocation, OwnedFd::from(reader).into()).unwrap();
    assert!(matches!(source, Source::Polled(_)));
    (source, writer)
}

fn interruption(error: &io::Error) -> Interrupted {
    assert_ne!(error.kind(), io::ErrorKind::Interrupted, "{error}");
    *error
        .get_ref()
        .and_then(|source| source.downcast_ref::<Interrupted>())
        .unwrap_or_else(|| panic!("expected an interruption, got {error:?}"))
}

fn mkfifo(directory: &Path) -> PathBuf {
    let path = directory.join("input.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo failed: {status:?}");
    path
}

#[test]
fn cancellation_interrupts_a_read_waiting_for_pipe_data() {
    let cancellation = Cancellation::default();
    let invocation = test_invocation(None, cancellation.clone());
    let (mut source, _writer) = polled_pipe(&invocation);
    let started = Instant::now();
    let error = thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(LATER);
            cancellation.cancel();
        });
        source.read(&mut [0; 16]).unwrap_err()
    });
    assert!(matches!(interruption(&error), Interrupted::Cancelled(_)));
    assert!(started.elapsed() >= LATER && started.elapsed() < PROMPTLY);
}

#[test]
fn deadline_interrupts_a_read_waiting_for_pipe_data() {
    let invocation = test_invocation(Some(Duration::from_millis(200)), Cancellation::default());
    let (mut source, _writer) = polled_pipe(&invocation);
    let started = Instant::now();
    let error = source.read(&mut [0; 16]).unwrap_err();
    assert!(matches!(interruption(&error), Interrupted::Exceeded(_)));
    assert!(started.elapsed() < PROMPTLY);
}

#[test]
fn data_that_arrives_later_is_read_and_writer_close_is_eof() {
    let invocation = test_invocation(Some(PROMPTLY), Cancellation::default());
    let (mut source, mut writer) = polled_pipe(&invocation);
    let mut bytes = Vec::new();
    thread::scope(|scope| {
        scope.spawn(move || {
            thread::sleep(LATER);
            writer.write_all(b"late").unwrap();
            thread::sleep(LATER);
            writer.write_all(b" bytes").unwrap();
        });
        source.read_to_end(&mut bytes).unwrap();
    });
    assert_eq!(bytes, b"late bytes");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn fifo_without_a_writer_opens_and_waits_instead_of_reading_eof() {
    let directory = tempfile::tempdir().unwrap();
    let fifo = mkfifo(directory.path());

    let invocation = test_invocation(Some(Duration::from_millis(300)), Cancellation::default());
    let mut source = open(&invocation, &fifo).unwrap();
    let error = source.read(&mut [0; 16]).unwrap_err();
    assert!(matches!(interruption(&error), Interrupted::Exceeded(_)));

    let invocation = test_invocation(Some(PROMPTLY), Cancellation::default());
    let mut source = open(&invocation, &fifo).unwrap();
    let mut bytes = Vec::new();
    thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(LATER);
            let mut writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
            writer.write_all(b"from fifo").unwrap();
        });
        source.read_to_end(&mut bytes).unwrap();
    });
    assert_eq!(bytes, b"from fifo");
}

#[test]
fn a_unix_socket_is_polled_like_a_pipe() {
    let (reader, _writer) = UnixStream::pair().unwrap();
    let invocation = test_invocation(Some(PROMPTLY), Cancellation::default());
    let source = classify(&invocation, File::from(OwnedFd::from(reader))).unwrap();
    assert!(matches!(source, Source::Polled(_)));
}

#[cfg(target_os = "linux")]
#[test]
fn a_non_retryable_read_error_surfaces_instead_of_retrying_until_the_deadline() {
    let inotify = rustix::fs::inotify::init(rustix::fs::inotify::CreateFlags::CLOEXEC).unwrap();
    let directory = tempfile::tempdir().unwrap();
    rustix::fs::inotify::add_watch(
        &inotify,
        directory.path(),
        rustix::fs::inotify::WatchFlags::CREATE,
    )
    .unwrap();
    std::fs::write(directory.path().join("created"), b"").unwrap();
    let invocation = test_invocation(Some(PROMPTLY), Cancellation::default());
    let mut source = Source::Polled(super::Polled {
        file: inotify.into(),
        invocation,
    });
    let started = Instant::now();
    let error = source.read(&mut [0; 4]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
    assert!(started.elapsed() < PROMPTLY);
}

#[test]
fn duplicated_stdin_leaves_the_shared_descriptor_flags_and_open_state() {
    let (reader, mut writer) = io::pipe().unwrap();
    let flags = rustix::fs::fcntl_getfl(reader.as_fd()).unwrap();
    let invocation = test_invocation(Some(Duration::from_millis(100)), Cancellation::default());
    let mut source = duplicate(&invocation, reader.as_fd()).unwrap();
    assert!(matches!(source, Source::Polled(_)));
    let error = source.read(&mut [0; 16]).unwrap_err();
    assert!(matches!(interruption(&error), Interrupted::Exceeded(_)));
    drop(source);

    assert_eq!(rustix::fs::fcntl_getfl(reader.as_fd()).unwrap(), flags);
    writer.write_all(b"still open").unwrap();
    drop(writer);
    let mut bytes = Vec::new();
    (&reader).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"still open");
}

#[cfg(target_os = "linux")]
fn entries(directory: &str) -> usize {
    std::fs::read_dir(directory).unwrap().count()
}

#[test]
fn repeated_cancellations_leak_no_descriptors_or_threads() {
    #[cfg(target_os = "linux")]
    let before = (entries("/proc/self/fd"), entries("/proc/self/task"));
    for _ in 0..20 {
        let cancellation = Cancellation::default();
        let invocation = test_invocation(None, cancellation.clone());
        let (mut source, writer) = polled_pipe(&invocation);
        let error = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(10));
                cancellation.cancel();
            });
            source.read(&mut [0; 16]).unwrap_err()
        });
        assert!(matches!(interruption(&error), Interrupted::Cancelled(_)));
        drop((source, writer));
    }
    #[cfg(target_os = "linux")]
    {
        let settled = Instant::now();
        loop {
            let now = (entries("/proc/self/fd"), entries("/proc/self/task"));
            if now.0 <= before.0 && now.1 <= before.1 {
                break;
            }
            assert!(
                settled.elapsed() < PROMPTLY,
                "descriptors and threads went from {before:?} to {now:?}"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn a_fifo_is_read_in_full_through_an_ordinary_blocking_open() {
    let directory = tempfile::tempdir().unwrap();
    let fifo = mkfifo(directory.path());
    let invocation = test_invocation(Some(PROMPTLY), Cancellation::default());
    let mut bytes = Vec::new();
    thread::scope(|scope| {
        scope.spawn(|| {
            let mut writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
            writer.write_all(b"from fifo").unwrap();
        });
        let mut source = open(&invocation, &fifo).unwrap();
        assert!(matches!(source, Source::File(_)));
        source.read_to_end(&mut bytes).unwrap();
    });
    assert_eq!(bytes, b"from fifo");
}
