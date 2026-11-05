// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! On Unix, reads from pipes, FIFOs, sockets, and character devices wait for readiness in short
//! slices and fail with the invocation's interruption once it is cancelled or past its deadline.
//! Regular files keep ordinary reads. Windows offers no safe readiness wait for anonymous or named
//! pipes, so its reads still block.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::errors::CliError;
use crate::invocation::Invocation;

pub(super) enum Source {
    File(File),
    #[cfg(unix)]
    Polled(Polled),
    #[cfg(not(unix))]
    Stdin(io::StdinLock<'static>),
}

impl Source {
    pub(super) fn is_regular_file(&self) -> bool {
        matches!(self, Self::File(file) if file.metadata().is_ok_and(|metadata| metadata.is_file()))
    }
}

impl Read for Source {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(buffer),
            #[cfg(unix)]
            Self::Polled(polled) => polled.read(buffer),
            #[cfg(not(unix))]
            Self::Stdin(stdin) => stdin.read(buffer),
        }
    }
}

/// Prefers the invocation's pending interruption, which an interrupted read surfaces only as an
/// I/O error, so it reports like every other cancellation or deadline.
pub(super) fn interrupted_or(invocation: &Invocation, error: CliError) -> CliError {
    invocation.check().err().unwrap_or(error)
}

/// On Linux, opening never waits for a FIFO writer.
#[cfg(unix)]
pub(super) fn open(invocation: &Invocation, path: &Path) -> io::Result<Source> {
    use std::os::unix::fs::OpenOptionsExt;
    // FIFO readiness is only verified on Linux. On macOS, polling a FIFO
    // opened this way never delivered the written data or EOF, so FIFOs keep
    // the ordinary blocking open and reads there, decided by stat before
    // opening so a writer never pairs with a probe descriptor about to close.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    if std::os::unix::fs::FileTypeExt::is_fifo(&std::fs::metadata(path)?.file_type()) {
        return File::open(path).map(Source::File);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed())
        .open(path)?;
    classify(invocation, file)
}

/// Reads a duplicate of standard input, leaving the shared descriptor's flags untouched.
#[cfg(unix)]
pub(super) fn stdin(invocation: &Invocation) -> io::Result<Source> {
    use std::os::fd::AsFd;
    duplicate(invocation, io::stdin().as_fd())
}

#[cfg(unix)]
fn duplicate(
    invocation: &Invocation,
    descriptor: std::os::fd::BorrowedFd<'_>,
) -> io::Result<Source> {
    classify(invocation, File::from(descriptor.try_clone_to_owned()?))
}

#[cfg(unix)]
fn classify(invocation: &Invocation, file: File) -> io::Result<Source> {
    use std::os::unix::fs::FileTypeExt;
    let kind = file.metadata()?.file_type();
    if kind.is_fifo() || kind.is_socket() || kind.is_char_device() {
        return Ok(Source::Polled(Polled {
            file,
            invocation: invocation.clone(),
        }));
    }
    Ok(Source::File(file))
}

#[cfg(not(unix))]
pub(super) fn open(_: &Invocation, path: &Path) -> io::Result<Source> {
    File::open(path).map(Source::File)
}

#[cfg(not(unix))]
pub(super) fn stdin(_: &Invocation) -> io::Result<Source> {
    Ok(Source::Stdin(io::stdin().lock()))
}

/// Reads only after `poll` reports the descriptor ready, so a FIFO that has not had a writer yet
/// keeps waiting instead of reading as EOF. An interruption fails the read with an
/// [`io::ErrorKind::Other`] error, never [`io::ErrorKind::Interrupted`], which callers retry.
#[cfg(unix)]
pub(super) struct Polled {
    file: File,
    invocation: Invocation,
}

#[cfg(unix)]
impl Polled {
    fn next_wait(&self) -> io::Result<std::time::Duration> {
        use packetcraftr_netio::deadline::POLL_INTERVAL;
        self.invocation
            .check_interrupted()
            .map_err(io::Error::other)?;
        Ok(self
            .invocation
            .deadline
            .as_ref()
            .map_or(POLL_INTERVAL, |deadline| {
                deadline
                    .remaining()
                    .map_or(std::time::Duration::ZERO, |remaining| {
                        remaining.min(POLL_INTERVAL)
                    })
            }))
    }

    fn ready_within(&self, wait: std::time::Duration) -> io::Result<bool> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let timeout = Timespec::try_from(wait).map_err(io::Error::other)?;
        match poll(
            &mut [PollFd::new(&self.file, PollFlags::IN)],
            Some(&timeout),
        ) {
            Ok(ready) => Ok(ready > 0),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(unix)]
impl Read for Polled {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let wait = self.next_wait()?;
            if !self.ready_within(wait)? {
                continue;
            }
            match self.file.read(buffer) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
}

#[cfg(test)]
pub(super) fn test_invocation(
    duration: Option<std::time::Duration>,
    cancellation: packetcraftr_core::budget::Cancellation,
) -> Invocation {
    Invocation::new(
        crate::output::contract::Format::Json,
        crate::invocation::StreamEncoder::new(crate::output::contract::Command::Build, io::sink()),
        duration,
        cancellation,
        None,
    )
}

#[cfg(all(test, unix))]
mod tests;
