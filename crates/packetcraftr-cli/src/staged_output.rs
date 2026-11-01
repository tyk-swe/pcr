// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Staged output publication bound to the directory selected before input is
//! read.
//!
//! A destination is staged as a temporary file inside its parent directory and
//! published without overwriting. Documentation regeneration uses a separate
//! replacement entrypoint for missing destinations or regular files, keeping
//! the original until an atomic rename. Atomic publication is not crash
//! durability: the staged bytes are synced, the directory entry is not.
//!
//! # Threat model
//!
//! Other local accounts that can write to the requested parent directory or
//! any of its ancestors may retarget those paths at any time, by swapping a
//! symlink or renaming a directory and putting another in its place. On Unix
//! the parent is opened once when staging starts and every later step
//! (destination checks, staging, publication, cleanup) is relative to that
//! handle, so output only ever lands in the directory object selected then.
//!
//! The same actors may substitute another file at a staging name. On Linux,
//! output is staged as an unnamed `O_TMPFILE` and linked into place through
//! its open descriptor, so there is no staging name to substitute. Elsewhere,
//! and on Linux filesystems without `O_TMPFILE` or without procfs, the staging
//! file has a hidden random name: publication is refused when that name no
//! longer refers to the file this process wrote, and an entry that turns out
//! not to be the staged file after the atomic publish fails the command
//! loudly. No-clobber publication then removes that entry, while replacement
//! reports that the previous content could not be preserved.
//!
//! Actors running as the same user are out of scope, since they can already
//! write the output or the process itself. A filesystem that lacks a required
//! primitive produces an error rather than a silently weaker publication.
//!
//! On Windows the parent directory is held open without delete sharing while
//! output is staged, so the operating system refuses to rename or delete that
//! directory, and publication goes through `tempfile`'s path-based rename.
//! Retargeting an ancestor of the parent and substituting the staging name
//! are not prevented there, and this path has not been verified natively.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use packetcraftr_core::error::{Classification, Kind};

use crate::errors::CliError;
use crate::output::envelope::source_causes;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(all(test, unix))]
mod tests;

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLISH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, packetcraftr_proc_fd_paths))]
thread_local! {
    static FORCE_NAMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs the test hook installed for the current thread, after the
/// pre-publication checks and immediately before the publishing call.
fn before_publish() {
    #[cfg(test)]
    if let Some(hook) = BEFORE_PUBLISH.take() {
        hook();
    }
}

const CLASSIFICATION: Classification = Classification::new(
    "io.output_file",
    Kind::Io,
    Some("choose a destination that does not exist inside a writable directory"),
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Publication {
    NoClobber,
    Replace,
}

impl Publication {
    fn action(self) -> &'static str {
        match self {
            Self::NoClobber => "publish",
            Self::Replace => "replace",
        }
    }
}

/// What the bound directory holds at the destination name.
#[derive(Debug)]
enum Existing {
    Missing,
    Regular(platform::Permissions),
    Other,
}

#[derive(Debug)]
pub(crate) struct StagedFile {
    staged: platform::Staged,
    file_name: std::ffi::OsString,
    /// The requested path, for messages and reports.
    destination: PathBuf,
    invocation: crate::invocation::Invocation,
    publication: Publication,
    permissions: Option<platform::Permissions>,
}

impl StagedFile {
    /// Refuses a destination that already exists — including a dangling
    /// symlink — or that names a directory rather than a file, before any
    /// input is read. The parent directory is bound at this point.
    pub(crate) fn stage(
        invocation: &crate::invocation::Invocation,
        destination: &Path,
    ) -> Result<Self, CliError> {
        Self::stage_mode(invocation, destination, Publication::NoClobber)
    }

    /// Stage regeneration of a missing or regular file. Other output remains
    /// no-clobber through `stage` and `persist`.
    pub(crate) fn stage_replacement(
        invocation: &crate::invocation::Invocation,
        destination: &Path,
    ) -> Result<Self, CliError> {
        Self::stage_mode(invocation, destination, Publication::Replace)
    }

    fn stage_mode(
        invocation: &crate::invocation::Invocation,
        destination: &Path,
        publication: Publication,
    ) -> Result<Self, CliError> {
        invocation.check()?;
        let Some(file_name) = file_name(destination) else {
            return Err(CliError::from_classification(
                CLASSIFICATION,
                format!(
                    "output destination {} requires a file name",
                    destination.display()
                ),
                Vec::new(),
            ));
        };
        let requested = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = platform::Directory::open(requested)
            .map_err(|source| output("stage", destination, source))?;
        let existing = directory
            .existing(file_name)
            .map_err(|source| output("inspect", destination, source))?;
        let permissions = match (publication, existing) {
            (_, Existing::Missing) => None,
            (Publication::Replace, Existing::Regular(permissions)) => Some(permissions),
            (_, Existing::Regular(_) | Existing::Other) => {
                return Err(CliError::from_classification(
                    CLASSIFICATION,
                    format!(
                        "output destination {} already exists",
                        destination.display()
                    ),
                    Vec::new(),
                ));
            }
        };
        // Match ordinary file creation (0666 filtered by the process umask)
        // for new documentation, while other staged output stays private.
        let ordinary = publication == Publication::Replace && permissions.is_none();
        let staged = directory
            .stage(ordinary)
            .map_err(|source| output("stage", destination, source))?;
        Ok(Self {
            staged,
            file_name: file_name.to_owned(),
            destination: destination.to_owned(),
            invocation: invocation.clone(),
            publication,
            permissions,
        })
    }

    pub(crate) fn as_file_mut(&mut self) -> &mut std::fs::File {
        self.staged.file_mut()
    }

    /// Durably flushes the staged bytes. Callers check cancellation and deadlines
    /// after this potentially blocking operation, before persisting. Callers
    /// publishing several files sync every file before persisting any.
    pub(crate) fn sync(&self) -> Result<(), CliError> {
        self.invocation.check()?;
        // Apply the original mode after writing: Unix writes can clear set-ID
        // bits. Sync both bytes and permissions before publication.
        if let Some(permissions) = &self.permissions {
            self.staged
                .set_permissions(permissions)
                .map_err(|source| output("set permissions for", &self.destination, source))?;
        }
        self.staged
            .file()
            .sync_all()
            .map_err(|source| output("sync", &self.destination, source))?;
        self.invocation.check()
    }

    /// Publishes into the directory bound at staging, without overwriting
    /// unless staged as a replacement.
    pub(crate) fn persist(self) -> Result<Published, CliError> {
        // This is the commit boundary. Expiry after a successful publication
        // must not claim that the already-published artifact was unpublished.
        self.invocation.check()?;
        if self.publication == Publication::Replace {
            self.check_replaceable()?;
        }
        let Self {
            staged,
            file_name,
            destination,
            publication,
            ..
        } = self;
        staged
            .publish(&file_name, publication)
            .map_err(|source| output(publication.action(), &destination, source))?;
        Ok(Published { destination })
    }

    fn check_replaceable(&self) -> Result<(), CliError> {
        let inspect = |source| output("inspect replacement destination", &self.destination, source);
        match self.staged.existing(&self.file_name).map_err(inspect)? {
            Existing::Missing | Existing::Regular(_) => Ok(()),
            Existing::Other => Err(inspect(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "replacement requires a regular file or missing destination",
            ))),
        }
    }
}

/// A file this invocation published.
#[derive(Debug)]
pub(crate) struct Published {
    destination: PathBuf,
}

impl Published {
    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }
}

/// The destination's file name, unless the path names a directory. Path
/// components normalize trailing separators and `/.`, so the raw bytes decide.
fn file_name(destination: &Path) -> Option<&OsStr> {
    let bytes = destination.as_os_str().as_encoded_bytes();
    let ends_in_separator = bytes
        .last()
        .is_some_and(|byte| std::path::is_separator(char::from(*byte)));
    let ends_in_current_directory = bytes.ends_with(b".")
        && bytes
            .get(bytes.len().saturating_sub(2))
            .is_some_and(|byte| std::path::is_separator(char::from(*byte)));
    if ends_in_separator || ends_in_current_directory {
        return None;
    }
    destination.file_name()
}

fn output(action: &'static str, destination: &Path, source: std::io::Error) -> CliError {
    CliError::from_classification(
        CLASSIFICATION,
        format!("{action} output {}", destination.display()),
        source_causes(&source),
    )
}
