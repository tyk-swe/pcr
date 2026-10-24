// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Staged output publication bound to the directory selected before input is
//! read.
//!
//! A destination is staged as a temporary file inside its parent directory and
//! published with a no-clobber rename. Documentation regeneration uses a
//! separate replacement entrypoint for missing destinations or regular files,
//! keeping the original until atomic rename. Both steps go through an
//! [`OutputDirectory`] opened at staging time: with procfs, staging and
//! publication address the directory handle itself, so a parent path retargeted
//! by another local actor (symlink swap or a renamed and replaced directory)
//! cannot redirect the output. Elsewhere staging and publication use the
//! physical directory resolved at staging, its identity is re-verified
//! immediately before publication, and a change is refused.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use packetcraftr_core::error::{Classification, Kind};

use crate::cancellation::StagedRegistration;
use crate::errors::CliError;
use crate::output::envelope::source_causes;

const CLASSIFICATION: Classification = Classification::new(
    "io.output_file",
    Kind::Io,
    Some("choose a destination that does not exist inside a writable directory"),
);

/// Identity of a directory, compared to detect a retargeted parent.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
}

/// Identity of a directory, compared to detect a retargeted parent. Handle
/// identity is unavailable on this platform, so the resolved path stands in.
#[cfg(not(unix))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity(PathBuf);

impl Identity {
    #[cfg(unix)]
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    /// The identity the requested parent path currently resolves to.
    fn current(requested: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            std::fs::metadata(requested).map(|metadata| Self::from_metadata(&metadata))
        }
        #[cfg(not(unix))]
        {
            std::fs::canonicalize(requested).map(Self)
        }
    }
}

/// The parent directory selected at staging time.
#[derive(Debug)]
struct OutputDirectory {
    /// The parent path as requested, kept for messages and for platforms
    /// without handle-relative paths.
    requested: PathBuf,
    /// Held for the staged file's lifetime: it keeps the directory inode alive
    /// so a replacement cannot reuse it, and procfs paths resolve through it.
    #[cfg(unix)]
    _handle: std::fs::File,
    identity: Identity,
    /// Where staged files are created and published: the handle-relative
    /// procfs path when available, otherwise the physical directory the
    /// requested path resolved to at staging.
    base: PathBuf,
}

impl OutputDirectory {
    fn open(requested: &Path, destination: &Path) -> Result<Self, CliError> {
        let stage = |source| output("stage", destination, source);
        #[cfg(unix)]
        {
            let handle = std::fs::File::open(requested).map_err(stage)?;
            let metadata = handle.metadata().map_err(stage)?;
            if !metadata.is_dir() {
                return Err(stage(std::io::Error::from(
                    std::io::ErrorKind::NotADirectory,
                )));
            }
            let identity = Identity::from_metadata(&metadata);
            let base = match proc_fd_base(&handle, identity) {
                Some(base) => base,
                // Without handle-relative paths, stage and publish at the
                // physical directory resolved now, so a later change to an
                // alias in the requested path cannot move the staged file.
                None => std::fs::canonicalize(requested).map_err(stage)?,
            };
            Ok(Self {
                requested: requested.to_owned(),
                _handle: handle,
                identity,
                base,
            })
        }
        #[cfg(not(unix))]
        {
            let identity = Identity::current(requested).map_err(stage)?;
            if !std::fs::metadata(requested).map_err(stage)?.is_dir() {
                return Err(stage(std::io::Error::from(
                    std::io::ErrorKind::NotADirectory,
                )));
            }
            let base = identity.0.clone();
            Ok(Self {
                requested: requested.to_owned(),
                identity,
                base,
            })
        }
    }

    fn join(&self, name: &OsStr) -> PathBuf {
        self.base.join(name)
    }

    /// Refuses publication when the requested parent no longer resolves to the
    /// directory selected at staging.
    fn verify_unchanged(&self, destination: &Path) -> Result<(), CliError> {
        let causes = match Identity::current(&self.requested) {
            Ok(identity) if identity == self.identity => return Ok(()),
            Ok(_) => Vec::new(),
            Err(source) => source_causes(&source),
        };
        Err(CliError::from_classification(
            CLASSIFICATION,
            format!(
                "output parent for {} changed since staging",
                destination.display()
            ),
            causes,
        ))
    }
}

/// The handle-relative path of `handle` when procfs serves it for this process.
#[cfg(packetcraftr_proc_fd_paths)]
fn proc_fd_base(handle: &std::fs::File, identity: Identity) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    let base = PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()));
    let metadata = std::fs::metadata(&base).ok()?;
    (metadata.is_dir() && Identity::from_metadata(&metadata) == identity).then_some(base)
}

#[cfg(all(unix, not(packetcraftr_proc_fd_paths)))]
fn proc_fd_base(_handle: &std::fs::File, _identity: Identity) -> Option<PathBuf> {
    None
}

#[derive(Debug)]
pub(crate) struct StagedFile {
    /// Declared first so the temporary file is unlinked while the directory
    /// handle is still open.
    file: tempfile::NamedTempFile,
    parent: OutputDirectory,
    file_name: OsString,
    /// The requested path, for messages and reports.
    destination: PathBuf,
    invocation: crate::invocation::Invocation,
    replace: bool,
    permissions: Option<std::fs::Permissions>,
    /// Declared last so the file is unlinked before its path is deregistered.
    _registration: StagedRegistration,
}

impl StagedFile {
    /// Refuses a destination that already exists — including a dangling
    /// symlink — or that names a directory rather than a file, before any
    /// input is read. The parent directory is bound at this point.
    pub(crate) fn stage(
        invocation: &crate::invocation::Invocation,
        destination: &Path,
    ) -> Result<Self, CliError> {
        Self::stage_mode(invocation, destination, false)
    }

    /// Stage regeneration of a missing or regular file. Other output remains
    /// no-clobber through `stage` and `persist`.
    pub(crate) fn stage_replacement(
        invocation: &crate::invocation::Invocation,
        destination: &Path,
    ) -> Result<Self, CliError> {
        Self::stage_mode(invocation, destination, true)
    }

    fn stage_mode(
        invocation: &crate::invocation::Invocation,
        destination: &Path,
        replace: bool,
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
        match std::fs::symlink_metadata(destination) {
            Ok(metadata) if replace && metadata.is_file() => {}
            Ok(_) => {
                return Err(CliError::from_classification(
                    CLASSIFICATION,
                    format!(
                        "output destination {} already exists",
                        destination.display()
                    ),
                    Vec::new(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(output("inspect", destination, source)),
        }
        let requested = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = OutputDirectory::open(requested, destination)?;
        let permissions = if replace {
            replacement_permissions(&parent.join(file_name), destination)?
        } else {
            None
        };
        let file = tempfile::NamedTempFile::new_in(&parent.base)
            .map_err(|source| output("stage", destination, source))?;
        let registration = StagedRegistration::new(file.path());
        Ok(Self {
            file,
            parent,
            file_name: file_name.to_owned(),
            destination: destination.to_owned(),
            invocation: invocation.clone(),
            replace,
            permissions,
            _registration: registration,
        })
    }

    pub(crate) fn as_file_mut(&mut self) -> &mut std::fs::File {
        self.file.as_file_mut()
    }

    /// Durably flushes the staged bytes. Callers check cancellation and deadlines
    /// after this potentially blocking operation, before persisting. Callers
    /// publishing several files sync every file before persisting any.
    pub(crate) fn sync(&self) -> Result<(), CliError> {
        self.invocation.check()?;
        // Apply the original mode after writing: Unix writes can clear set-ID
        // bits. Sync both bytes and permissions before publication.
        if let Some(permissions) = &self.permissions {
            self.file
                .as_file()
                .set_permissions(permissions.clone())
                .map_err(|source| output("set permissions for", &self.destination, source))?;
        }
        self.file
            .as_file()
            .sync_all()
            .map_err(|source| output("sync", &self.destination, source))?;
        self.invocation.check()
    }

    /// Publishes into the directory bound at staging without overwriting.
    pub(crate) fn persist(self) -> Result<Published, CliError> {
        // This is the commit boundary. Expiry after a successful rename must
        // not claim that the already-published artifact was unpublished.
        self.invocation.check()?;
        self.parent.verify_unchanged(&self.destination)?;
        if self.replace {
            replacement_permissions(&self.parent.join(&self.file_name), &self.destination)?;
        }
        // `parent` is bound before `file` so it drops after it: a failed
        // rename unlinks the staged file through the still-open handle.
        let Self {
            parent,
            file,
            file_name,
            destination,
            _registration,
            replace,
            ..
        } = self;
        if replace {
            file.persist(parent.join(&file_name))
                .map_err(|error| output("replace", &destination, error.error))?;
        } else {
            file.persist_noclobber(parent.join(&file_name))
                .map_err(|error| output("publish", &destination, error.error))?;
        }
        Ok(Published { destination })
    }
}

fn replacement_permissions(
    path: &Path,
    destination: &Path,
) -> Result<Option<std::fs::Permissions>, CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata.permissions())),
        Ok(_) => Err(output(
            "inspect replacement destination",
            destination,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "replacement requires a regular file or missing destination",
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(output(
            "inspect replacement destination",
            destination,
            source,
        )),
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
