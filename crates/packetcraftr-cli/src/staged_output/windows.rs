// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Path-based publication while the parent directory is held open, so it
//! cannot be renamed or deleted until the staged file is gone.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{Existing, Publication, before_publish};
use crate::cancellation::{StagedEntry, StagedRegistration};

pub(super) type Permissions = std::fs::Permissions;

// Values from the Win32 `CreateFileW` documentation (winnt.h).
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

#[derive(Debug)]
pub(super) struct Directory {
    path: PathBuf,
    /// Omitting `FILE_SHARE_DELETE` makes Windows refuse to rename or delete
    /// this directory while the handle is open.
    _handle: File,
}

impl Directory {
    pub(super) fn open(requested: &Path) -> io::Result<Self> {
        let handle = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(requested)?;
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::from(io::ErrorKind::NotADirectory));
        }
        Ok(Self {
            path: requested.to_owned(),
            _handle: handle,
        })
    }

    pub(super) fn existing(&self, name: &OsStr) -> io::Result<Existing> {
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(metadata) if metadata.is_file() => Ok(Existing::Regular(metadata.permissions())),
            Ok(_) => Ok(Existing::Other),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Existing::Missing),
            Err(error) => Err(error),
        }
    }

    /// Windows has no creation mode to choose, so `_ordinary` changes nothing.
    pub(super) fn stage(self, _ordinary: bool) -> io::Result<Staged> {
        let file = tempfile::Builder::new().tempfile_in(&self.path)?;
        let registration = StagedRegistration::new(Arc::new(StagingPath(file.path().to_owned())));
        Ok(Staged {
            file,
            _registration: registration,
            directory: self,
        })
    }
}

#[derive(Debug)]
pub(super) struct Staged {
    /// Declared first so the temporary file is unlinked while the directory
    /// handle is still open and before its path is deregistered.
    file: tempfile::NamedTempFile,
    _registration: StagedRegistration,
    directory: Directory,
}

impl Staged {
    pub(super) fn file(&self) -> &File {
        self.file.as_file()
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        self.file.as_file_mut()
    }

    pub(super) fn existing(&self, name: &OsStr) -> io::Result<Existing> {
        self.directory.existing(name)
    }

    pub(super) fn set_permissions(&self, permissions: &Permissions) -> io::Result<()> {
        self.file.as_file().set_permissions(permissions.clone())
    }

    pub(super) fn publish(self, name: &OsStr, publication: Publication) -> io::Result<()> {
        let Self {
            file,
            _registration,
            directory,
        } = self;
        let destination = directory.path.join(name);
        before_publish();
        let published = match publication {
            Publication::NoClobber => file.persist_noclobber(&destination),
            Publication::Replace => file.persist(&destination),
        };
        published.map_err(|error| error.error)?;
        Ok(())
    }
}

#[derive(Debug)]
struct StagingPath(PathBuf);

impl StagedEntry for StagingPath {
    fn remove(&self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
