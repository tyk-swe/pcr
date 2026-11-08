// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Publication relative to a directory descriptor, so no step resolves the
//! requested parent path again after staging starts.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::{Existing, Publication, before_publish};
use crate::cancellation::{StagedEntry, StagedRegistration};

pub(super) type Permissions = Mode;

/// The parent directory, opened once when staging starts.
#[derive(Debug)]
pub(super) struct Directory(Arc<OwnedFd>);

impl Directory {
    pub(super) fn open(requested: &Path) -> io::Result<Self> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        Ok(Self(Arc::new(rustix::fs::open(
            requested,
            flags,
            Mode::empty(),
        )?)))
    }

    pub(super) fn existing(&self, name: &OsStr) -> io::Result<Existing> {
        match rustix::fs::statat(&*self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {
                Ok(Existing::Regular(Mode::from_raw_mode(stat.st_mode)))
            }
            Ok(_) => Ok(Existing::Other),
            Err(Errno::NOENT) => Ok(Existing::Missing),
            Err(error) => Err(error.into()),
        }
    }

    /// Creates the staging file: `ordinary` requests the mode of ordinary file
    /// creation instead of a private one.
    pub(super) fn stage(self, ordinary: bool) -> io::Result<Staged> {
        let mode = if ordinary {
            Mode::from_raw_mode(0o666)
        } else {
            Mode::RUSR | Mode::WUSR
        };
        #[cfg(packetcraftr_proc_fd_paths)]
        if let Some(file) = anchored(&self.0, mode) {
            return Ok(Staged {
                file,
                directory: self,
                staging: Staging::Anchored,
            });
        }
        let name = hidden_name()?;
        let flags =
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let file = File::from(rustix::fs::openat(&*self.0, &name, flags, mode)?);
        let named = Named::new(&self.0, name, &file)?;
        Ok(Staged {
            file,
            directory: self,
            staging: Staging::Named(named),
        })
    }
}

#[derive(Debug)]
pub(super) struct Staged {
    file: File,
    directory: Directory,
    staging: Staging,
}

#[derive(Debug)]
enum Staging {
    /// An unnamed `O_TMPFILE` whose procfs link was verified at staging.
    #[cfg(packetcraftr_proc_fd_paths)]
    Anchored,
    Named(Named),
}

impl Staged {
    pub(super) fn directory(&self) -> io::Result<Directory> {
        Ok(Directory(Arc::clone(&self.directory.0)))
    }

    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(super) fn existing(&self, name: &OsStr) -> io::Result<Existing> {
        self.directory.existing(name)
    }

    pub(super) fn set_permissions(&self, mode: &Mode) -> io::Result<()> {
        Ok(rustix::fs::fchmod(&self.file, *mode)?)
    }

    pub(super) fn publish(self, name: &OsStr, publication: Publication) -> io::Result<()> {
        let Self {
            file,
            directory: Directory(directory),
            staging,
        } = self;
        match staging {
            #[cfg(packetcraftr_proc_fd_paths)]
            Staging::Anchored => match publication {
                Publication::NoClobber => {
                    let link = proc_fd_path(&file);
                    before_publish();
                    rustix::fs::linkat(
                        rustix::fs::CWD,
                        &link,
                        &*directory,
                        name,
                        AtFlags::SYMLINK_FOLLOW,
                    )?;
                }
                Publication::Replace => {
                    let staging = hidden_name()?;
                    rustix::fs::linkat(
                        rustix::fs::CWD,
                        proc_fd_path(&file),
                        &*directory,
                        &staging,
                        AtFlags::SYMLINK_FOLLOW,
                    )?;
                    publish_named(&Named::new(&directory, staging, &file)?, name, publication)?;
                }
            },
            Staging::Named(named) => publish_named(&named, name, publication)?,
        }
        verify_published(&directory, &file, name, publication)
    }
}

/// Opens an unnamed file in `directory` when the filesystem supports
/// `O_TMPFILE` and procfs links its descriptor back to the same object.
#[cfg(packetcraftr_proc_fd_paths)]
fn anchored(directory: &OwnedFd, mode: Mode) -> Option<File> {
    #[cfg(test)]
    if super::FORCE_NAMED.get() {
        return None;
    }
    let flags = OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC;
    let file = File::from(rustix::fs::openat(directory, ".", flags, mode).ok()?);
    let linked = rustix::fs::stat(proc_fd_path(&file)).ok()?;
    same_object(&linked, &rustix::fs::fstat(&file).ok()?).then_some(file)
}

#[cfg(packetcraftr_proc_fd_paths)]
fn proc_fd_path(file: &File) -> String {
    use std::os::fd::AsRawFd;
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

fn publish_named(named: &Named, name: &OsStr, publication: Publication) -> io::Result<()> {
    let staging = &named.entry;
    if !staging.is_ours()? {
        return Err(io::Error::other(
            "staging entry no longer refers to the staged file",
        ));
    }
    let directory = &*staging.directory;
    before_publish();
    match publication {
        Publication::NoClobber => rename_noreplace(staging, name),
        Publication::Replace => Ok(rustix::fs::renameat(
            directory,
            &staging.name,
            directory,
            name,
        )?),
    }
}

/// Never implemented as an existence check followed by a replacing rename:
/// both branches fail atomically when `name` exists.
fn rename_noreplace(staging: &StagingName, name: &OsStr) -> io::Result<()> {
    let directory = &*staging.directory;
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    match rustix::fs::renameat_with(
        directory,
        &staging.name,
        directory,
        name,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => return Ok(()),
        Err(errno)
            if [Errno::INVAL, Errno::NOSYS, Errno::OPNOTSUPP, Errno::NOTSUP].contains(&errno) => {}
        Err(errno) => return Err(errno.into()),
    }
    rustix::fs::linkat(directory, &staging.name, directory, name, AtFlags::empty())?;
    staging.remove_if_ours();
    Ok(())
}

/// Turns a substitution that raced the atomic publication into a loud failure.
fn verify_published(
    directory: &OwnedFd,
    file: &File,
    name: &OsStr,
    publication: Publication,
) -> io::Result<()> {
    let published = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if same_object(&published, &rustix::fs::fstat(file)?) {
        return Ok(());
    }
    match publication {
        Publication::NoClobber => {
            // The no-clobber publish created this entry, so nothing that
            // existed before is lost by removing it.
            let _ = rustix::fs::unlinkat(directory, name, AtFlags::empty());
            Err(io::Error::other(
                "published entry is not the staged file and was removed",
            ))
        }
        Publication::Replace => Err(io::Error::other(
            "published entry is not the staged file, and the previous content could not be preserved",
        )),
    }
}

fn same_object(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn hidden_name() -> io::Result<OsString> {
    Ok(format!(
        ".packetcraftr-{:016x}.tmp",
        packetcraftr_netio::entropy::OsEntropy.u64()?
    )
    .into())
}

/// A staging file's name in the bound directory, removed on every failure,
/// on drop, and by a forced exit, but only while it still names the file
/// this process staged.
#[derive(Debug)]
struct Named {
    entry: Arc<StagingName>,
    _registration: StagedRegistration,
}

impl Named {
    fn new(directory: &Arc<OwnedFd>, name: OsString, file: &File) -> io::Result<Self> {
        let duplicate = match file.try_clone() {
            Ok(duplicate) => duplicate,
            Err(error) => {
                let _ = remove_if_names(directory, &name, file);
                return Err(error);
            }
        };
        let entry = Arc::new(StagingName {
            directory: Arc::clone(directory),
            name,
            file: duplicate,
        });
        let registration = StagedRegistration::new(Arc::clone(&entry) as Arc<dyn StagedEntry>);
        Ok(Self {
            entry,
            _registration: registration,
        })
    }
}

impl Drop for Named {
    fn drop(&mut self) {
        self.entry.remove_if_ours();
    }
}

#[derive(Debug)]
struct StagingName {
    directory: Arc<OwnedFd>,
    name: OsString,
    /// A duplicate of the staged file's descriptor, for identity checks.
    file: File,
}

impl StagingName {
    fn is_ours(&self) -> io::Result<bool> {
        names(&self.directory, &self.name, &self.file)
    }

    fn remove_if_ours(&self) {
        let _ = remove_if_names(&self.directory, &self.name, &self.file);
    }
}

impl StagedEntry for StagingName {
    fn remove(&self) {
        self.remove_if_ours();
    }
}

/// Whether `name` in `directory` is a link to `file` itself.
fn names(directory: &OwnedFd, name: &OsStr, file: &File) -> io::Result<bool> {
    let entry = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(same_object(&entry, &rustix::fs::fstat(file)?))
}

fn remove_if_names(directory: &OwnedFd, name: &OsStr, file: &File) -> io::Result<()> {
    if names(directory, name, file)? {
        rustix::fs::unlinkat(directory, name, AtFlags::empty())?;
    }
    Ok(())
}
