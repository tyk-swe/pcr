// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Staged output publication bound to the directory selected before input is
//! read.
//!
//! A destination is staged as a temporary file inside its parent directory and
//! published with a no-clobber rename. Both steps go through an
//! [`OutputDirectory`] opened at staging time: with procfs, staging,
//! publication, and rollback address the directory handle itself, so a parent
//! path retargeted by another local actor (symlink swap or a renamed and
//! replaced directory) cannot redirect the output. Elsewhere staging and
//! publication use the physical directory resolved at staging, its identity is
//! re-verified immediately before publication and rollback, and a change is
//! refused.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use packetcraftr_core::error::{Classification, Kind};

use crate::cancellation::StagedRegistration;
use crate::errors::{CliError, source_causes};

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
    handle_relative: bool,
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
            let (base, handle_relative) = match proc_fd_base(&handle, identity) {
                Some(base) => (base, true),
                // Without handle-relative paths, stage and publish at the
                // physical directory resolved now, so a later change to an
                // alias in the requested path cannot move the staged file.
                None => (std::fs::canonicalize(requested).map_err(stage)?, false),
            };
            Ok(Self {
                requested: requested.to_owned(),
                _handle: handle,
                identity,
                base,
                handle_relative,
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
                handle_relative: false,
            })
        }
    }

    fn join(&self, name: &OsStr) -> PathBuf {
        self.base.join(name)
    }

    /// Whether the requested parent still resolves to the directory selected
    /// at staging.
    fn still_bound(&self) -> std::io::Result<bool> {
        Identity::current(&self.requested).map(|identity| identity == self.identity)
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
    /// Declared last so the file is unlinked before its path is deregistered.
    _registration: StagedRegistration,
}

impl StagedFile {
    /// Refuses a destination that already exists — including a dangling
    /// symlink — or that names a directory rather than a file, before any
    /// input is read. The parent directory is bound at this point.
    pub(crate) fn stage(destination: &Path) -> Result<Self, CliError> {
        crate::cancellation::check()?;
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
        let file = tempfile::NamedTempFile::new_in(&parent.base)
            .map_err(|source| output("stage", destination, source))?;
        let registration = StagedRegistration::new(file.path());
        Ok(Self {
            file,
            parent,
            file_name: file_name.to_owned(),
            destination: destination.to_owned(),
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
        crate::cancellation::check()?;
        self.file
            .as_file()
            .sync_all()
            .map_err(|source| output("sync", &self.destination, source))?;
        crate::cancellation::check()
    }

    /// Publishes into the directory bound at staging without overwriting.
    pub(crate) fn persist(self) -> Result<Published, CliError> {
        // This is the commit boundary. Expiry after a successful rename must
        // not claim that the already-published artifact was rolled back.
        crate::cancellation::check()?;
        self.parent.verify_unchanged(&self.destination)?;
        // `parent` is bound before `file` so it drops after it: a failed
        // rename unlinks the staged file through the still-open handle.
        let Self {
            parent,
            file,
            file_name,
            destination,
            _registration,
        } = self;
        file.persist_noclobber(parent.join(&file_name))
            .map_err(|error| output("publish", &destination, error.error))?;
        Ok(Published {
            parent,
            file_name,
            destination,
        })
    }
}

/// A file this invocation published, removable through the directory it was
/// published into.
#[derive(Debug)]
pub(crate) struct Published {
    parent: OutputDirectory,
    file_name: OsString,
    destination: PathBuf,
}

impl Published {
    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }

    /// Removes exactly the file this invocation published; refuses when the
    /// requested parent no longer resolves to the publication directory.
    pub(crate) fn remove(&self) -> std::io::Result<()> {
        if !self.parent.handle_relative && !self.parent.still_bound()? {
            return Err(std::io::Error::other(
                "output parent changed since publication",
            ));
        }
        std::fs::remove_file(self.parent.join(&self.file_name))
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[cfg(unix)]
    fn aliased_directories() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("root directory");
        let original = root.path().join("original");
        let replacement = root.path().join("replacement");
        let alias = root.path().join("alias");
        std::fs::create_dir(&original).expect("original directory");
        std::fs::create_dir(&replacement).expect("replacement directory");
        std::os::unix::fs::symlink(&original, &alias).expect("parent alias");
        std::fs::write(original.join("source.pcap"), b"source capture").expect("source sentinel");
        (root, original, replacement, alias)
    }

    #[test]
    fn stage_rejects_an_existing_destination_without_staging() {
        let directory = tempfile::tempdir().expect("destination dir");
        let occupied = directory.path().join("occupied.pcapng");
        std::fs::write(&occupied, b"mine").expect("occupying file");

        let error = StagedFile::stage(&occupied).expect_err("occupied destination fails");
        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(error.exit_code(), 5);
        assert!(error.message.contains("already exists"));
        assert!(error.message.contains("occupied.pcapng"));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read(&occupied).unwrap(), b"mine");
    }

    #[cfg(unix)]
    #[test]
    fn stage_rejects_a_dangling_symlink_without_staging() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("dangling.pcapng");
        std::os::unix::fs::symlink("missing-target", &destination).expect("dangling symlink");

        let error = StagedFile::stage(&destination).expect_err("dangling symlink fails");
        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.contains("already exists"));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_destination_appearing_after_staging_fails_publish_without_clobbering() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("out.pcapng");
        let staged = StagedFile::stage(&destination).expect("absent destination stages");
        std::fs::write(&destination, b"someone else").expect("colliding file");

        staged.sync().expect("sync succeeds");
        let error = staged.persist().expect_err("colliding destination fails");
        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(error.exit_code(), 5);
        assert!(!error.causes.is_empty());
        assert_eq!(std::fs::read(&destination).unwrap(), b"someone else");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_staged_file_publishes_under_its_requested_name() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("out.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("stage");
        staged.as_file_mut().write_all(b"payload").unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);

        let published = staged.persist().expect("publish");

        assert_eq!(published.destination(), destination);
        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        published.remove().expect("remove published file");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_missing_parent_directory_is_refused_at_staging() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("missing").join("out.pcapng");

        let error = StagedFile::stage(&destination).expect_err("missing parent fails");

        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.starts_with("stage output "));
        assert!(!error.causes.is_empty());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn unresolved_directory_suffixes_are_refused_before_staging() {
        for suffix in ["/", "/."] {
            let directory = tempfile::tempdir().expect("destination directory");
            let mut name = directory.path().join("out").into_os_string();
            name.push(suffix);
            let destination = PathBuf::from(name);

            let error = StagedFile::stage(&destination).expect_err("directory suffix fails");

            assert_eq!(error.classification.code, "io.output_file");
            assert!(error.message.contains("requires a file name"));
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn collision_retarget_preserves_files_cleans_staging() {
        let (_root, original, replacement, alias) = aliased_directories();
        let destination = alias.join("out.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("stage through alias");
        staged
            .as_file_mut()
            .write_all(b"new capture")
            .expect("write staged capture");
        std::fs::write(replacement.join("out.pcapng"), b"existing capture")
            .expect("destination sentinel");
        std::fs::remove_file(&alias).expect("remove original alias");
        std::os::unix::fs::symlink(&replacement, &alias).expect("retarget parent alias");

        staged.sync().expect("sync original staged file");
        let error = staged.persist().expect_err("refuse existing destination");

        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(error.exit_code(), 5);
        assert!(error.message.contains("changed since staging"));
        assert!(error.message.contains(&destination.display().to_string()));
        assert_eq!(
            std::fs::read(replacement.join("out.pcapng")).unwrap(),
            b"existing capture"
        );
        assert_eq!(
            std::fs::read(original.join("source.pcap")).unwrap(),
            b"source capture"
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&replacement).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn empty_directory_retarget_refused() {
        let (_root, original, replacement, alias) = aliased_directories();
        let destination = alias.join("out.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("stage through alias");
        staged
            .as_file_mut()
            .write_all(b"new capture")
            .expect("write staged capture");
        std::fs::remove_file(&alias).expect("remove original alias");
        std::os::unix::fs::symlink(&replacement, &alias).expect("retarget parent alias");

        staged.sync().expect("sync original staged file");
        let error = staged.persist().expect_err("refuse retargeted parent");

        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.contains("changed since staging"));
        assert!(!destination.exists());
        assert!(!original.join("out.pcapng").exists());
        assert_eq!(
            std::fs::read(original.join("source.pcap")).unwrap(),
            b"source capture"
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&replacement).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_renamed_and_replaced_parent_is_refused_without_publishing() {
        let root = tempfile::tempdir().expect("root directory");
        let original = root.path().join("original");
        let replacement = root.path().join("replacement");
        let moved = root.path().join("moved");
        std::fs::create_dir(&original).expect("original directory");
        std::fs::create_dir(&replacement).expect("replacement directory");
        std::fs::write(original.join("source.pcap"), b"source capture").expect("source sentinel");
        std::fs::write(replacement.join("out.pcapng"), b"replacement sentinel")
            .expect("replacement sentinel");
        let destination = original.join("out.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("stage in original");
        staged
            .as_file_mut()
            .write_all(b"new capture")
            .expect("write staged capture");
        std::fs::rename(&original, &moved).expect("move the real directory away");
        std::fs::rename(&replacement, &original).expect("replace it at the same path");

        staged.sync().expect("sync staged file");
        let error = staged.persist().expect_err("refuse replaced parent");

        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.contains("changed since staging"));
        assert_eq!(
            std::fs::read(original.join("out.pcapng")).unwrap(),
            b"replacement sentinel"
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(moved.join("source.pcap")).unwrap(),
            b"source capture"
        );
        assert!(!moved.join("out.pcapng").exists());
        // Staged bytes travelled with the directory; only a handle-relative
        // path can still remove them.
        if cfg!(packetcraftr_proc_fd_paths) {
            assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
        }
    }

    #[cfg(packetcraftr_proc_fd_paths)]
    #[test]
    fn publication_binds_to_the_directory_handle_when_the_requested_path_moves() {
        let root = tempfile::tempdir().expect("root directory");
        let original = root.path().join("original");
        let moved = root.path().join("moved");
        std::fs::create_dir(&original).expect("original directory");
        let destination = original.join("out.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("stage in original");
        staged.as_file_mut().write_all(b"payload").unwrap();
        assert!(staged.file.path().starts_with("/proc/self/fd/"));
        std::fs::rename(&original, &moved).expect("move the real directory away");

        let error = staged
            .persist()
            .expect_err("refuse a missing requested parent");

        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.contains("changed since staging"));
        assert!(!error.causes.is_empty());
        assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 0);
        assert!(!original.exists());
    }

    #[cfg(unix)]
    #[test]
    fn published_remove_unlinks_exactly_the_published_file() {
        let (_root, original, replacement, alias) = aliased_directories();
        let destination = alias.join("out.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("stage through alias");
        staged.as_file_mut().write_all(b"payload").unwrap();
        let published = staged.persist().expect("publish through alias");
        assert_eq!(
            std::fs::read(original.join("out.pcapng")).unwrap(),
            b"payload"
        );
        std::fs::write(replacement.join("out.pcapng"), b"replacement sentinel").unwrap();
        std::fs::remove_file(&alias).expect("remove original alias");
        std::os::unix::fs::symlink(&replacement, &alias).expect("retarget parent alias");

        let removed = published.remove();

        if cfg!(packetcraftr_proc_fd_paths) {
            removed.expect("remove through the directory handle");
            assert!(!original.join("out.pcapng").exists());
        } else {
            let error = removed.expect_err("refuse a retargeted parent");
            assert!(error.to_string().contains("changed since publication"));
            assert_eq!(
                std::fs::read(original.join("out.pcapng")).unwrap(),
                b"payload"
            );
        }
        assert_eq!(
            std::fs::read(replacement.join("out.pcapng")).unwrap(),
            b"replacement sentinel"
        );
        assert_eq!(published.destination(), destination);
    }

    #[cfg(packetcraftr_test_non_utf8_paths)]
    #[test]
    fn a_non_utf8_destination_is_published_losslessly() {
        use std::os::unix::ffi::OsStringExt;

        let directory = tempfile::tempdir().expect("destination directory");
        let destination = directory
            .path()
            .join(OsString::from_vec(b"capture-\xff.pcap".to_vec()));
        let mut staged = StagedFile::stage(&destination).expect("stage non-UTF8 destination");
        staged.as_file_mut().write_all(b"payload").unwrap();

        staged.persist().expect("publish lossless destination");

        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
