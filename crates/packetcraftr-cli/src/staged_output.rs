// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use packetcraftr_core::error::{Classification, Kind};

use crate::cancellation::StagedRegistration;
use crate::errors::{CliError, source_causes};

const CLASSIFICATION: Classification = Classification::new(
    "io.output_file",
    Kind::Io,
    Some("choose a destination that does not exist inside a writable directory"),
);

#[derive(Debug)]
pub(crate) struct StagedFile {
    file: tempfile::NamedTempFile,
    selected_parent: PathBuf,
    publication_destination: PathBuf,
    destination: PathBuf,
    /// Declared last so the file is unlinked before its path is deregistered.
    _registration: StagedRegistration,
}

impl StagedFile {
    /// Refuses a destination that already exists — including a dangling
    /// symlink — before any input is read.
    pub(crate) fn stage(destination: &Path) -> Result<Self, CliError> {
        let parent = Self::resolve_parent(destination)?;
        Self::stage_in_parent(destination, &parent)
    }

    pub(crate) fn resolve_parent(destination: &Path) -> Result<PathBuf, CliError> {
        crate::cancellation::check()?;
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::canonicalize(parent).map_err(|source| output("stage", destination, source))
    }

    pub(crate) fn stage_in_parent(
        destination: &Path,
        selected_parent: &Path,
    ) -> Result<Self, CliError> {
        crate::cancellation::check()?;
        // Path components normalize trailing separators and `/.`. Preserve
        // their directory requirement rather than publishing a regular file.
        let bytes = destination.as_os_str().as_encoded_bytes();
        let ends_in_separator = bytes
            .last()
            .is_some_and(|byte| std::path::is_separator(char::from(*byte)));
        let ends_in_current_directory = bytes.ends_with(b".")
            && bytes
                .get(bytes.len().saturating_sub(2))
                .is_some_and(|byte| std::path::is_separator(char::from(*byte)));
        if ends_in_separator || ends_in_current_directory || destination.file_name().is_none() {
            return Err(CliError::from_classification(
                CLASSIFICATION,
                format!(
                    "output destination {} requires a file name",
                    destination.display()
                ),
                Vec::new(),
            ));
        }
        let suffix = destination
            .strip_prefix(destination.parent().unwrap_or(Path::new("")))
            .map_err(|source| {
                CliError::from_classification(
                    CLASSIFICATION,
                    format!("stage output {}", destination.display()),
                    source_causes(&source),
                )
            })?;
        let publication_destination = selected_parent.join(suffix);
        match std::fs::symlink_metadata(&publication_destination) {
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
        // Staging, publication, and cleanup use the directory selected initially.
        let file = tempfile::NamedTempFile::new_in(selected_parent)
            .map_err(|source| output("stage", destination, source))?;
        let registration = StagedRegistration::new(file.path());
        Ok(Self {
            file,
            selected_parent: selected_parent.to_owned(),
            publication_destination,
            destination: destination.to_owned(),
            _registration: registration,
        })
    }

    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }

    pub(crate) fn publication_destination(&self) -> &Path {
        &self.publication_destination
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

    pub(crate) fn persist(self) -> Result<(), CliError> {
        // This is the commit boundary. Expiry after a successful rename must
        // not claim that the already-published artifact was rolled back.
        crate::cancellation::check()?;
        if Self::resolve_parent(&self.destination)? != self.selected_parent {
            return Err(CliError::from_classification(
                CLASSIFICATION,
                format!(
                    "output parent for {} changed since staging",
                    self.destination.display()
                ),
                Vec::new(),
            ));
        }
        let destination = self.destination;
        self.file
            .persist_noclobber(&self.publication_destination)
            .map_err(|error| output("publish", &destination, error.error))?;
        Ok(())
    }
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

    #[cfg(unix)]
    #[test]
    fn a_parent_alias_retargeted_to_a_collision_preserves_files_and_cleans_staging() {
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
    fn a_parent_alias_retargeted_to_an_empty_directory_is_refused_without_publishing() {
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

    #[test]
    fn unresolved_directory_suffixes_are_not_published_as_regular_files() {
        for suffix in ["/", "/."] {
            let directory = tempfile::tempdir().expect("destination directory");
            let mut name = directory.path().join("out").into_os_string();
            name.push(suffix);
            let destination = PathBuf::from(name);
            match StagedFile::stage(&destination) {
                Ok(mut staged) => {
                    staged.as_file_mut().write_all(b"payload").unwrap();
                    assert!(staged.persist().is_err());
                }
                Err(error) => assert_eq!(error.classification.code, "io.output_file"),
            }
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[cfg(packetcraftr_test_non_utf8_paths)]
    #[test]
    fn a_non_utf8_destination_is_published_losslessly() {
        use std::ffi::OsString;
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
