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
    destination: PathBuf,
    /// Declared last so the file is unlinked before its path is deregistered.
    _registration: StagedRegistration,
}

impl StagedFile {
    /// Refuses a destination that already exists — including a dangling
    /// symlink — before any input is read.
    pub(crate) fn stage(destination: &Path) -> Result<Self, CliError> {
        crate::cancellation::check()?;
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
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Resolve parent aliases so temporary-file cleanup keeps its original path.
        // Publication continues to use the requested destination.
        let parent =
            std::fs::canonicalize(parent).map_err(|source| output("stage", destination, source))?;
        let file = tempfile::NamedTempFile::new_in(parent)
            .map_err(|source| output("stage", destination, source))?;
        let registration = StagedRegistration::new(file.path());
        Ok(Self {
            file,
            destination: destination.to_owned(),
            _registration: registration,
        })
    }

    pub(crate) fn destination(&self) -> &Path {
        &self.destination
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
        let destination = self.destination;
        self.file
            .persist_noclobber(&destination)
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
    #[cfg(unix)]
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
    fn a_parent_alias_retargeted_to_an_empty_directory_publishes_at_the_requested_path() {
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
        staged.persist().expect("publish at retargeted destination");

        assert_eq!(std::fs::read(&destination).unwrap(), b"new capture");
        assert_eq!(
            std::fs::read(original.join("source.pcap")).unwrap(),
            b"source capture"
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&replacement).unwrap().count(), 1);
    }
}
