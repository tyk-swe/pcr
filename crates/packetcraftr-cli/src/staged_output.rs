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
    use super::*;

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
}
