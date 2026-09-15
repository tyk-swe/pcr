// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Atomic publication of command output files: stage beside the destination,
//! sync, then rename without clobbering. Shared by every `--write` path.

use std::path::{Path, PathBuf};

use packetcraftr_core::error::{Classification, Kind};

use crate::errors::CliError;

/// One classification for every staged-output failure.
const CLASSIFICATION: Classification = Classification::new(
    "io.output_file",
    Kind::Io,
    Some("choose a destination that does not exist inside a writable directory"),
);

/// A temporary output file staged beside the path it publishes to.
#[derive(Debug)]
pub(crate) struct StagedFile {
    file: tempfile::NamedTempFile,
    destination: PathBuf,
}

impl StagedFile {
    /// Refuses a destination that already exists — including a dangling
    /// symlink — before any input is read, then stages a temporary file in
    /// the destination's directory so publication is a same-filesystem rename.
    pub(crate) fn stage(destination: &Path) -> Result<Self, CliError> {
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
        Ok(Self {
            file,
            destination: destination.to_owned(),
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
        self.file
            .as_file()
            .sync_all()
            .map_err(|source| output("sync", &self.destination, source))
    }

    /// Publishes the staged file at its destination without clobbering.
    pub(crate) fn persist(self) -> Result<(), CliError> {
        let destination = self.destination;
        self.file
            .persist_noclobber(&destination)
            .map_err(|error| output("publish", &destination, error.error))?;
        Ok(())
    }
}

fn output(action: &'static str, destination: &Path, source: std::io::Error) -> CliError {
    let causes = std::iter::once(source.to_string())
        .chain(packetcraftr_core::error::source_chain(&source))
        .collect();
    CliError::from_classification(
        CLASSIFICATION,
        format!("{action} output {}: {source}", destination.display()),
        causes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::error::Classified;
    use std::io::Write;

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
    fn publish_writes_the_staged_bytes_to_the_destination() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("out.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("absent destination stages");
        staged.as_file_mut().write_all(b"payload").unwrap();
        staged.sync().expect("sync succeeds");
        staged.persist().expect("publish succeeds");
        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
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
        // The un-published staged file cleans itself up.
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn output_failures_preserve_the_io_source_chain() {
        #[derive(Debug, thiserror::Error)]
        #[error("storage backend failed")]
        struct StorageFailure;

        let source = std::io::Error::other(StorageFailure);
        let error = output("stage", Path::new("out.pcapng"), source);

        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(error.causes, ["storage backend failed"]);
        assert_eq!(
            error.output_error().causes,
            ["storage backend failed"],
            "machine output retains the I/O source"
        );
        assert_eq!(
            error.into_boundary_error().causes(),
            ["storage backend failed"],
            "boundary errors retain the I/O source"
        );
    }
}
