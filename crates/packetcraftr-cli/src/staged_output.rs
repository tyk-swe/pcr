// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Atomic publication of command output files: stage beside the destination,
//! sync, then rename without clobbering. Shared by every `--write` path.
//!
//! A command generating several artifacts keeps one open [`StagedFile`] at a
//! time, turning each completed file into a [`SealedFile`] — a synchronized,
//! closed temporary path that publishes later. [`publish_ordered`] commits
//! such files in order and rolls back only what this invocation created.

use std::path::{Path, PathBuf};

use packetcraftr_core::error::{Classification, Kind};

use crate::errors::CliError;

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

/// The absent-destination check [`StagedFile::stage`] performs, for commands
/// that validate every predicted destination before generating any output: a
/// file, a dangling symlink, or an uninspectable path all fail the same way
/// staging would.
pub(crate) fn check_absent(destination: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(destination) {
        Ok(_) => Err(occupied(destination)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(output("inspect", destination, source)),
    }
}

/// The `io.output_file` refusal for a destination already present.
fn occupied(destination: &Path) -> CliError {
    CliError::from_classification(
        CLASSIFICATION,
        format!(
            "output destination {} already exists",
            destination.display()
        ),
        Vec::new(),
    )
}

/// The `io.output_file` refusal for a path that exists but cannot hold
/// staged outputs.
pub(crate) fn invalid_directory(directory: &Path) -> CliError {
    CliError::from_classification(
        CLASSIFICATION,
        format!(
            "output directory {} is not a directory",
            directory.display()
        ),
        Vec::new(),
    )
}

impl StagedFile {
    /// Refuses a destination that already exists — including a dangling
    /// symlink — before any input is read, then stages a temporary file in
    /// the destination's directory so publication is a same-filesystem rename.
    pub(crate) fn stage(destination: &Path) -> Result<Self, CliError> {
        crate::cancellation::check()?;
        check_absent(destination)?;
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
        crate::cancellation::check()?;
        self.file
            .as_file()
            .sync_all()
            .map_err(|source| output("sync", &self.destination, source))?;
        crate::cancellation::check()
    }

    /// Syncs the staged bytes and closes the descriptor, keeping the private
    /// temporary path for a later no-clobber [`SealedFile::persist`]. A command
    /// generating several artifacts seals each one as its bytes complete, so
    /// only one output descriptor is ever open.
    pub(crate) fn seal(self) -> Result<SealedFile, CliError> {
        self.seal_with(Self::sync)
    }

    /// `seal` with the synchronization injectable, as in `follow`'s
    /// `publish_with`: a sync failure abandons the staged temporary file.
    fn seal_with(
        self,
        sync: impl FnOnce(&Self) -> Result<(), CliError>,
    ) -> Result<SealedFile, CliError> {
        sync(&self)?;
        let Self { file, destination } = self;
        Ok(SealedFile {
            path: file.into_temp_path(),
            destination,
        })
    }

    /// Publishes the staged file at its destination without clobbering.
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

/// A synchronized staged file whose descriptor is closed: only its private
/// temporary path remains, publishable once at `destination` without
/// clobbering. Dropping it removes the unpublished path, best effort, exactly
/// as an un-committed [`StagedFile`] does.
#[derive(Debug)]
pub(crate) struct SealedFile {
    path: tempfile::TempPath,
    destination: PathBuf,
}

impl SealedFile {
    /// The path [`persist`](Self::persist) publishes this file at.
    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }

    /// Publishes the sealed file at its destination without clobbering.
    pub(crate) fn persist(self) -> Result<(), CliError> {
        // This is the commit boundary, exactly as for StagedFile::persist:
        // expiry after a successful rename must not claim rollback.
        crate::cancellation::check()?;
        let destination = self.destination;
        self.path
            .persist_noclobber(&destination)
            .map_err(|error| output("publish", &destination, error.error))?;
        Ok(())
    }
}

/// A file [`publish_ordered`] commits: `destination` names the path the
/// publish creates, which ordered rollback removes again.
pub(crate) trait Publishable {
    /// The path this file commits at.
    fn destination(&self) -> &Path;
}

impl Publishable for StagedFile {
    fn destination(&self) -> &Path {
        self.destination()
    }
}

impl Publishable for SealedFile {
    fn destination(&self) -> &Path {
        self.destination()
    }
}

/// Publishes `files` in the given order through `persist`, which performs the
/// no-clobber commit. The returned paths are the destinations created, in the
/// same order.
///
/// On the first commit failure — including interruption — `remove` deletes
/// each destination this invocation already published, in commit order; a
/// destination whose commit failed is never touched. The primary error keeps
/// its classification, message, and causes, amended with the rolled-back
/// count; each failed removal appends as a `{owner} rollback` secondary
/// naming its remaining path. This is not a multi-file transaction: after a
/// rollback failure some committed paths may remain, and the report says how
/// many were removed.
pub(crate) fn publish_ordered<F, T>(
    files: Vec<(F, T)>,
    owner: &'static str,
    mut persist: impl FnMut(F) -> Result<(), CliError>,
    mut remove: impl FnMut(&Path) -> std::io::Result<()>,
) -> Result<Vec<T>, CliError>
where
    F: Publishable,
{
    let mut published = Vec::new();
    let mut reports = Vec::new();
    for (file, report) in files {
        let destination = file.destination().to_owned();
        match persist(file) {
            Ok(()) => {
                published.push(destination);
                reports.push(report);
            }
            Err(error) => {
                let mut rolled_back = 0;
                let mut failures = Vec::new();
                for path in &published {
                    match remove(path) {
                        Ok(()) => rolled_back += 1,
                        Err(source) => failures.push(CliError::new(
                            Kind::Io,
                            format!(
                                "remove published {owner} output {}: {source}",
                                path.display()
                            ),
                        )),
                    }
                }
                let mut failure = CliError::from_classification(
                    error.classification,
                    format!(
                        "{}; rolled back {rolled_back} published file(s)",
                        error.message,
                    ),
                    error.causes,
                );
                for cleanup in failures {
                    failure = failure.with_secondary(&format!("{owner} rollback"), cleanup);
                }
                return Err(failure);
            }
        }
    }
    Ok(reports)
}

/// An artifact I/O failure (`io.output_file`), keeping the error's own text
/// and its source chain — including a compression wrapper — in the causes.
pub(crate) fn output(
    action: &'static str,
    destination: &Path,
    source: impl std::error::Error,
) -> CliError {
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
    #[test]
    fn a_sealed_file_publishes_the_staged_bytes_at_its_destination() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("sealed.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("absent destination stages");
        staged.as_file_mut().write_all(b"payload").unwrap();

        let sealed = staged.seal().expect("seal succeeds");
        assert_eq!(sealed.destination(), destination.as_path());
        sealed.persist().expect("publish succeeds");
        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
    }

    #[test]
    fn a_seal_sync_failure_abandons_the_staged_temporary_file() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("sealed.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("absent destination stages");
        staged.as_file_mut().write_all(b"payload").unwrap();

        let error = staged
            .seal_with(|_| Err(CliError::new(Kind::Io, "injected sync failure")))
            .expect_err("the injected sync fails");
        assert!(error.message.contains("injected sync failure"));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(!destination.exists());
    }

    #[test]
    fn an_unpublished_sealed_file_removes_its_temporary_path_on_drop() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("unpublished.pcapng");
        let mut staged = StagedFile::stage(&destination).expect("absent destination stages");
        staged.as_file_mut().write_all(b"discarded").unwrap();

        let sealed = staged.seal().expect("seal succeeds");
        drop(sealed);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(!destination.exists());
    }

    #[test]
    fn a_sealed_file_rereads_the_absent_destination_at_publish() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("sealed.pcapng");
        let staged = StagedFile::stage(&destination).expect("absent destination stages");
        let sealed = staged.seal().expect("seal succeeds");
        std::fs::write(&destination, b"someone else").expect("colliding file");

        let error = sealed.persist().expect_err("colliding destination fails");
        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(std::fs::read(&destination).unwrap(), b"someone else");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    /// Seals one named part file per index.
    fn sealed_parts(directory: &Path, count: u64) -> Vec<(SealedFile, u64)> {
        (1..=count)
            .map(|index| {
                let destination = directory.join(format!("part-{index:06}.pcapng"));
                let mut staged =
                    StagedFile::stage(&destination).expect("absent destination stages");
                staged
                    .as_file_mut()
                    .write_all(format!("part {index}").as_bytes())
                    .unwrap();
                (staged.seal().expect("seal succeeds"), index)
            })
            .collect()
    }

    #[test]
    fn ordered_publication_commits_every_file_in_order_and_returns_reports() {
        let directory = tempfile::tempdir().expect("destination dir");
        let files = sealed_parts(directory.path(), 3);
        let reports = publish_ordered(files, "split", SealedFile::persist, |path| {
            std::fs::remove_file(path)
        })
        .expect("publish succeeds");
        assert_eq!(reports, [1, 2, 3]);
        for index in 1..=3_u64 {
            assert_eq!(
                std::fs::read(directory.path().join(format!("part-{index:06}.pcapng"))).unwrap(),
                format!("part {index}").as_bytes()
            );
        }
    }

    #[test]
    fn a_failed_commit_rolls_back_only_what_this_invocation_published() {
        let directory = tempfile::tempdir().expect("destination dir");
        let files = sealed_parts(directory.path(), 3);
        let mut commits = 0;
        let error = publish_ordered(
            files,
            "split",
            |sealed| {
                commits += 1;
                if commits == 2 {
                    Err(CliError::new(Kind::Io, "injected commit failure"))
                } else {
                    sealed.persist()
                }
            },
            |path| std::fs::remove_file(path),
        )
        .expect_err("the second commit fails");
        assert!(error.message.contains("injected commit failure"));
        assert!(error.message.contains("rolled back 1 published file(s)"));
        // The published first part is gone and the two unpublished sealed
        // files cleaned their temporary paths on drop.
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_failed_rollback_reports_the_path_that_remains() {
        let directory = tempfile::tempdir().expect("destination dir");
        let files = sealed_parts(directory.path(), 2);
        let mut commits = 0;
        let error = publish_ordered(
            files,
            "split",
            |sealed| {
                commits += 1;
                if commits == 2 {
                    Err(CliError::new(Kind::Io, "injected commit failure"))
                } else {
                    sealed.persist()
                }
            },
            |_| Err(std::io::Error::other("injected rollback failure")),
        )
        .expect_err("the second commit fails");
        assert!(error.message.contains("rolled back 0 published file(s)"));
        assert!(error.message.contains("split rollback also failed"));
        assert!(error.message.contains("part-000001.pcapng"));
        assert!(error.message.contains("injected rollback failure"));
        assert!(directory.path().join("part-000001.pcapng").is_file());
        assert!(!directory.path().join("part-000002.pcapng").exists());
    }

    #[test]
    fn interruption_at_a_later_commit_rolls_back_the_published_files() {
        use packetcraftr_core::budget::Deadline;
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        use std::time::{Duration, Instant};

        let ticks = Arc::new(AtomicU64::new(0));
        let observed = ticks.clone();
        let start = Instant::now();
        let deadline = Arc::new(Deadline::with_time_source(
            Duration::from_millis(5),
            move || start + Duration::from_millis(observed.load(Ordering::SeqCst)),
        ));
        let _scope = crate::invocation::enter_deadline(Some(deadline));
        let directory = tempfile::tempdir().unwrap();
        let files = sealed_parts(directory.path(), 2);
        let mut commits = 0;
        let error = publish_ordered(
            files,
            "split",
            |sealed| {
                commits += 1;
                if commits == 2 {
                    ticks.store(6, Ordering::SeqCst);
                }
                sealed.persist()
            },
            |path| std::fs::remove_file(path),
        )
        .expect_err("the second commit expires");
        assert_eq!(error.classification.code, "policy.duration_limit");
        assert!(error.message.contains("rolled back 1 published file(s)"));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn expiry_at_the_commit_boundary_leaves_no_destination_or_staged_file() {
        use packetcraftr_core::budget::Deadline;
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        use std::time::{Duration, Instant};

        let ticks = Arc::new(AtomicU64::new(0));
        let observed = ticks.clone();
        let start = Instant::now();
        let deadline = Arc::new(Deadline::with_time_source(
            Duration::from_millis(5),
            move || start + Duration::from_millis(observed.load(Ordering::SeqCst)),
        ));
        let _scope = crate::invocation::enter_deadline(Some(deadline));
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("expired.pcap");
        let mut staged = StagedFile::stage(&destination).unwrap();
        staged.as_file_mut().write_all(b"prepared").unwrap();
        staged.sync().unwrap();
        ticks.store(6, Ordering::SeqCst);
        let error = staged.persist().unwrap_err();
        assert_eq!(error.classification.code, "policy.duration_limit");
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn expiry_after_commit_does_not_remove_an_already_published_artifact() {
        use packetcraftr_core::budget::Deadline;
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        use std::time::{Duration, Instant};

        let ticks = Arc::new(AtomicU64::new(0));
        let observed = ticks.clone();
        let start = Instant::now();
        let deadline = Arc::new(Deadline::with_time_source(
            Duration::from_millis(5),
            move || start + Duration::from_millis(observed.load(Ordering::SeqCst)),
        ));
        let _scope = crate::invocation::enter_deadline(Some(deadline));
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("committed.pcap");
        let mut staged = StagedFile::stage(&destination).unwrap();
        staged.as_file_mut().write_all(b"committed").unwrap();
        staged.sync().unwrap();
        staged.persist().unwrap();
        ticks.store(6, Ordering::SeqCst);
        assert!(crate::invocation::check().is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"committed");
    }
}
