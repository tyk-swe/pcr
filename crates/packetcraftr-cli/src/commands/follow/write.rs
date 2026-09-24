// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Staged per-direction payload files for `follow --write`.

use std::io::Write;
use std::path::Path;

use packetcraftr_core::analysis::StreamRef;
use packetcraftr_core::analysis::follow::{Chunk, PeerDirection};
use packetcraftr_core::error::Kind;

use crate::errors::CliError;
use crate::staged_output::StagedFile;

use super::arguments::Direction as Selected;

#[derive(Debug)]
struct Staged {
    direction: PeerDirection,
    file: StagedFile,
    bytes: u64,
}

#[derive(Clone, Debug)]
pub(super) struct Written {
    pub(super) direction: PeerDirection,
    pub(super) path: String,
    pub(super) bytes: u64,
}

impl From<Written> for packetcraftr_cli::output::follow::WrittenFile {
    fn from(value: Written) -> Self {
        Self {
            direction: value.direction,
            path: value.path,
            bytes: value.bytes,
        }
    }
}

/// Stages per-direction files under one output-byte budget. Each publishes
/// atomically without overwriting, in deterministic order. On failure, attempts
/// to remove files already published and reports cleanup errors; unpublished
/// temporary files are removed on drop.
#[derive(Debug)]
pub(super) struct DirectionFiles {
    staged: Vec<Staged>,
    remaining: usize,
}

impl DirectionFiles {
    /// Stages one file per selected direction, failing before any capture is
    /// read when the directory or a destination is unusable.
    pub(super) fn stage(
        directory: &Path,
        selector: StreamRef,
        selected: Selected,
        max_bytes: usize,
    ) -> Result<Self, CliError> {
        let directions: &[PeerDirection] = match selected {
            Selected::Both => &[PeerDirection::ClientToServer, PeerDirection::ServerToClient],
            Selected::Client => &[PeerDirection::ClientToServer],
            Selected::Server => &[PeerDirection::ServerToClient],
        };
        let mut staged = Vec::with_capacity(directions.len());
        for direction in directions {
            let destination = directory.join(format!(
                "{}-{}-{}.bin",
                selector.transport.as_str(),
                selector.index,
                direction_name(*direction),
            ));
            let file = StagedFile::stage(&destination)?;
            staged.push(Staged {
                direction: *direction,
                file,
                bytes: 0,
            });
        }
        Ok(Self {
            staged,
            remaining: max_bytes,
        })
    }

    /// Appends one chunk to its direction's staged file, charging the shared
    /// output-byte budget across every direction file.
    pub(super) fn write(&mut self, chunk: &Chunk) -> Result<(), CliError> {
        let Some(staged) = self
            .staged
            .iter_mut()
            .find(|staged| staged.direction == chunk.direction)
        else {
            return Ok(());
        };
        if chunk.bytes.len() > self.remaining {
            return Err(CliError::new(
                Kind::Policy,
                "follow output exceeds --max-application-output-bytes",
            ));
        }
        self.remaining -= chunk.bytes.len();
        staged
            .file
            .as_file_mut()
            .write_all(&chunk.bytes)
            .map_err(|source| {
                let mut error = CliError::new(Kind::Io, format!("write follow payload: {source}"));
                error.causes = std::iter::once(source.to_string())
                    .chain(packetcraftr_core::error::source_chain(&source))
                    .collect();
                error
            })?;
        staged.bytes = staged
            .bytes
            .saturating_add(u64::try_from(chunk.bytes.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    /// Flushes and publishes in deterministic order, including empty
    /// directions. On failure, removes published files where possible and
    /// reports cleanup errors.
    pub(super) fn publish(self) -> Result<Vec<Written>, CliError> {
        self.publish_with(StagedFile::sync, |path| std::fs::remove_file(path))
    }

    fn publish_with(
        self,
        mut sync: impl FnMut(&StagedFile) -> Result<(), CliError>,
        mut remove: impl FnMut(&Path) -> std::io::Result<()>,
    ) -> Result<Vec<Written>, CliError> {
        // No destination is published until every staged file is synchronized.
        for staged in &self.staged {
            sync(&staged.file)?;
        }
        let mut published = Vec::new();
        let mut written = Vec::new();
        for staged in self.staged {
            let destination = staged.file.destination().to_owned();
            match staged.file.persist() {
                Ok(()) => {
                    written.push(Written {
                        direction: staged.direction,
                        path: destination.display().to_string(),
                        bytes: staged.bytes,
                    });
                    published.push(destination);
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
                                    "remove published follow output {}: {source}",
                                    path.display(),
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
                        failure = failure.with_secondary("follow rollback", cleanup);
                    }
                    return Err(failure);
                }
            }
        }
        Ok(written)
    }
}

fn direction_name(direction: PeerDirection) -> &'static str {
    match direction {
        PeerDirection::ClientToServer => "client",
        PeerDirection::ServerToClient => "server",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::analysis::StreamTransport;

    fn selector() -> StreamRef {
        StreamRef {
            transport: StreamTransport::Tcp,
            index: 7,
        }
    }

    fn chunk(direction: PeerDirection, bytes: &'static [u8]) -> Chunk {
        Chunk {
            direction,
            direction_generation: 0,
            number: 1,
            bytes: bytes.into(),
        }
    }

    #[test]
    fn staged_directions_publish_under_deterministic_names() {
        let directory = tempfile::tempdir().expect("destination dir");
        let mut files =
            DirectionFiles::stage(directory.path(), selector(), Selected::Both, usize::MAX)
                .expect("staging succeeds");
        files
            .write(&chunk(PeerDirection::ClientToServer, b"hello"))
            .unwrap();
        files
            .write(&chunk(PeerDirection::ServerToClient, b"world!"))
            .unwrap();
        files
            .write(&chunk(PeerDirection::ClientToServer, b" again"))
            .unwrap();
        let written = files.publish().expect("publish succeeds");
        assert_eq!(
            written
                .iter()
                .map(|file| (file.direction, file.bytes))
                .collect::<Vec<_>>(),
            [
                (PeerDirection::ClientToServer, 11),
                (PeerDirection::ServerToClient, 6),
            ]
        );
        assert_eq!(
            std::fs::read(directory.path().join("tcp-7-client.bin")).unwrap(),
            b"hello again"
        );
        assert_eq!(
            std::fs::read(directory.path().join("tcp-7-server.bin")).unwrap(),
            b"world!"
        );
    }

    #[test]
    fn staging_rejects_existing_destinations_before_any_write() {
        let directory = tempfile::tempdir().expect("destination dir");
        let occupied = directory.path().join("tcp-7-server.bin");
        std::fs::write(&occupied, b"mine").expect("occupying file");
        let error = DirectionFiles::stage(directory.path(), selector(), Selected::Both, 16)
            .expect_err("occupied destination fails");
        assert!(error.message.contains("already exists"));
        assert_eq!(std::fs::read(&occupied).unwrap(), b"mine");
    }

    #[test]
    fn publish_failure_rolls_back_files_published_by_this_invocation() {
        let directory = tempfile::tempdir().expect("destination dir");
        let mut files =
            DirectionFiles::stage(directory.path(), selector(), Selected::Both, usize::MAX)
                .expect("staging succeeds");
        files
            .write(&chunk(PeerDirection::ClientToServer, b"hello"))
            .unwrap();
        files
            .write(&chunk(PeerDirection::ServerToClient, b"world"))
            .unwrap();
        // A colliding server destination appears after staging: publishing the
        // client file must be rolled back and the colliding file untouched.
        let collision = directory.path().join("tcp-7-server.bin");
        std::fs::write(&collision, b"someone else").expect("colliding file");
        let error = files.publish().expect_err("publish fails");
        assert!(error.message.contains("rolled back 1 published file(s)"));
        assert!(!directory.path().join("tcp-7-client.bin").exists());
        assert_eq!(std::fs::read(&collision).unwrap(), b"someone else");
    }

    #[test]
    fn synchronization_failure_leaves_no_published_files_and_allows_retry() {
        let directory = tempfile::tempdir().expect("destination dir");
        let files = DirectionFiles::stage(directory.path(), selector(), Selected::Both, 16)
            .expect("staging succeeds");
        let mut calls = 0;
        let error = files
            .publish_with(
                |staged: &StagedFile| {
                    calls += 1;
                    if calls == 2 {
                        Err(CliError::new(
                            Kind::Io,
                            format!(
                                "sync follow output {}: injected synchronization failure",
                                staged.destination().display()
                            ),
                        ))
                    } else {
                        staged.sync()
                    }
                },
                |path: &Path| std::fs::remove_file(path),
            )
            .expect_err("the second synchronization fails");
        assert_eq!(calls, 2);
        assert!(error.message.contains("sync follow output"));
        assert!(error.message.contains("tcp-7-server.bin"));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        DirectionFiles::stage(directory.path(), selector(), Selected::Both, 16)
            .expect("retry stages cleanly")
            .publish()
            .expect("retry publishes both files");
    }

    #[test]
    fn unselected_and_empty_directions_stage_exactly_what_was_chosen() {
        let directory = tempfile::tempdir().expect("destination dir");
        let files =
            DirectionFiles::stage(directory.path(), selector(), Selected::Client, usize::MAX)
                .expect("staging succeeds");
        let written = files.publish().expect("publish succeeds");
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].direction, PeerDirection::ClientToServer);
        assert_eq!(written[0].bytes, 0);
        assert_eq!(
            std::fs::read(directory.path().join("tcp-7-client.bin")).unwrap(),
            b""
        );
        assert!(!directory.path().join("tcp-7-server.bin").exists());
    }

    #[test]
    fn the_output_byte_budget_is_shared_across_directions() {
        let directory = tempfile::tempdir().expect("destination dir");
        let mut files = DirectionFiles::stage(directory.path(), selector(), Selected::Both, 6)
            .expect("staging succeeds");
        files
            .write(&chunk(PeerDirection::ClientToServer, b"hello"))
            .unwrap();
        files
            .write(&chunk(PeerDirection::ServerToClient, b"w"))
            .unwrap();
        let error = files
            .write(&chunk(PeerDirection::ServerToClient, b"orld"))
            .expect_err("shared budget trips");
        assert!(error.message.contains("--max-application-output-bytes"));
        drop(files);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn rollback_failure_reports_the_file_that_remains() {
        let directory = tempfile::tempdir().unwrap();
        let files =
            DirectionFiles::stage(directory.path(), selector(), Selected::Both, 16).unwrap();
        std::fs::write(directory.path().join("tcp-7-server.bin"), b"collision").unwrap();
        let error = files
            .publish_with(StagedFile::sync, |_| {
                Err(std::io::Error::other("injected rollback failure"))
            })
            .unwrap_err();
        assert!(error.message.contains("rolled back 0 published file(s)"));
        assert!(error.message.contains("tcp-7-client.bin"));
        assert!(error.message.contains("injected rollback failure"));
        assert!(directory.path().join("tcp-7-client.bin").is_file());
        assert_eq!(
            std::fs::read(directory.path().join("tcp-7-server.bin")).unwrap(),
            b"collision"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_dangling_symlinks_without_creating_temporary_files() {
        use std::path::PathBuf;

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("tcp-7-client.bin");
        std::os::unix::fs::symlink("missing-target", &destination).unwrap();
        let error =
            DirectionFiles::stage(directory.path(), selector(), Selected::Both, 16).unwrap_err();
        assert!(error.message.contains("already exists"));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_link(destination).unwrap(),
            PathBuf::from("missing-target")
        );
    }
}
