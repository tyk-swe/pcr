// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

/// Each file publishes atomically without overwriting, in deterministic order.
#[derive(Debug)]
pub(super) struct DirectionFiles {
    staged: Vec<Staged>,
    remaining: usize,
}

impl DirectionFiles {
    /// Fails before any capture is read when the directory or a destination is unusable.
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
            .map_err(|source| CliError::wrapping(Kind::Io, "write follow payload", &source))?;
        staged.bytes = staged
            .bytes
            .saturating_add(u64::try_from(chunk.bytes.len()).unwrap_or(u64::MAX));
        Ok(())
    }

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
}
