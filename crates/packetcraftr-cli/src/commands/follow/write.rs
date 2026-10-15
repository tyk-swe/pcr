// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::Path;

use packetcraftr_core::analysis::StreamRef;
use packetcraftr_core::analysis::follow::{Chunk, PeerDirection};
use packetcraftr_core::error::Kind;

use crate::errors::CliError;
use crate::staged_output::{Published, StagedFile};

use super::arguments::Direction as Selected;

#[derive(Debug)]
struct Staged {
    direction: PeerDirection,
    file: StagedFile,
    bytes: u64,
    /// Payload not yet written, so small chunks reach the file in larger writes.
    pending: Vec<u8>,
}

impl Staged {
    const WRITE_SIZE: usize = 64 * 1024;

    fn write_pending(&mut self) -> Result<(), CliError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.file
            .as_file_mut()
            .write_all(&self.pending)
            .map_err(|source| CliError::wrapping(Kind::Io, "write follow payload", &source))?;
        self.pending.clear();
        Ok(())
    }
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
        invocation: &crate::invocation::Invocation,
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
            let file = StagedFile::stage(invocation, &destination)?;
            staged.push(Staged {
                direction: *direction,
                file,
                bytes: 0,
                pending: Vec::new(),
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
        if staged.pending.len() + chunk.bytes.len() > Staged::WRITE_SIZE {
            staged.write_pending()?;
        }
        if chunk.bytes.len() >= Staged::WRITE_SIZE {
            staged
                .file
                .as_file_mut()
                .write_all(&chunk.bytes)
                .map_err(|source| CliError::wrapping(Kind::Io, "write follow payload", &source))?;
        } else {
            staged.pending.extend_from_slice(&chunk.bytes);
        }
        staged.bytes = staged
            .bytes
            .saturating_add(u64::try_from(chunk.bytes.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    pub(super) fn publish(self) -> Result<Vec<Written>, CliError> {
        self.publish_with(StagedFile::sync, Published::remove)
    }

    /// Rollback removes each published file through the directory it was
    /// published into, never through a re-resolved requested path.
    fn publish_with(
        mut self,
        mut sync: impl FnMut(&StagedFile) -> Result<(), CliError>,
        mut remove: impl FnMut(&Published) -> std::io::Result<()>,
    ) -> Result<Vec<Written>, CliError> {
        // No destination is published until every staged file is written and synchronized.
        for staged in &mut self.staged {
            staged.write_pending()?;
            sync(&staged.file)?;
        }
        let mut published: Vec<Published> = Vec::new();
        let mut written = Vec::new();
        for staged in self.staged {
            match staged.file.persist() {
                Ok(file) => {
                    written.push(Written {
                        direction: staged.direction,
                        path: file.destination().display().to_string(),
                        bytes: staged.bytes,
                    });
                    published.push(file);
                }
                Err(error) => {
                    let mut rolled_back = 0;
                    let mut failures = Vec::new();
                    for file in &published {
                        match remove(file) {
                            Ok(()) => rolled_back += 1,
                            Err(source) => failures.push(CliError::new(
                                Kind::Io,
                                format!(
                                    "remove published follow output {}: {source}",
                                    file.destination().display(),
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
