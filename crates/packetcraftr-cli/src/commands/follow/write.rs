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
        self.publish_with(StagedFile::sync, Published::remove)
    }

    /// Rollback removes each published file through the directory it was
    /// published into, never through a re-resolved requested path.
    fn publish_with(
        self,
        mut sync: impl FnMut(&StagedFile) -> Result<(), CliError>,
        mut remove: impl FnMut(&Published) -> std::io::Result<()>,
    ) -> Result<Vec<Written>, CliError> {
        // No destination is published until every staged file is synchronized.
        for staged in &self.staged {
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

    #[cfg(unix)]
    fn aliased_directories() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
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

    #[cfg(unix)]
    fn staged_directions(alias: &Path) -> DirectionFiles {
        let mut files = DirectionFiles::stage(alias, selector(), Selected::Both, 8)
            .expect("stage both directions through alias");
        files
            .write(&chunk(PeerDirection::ClientToServer, b"ping"))
            .expect("write client");
        files
            .write(&chunk(PeerDirection::ServerToClient, b"pong"))
            .expect("write server");
        files
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

    #[cfg(unix)]
    #[test]
    fn a_parent_alias_retargeted_to_a_collision_is_refused_before_publication() {
        let (_root, original, replacement, alias) = aliased_directories();
        let files = staged_directions(&alias);
        std::fs::write(replacement.join("tcp-7-server.bin"), b"existing payload")
            .expect("server sentinel");
        std::fs::remove_file(&alias).expect("remove original alias");
        std::os::unix::fs::symlink(&replacement, &alias).expect("retarget parent alias");

        let error = files.publish().expect_err("refuse server collision");

        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(error.exit_code(), 5);
        assert!(error.message.contains("changed since staging"));
        assert!(error.message.contains("rolled back 0 published file(s)"));
        assert!(!replacement.join("tcp-7-client.bin").exists());
        assert!(!original.join("tcp-7-client.bin").exists());
        assert_eq!(
            std::fs::read(replacement.join("tcp-7-server.bin")).unwrap(),
            b"existing payload"
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
        let files = staged_directions(&alias);
        std::fs::remove_file(&alias).expect("remove original alias");
        std::os::unix::fs::symlink(&replacement, &alias).expect("retarget parent alias");

        let error = files.publish().expect_err("refuse retargeted parent");

        assert_eq!(error.classification.code, "io.output_file");
        assert!(error.message.contains("changed since staging"));
        assert_eq!(
            std::fs::read(original.join("source.pcap")).unwrap(),
            b"source capture"
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(&replacement).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn stable_parent_alias_publishes_both_directions() {
        let (_root, original, replacement, alias) = aliased_directories();
        let written = staged_directions(&alias)
            .publish()
            .expect("publish both directions");

        assert_eq!(written.len(), 2);
        assert_eq!(
            written[0].path,
            alias.join("tcp-7-client.bin").display().to_string()
        );
        assert_eq!(
            written[1].path,
            alias.join("tcp-7-server.bin").display().to_string()
        );
        assert_eq!(written[0].bytes, 4);
        assert_eq!(written[1].bytes, 4);
        assert_eq!(
            std::fs::read(original.join("tcp-7-client.bin")).unwrap(),
            b"ping"
        );
        assert_eq!(
            std::fs::read(original.join("tcp-7-server.bin")).unwrap(),
            b"pong"
        );
        assert_eq!(
            std::fs::read(original.join("source.pcap")).unwrap(),
            b"source capture"
        );
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 3);
        assert_eq!(std::fs::read_dir(&replacement).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_after_a_retargeted_parent_alias_never_touches_the_replacement() {
        let (_root, original, replacement, alias) = aliased_directories();
        let files = staged_directions(&alias);
        std::fs::write(original.join("tcp-7-server.bin"), b"existing server").unwrap();
        std::fs::write(
            replacement.join("tcp-7-client.bin"),
            b"replacement sentinel",
        )
        .unwrap();

        let error = files
            .publish_with(StagedFile::sync, |published| {
                std::fs::remove_file(&alias)?;
                std::os::unix::fs::symlink(&replacement, &alias)?;
                published.remove()
            })
            .expect_err("server collision rolls back the client");

        if cfg!(packetcraftr_proc_fd_paths) {
            assert!(error.message.contains("rolled back 1 published file(s)"));
            assert!(!error.message.contains("also failed"), "{error:?}");
            assert!(!original.join("tcp-7-client.bin").exists());
            assert_eq!(std::fs::read_dir(&original).unwrap().count(), 2);
        } else {
            assert!(error.message.contains("rolled back 0 published file(s)"));
            assert!(error.message.contains("follow rollback also failed"));
            assert!(
                error.causes.iter().any(|cause| {
                    cause.contains("changed since publication")
                        && cause.contains(&alias.join("tcp-7-client.bin").display().to_string())
                }),
                "{error:?}"
            );
            assert_eq!(
                std::fs::read(original.join("tcp-7-client.bin")).unwrap(),
                b"ping"
            );
            assert_eq!(std::fs::read_dir(&original).unwrap().count(), 3);
        }
        assert_eq!(
            std::fs::read(original.join("tcp-7-server.bin")).unwrap(),
            b"existing server"
        );
        assert_eq!(
            std::fs::read(original.join("source.pcap")).unwrap(),
            b"source capture"
        );
        assert_eq!(
            std::fs::read(replacement.join("tcp-7-client.bin")).unwrap(),
            b"replacement sentinel"
        );
        assert_eq!(std::fs::read_dir(&replacement).unwrap().count(), 1);
    }
}
