// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one message body `--body-message`/`--write` publishes, split into two
//! disjoint owners: `BodyWriter` streams entity spans into the staged file
//! while hashing and counting them, and `SelectedMessage` tracks the observed
//! terminal evidence the publication decision needs. The collector borrows
//! only the writer; the event callback owns the evidence.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use packetcraftr_core::analysis::http::{BodySink, Event, Message, Status};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind, source_chain};
use packetcraftr_core::protocol::application::http;
use sha2::{Digest, Sha256};

use crate::errors::CliError;
use crate::output::http as wire;
use crate::staged_output::{self, StagedFile};

/// Streams one selected message's entity spans into the staged artifact.
///
/// The command keeps the [`StagedFile`]; this borrows its file through a
/// 64 KiB buffer and owns only the incremental SHA-256 and the accepted-byte
/// count. Cancellation and the invocation deadline gate every write, and the
/// digest covers exactly the bytes the file accepted.
pub(super) struct BodyWriter<'a> {
    writer: BufWriter<&'a mut std::fs::File>,
    destination: PathBuf,
    sha256: Sha256,
    bytes: u64,
}

impl<'a> BodyWriter<'a> {
    /// Wraps the staged file in the body sink's bounded writer.
    pub(super) fn new(file: &'a mut std::fs::File, destination: PathBuf) -> Self {
        Self {
            writer: BufWriter::with_capacity(64 * 1024, file),
            destination,
            sha256: Sha256::new(),
            bytes: 0,
        }
    }

    /// The number of body bytes the file accepted.
    pub(super) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The lowercase hex digest of every accepted byte.
    pub(super) fn sha256(&self) -> String {
        crate::output::hex::compact_hex(&self.sha256.clone().finalize())
    }

    /// The artifact destination, for the published record.
    pub(super) fn destination(&self) -> &Path {
        &self.destination
    }

    /// Pushes the buffered tail into the staged file and ends the borrow, so
    /// the staged file can sync and persist. Durability belongs to
    /// [`StagedFile::sync`], not this flush.
    pub(super) fn seal(mut self) -> Result<(), CliError> {
        self.writer
            .flush()
            .map_err(|source| staged_output::output("write", &self.destination, source))
    }
}

impl BodySink for BodyWriter<'_> {
    /// Checks cancellation and the deadline before writing, then hashes and
    /// counts exactly what the file accepted. A refusal is terminal: the
    /// `io.output_file` classification and I/O source cross the boundary.
    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        crate::cancellation::check().map_err(CliError::into_boundary_error)?;
        self.writer.write_all(bytes).map_err(|source| {
            staged_output::output("write", &self.destination, source).into_boundary_error()
        })?;
        self.sha256.update(bytes);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        Ok(())
    }
}

/// The observed terminal evidence for the selected message index.
///
/// The event callback records it independently of the sink; `None` fields
/// mean the message never published its record.
#[derive(Debug)]
pub(super) struct SelectedMessage {
    index: u64,
    status: Option<Status>,
    stream: u64,
    generation: u64,
    body_bytes: u64,
    error: Option<http::Error>,
}

impl SelectedMessage {
    /// Tracks the one-based message index `--body-message` selected.
    pub(super) fn new(index: u64) -> Self {
        Self {
            index,
            status: None,
            stream: 0,
            generation: 0,
            body_bytes: 0,
            error: None,
        }
    }

    /// Records the selected message's terminal evidence from each collector
    /// event; every other message's record leaves the selection untouched.
    pub(super) fn observe(&mut self, event: &Event) {
        if let Event::Message(message) = event {
            self.observe_message(message);
        }
    }

    fn observe_message(&mut self, message: &Message) {
        if message.index == self.index {
            self.status = Some(message.status);
            self.stream = message.stream;
            self.generation = message.generation;
            self.body_bytes = message.body_bytes;
            self.error = message.error.clone();
        }
    }

    /// Validates the selected outcome against the publication failure table
    /// and builds the artifact record only a `complete` report may carry.
    ///
    /// `bytes`/`sha256` describe the staged file, `path` is the destination
    /// the caller published under its own spelling.
    pub(super) fn artifact(
        &self,
        bytes: u64,
        sha256: String,
        path: String,
    ) -> Result<wire::BodyExport, CliError> {
        let Some(status) = self.status else {
            return Err(CliError::from_classification(
                Classification::new(
                    "cli.http_body_message",
                    Kind::Usage,
                    Some("list the messages this invocation parsed, then select a reported index"),
                ),
                format!("selected HTTP message {} was not observed", self.index),
                Vec::new(),
            ));
        };
        match status {
            Status::Complete => {}
            Status::Limit => return Err(self.limit_error()),
            _ => return Err(self.incomplete_error(status)),
        }
        if bytes != self.body_bytes {
            return Err(CliError::from_classification(
                Classification::new(
                    "internal.http_body_evidence",
                    Kind::Internal,
                    Some("report the capture and command as an internal invariant failure"),
                ),
                format!(
                    "selected HTTP message {} recorded {} body bytes but the artifact wrote {bytes}",
                    self.index, self.body_bytes,
                ),
                Vec::new(),
            ));
        }
        Ok(wire::BodyExport {
            message: self.index,
            stream: self.stream,
            generation: self.generation,
            path,
            bytes,
            sha256,
            representation: wire::Representation::HttpBodyAfterDechunking,
        })
    }

    /// A non-complete, non-limit terminal status fails as a packet condition
    /// naming the index and status, with the message's own HTTP cause when
    /// the parser recorded one.
    fn incomplete_error(&self, status: Status) -> CliError {
        CliError::from_classification(
            Classification::new(
                "packet.http_body_incomplete",
                Kind::Packet,
                Some("only a message that completed cleanly can export its body"),
            ),
            format!(
                "selected HTTP message {} ended with status {}",
                self.index,
                wire::Status::from(status),
            ),
            self.http_causes(),
        )
    }

    /// A limit status keeps the original HTTP limit cause under its own
    /// `policy.http_limit` classification.
    fn limit_error(&self) -> CliError {
        let classification = match &self.error {
            Some(error @ http::Error::Limit(_)) => error.classification(),
            _ => Classification::new("policy.http_limit", Kind::Policy, None),
        };
        CliError::from_classification(
            classification,
            format!(
                "selected HTTP message {} ended with status limit",
                self.index
            ),
            self.http_causes(),
        )
    }

    /// The recorded HTTP parse failure and its distinct sources, outermost
    /// first; empty when the terminal status carried none.
    fn http_causes(&self) -> Vec<String> {
        self.error
            .iter()
            .flat_map(|error| std::iter::once(error.to_string()).chain(source_chain(error)))
            .collect()
    }
}

/// Synchronizes the sealed artifact durably, rechecks cancellation and the
/// invocation deadline, then publishes it without clobbering — the last step
/// before a prepared report may publish.
pub(super) fn commit(staged: StagedFile) -> Result<(), CliError> {
    commit_with(staged, StagedFile::sync, StagedFile::persist)
}

/// The commit sequence with each fallible step injectable, so tests can drive
/// sync/persist failures and deadline races without privileged filesystem
/// behavior.
fn commit_with(
    staged: StagedFile,
    sync: impl FnOnce(&StagedFile) -> Result<(), CliError>,
    persist: impl FnOnce(StagedFile) -> Result<(), CliError>,
) -> Result<(), CliError> {
    sync(&staged)?;
    crate::cancellation::check()?;
    persist(staged)
}

#[cfg(test)]
mod tests {
    use packetcraftr_core::analysis::application;
    use packetcraftr_core::budget::Deadline;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    fn staged(destination: &Path) -> StagedFile {
        StagedFile::stage(destination).expect("absent destination stages")
    }

    #[test]
    fn body_writer_hashes_exactly_the_accepted_bytes() {
        let directory = tempfile::tempdir().expect("staging dir");
        let destination = directory.path().join("body.bin");
        let mut file = staged(&destination);
        {
            let staged_path = file.destination().to_owned();
            let mut writer = BodyWriter::new(file.as_file_mut(), staged_path.clone());
            BodySink::write(&mut writer, b"\x00gzip\xc3\x28").expect("first span");
            BodySink::write(&mut writer, b"tail").expect("second span");
            assert_eq!(writer.bytes(), 11);
            assert_eq!(writer.sha256().len(), 64);
            assert_eq!(writer.destination(), staged_path.as_path());
            writer.seal().expect("buffered tail flushes");
        }
        let staged_path = std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .expect("one staged file")
            .expect("entry readable")
            .path();
        let staged_bytes = std::fs::read(&staged_path).expect("staged bytes readable");
        assert_eq!(staged_bytes, b"\x00gzip\xc3\x28tail");
        file.sync().expect("sync");
        file.persist().expect("publish");
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"\x00gzip\xc3\x28tail"
        );
    }

    /// A file whose writes all fail drives the sink refusal without needing
    /// any privileged filesystem behavior.
    #[cfg(packetcraftr_test_dev_full)]
    #[test]
    fn a_sink_write_failure_keeps_the_io_output_classification_and_source() {
        assert!(
            std::fs::metadata("/dev/full").is_ok(),
            "the sink write-failure test requires /dev/full"
        );
        let mut full = std::fs::File::create("/dev/full").expect("/dev/full opens");
        let mut writer = BodyWriter::new(&mut full, PathBuf::from("artifact.bin"));
        // The 64 KiB buffer accepts spans until it flushes; overflow it.
        let span = vec![0xABu8; 80 * 1024];
        let error = BodySink::write(&mut writer, &span).expect_err("write must fail");
        assert_eq!(error.classification().code, "io.output_file");
        assert_eq!(error.classification().kind, Kind::Io);
        let causes = error.as_causes();
        assert!(causes[0].contains("artifact.bin"), "{causes:?}");
    }

    #[test]
    fn deadline_expiry_gates_the_sink_write() {
        let ticks = Arc::new(AtomicU64::new(0));
        let observed = ticks.clone();
        let start = Instant::now();
        let deadline = Arc::new(Deadline::with_time_source(
            Duration::from_millis(5),
            move || start + Duration::from_millis(observed.load(Ordering::SeqCst)),
        ));
        let _scope = crate::invocation::enter_deadline(Some(deadline));
        let mut file = tempfile::NamedTempFile::new().expect("staging file");
        let mut writer = BodyWriter::new(file.as_file_mut(), PathBuf::from("out.bin"));
        ticks.store(6, Ordering::SeqCst);
        let error = BodySink::write(&mut writer, b"late").expect_err("expired write fails");
        assert_eq!(error.classification().code, "policy.duration_limit");
    }

    fn selected(
        status: Option<Status>,
        body_bytes: u64,
        error: Option<http::Error>,
    ) -> SelectedMessage {
        SelectedMessage {
            index: 2,
            status,
            stream: 7,
            generation: 3,
            body_bytes,
            error,
        }
    }

    #[test]
    fn a_complete_selection_publishes_the_artifact_record() {
        let artifact = selected(Some(Status::Complete), 5, None)
            .artifact(5, "a".repeat(64), "dir/body.bin".to_owned())
            .expect("complete selection publishes");
        assert_eq!(artifact.message, 2);
        assert_eq!(artifact.stream, 7);
        assert_eq!(artifact.generation, 3);
        assert_eq!(artifact.path, "dir/body.bin");
        assert_eq!(artifact.bytes, 5);
        assert_eq!(artifact.sha256, "a".repeat(64));
        assert_eq!(
            artifact.representation,
            wire::Representation::HttpBodyAfterDechunking
        );
    }

    #[test]
    fn an_unobserved_selection_is_a_usage_failure() {
        let error = selected(None, 0, None)
            .artifact(0, "digest".to_owned(), "body.bin".to_owned())
            .expect_err("absent selection fails");
        assert_eq!(error.classification.code, "cli.http_body_message");
        assert_eq!(error.classification.kind, Kind::Usage);
        assert_eq!(error.exit_code(), 2);
        assert!(error.message.contains("message 2"));
    }

    #[test]
    fn a_noncomplete_selection_is_a_packet_failure_with_the_http_cause() {
        for (status, text) in [
            (Status::Incomplete, "incomplete"),
            (Status::Malformed, "malformed"),
            (Status::Gap, "gap"),
            (Status::Conflict, "conflict"),
            (Status::Reset, "reset"),
            (Status::Evicted, "evicted"),
            (Status::Upgrade, "upgrade"),
        ] {
            let error = selected(Some(status), 0, None)
                .artifact(0, "digest".to_owned(), "body.bin".to_owned())
                .expect_err("noncomplete selection fails");
            assert_eq!(
                error.classification.code, "packet.http_body_incomplete",
                "status {text}"
            );
            assert_eq!(error.classification.kind, Kind::Packet);
            assert_eq!(error.exit_code(), 3);
            assert!(
                error
                    .message
                    .contains(&format!("message 2 ended with status {text}")),
                "status {text}: {}",
                error.message
            );
        }
        // The parser's HTTP cause rides in the failure's causes.
        let error = selected(
            Some(Status::Malformed),
            0,
            Some(http::Error::Invalid("header uses a bare CR or LF")),
        )
        .artifact(0, "digest".to_owned(), "body.bin".to_owned())
        .expect_err("malformed selection fails");
        assert_eq!(error.causes, ["HTTP/1 header uses a bare CR or LF"]);
    }

    #[test]
    fn a_limit_selection_retains_the_http_limit_cause() {
        let error = selected(
            Some(Status::Limit),
            0,
            Some(http::Error::Limit(http::Limit::BodyBytes)),
        )
        .artifact(0, "digest".to_owned(), "body.bin".to_owned())
        .expect_err("limit selection fails");
        assert_eq!(error.classification.code, "policy.http_limit");
        assert_eq!(error.classification.kind, Kind::Policy);
        assert_eq!(error.exit_code(), 6);
        assert_eq!(error.causes, ["HTTP/1 exceeds its body bytes limit"]);
        // A limit status without a recorded cause still classifies the same.
        let error = selected(Some(Status::Limit), 0, None)
            .artifact(0, "digest".to_owned(), "body.bin".to_owned())
            .expect_err("limit selection fails");
        assert_eq!(error.classification.code, "policy.http_limit");
        assert_eq!(error.exit_code(), 6);
    }

    #[test]
    fn a_byte_count_mismatch_is_an_internal_evidence_failure() {
        let error = selected(Some(Status::Complete), 5, None)
            .artifact(4, "digest".to_owned(), "body.bin".to_owned())
            .expect_err("mismatched count fails");
        assert_eq!(error.classification.code, "internal.http_body_evidence");
        assert_eq!(error.classification.kind, Kind::Internal);
        assert_eq!(error.exit_code(), 70);
    }

    #[test]
    fn commit_persists_after_a_successful_sync() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("body.bin");
        let mut file = staged(&destination);
        file.as_file_mut().write_all(b"payload").unwrap();
        commit(file).expect("commit publishes");
        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
    }

    #[test]
    fn a_sync_failure_never_reaches_persist() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("body.bin");
        let file = staged(&destination);
        let persisted = std::cell::Cell::new(false);
        let error = commit_with(
            file,
            |_| Err(CliError::new(Kind::Io, "injected sync failure")),
            |staged| {
                persisted.set(true);
                staged.persist()
            },
        )
        .expect_err("sync failure fails the commit");
        assert_eq!(error.message, "injected sync failure");
        assert!(!persisted.get());
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_persist_failure_surfaces_after_sync_without_a_destination() {
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("body.bin");
        let file = staged(&destination);
        let synced = std::cell::Cell::new(false);
        let error = commit_with(
            file,
            |staged| {
                synced.set(true);
                staged.sync()
            },
            |_| Err(CliError::new(Kind::Io, "injected persist failure")),
        )
        .expect_err("persist failure fails the commit");
        assert!(synced.get());
        assert_eq!(error.message, "injected persist failure");
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn deadline_expiry_at_the_recheck_blocks_persist() {
        let ticks = Arc::new(AtomicU64::new(0));
        let observed = ticks.clone();
        let start = Instant::now();
        let deadline = Arc::new(Deadline::with_time_source(
            Duration::from_millis(5),
            move || start + Duration::from_millis(observed.load(Ordering::SeqCst)),
        ));
        let _scope = crate::invocation::enter_deadline(Some(deadline));
        let directory = tempfile::tempdir().expect("destination dir");
        let destination = directory.path().join("body.bin");
        let file = staged(&destination);
        ticks.store(6, Ordering::SeqCst);
        let persisted = std::cell::Cell::new(false);
        let error = commit_with(file, StagedFile::sync, |staged| {
            persisted.set(true);
            staged.persist()
        })
        .expect_err("expired commit fails");
        assert_eq!(error.classification.code, "policy.duration_limit");
        assert!(!persisted.get());
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_sink_refusal_surfaces_as_application_output() {
        let boundary = staged_output::output(
            "write",
            Path::new("artifact.bin"),
            std::io::Error::other("storage full"),
        )
        .into_boundary_error();
        let error = CliError::classified(application::Error::Output(boundary));
        assert_eq!(error.classification.code, "io.output_file");
        assert_eq!(error.exit_code(), 5);
        assert_eq!(error.message, "application event output failed");
        assert!(error.causes[0].contains("artifact.bin"));
        assert_eq!(error.causes[1], "storage full");
    }
}
