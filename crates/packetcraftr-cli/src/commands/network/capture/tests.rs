// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::thread;

use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    frame::LinkType,
    registry::Registry,
};

use super::*;
use crate::invocation::{Invocation, StreamEncoder};

const TEST_WAIT: Duration = Duration::from_secs(10);

struct Provider;

struct Session(net::capture::Metadata);

fn read_failure() -> net::Error {
    net::Error::Capture {
        message: "controlled capture read failure".to_owned(),
        source: None,
    }
}

impl net::capture::Provider for Provider {
    type Capture = Session;

    fn arm_capture(
        &self,
        request: &net::capture::Request,
        _: &Deadline,
    ) -> Result<Self::Capture, net::Error> {
        Ok(Session(net::capture::Metadata {
            interface: request.interface.clone(),
            link_type: LinkType::ETHERNET,
            snap_length: request.settings.limits.snap_length,
            native: Default::default(),
        }))
    }
}

impl net::capture::Session for Session {
    fn metadata(&self) -> &net::capture::Metadata {
        &self.0
    }

    fn wait_ready(&mut self, _: &Deadline) -> Result<(), net::Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _: &Deadline,
    ) -> Result<Option<net::capture::Captured>, net::Error> {
        Err(read_failure())
    }

    fn stats(&self) -> net::capture::Stats {
        net::capture::Stats::default()
    }

    fn shutdown(&mut self) -> Result<(), net::Error> {
        Ok(())
    }
}

struct Flush<F>(F);

impl<F: FnMut() -> io::Result<()>> io::Write for Flush<F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        (self.0)()
    }
}

fn capture_with_output(
    window: Duration,
    binary: impl io::Write + Send + 'static,
) -> Result<(), CliError> {
    let format = Format::PcapNg;
    let invocation = Invocation::new(
        format,
        StreamEncoder::new(Command::Capture, io::sink()),
        None,
        Cancellation::default(),
        None,
    );
    let client = Client::new(
        Arc::new(Registry::default()),
        Policy::default(),
        ProviderSet::capture(net::interface::SystemProvider, Provider),
    );
    let request = workflow::Request::new(
        net::capture::GroupRequest::new(
            vec![net::interface::Id {
                index: 1,
                name: "controlled".to_owned(),
            }],
            net::capture::Limits::default(),
        ),
        window,
    );
    drive(
        &invocation,
        &client,
        request,
        Output {
            binary,
            format,
            compression: Compression::None,
            selector: None,
            decoding: None,
            projector: None,
            files: None,
        },
    )
}

#[test]
fn capture_returns_while_output_finalization_is_blocked() {
    let (finalizing, entered) = mpsc::channel();
    let (release, wait) = mpsc::channel::<()>();
    let (completed, result) = mpsc::channel();
    let output = Flush(move || {
        finalizing.send(()).unwrap();
        let _ = wait.recv();
        Ok(())
    });
    let command = thread::spawn(move || {
        completed
            .send(capture_with_output(Duration::ZERO, output))
            .unwrap();
    });
    let started = entered.recv_timeout(TEST_WAIT);
    let outcome = result.recv_timeout(TEST_WAIT);
    drop(release);
    command.join().unwrap();
    started.unwrap();

    let error = outcome.unwrap().unwrap_err().output_error();
    assert_eq!(error.kind, output::envelope::Kind::Io);
    assert!(error.message.contains("finalization was not confirmed"));
    assert!(error.capture.is_some());
}

#[test]
fn capture_keeps_primary_failure_when_finalization_fails() {
    let error = capture_with_output(
        TEST_WAIT,
        Flush(|| Err(io::Error::other("controlled flush failure"))),
    )
    .unwrap_err()
    .output_error();

    assert_eq!(error.code, read_failure().classification().code.as_str());
    assert!(
        error
            .causes
            .iter()
            .any(|cause| cause.contains("controlled capture read failure"))
    );
    assert!(
        error
            .causes
            .iter()
            .any(|cause| cause.contains("controlled flush failure"))
    );
    assert!(error.capture.is_some());
}
