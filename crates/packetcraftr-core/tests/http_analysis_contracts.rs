// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::http::setup;
use common::tls_capture::Stream;
use common::{assert_invalid_application_limit, reader, registry};
use packetcraftr_core::{
    analysis::{
        self, Constraint, Options,
        application::Limits,
        http::{Collector, Event, Status},
    },
    error::{BoundaryError, Classified},
};

#[test]
fn limit_conn_fails_run_after_delivery() {
    let (mut capture, mut first) = setup();
    capture.client(&mut first, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut first, b"HTTP/1.1 204 No Content\r\n\r\n");
    let mut second = Stream {
        server_port: 80,
        ..Stream::new(40_001)
    };
    capture.open(&mut second);

    let limits = Limits {
        max_streams: 1,
        ..Limits::default()
    };
    let mut collector = Collector::new(limits, vec![80], 1024).unwrap();
    let mut delivered = Vec::new();
    let error = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            delivered.extend(
                collector
                    .observe(&record)
                    .map_err(BoundaryError::from_error)?,
            );
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.application_limit");
    assert_eq!(
        error.causes(),
        ["application analysis exceeds max_streams=1"]
    );
    assert!(
        matches!(
            delivered.as_slice(),
            [Event::Message(request), Event::Message(response)]
                if request.status == Status::Complete && response.status == Status::Complete
        ),
        "{delivered:?}"
    );
}

#[test]
fn body_byte_within_ceiling() {
    for (max_body_bytes, reason) in [
        (0, Constraint::NonZero),
        (
            256 * 1024 * 1024 + 1,
            Constraint::AtMost {
                maximum: 256 * 1024 * 1024,
            },
        ),
    ] {
        let error = Collector::new(Limits::default(), vec![80], max_body_bytes)
            .err()
            .expect("invalid body limit must be rejected");
        assert_invalid_application_limit(error, "max_http_body_bytes", max_body_bytes, reason);
    }
    assert!(Collector::new(Limits::default(), vec![80], 256 * 1024 * 1024).is_ok());
}
