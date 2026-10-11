// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use packetcraftr_core::budget::{Cancellation, Interrupted};

use super::test_support::{CERTIFICATE, Peer, RESPONSE};
use super::*;

fn numeric() -> ServerName {
    ServerName::Numeric(Ipv4Addr::LOCALHOST.into())
}

#[test]
fn encrypted_exchange_records_self_signed_chain_protocol_cipher_and_sni() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for name in [
            numeric(),
            ServerName::Declared("fixture.example.test".into()),
        ] {
            let peer = Peer::new(version, false);
            let observed = Arc::clone(&peer.observed);
            let expected_name = match &name {
                ServerName::Numeric(_) => None,
                ServerName::Declared(name) => Some(name.clone()),
            };
            let authorized = Arc::new(Mutex::new(Vec::new()));
            let authorized_hook = Arc::clone(&authorized);
            let deadline = Deadline::new(Duration::from_secs(1));
            let handshake = connect(peer, name, Limits::default(), &deadline, move |bytes| {
                authorized_hook.lock().unwrap().extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();
            assert!(handshake.evidence.handshake_complete);
            assert_eq!(
                handshake.evidence.certificates,
                [Bytes::copy_from_slice(CERTIFICATE)]
            );
            assert!(!handshake.evidence.certificates_truncated);
            assert!(handshake.evidence.protocol_version.is_some());
            assert!(handshake.evidence.cipher_suite.is_some());
            let mut stream = handshake.result.unwrap();
            let report = crate::tcp::exchange(
                &mut stream,
                b"HEAD / HTTP/1.0\r\n\r\n",
                128,
                &deadline,
                |bytes| bytes.ends_with(b"\r\n\r\n"),
            )
            .unwrap();
            assert!(matches!(report.outcome, crate::bounded::Outcome::Complete));
            assert_eq!(report.response.as_ref(), RESPONSE);
            let evidence = stream.evidence();
            let observed = observed.lock().unwrap();
            assert_eq!(observed.server_name, expected_name);
            assert_eq!(evidence.wire_bytes_sent, observed.ciphertext.len());
            assert_eq!(observed.ciphertext, *authorized.lock().unwrap());
            assert!(
                !observed
                    .ciphertext
                    .windows(RESPONSE.len())
                    .any(|bytes| bytes == RESPONSE)
            );
            assert!(evidence.wire_bytes_read > RESPONSE.len());
            assert!(evidence.steps > handshake.evidence.steps);
        }
    }
}

#[test]
fn invalid_handshake_signature_fails_with_presented_certificate_evidence() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let handshake = connect(
            Peer::new(version, true),
            numeric(),
            Limits::default(),
            &Deadline::new(Duration::from_secs(1)),
            |_| Ok(()),
        )
        .unwrap();
        assert!(matches!(handshake.result, Err(Error::Protocol(_))));
        assert!(!handshake.evidence.handshake_complete);
        assert_eq!(
            handshake.evidence.certificates,
            [Bytes::copy_from_slice(CERTIFICATE)]
        );
        assert!(handshake.evidence.wire_bytes_read > 0);
    }
}

#[test]
fn certificate_retention_never_slices_der_and_can_be_disabled() {
    for cap in [0, CERTIFICATE.len() - 1, CERTIFICATE.len()] {
        let limits = Limits {
            max_certificate_bytes: cap,
            ..Limits::default()
        };
        let handshake = connect(
            Peer::new(&rustls::version::TLS13, false),
            numeric(),
            limits,
            &Deadline::new(Duration::from_secs(1)),
            |_| Ok(()),
        )
        .unwrap();
        assert!(handshake.result.is_ok());
        assert_eq!(
            handshake.evidence.certificates_truncated,
            cap < CERTIFICATE.len()
        );
        assert_eq!(
            handshake.evidence.certificates.len(),
            usize::from(cap == CERTIFICATE.len())
        );
    }
}

#[test]
fn cancellation_at_timeout_and_authorization_boundaries_prevents_wire_writes() {
    for at_timeout in [true, false] {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal.clone()));
        let mut peer = Peer::new(&rustls::version::TLS13, false);
        let observed = Arc::clone(&peer.observed);
        if at_timeout {
            peer.cancel_on_timeout = Some(signal.clone());
        }
        let handshake = connect(peer, numeric(), Limits::default(), &deadline, move |_| {
            signal.cancel();
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            handshake.result,
            Err(Error::Interrupted(Interrupted::Cancelled(_)))
        ));
        assert_eq!(handshake.evidence.wire_bytes_sent, 0);
        assert_eq!(observed.lock().unwrap().writes, 0);
    }
}

#[test]
fn cancellation_before_native_flush_and_read_prevents_those_calls() {
    for cancel_at in [2, 3] {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal.clone()));
        let mut peer = Peer::new(&rustls::version::TLS13, false);
        peer.cancel_on_timeout = Some(signal);
        peer.cancel_at_timeout_call = cancel_at;
        let observed = Arc::clone(&peer.observed);
        let handshake = connect(peer, numeric(), Limits::default(), &deadline, |_| Ok(())).unwrap();
        assert!(matches!(
            handshake.result,
            Err(Error::Interrupted(Interrupted::Cancelled(_)))
        ));
        let observed = observed.lock().unwrap();
        assert_eq!(observed.reads, 0);
        assert_eq!(observed.flushes, usize::from(cancel_at == 3));
        assert_eq!(observed.writes, 1);
    }
}

#[test]
fn refusing_wire_authorization_preserves_its_source_and_prevents_transmission() {
    let peer = Peer::new(&rustls::version::TLS13, false);
    let observed = Arc::clone(&peer.observed);
    let handshake = connect(
        peer,
        numeric(),
        Limits::default(),
        &Deadline::new(Duration::from_secs(1)),
        |_| Err(io::ErrorKind::PermissionDenied.into()),
    )
    .unwrap();
    assert!(
        matches!(handshake.result, Err(Error::Io(source)) if source.kind() == io::ErrorKind::PermissionDenied)
    );
    assert_eq!(observed.lock().unwrap().writes, 0);
    assert_eq!(handshake.evidence.wire_bytes_sent, 0);
}

#[test]
fn handshake_failure_retains_partial_wire_writes() {
    let mut peer = Peer::new(&rustls::version::TLS13, false);
    peer.silent = true;
    peer.fail_after_write = Some(17);
    let handshake = connect(
        peer,
        numeric(),
        Limits::default(),
        &Deadline::new(Duration::from_secs(1)),
        |_| Ok(()),
    )
    .unwrap();
    assert!(
        matches!(handshake.result, Err(Error::Io(source)) if source.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(handshake.evidence.wire_bytes_sent, 17);
    assert_eq!(handshake.evidence.wire_bytes_read, 0);
}

#[test]
fn handshake_read_cap_does_not_read_past_its_wire_budget() {
    let handshake = connect(
        Peer::new(&rustls::version::TLS13, false),
        numeric(),
        Limits {
            max_wire_bytes_read: 17,
            ..Limits::default()
        },
        &Deadline::new(Duration::from_secs(1)),
        |_| Ok(()),
    )
    .unwrap();
    assert!(matches!(
        handshake.result,
        Err(Error::WireLimit {
            direction: Direction::Read,
            limit: 17
        })
    ));
    assert_eq!(handshake.evidence.wire_bytes_read, 17);
}

#[test]
fn handshake_bytes_steps_and_time_are_independently_bounded() {
    let mut peer = Peer::new(&rustls::version::TLS13, false);
    peer.silent = true;
    let handshake = connect(
        peer,
        numeric(),
        Limits {
            max_wire_bytes_sent: 17,
            ..Limits::default()
        },
        &Deadline::new(Duration::from_secs(1)),
        |_| Ok(()),
    )
    .unwrap();
    assert!(matches!(
        handshake.result,
        Err(Error::WireLimit {
            direction: Direction::Sent,
            limit: 17
        })
    ));
    assert_eq!(handshake.evidence.wire_bytes_sent, 17);

    let mut peer = Peer::new(&rustls::version::TLS13, false);
    peer.silent = true;
    let handshake = connect(
        peer,
        numeric(),
        Limits {
            max_steps: 3,
            ..Limits::default()
        },
        &Deadline::new(Duration::from_secs(1)),
        |_| Ok(()),
    )
    .unwrap();
    assert!(matches!(
        handshake.result,
        Err(Error::StepLimit { limit: 3 })
    ));
    assert_eq!(handshake.evidence.steps, 3);

    let mut peer = Peer::new(&rustls::version::TLS13, false);
    peer.silent = true;
    let handshake = connect(
        peer,
        numeric(),
        Limits {
            handshake_timeout: Duration::from_nanos(1),
            max_steps: 4096,
            ..Limits::default()
        },
        &Deadline::new(Duration::from_secs(1)),
        |_| Ok(()),
    )
    .unwrap();
    assert!(matches!(
        handshake.result,
        Err(Error::Interrupted(Interrupted::Exceeded(_)))
    ));
}

#[test]
fn application_exchange_retains_partial_write_and_read_failure_evidence() {
    let deadline = Deadline::new(Duration::from_secs(1));
    let peer = Peer::new(&rustls::version::TLS13, false);
    let handshake = connect(peer, numeric(), Limits::default(), &deadline, |_| Ok(())).unwrap();
    let mut stream = handshake.result.unwrap();
    let sent = stream.evidence().wire_bytes_sent;
    stream.wire.inner.fail_after_write = Some(sent + 17);
    let report = crate::tcp::exchange(
        &mut stream,
        b"HEAD / HTTP/1.0\r\n\r\n",
        128,
        &deadline,
        |_| false,
    )
    .unwrap();
    assert!(matches!(report.outcome, crate::bounded::Outcome::Failed(_)));
    assert_eq!(report.bytes_sent, 19);
    assert_eq!(stream.evidence().wire_bytes_sent, sent + 17);

    let peer = Peer::new(&rustls::version::TLS13, false);
    let handshake = connect(peer, numeric(), Limits::default(), &deadline, |_| Ok(())).unwrap();
    let mut stream = handshake.result.unwrap();
    stream.wire.inner.fail_read = true;
    let report = crate::tcp::exchange(&mut stream, b"request", 128, &deadline, |_| false).unwrap();
    assert_eq!(report.bytes_sent, 7);
    assert!(report.response.is_empty());
    assert!(
        matches!(report.outcome, crate::bounded::Outcome::Failed(source) if source.kind() == io::ErrorKind::ConnectionReset)
    );

    let peer = Peer::new(&rustls::version::TLS13, false);
    let handshake = connect(peer, numeric(), Limits::default(), &deadline, |_| Ok(())).unwrap();
    let mut stream = handshake.result.unwrap();
    stream.wire.inner.fail_after_response = true;
    let report = crate::tcp::exchange(&mut stream, b"request", 128, &deadline, |_| false).unwrap();
    assert_eq!(report.response.as_ref(), RESPONSE);
    assert!(
        matches!(report.outcome, crate::bounded::Outcome::Failed(source) if source.kind() == io::ErrorKind::ConnectionReset)
    );
}

#[test]
fn application_io_cannot_extend_lifetime_wire_step_or_deadline_limits() {
    let deadline = Deadline::new(Duration::from_secs(1));
    for sent_limit in [true, false] {
        let handshake = connect(
            Peer::new(&rustls::version::TLS13, false),
            numeric(),
            Limits::default(),
            &deadline,
            |_| Ok(()),
        )
        .unwrap();
        let mut stream = handshake.result.unwrap();
        if sent_limit {
            stream.wire.limits.max_wire_bytes_sent = stream.wire.bytes_sent + 17;
        } else {
            stream.wire.limits.max_steps = stream.wire.steps;
        }
        let report =
            crate::tcp::exchange(&mut stream, b"request", 128, &deadline, |_| false).unwrap();
        assert_eq!(report.bytes_sent, 7);
        assert!(matches!(report.outcome, crate::bounded::Outcome::Failed(_)));
        if sent_limit {
            assert_eq!(
                stream.evidence().wire_bytes_sent,
                handshake.evidence.wire_bytes_sent + 17
            );
        }
    }
    let signal = Cancellation::default();
    let session_deadline =
        Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal.clone()));
    let handshake = connect(
        Peer::new(&rustls::version::TLS13, false),
        numeric(),
        Limits::default(),
        &session_deadline,
        |_| Ok(()),
    )
    .unwrap();
    let mut stream = handshake.result.unwrap();
    signal.cancel();
    let source = stream.write(b"request").unwrap_err();
    assert!(matches!(
        source
            .get_ref()
            .and_then(|source| source.downcast_ref::<Error>()),
        Some(Error::Interrupted(Interrupted::Cancelled(_)))
    ));
    let report = crate::tcp::exchange(&mut stream, b"request", 128, &deadline, |_| false).unwrap();
    assert_eq!(report.bytes_sent, 0);
    assert!(
        matches!(report.outcome, crate::bounded::Outcome::Failed(source) if matches!(
            source.get_ref().and_then(|source| source.downcast_ref::<Error>()),
            Some(Error::Interrupted(Interrupted::Cancelled(_)))
        ))
    );
    assert_eq!(
        stream.evidence().wire_bytes_sent,
        handshake.evidence.wire_bytes_sent
    );
}

#[test]
fn invalid_limits_and_undeclared_names_fail_before_any_provider_io() {
    assert!(
        Limits {
            max_steps: 0,
            ..Limits::default()
        }
        .validate()
        .is_err()
    );
    assert!(ServerName::Declared("127.0.0.1".into()).validate().is_err());
    assert!(ServerName::Declared("bad name".into()).validate().is_err());
    assert!(numeric().validate().is_ok());
    let peer = Peer::new(&rustls::version::TLS13, false);
    let observed = Arc::clone(&peer.observed);
    assert!(matches!(
        connect(
            peer,
            numeric(),
            Limits {
                max_steps: 0,
                ..Limits::default()
            },
            &Deadline::new(Duration::from_secs(1)),
            |_| Ok(())
        ),
        Err(Error::InvalidLimits)
    ));
    assert_eq!(observed.lock().unwrap().writes, 0);
    assert_eq!(observed.lock().unwrap().reads, 0);
}
