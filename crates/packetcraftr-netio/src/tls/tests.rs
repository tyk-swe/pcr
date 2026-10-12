// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::time::Instant;

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
fn later_tls_record_errors_retain_decrypted_exchange_bytes_and_their_source() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for max_read in [usize::MAX, 5] {
            let deadline = Deadline::new(Duration::from_secs(1));
            let peer = Peer::new(version, false);
            let observed = Arc::clone(&peer.observed);
            let handshake =
                connect(peer, numeric(), Limits::default(), &deadline, |_| Ok(())).unwrap();
            let mut stream = handshake.result.unwrap();
            // A record with an invalid content type follows the valid response,
            // either in the same native read or across fragmented reads.
            assert!(stream.terminal_error().is_none());
            stream.wire.inner.response_suffix = vec![0xff, 0x03, 0x03, 0, 1, 0];
            stream.wire.inner.max_read = max_read;
            let reads_before = observed.lock().unwrap().reads;
            let report =
                crate::tcp::exchange(&mut stream, b"request", 128, &deadline, |_| false).unwrap();
            assert_eq!(report.response.as_ref(), RESPONSE);
            assert_eq!(report.bytes_sent, 7);
            let crate::bounded::Outcome::Failed(source) = report.outcome else {
                panic!("the subsequent record must fail the exchange");
            };
            assert_eq!(source.kind(), io::ErrorKind::InvalidData);
            assert!(matches!(
                source
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<Error>()),
                Some(Error::Protocol(_))
            ));
            if max_read == usize::MAX {
                assert_eq!(observed.lock().unwrap().reads, reads_before + 1);
            }
            let evidence = stream.evidence();
            let reads = observed.lock().unwrap().reads;
            let retained = stream.terminal_error().unwrap();
            assert_eq!(retained.kind(), source.kind());
            assert_eq!(retained.to_string(), source.to_string());
            let repeated = stream.read(&mut [0; 128]).unwrap_err();
            assert_eq!(repeated.kind(), source.kind());
            assert_eq!(repeated.to_string(), source.to_string());
            assert_eq!(stream.evidence(), evidence);
            assert_eq!(observed.lock().unwrap().reads, reads);
        }
    }
}

#[test]
fn interruption_during_successful_read_retains_plaintext_without_more_wire_io() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for cancelled in [true, false] {
            let signal = Cancellation::default();
            let now = Arc::new(Mutex::new(Instant::now()));
            let time_source = Arc::clone(&now);
            let deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
                *time_source.lock().unwrap()
            })
            .with_cancellation(Some(signal.clone()));
            let peer = Peer::new(version, false);
            let observed = Arc::clone(&peer.observed);
            let handshake =
                connect(peer, numeric(), Limits::default(), &deadline, |_| Ok(())).unwrap();
            let mut stream = handshake.result.unwrap();
            stream.wire.inner.on_response_read = Some(Box::new(move || {
                if cancelled {
                    signal.cancel();
                } else {
                    *now.lock().unwrap() += Duration::from_secs(2);
                }
            }));
            let reads_before = observed.lock().unwrap().reads;
            let writes_before = observed.lock().unwrap().writes;
            let flushes_before = observed.lock().unwrap().flushes;
            let wire_bytes_before = stream.evidence().wire_bytes_read;
            let report = crate::tcp::exchange(&mut stream, b"request", 128, &deadline, |bytes| {
                bytes == RESPONSE
            })
            .unwrap();
            assert_eq!(report.response.as_ref(), RESPONSE);
            assert_eq!(report.bytes_sent, 7);
            assert!(matches!(
                (cancelled, report.outcome),
                (true, crate::bounded::Outcome::Cancelled)
                    | (false, crate::bounded::Outcome::TimedOut)
            ));
            assert_eq!(observed.lock().unwrap().reads, reads_before + 1);
            assert_eq!(observed.lock().unwrap().writes, writes_before + 1);
            assert_eq!(observed.lock().unwrap().flushes, flushes_before + 1);
            assert!(stream.evidence().wire_bytes_read > wire_bytes_before + RESPONSE.len());
            assert_eq!(
                stream.evidence().wire_bytes_read,
                observed.lock().unwrap().bytes_read
            );

            let evidence = stream.evidence();
            assert!(stream.read(&mut [0; 128]).is_err());
            assert_eq!(stream.evidence(), evidence);
            assert_eq!(observed.lock().unwrap().reads, reads_before + 1);
        }
    }
}

#[test]
fn shorter_exchange_deadline_bounds_tls_read_write_and_flush_retries() {
    for stalled_operation in ["read", "write", "flush"] {
        let lifetime = Deadline::new(Duration::from_secs(2));
        let peer = Peer::new(&rustls::version::TLS13, false);
        let observed = Arc::clone(&peer.observed);
        let handshake = connect(peer, numeric(), Limits::default(), &lifetime, |_| Ok(())).unwrap();
        let mut stream = handshake.result.unwrap();
        let sent_before = stream.evidence().wire_bytes_sent;
        let reads_before = observed.lock().unwrap().reads;
        match stalled_operation {
            "read" => stream.wire.inner.stall_read = true,
            "write" => stream.wire.inner.stall_after_write = Some(sent_before + 17),
            "flush" => stream.wire.inner.stall_flush = true,
            _ => unreachable!(),
        }
        let deadline = Deadline::new(Duration::from_millis(50));
        let started = Instant::now();
        let report =
            crate::tcp::exchange(&mut stream, b"request", 128, &deadline, |_| false).unwrap();
        assert!(matches!(report.outcome, crate::bounded::Outcome::TimedOut));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(lifetime.enforce().is_ok());
        assert_eq!(report.bytes_sent, 7);
        assert!(report.response.is_empty());
        if stalled_operation == "write" {
            assert_eq!(stream.evidence().wire_bytes_sent, sent_before + 17);
        }
        if stalled_operation != "read" {
            assert_eq!(observed.lock().unwrap().reads, reads_before);
        }
    }
}

#[test]
fn application_timeouts_are_retryable_and_do_not_lose_pending_native_flush() {
    use crate::tcp::Stream as _;

    let lifetime = Deadline::new(Duration::from_secs(2));
    let peer = Peer::new(&rustls::version::TLS13, false);
    let observed = Arc::clone(&peer.observed);
    let handshake = connect(peer, numeric(), Limits::default(), &lifetime, |_| Ok(())).unwrap();
    let mut stream = handshake.result.unwrap();
    let timeout = Some(Duration::from_millis(5));
    stream.set_write_timeout(timeout).unwrap();
    stream.write_all(b"request").unwrap();
    stream.wire.inner.stall_flush = true;
    assert_eq!(stream.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    let ciphertext = observed.lock().unwrap().ciphertext.clone();
    let flushes = observed.lock().unwrap().flushes;
    let sent = stream.evidence().wire_bytes_sent;

    stream.wire.inner.stall_flush = false;
    stream.flush().unwrap();
    assert_eq!(observed.lock().unwrap().flushes, flushes + 1);
    assert_eq!(observed.lock().unwrap().ciphertext, ciphertext);
    assert_eq!(stream.evidence().wire_bytes_sent, sent);

    stream.set_read_timeout(timeout).unwrap();
    stream.wire.inner.stall_read = true;
    assert_eq!(
        stream.read(&mut [0; 128]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    stream.wire.inner.stall_read = false;
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = [0; 128];
    let count = stream.read(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], RESPONSE);

    assert_eq!(
        stream
            .set_read_timeout(Some(Duration::ZERO))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        stream
            .set_write_timeout(Some(Duration::ZERO))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
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
