// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::budget::Cancellation;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
struct Transmitter(AtomicUsize);
impl transmit::Provider for Transmitter {
    fn send(
        &self,
        outbound: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let bytes = match outbound {
            transmit::Outbound::Layer2(frame) => frame.bytes().clone(),
            _ => unreachable!(),
        };
        Ok(transmit::Report::committed(bytes.len(), bytes))
    }
}
struct Session {
    metadata: capture::Metadata,
    cancellation: Cancellation,
    cancel_before_send: bool,
    reads: usize,
}
impl capture::Session for Session {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        self.reads += 1;
        if self.cancel_before_send || !deadline.limit().is_zero() {
            self.cancellation.cancel();
            if !self.cancel_before_send {
                // The wait itself has no cancellation; its parent must retain it.
                assert!(deadline.cancellation().is_none());
                assert!(deadline.check_cancelled().is_err());
            }
        }
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }
    fn stats(&self) -> capture::Stats {
        Default::default()
    }
}
struct Captures;
impl capture::Provider for Captures {
    type Capture = Session;
    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<Session, packetcraftr_netio::Error> {
        unreachable!()
    }
}
#[test]
fn incomplete_capture_identity_never_reaches_injected_provider() {
    for interface in [
        packetcraftr_netio::interface::Id {
            name: String::new(),
            index: 1,
        },
        packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 0,
        },
    ] {
        let request = Request {
            interface,
            interface_source: "192.168.1.1".parse().unwrap(),
            interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            target: "192.168.1.2".parse().unwrap(),
            vlan_tags: vec![],
            mtu: 1500,
            link_type: packetcraftr_core::frame::LinkType::ETHERNET,
        };
        let transmitter = Transmitter(AtomicUsize::new(0));
        let state = State::default();
        // Captures::arm_capture panics if the validation boundary is bypassed.
        let result = state
            .over(&transmitter, &Captures)
            .resolve(&request, &Deadline::new(Duration::from_secs(1)));
        assert!(result.is_err());
        assert_eq!(transmitter.0.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn parent_cancellation_reaches_reads_and_prevents_unsent_attempts() {
    for cancel_before_send in [false, true] {
        let request = Request {
            interface: packetcraftr_netio::interface::Id {
                name: "test0".into(),
                index: 1,
            },
            interface_source: "192.168.1.1".parse().unwrap(),
            interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            target: "192.168.1.2".parse().unwrap(),
            vlan_tags: vec![],
            mtu: 1500,
            link_type: packetcraftr_core::frame::LinkType::ETHERNET,
        };
        let cancellation = Cancellation::default();
        let parent =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancellation.clone()));
        let deadline = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
        let mut session = Session {
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: request.link_type,
                snap_length: 1500,
                native: Default::default(),
            },
            cancellation,
            cancel_before_send,
            reads: 0,
        };
        let transmitter = Transmitter(AtomicUsize::new(0));
        let state = State::default();
        let active = state.over(&transmitter, &Captures);
        let decision = discovery_decision(&request);
        let bytes = build_request_frame(&request).unwrap();
        let result = active
            .exchange(
                &request,
                &bytes,
                transmit::Route {
                    decision: &decision,
                    mode: Mode::Layer2,
                    lookup_destination: None,
                },
                &mut session,
                &deadline,
            )
            .unwrap();
        let expected = u32::from(!cancel_before_send);
        assert_eq!(result.attempts, expected);
        assert_eq!(transmitter.0.load(Ordering::SeqCst), expected as usize);
        assert_eq!(session.reads, if cancel_before_send { 1 } else { 2 });
    }
}

struct InterruptedSession {
    metadata: capture::Metadata,
    cancellation: Cancellation,
    reads: usize,
    elapsed: Option<Arc<std::sync::Mutex<Duration>>>,
}

impl capture::Session for InterruptedSession {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        self.reads += 1;
        match self.reads {
            1 => Ok(None),
            2 => {
                if let Some(elapsed) = &self.elapsed {
                    *elapsed.lock().unwrap() = Duration::from_secs(2);
                }
                Ok(Some(capture::Captured::new(
                    Frame::new(
                        Some(std::time::SystemTime::now()),
                        self.metadata.link_type,
                        [0_u8; 60].to_vec(),
                    )
                    .unwrap(),
                    Some(Instant::now()),
                )))
            }
            _ => {
                self.cancellation.cancel();
                Err(deadline.check_cancelled().unwrap_err().into())
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        Default::default()
    }
}

struct InterruptedCapture(std::sync::Mutex<Option<InterruptedSession>>);

impl capture::Provider for InterruptedCapture {
    type Capture = InterruptedSession;

    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        Ok(self.0.lock().unwrap().take().unwrap())
    }
}

#[test]
fn interrupted_read_retains_sent_attempt_and_capture_evidence() {
    let request = Request {
        interface: packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 1,
        },
        interface_source: "192.168.1.1".parse().unwrap(),
        interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
        target: "192.168.1.2".parse().unwrap(),
        vlan_tags: vec![],
        mtu: 1500,
        link_type: packetcraftr_core::frame::LinkType::ETHERNET,
    };
    let cancellation = Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancellation.clone()));
    let deadline = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
    let capture = InterruptedCapture(std::sync::Mutex::new(Some(InterruptedSession {
        metadata: capture::Metadata {
            interface: request.interface.clone(),
            link_type: request.link_type,
            snap_length: 1500,
            native: Default::default(),
        },
        cancellation,
        reads: 0,
        elapsed: None,
    })));
    let transmitter = Transmitter(AtomicUsize::new(0));
    let error = State::default()
        .over(&transmitter, &capture)
        .resolve(&request, &deadline)
        .unwrap_err();
    let Error::Io {
        spent: Some(spent),
        source,
        ..
    } = error
    else {
        panic!("expected an interrupted capture read");
    };
    assert_eq!(spent.attempts, 1);
    assert_eq!(transmitter.0.load(Ordering::SeqCst), 1);
    assert_eq!(spent.captured.len(), 1);
    assert_eq!(spent.captured[0].bytes().as_ref(), [0_u8; 60]);
    assert!(matches!(source, packetcraftr_netio::Error::Cancelled(_)));
}

#[test]
fn dequeued_frame_survives_wait_interruption() {
    let request = Request {
        interface: packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 1,
        },
        interface_source: "192.168.1.1".parse().unwrap(),
        interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
        target: "192.168.1.2".parse().unwrap(),
        vlan_tags: vec![],
        mtu: 1500,
        link_type: packetcraftr_core::frame::LinkType::ETHERNET,
    };
    let started = Instant::now();
    let elapsed = Arc::new(std::sync::Mutex::new(Duration::ZERO));
    let clock = Arc::clone(&elapsed);
    let deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
        started + *clock.lock().unwrap()
    });
    let decision = discovery_decision(&request);
    let bytes = build_request_frame(&request).unwrap();
    let transmitter = Transmitter(AtomicUsize::new(0));
    let mut session = InterruptedSession {
        metadata: capture::Metadata {
            interface: request.interface.clone(),
            link_type: request.link_type,
            snap_length: 1500,
            native: Default::default(),
        },
        cancellation: Cancellation::default(),
        reads: 0,
        elapsed: Some(elapsed),
    };
    let outcome = State::default()
        .over(&transmitter, &Captures)
        .exchange(
            &request,
            &bytes,
            transmit::Route {
                decision: &decision,
                mode: Mode::Layer2,
                lookup_destination: None,
            },
            &mut session,
            &deadline,
        )
        .unwrap();
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.captured.len(), 1);
    assert_eq!(outcome.captured[0].bytes().as_ref(), [0_u8; 60]);
    assert!(!outcome.evidence_truncated);
}
