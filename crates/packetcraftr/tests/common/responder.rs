// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A scripted layer-3 network for the probe workflows: one on-link route, a
//! transmitter that answers each IPv4 TCP probe, and capture sessions that
//! hand those answers back.
//!
//! The destination answers a probe with a SYN/ACK (or, with
//! [`State::tied_resets`], two equally ranked resets). With [`State::hops`]
//! set, a probe whose TTL is below it is answered instead by the router at
//! that hop with an ICMP time-exceeded error quoting the probe.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::Builder;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_netio::interface::Id;
use packetcraftr_netio::link::Capability;
use packetcraftr_netio::{self as net, capture, route, transmit};

/// What the scripted network has seen, and how it answers.
#[derive(Default)]
pub(crate) struct State {
    pub(crate) ready: bool,
    pub(crate) armed: usize,
    pub(crate) shutdowns: usize,
    pub(crate) sends: usize,
    pub(crate) pending: usize,
    /// The most answers queued at once.
    pub(crate) peak: usize,
    pub(crate) replies: VecDeque<capture::Captured>,
    /// Fails the send after this many confirmed sends.
    pub(crate) fail_after: Option<usize>,
    /// When each probe was sent, on [`send_clock`](Self::send_clock).
    pub(crate) send_times: Vec<Instant>,
    /// The time source send times are recorded on; real time when absent.
    pub(crate) send_clock: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
    /// Hands the next answer back once with this ingress marker instead of
    /// its own.
    pub(crate) bad_ingress: Option<Option<Instant>>,
    pub(crate) suppress_replies: bool,
    /// Holds every answer back until this many probes were sent.
    pub(crate) hold_replies_until: usize,
    /// Answers each probe at once with two equally ranked resets that share
    /// one ingress time and differ only in their IP identification.
    pub(crate) tied_resets: bool,
    /// The TTL at which a probe reaches the destination; lower TTLs are
    /// answered by the router at that hop.
    pub(crate) hops: Option<u8>,
    /// The TTL of every probe sent, in send order.
    pub(crate) ttls: Vec<u8>,
}

/// The address of the router that answers a probe sent with `ttl`.
pub(crate) fn router(ttl: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 100 + ttl)
}

/// Transmits and captures over one shared [`State`].
#[derive(Clone)]
pub(crate) struct Io(pub(crate) Arc<Mutex<State>>);

/// Puts every destination on-link over one layer-3 interface.
#[derive(Clone, Copy, Default)]
pub(crate) struct Routes;

impl route::Provider for Routes {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&Id>,
        _: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<route::Decision, Infallible> {
        Ok(route::Decision {
            interface: Id {
                index: 1,
                name: "fixture0".to_owned(),
            },
            source_mac: None,
            selected_source: Some("192.0.2.1".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: route::SelectionReason::OnLink,
            destination_scope: route::Scope::Link,
            mtu: 1500,
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}

fn frame(packet: Packet) -> Frame {
    let wire = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap()
        .bytes;
    Frame::new(SystemTime::now(), LinkType::RAW, wire).unwrap()
}

impl transmit::Provider for Io {
    fn send(&self, frame_out: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let mut state = self.0.lock().unwrap();
        assert!(state.ready, "capture must be ready before every send");
        if state.fail_after == Some(state.sends) {
            return Err(net::Error::Capture {
                message: "fixture send failure".to_owned(),
                source: None,
            });
        }
        let wire = frame_out.bytes().clone();
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, wire.clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        let ip = decoded.packet.get::<Ipv4>().unwrap();
        let tcp = decoded.packet.get::<Tcp>().unwrap();
        let reply = |identification: u16, flags: u16| {
            let mut response = Packet::new();
            response.push(Ipv4 {
                identification,
                source: ip.destination,
                destination: ip.source,
                ..Default::default()
            });
            response.push(Tcp {
                source_port: tcp.destination_port,
                destination_port: tcp.source_port,
                sequence: 100,
                acknowledgment: tcp.sequence.wrapping_add(1),
                flags,
                ..Default::default()
            });
            frame(response)
        };
        let report = transmit::Report::committed(wire.len(), wire.clone());
        let ingress = Instant::now();
        let replies = match state.hops {
            Some(hops) if ip.ttl < hops => {
                let mut body = vec![0_u8; 4];
                body.extend_from_slice(&wire[..wire.len().min(28)]);
                let mut error = Packet::new();
                error.push(Ipv4 {
                    source: router(ip.ttl),
                    destination: ip.source,
                    ..Default::default()
                });
                error.push(Icmpv4 {
                    icmp_type: 11,
                    code: 0,
                    body: Bytes::from(body),
                    ..Default::default()
                });
                vec![frame(error)]
            }
            _ if state.tied_resets => {
                vec![reply(2, Tcp::RST | Tcp::ACK), reply(1, Tcp::RST | Tcp::ACK)]
            }
            _ => vec![reply(0, Tcp::SYN | Tcp::ACK)],
        };
        for frame in replies {
            state
                .replies
                .push_back(capture::Captured::new(frame, ingress));
            state.pending += 1;
        }
        state.sends += 1;
        state.ttls.push(ip.ttl);
        state.peak = state.peak.max(state.pending);
        let sent_at = state
            .send_clock
            .as_ref()
            .map_or_else(Instant::now, |now| now());
        state.send_times.push(sent_at);
        Ok(report)
    }
}

/// A capture session over the shared [`State`].
pub(crate) struct Capture {
    state: Arc<Mutex<State>>,
    metadata: capture::Metadata,
}

impl capture::Session for Capture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), net::Error> {
        self.state.lock().unwrap().ready = true;
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, net::Error> {
        let mut state = self.state.lock().unwrap();
        if state.sends < state.hold_replies_until || state.suppress_replies {
            return Ok(None);
        }
        if let Some(marker) = state.bad_ingress.take()
            && let Some(captured) = state.replies.front()
        {
            return Ok(Some(capture::Captured::with_ingress_time(
                captured.frame.clone(),
                marker,
            )));
        }
        let captured = state.replies.pop_front();
        if captured.is_some() {
            state.pending -= 1;
        }
        Ok(captured)
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.state.lock().unwrap().shutdowns += 1;
        Ok(())
    }
    fn stats(&self) -> capture::Stats {
        let state = self.state.lock().unwrap();
        capture::Stats {
            received_frames: state.sends as u64,
            received_bytes: state.sends as u64 * 40,
            ..Default::default()
        }
    }
}

impl capture::Provider for Io {
    type Capture = Capture;
    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Capture, net::Error> {
        self.0.lock().unwrap().armed += 1;
        Ok(Capture {
            state: self.0.clone(),
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
        })
    }
}
