// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::Builder;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_core::protocol::{
    application::dns::Dns,
    transport::{Tcp, Udp},
};
use packetcraftr_netio::interface::Id;
use packetcraftr_netio::link::Capability;
use packetcraftr_netio::{self as net, capture, route, transmit};

use super::clock::VirtualClock;

#[derive(Default)]
pub(crate) struct State {
    pub(crate) ready: bool,
    pub(crate) armed: usize,
    pub(crate) shutdowns: usize,
    pub(crate) sends: usize,
    pub(crate) pending: usize,
    pub(crate) peak: usize,
    pub(crate) replies: VecDeque<capture::Captured>,
    pub(crate) fail_after: Option<usize>,
    pub(crate) send_times: Vec<Instant>,
    pub(crate) send_clock: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
    pub(crate) idle_clock: Option<VirtualClock>,
    pub(crate) bad_ingress: Option<Option<Instant>>,
    pub(crate) release_replies_after_timeout: bool,
    pub(crate) late_ingress: Option<Option<Instant>>,
    pub(crate) suppress_replies: bool,
    pub(crate) hold_replies_until: usize,
    pub(crate) tied_resets: bool,
    pub(crate) repeated_syn_acks: bool,
    pub(crate) mismatched_dns_replies: bool,
    pub(crate) hops: Option<u8>,
    pub(crate) ttls: Vec<u8>,
    pub(crate) sent_wires: Vec<Bytes>,
}

pub(crate) fn router(ttl: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 100 + ttl)
}

#[derive(Clone)]
pub(crate) struct Io(pub(crate) Arc<Mutex<State>>);

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
        let tcp = decoded.packet.get::<Tcp>();
        let reply = |identification: u16, flags: u16| {
            let tcp = tcp.expect("only TCP probes draw TCP replies");
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
        let icmp_error = |source, icmp_type, code| {
            let mut body = vec![0_u8; 4];
            body.extend_from_slice(&wire[..wire.len().min(28)]);
            let mut error = Packet::new();
            error.push(Ipv4 {
                source,
                destination: ip.source,
                ..Default::default()
            });
            error.push(Icmpv4 {
                icmp_type,
                code,
                body: Bytes::from(body),
                ..Default::default()
            });
            frame(error)
        };
        let report = transmit::Report::committed(wire.len(), wire.clone());
        let ingress = Instant::now();
        let replies = match state.hops {
            Some(hops) if ip.ttl < hops => vec![icmp_error(router(ip.ttl), 11, 0)],
            _ if tcp.is_none() && state.mismatched_dns_replies => {
                let udp = decoded.packet.get::<Udp>().unwrap();
                let query = decoded.packet.get::<Dns>().unwrap();
                (1..=2)
                    .map(|offset| {
                        let mut dns = query.clone();
                        dns.edit(|dns| {
                            dns.response = true;
                            dns.id = query.id.wrapping_add(offset);
                        });
                        let mut response = Packet::new();
                        response.push(Ipv4 {
                            source: ip.destination,
                            destination: ip.source,
                            ..Default::default()
                        });
                        response.push(Udp {
                            source_port: udp.destination_port,
                            destination_port: udp.source_port,
                            ..Default::default()
                        });
                        response.push(dns);
                        frame(response)
                    })
                    .collect()
            }
            // Every UDP port on the fixture host is closed.
            _ if tcp.is_none() => vec![icmp_error(ip.destination, 3, 3)],
            _ if state.repeated_syn_acks => {
                vec![reply(1, Tcp::SYN | Tcp::ACK), reply(2, Tcp::SYN | Tcp::ACK)]
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
        state.sent_wires.push(wire.clone());
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
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, net::Error> {
        let mut state = self.state.lock().unwrap();
        if state.sends < state.hold_replies_until || state.suppress_replies {
            return Ok(None);
        }
        if state.release_replies_after_timeout {
            if !deadline.limit().is_zero() {
                use packetcraftr::clock::Clock as _;
                let clock = state
                    .idle_clock
                    .as_ref()
                    .expect("late replies use a virtual clock");
                clock.advance(deadline.limit().saturating_add(Duration::from_micros(1)));
                let ingress = state.late_ingress.unwrap_or(Some(clock.now()));
                for captured in &mut state.replies {
                    captured.received_at = ingress;
                }
                state.release_replies_after_timeout = false;
            }
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
        } else if let Some(clock) = &state.idle_clock {
            // Empty immediate polls still perform work, so logical time must progress.
            clock.advance(deadline.limit().saturating_add(Duration::from_micros(1)));
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
