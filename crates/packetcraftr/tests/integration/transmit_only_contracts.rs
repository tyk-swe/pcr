// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use packetcraftr::{
    Client, ProviderSet,
    policy::{DestinationConstraint, Policy},
    send,
};
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    expression,
    packet::Packet,
    protocol::builtin,
};
use packetcraftr_netio::route::Provider as _;
use packetcraftr_netio::{
    interface,
    link::{Capability, Mode},
    route, transmit,
};
use std::{
    convert::Infallible,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

struct Routes {
    calls: Arc<AtomicUsize>,
    mtu: u32,
    capability: Capability,
}
impl route::Provider for Routes {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<route::Decision, Infallible> {
        assert!(deadline.enforce().is_ok());
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut decision =
            common::FixedRoutes.lookup_with_preferences(destination, None, None, deadline)?;
        decision.mtu = self.mtu;
        decision.capability = self.capability;
        Ok(decision)
    }
}

#[derive(Clone, Default)]
struct TransmitOnly(Arc<Mutex<Vec<Vec<u8>>>>);
impl transmit::Provider for TransmitOnly {
    fn send(
        &self,
        frame: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        assert!(matches!(frame, transmit::Outbound::Layer3(_)));
        self.0.lock().unwrap().push(frame.bytes().to_vec());
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

fn packet(destination: &str) -> Packet {
    expression::parse(
        &format!("ipv4(src=10.0.0.5,dst={destination})/udp(sport=12345,dport=9)/raw(text=hello)"),
        &builtin::registry(),
        expression::Limits::default(),
    )
    .unwrap()
}

fn policy() -> Policy {
    Policy {
        allowed_destinations: vec![DestinationConstraint::Exact("10.0.0.1".parse().unwrap())],
        max_packets_per_operation: 2,
        max_bytes_per_operation: 1_500,
        ..Policy::default()
    }
}

fn routes(calls: &Arc<AtomicUsize>) -> Routes {
    Routes {
        calls: Arc::clone(calls),
        mtu: 1_500,
        capability: Capability::Layer2AndLayer3,
    }
}

#[test]
fn authorized_layer3_send_needs_no_capture_and_keeps_cumulative_budgets() {
    let calls = Arc::new(AtomicUsize::new(0));
    let transmitter = TransmitOnly::default();
    let client = Client::new(
        builtin::registry(),
        policy(),
        ProviderSet::transmit(
            routes(&calls),
            common::Interfaces::default(),
            transmitter.clone(),
        ),
    );
    let mut request = send::Request::packet(packet("10.0.0.1"), send::Options::default());
    request.repeat = 2;
    let collector = send::Collector::default();
    let report = client.send_layer3(request, collector.clone()).unwrap();
    assert_eq!(report.stats.packets_completed, 2);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    let frames = transmitter.0.lock().unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], frames[1]);
    assert_eq!(
        report.stats.bytes,
        u64::try_from(frames[0].len() * 2).unwrap()
    );
    assert_eq!(collector.finish(report).unwrap().sent.len(), 2);
}

#[test]
fn denied_destination_packet_budget_and_layer2_intent_precede_provider_activity() {
    let calls = Arc::new(AtomicUsize::new(0));
    let transmitter = TransmitOnly::default();
    let client = Client::new(
        builtin::registry(),
        policy(),
        ProviderSet::transmit(
            routes(&calls),
            common::Interfaces::default(),
            transmitter.clone(),
        ),
    );
    assert!(
        client
            .send_layer3(
                send::Request::packet(packet("10.0.0.2"), send::Options::default()),
                send::Collector::default()
            )
            .is_err()
    );
    let mut oversized = send::Request::packet(packet("10.0.0.1"), send::Options::default());
    oversized.repeat = 3;
    assert!(
        client
            .send_layer3(oversized, send::Collector::default())
            .is_err()
    );
    let options = send::Options {
        plan: packetcraftr::route::Options {
            link_mode: Mode::Layer2,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        client
            .send_layer3(
                send::Request::packet(packet("10.0.0.1"), options),
                send::Collector::default()
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(transmitter.0.lock().unwrap().is_empty());
}

#[test]
fn mtu_interface_capability_and_wire_budget_fail_before_transmission() {
    for (mtu, capability, max_bytes) in [
        (20, Capability::Layer2AndLayer3, 1_500),
        (1_500, Capability::Layer2, 1_500),
        (1_500, Capability::Layer2AndLayer3, 1),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let transmitter = TransmitOnly::default();
        let client = Client::new(
            builtin::registry(),
            Policy {
                max_bytes_per_operation: max_bytes,
                ..policy()
            },
            ProviderSet::transmit(
                Routes {
                    calls: Arc::clone(&calls),
                    mtu,
                    capability,
                },
                common::Interfaces::default(),
                transmitter.clone(),
            ),
        );
        assert!(
            client
                .send_layer3(
                    send::Request::packet(packet("10.0.0.1"), send::Options::default()),
                    send::Collector::default()
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(transmitter.0.lock().unwrap().is_empty());
    }
}

#[derive(Clone)]
struct ChangingRoutes {
    decision: Arc<Mutex<route::Decision>>,
    calls: Arc<AtomicUsize>,
}

impl route::Provider for ChangingRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<route::Decision, Infallible> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.decision.lock().unwrap().clone())
    }
}

#[derive(Clone)]
struct PacingGate {
    now: Arc<Mutex<Instant>>,
    entered: mpsc::SyncSender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl packetcraftr::clock::Clock for PacingGate {
    type Error = std::io::Error;

    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }

    fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
        assert!(
            !delay.is_zero(),
            "the witness needs an explicit pacing wait"
        );
        self.entered.send(()).map_err(std::io::Error::other)?;
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .map_err(std::io::Error::other)?;
        *self.now.lock().unwrap() += delay;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum PacingChange {
    Mtu,
    Interface,
    Cancellation,
}

fn changed_during_pacing(change: PacingChange) {
    for layer3_entry in [false, true] {
        let deadline = Deadline::new(Duration::from_secs(10));
        let decision = common::FixedRoutes
            .lookup_with_preferences("10.0.0.1".parse().unwrap(), None, None, &deadline)
            .unwrap();
        let selected_interface = decision.interface.clone();
        let decision = Arc::new(Mutex::new(decision));
        let calls = Arc::new(AtomicUsize::new(0));
        let transmitter = TransmitOnly::default();
        let (entered, waiting) = mpsc::sync_channel(1);
        let (release, resumed) = mpsc::sync_channel(1);
        let clock = PacingGate {
            now: Arc::new(Mutex::new(Instant::now())),
            entered,
            release: Arc::new(Mutex::new(resumed)),
        };
        let cancellation = Cancellation::default();
        let client = Client::new(
            builtin::registry(),
            policy(),
            ProviderSet::packet(
                ChangingRoutes {
                    decision: Arc::clone(&decision),
                    calls: Arc::clone(&calls),
                },
                common::Interfaces::default(),
                common::NeverTransmit,
                transmitter.clone(),
            ),
        )
        .with_clock(clock)
        .with_cancellation(cancellation.clone());
        let mut request = send::Request::packet(
            packet("10.0.0.1"),
            send::Options {
                plan: packetcraftr::route::Options {
                    link_mode: Mode::Layer3,
                    interface: Some(selected_interface.into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        request.repeat = 2;
        request.rate = Some(1);
        let worker = std::thread::spawn(move || {
            if layer3_entry {
                client.send_layer3(request, send::Collector::default())
            } else {
                client.send(request, send::Collector::default())
            }
        });
        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(transmitter.0.lock().unwrap().len(), 1);
        match change {
            PacingChange::Mtu => decision.lock().unwrap().mtu = 20,
            PacingChange::Interface => {
                decision.lock().unwrap().interface = interface::Id {
                    index: 2,
                    name: "changed0".to_owned(),
                };
            }
            PacingChange::Cancellation => cancellation.cancel(),
        }
        release.send(()).unwrap();
        let result = worker.join().unwrap();
        assert!(
            result.is_err(),
            "{change:?}, layer3={layer3_entry}: {result:?}"
        );
        assert_eq!(
            transmitter.0.lock().unwrap().len(),
            1,
            "a pacing boundary cannot retain permission for a stale second send"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            if matches!(change, PacingChange::Cancellation) {
                1
            } else {
                2
            },
            "cancelled preparation must not observe a new route"
        );
    }
}

#[test]
fn pacing_wait_precedes_next_packet_mtu_validation() {
    changed_during_pacing(PacingChange::Mtu);
}

#[test]
fn pacing_wait_precedes_next_packet_interface_validation() {
    changed_during_pacing(PacingChange::Interface);
}

#[test]
fn cancellation_during_pacing_precedes_next_route_lookup() {
    changed_during_pacing(PacingChange::Cancellation);
}
