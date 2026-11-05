// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::Error;
use crate::interface::Id;
use crate::platform::transmit::namespace::{ExecutionContext, Reuse};
use crate::platform::transmit::session::{Backend as SessionBackend, Bounded, Preparation};
use crate::transmit::{Outbound, Provider, Report};

use super::preparation::{PreparedRawIp, prepare};
use super::submission::{map_raw_error, open_loopback};

// Linux reserves index 1 for the built-in loopback throughout the namespace lifetime.
const LOOPBACK_IFINDEX: u32 = 1;

#[derive(PartialEq, Eq)]
enum Family {
    Ipv4,
    Ipv6,
}

#[derive(PartialEq, Eq)]
struct Key {
    interface: Id,
    family: Family,
}

trait Environment: Send + Sync {
    fn verify(&self) -> Result<Reuse, Error>;
    fn verify_interface(&self, interface: &Id) -> Result<(), Error>;
}

struct NativeEnvironment(ExecutionContext);

impl Environment for NativeEnvironment {
    fn verify(&self) -> Result<Reuse, Error> {
        self.0.verify()
    }

    fn verify_interface(&self, interface: &Id) -> Result<(), Error> {
        crate::platform::interface::verify_identity(interface)
    }
}

trait Transport: Send + Sync {
    type Socket: Send;

    fn open(&self, packet: &PreparedRawIp) -> Result<Option<Self::Socket>, Error>;
    fn send(&self, socket: &mut Self::Socket, packet: PreparedRawIp) -> Result<Report, Error>;
}

struct NativeTransport;

impl Transport for NativeTransport {
    type Socket = socket2::Socket;

    fn open(&self, packet: &PreparedRawIp) -> Result<Option<Self::Socket>, Error> {
        open_loopback(packet).map_err(|error| map_raw_error(&packet.interface, error))
    }

    fn send(&self, socket: &mut Self::Socket, packet: PreparedRawIp) -> Result<Report, Error> {
        super::submit(socket, packet)
    }
}

struct Backend<P, E, T> {
    fallback: P,
    environment: E,
    transport: T,
}

impl<P: Provider, E: Environment, T: Transport> SessionBackend for Backend<P, E, T> {
    type Key = Key;
    type Packet<'a> = PreparedRawIp;
    type Resource = T::Socket;

    fn prepare(&self, outbound: Outbound<'_>) -> Result<Preparation<Key, PreparedRawIp>, Error> {
        let Reuse::Verified = self.environment.verify()? else {
            return Ok(Preparation::Fallback);
        };
        let Outbound::Layer3(frame) = outbound else {
            return Ok(Preparation::Fallback);
        };
        let interface = &frame.route().decision.interface;
        if interface.index != LOOPBACK_IFINDEX {
            return Ok(Preparation::Fallback);
        }
        self.environment.verify_interface(interface)?;
        let packet = prepare(frame)?;
        let family = match packet.destination {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        };
        Ok(Preparation::Reusable {
            key: Key {
                interface: interface.clone(),
                family,
            },
            packet,
        })
    }

    fn open(&self, packet: &PreparedRawIp) -> Result<Option<Self::Resource>, Error> {
        let socket = self.transport.open(packet)?;
        self.environment.verify_interface(&packet.interface)?;
        Ok(socket)
    }

    fn send(&self, socket: &mut Self::Resource, packet: PreparedRawIp) -> Result<Report, Error> {
        self.transport.send(socket, packet)
    }

    fn fallback(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        self.fallback.send(outbound)
    }
}

pub(in crate::platform::transmit) fn wrap(fallback: impl Provider + 'static) -> Box<dyn Provider> {
    Box::new(Bounded::new(Backend {
        fallback,
        environment: NativeEnvironment(ExecutionContext::capture()),
        transport: NativeTransport,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use bytes::Bytes;
    use packetcraftr_core::{frame::LinkType, protocol::checksum_parts};

    use super::*;
    use crate::{
        link::{Capability, Mode},
        route::{Decision, Scope, SelectionReason},
        transmit::Route,
    };

    #[derive(Default)]
    struct Counts {
        opens: AtomicUsize,
        drops: AtomicUsize,
        fallbacks: AtomicUsize,
        frames: Mutex<Vec<Bytes>>,
        bad_namespace: AtomicBool,
        bad_credentials: AtomicBool,
        bad_interface: AtomicBool,
        change_interface_on_open: AtomicBool,
        unsupported: AtomicBool,
        fail_send: AtomicBool,
    }

    struct FakeEnvironment(Arc<Counts>);

    impl Environment for FakeEnvironment {
        fn verify(&self) -> Result<Reuse, Error> {
            if self.0.bad_credentials.load(Ordering::SeqCst) {
                return Err(Error::Privilege {
                    message: "credentials changed".to_owned(),
                    source: None,
                });
            }
            if self.0.bad_namespace.load(Ordering::SeqCst) {
                return Err(Error::Send {
                    message: "namespace changed".to_owned(),
                    source: None,
                });
            }
            Ok(Reuse::Verified)
        }

        fn verify_interface(&self, _interface: &Id) -> Result<(), Error> {
            if self.0.bad_interface.load(Ordering::SeqCst) {
                return Err(Error::Send {
                    message: "interface changed".to_owned(),
                    source: None,
                });
            }
            Ok(())
        }
    }

    struct FakeSocket(Arc<Counts>);

    impl Drop for FakeSocket {
        fn drop(&mut self) {
            self.0.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct FakeTransport(Arc<Counts>);

    impl Transport for FakeTransport {
        type Socket = FakeSocket;

        fn open(&self, _packet: &PreparedRawIp) -> Result<Option<Self::Socket>, Error> {
            self.0.opens.fetch_add(1, Ordering::SeqCst);
            if self.0.unsupported.load(Ordering::SeqCst) {
                return Ok(None);
            }
            if self.0.change_interface_on_open.load(Ordering::SeqCst) {
                self.0.bad_interface.store(true, Ordering::SeqCst);
            }
            Ok(Some(FakeSocket(self.0.clone())))
        }

        fn send(&self, _socket: &mut Self::Socket, packet: PreparedRawIp) -> Result<Report, Error> {
            self.0.frames.lock().unwrap().push(packet.submission);
            if self.0.fail_send.load(Ordering::SeqCst) {
                return Err(Error::Send {
                    message: "native send failed".to_owned(),
                    source: None,
                });
            }
            Ok(Report::committed(
                packet.wire_bytes.len(),
                packet.wire_bytes,
            ))
        }
    }

    struct FakeFallback(Arc<Counts>);

    impl Provider for FakeFallback {
        fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
            self.0.fallbacks.fetch_add(1, Ordering::SeqCst);
            let bytes = outbound.bytes().clone();
            Ok(Report::committed(bytes.len(), bytes))
        }
    }

    fn session(counts: &Arc<Counts>) -> impl Provider {
        Bounded::new(Backend {
            fallback: FakeFallback(counts.clone()),
            environment: FakeEnvironment(counts.clone()),
            transport: FakeTransport(counts.clone()),
        })
    }

    fn decision(index: u32, source: IpAddr) -> Decision {
        Decision {
            interface: Id {
                name: "interface".to_owned(),
                index,
            },
            source_mac: None,
            selected_source: Some(source),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::Local,
            destination_scope: Scope::Host,
            mtu: 1500,
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        }
    }

    fn ipv6() -> (Bytes, IpAddr) {
        let destination = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let mut bytes = [0; 40];
        bytes[0] = 0x60;
        bytes[6] = 59;
        bytes[7] = 64;
        bytes[23] = 1;
        bytes[39] = 1;
        (Bytes::copy_from_slice(&bytes), destination)
    }

    fn ipv4() -> (Bytes, IpAddr) {
        let destination = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut bytes = [
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ];
        let checksum = checksum_parts(&[&bytes]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        (Bytes::copy_from_slice(&bytes), destination)
    }

    fn outbound<'a>(bytes: &'a Bytes, decision: &'a Decision, destination: IpAddr) -> Outbound<'a> {
        Outbound::try_new(
            bytes,
            Route {
                decision,
                mode: Mode::Layer3,
                lookup_destination: Some(destination),
            },
        )
        .unwrap()
    }

    #[test]
    fn preparation_rejects_incomplete_interfaces() {
        let (bytes, destination) = ipv6();
        for interface in [
            Id {
                name: String::new(),
                index: LOOPBACK_IFINDEX,
            },
            Id {
                name: "interface".into(),
                index: 0,
            },
        ] {
            let route = Decision {
                interface,
                ..decision(LOOPBACK_IFINDEX, destination)
            };
            let Outbound::Layer3(frame) = outbound(&bytes, &route, destination) else {
                unreachable!();
            };
            assert!(
                matches!(prepare(frame), Err(Error::InvalidTransmissionFrame { message })
                if message == "route-selected interface identity is incomplete")
            );
        }
    }

    #[test]
    fn loopback_reuses_socket_and_validates_frames() {
        let counts = Arc::new(Counts::default());
        let session = session(&counts);
        let (bytes, destination) = ipv6();
        let route = decision(LOOPBACK_IFINDEX, destination);
        for _ in 0..8 {
            session
                .send(outbound(&bytes, &route, destination))
                .unwrap()
                .validate_exact(&bytes)
                .unwrap();
        }
        assert_eq!(counts.opens.load(Ordering::SeqCst), 1);
        let frames = counts.frames.lock().unwrap().clone();
        assert_eq!(frames.len(), 8);
        assert!(frames.iter().all(|frame| frame == &bytes));

        let mut changed = bytes.to_vec();
        changed[7] /= 2;
        let changed = Bytes::from(changed);
        session
            .send(outbound(&changed, &route, destination))
            .unwrap()
            .validate_exact(&changed)
            .unwrap();
        assert_eq!(counts.frames.lock().unwrap().last(), Some(&changed));

        let other_destination = IpAddr::V6("::2".parse().unwrap());
        assert!(matches!(
            session.send(outbound(&bytes, &route, other_destination)),
            Err(Error::InvalidTransmissionFrame { .. })
        ));
        session.send(outbound(&bytes, &route, destination)).unwrap();
        assert_eq!(counts.opens.load(Ordering::SeqCst), 1);

        let (v4_bytes, v4_destination) = ipv4();
        let v4_route = decision(LOOPBACK_IFINDEX, v4_destination);
        session
            .send(outbound(&v4_bytes, &v4_route, v4_destination))
            .unwrap();
        let other_route = decision(LOOPBACK_IFINDEX + 1, destination);
        session
            .send(outbound(&bytes, &other_route, destination))
            .unwrap();
        assert_eq!(counts.fallbacks.load(Ordering::SeqCst), 2);
        assert_eq!(counts.opens.load(Ordering::SeqCst), 1);
        drop(session);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn loopback_stops_on_identity_or_send_failure() {
        let counts = Arc::new(Counts::default());
        let session = session(&counts);
        let (bytes, destination) = ipv4();
        let route = decision(LOOPBACK_IFINDEX, destination);
        session.send(outbound(&bytes, &route, destination)).unwrap();
        counts.bad_namespace.store(true, Ordering::SeqCst);
        assert!(session.send(outbound(&bytes, &route, destination)).is_err());
        let other_route = decision(LOOPBACK_IFINDEX + 1, destination);
        assert!(
            session
                .send(outbound(&bytes, &other_route, destination))
                .is_err()
        );
        counts.bad_namespace.store(false, Ordering::SeqCst);
        counts.bad_credentials.store(true, Ordering::SeqCst);
        assert!(matches!(
            session.send(outbound(&bytes, &route, destination)),
            Err(Error::Privilege { .. })
        ));
        assert!(matches!(
            session.send(outbound(&bytes, &other_route, destination)),
            Err(Error::Privilege { .. })
        ));
        counts.bad_credentials.store(false, Ordering::SeqCst);
        counts.bad_interface.store(true, Ordering::SeqCst);
        assert!(session.send(outbound(&bytes, &route, destination)).is_err());
        counts.bad_interface.store(false, Ordering::SeqCst);
        counts.fail_send.store(true, Ordering::SeqCst);
        assert!(session.send(outbound(&bytes, &route, destination)).is_err());
        assert!(session.send(outbound(&bytes, &route, destination)).is_err());
        assert_eq!(counts.frames.lock().unwrap().len(), 2);
        assert_eq!(counts.fallbacks.load(Ordering::SeqCst), 0);
        assert_eq!(counts.opens.load(Ordering::SeqCst), 1);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_snapshot_sends_every_frame_one_shot() {
        let counts = Arc::new(Counts::default());
        let empty_root = tempfile::tempdir().unwrap();
        let session = Bounded::new(Backend {
            fallback: FakeFallback(counts.clone()),
            environment: NativeEnvironment(ExecutionContext::capture_at(empty_root.path())),
            transport: FakeTransport(counts.clone()),
        });
        let (bytes, destination) = ipv4();
        let loopback = decision(LOOPBACK_IFINDEX, destination);
        let other = decision(LOOPBACK_IFINDEX + 1, destination);

        for route in [&loopback, &loopback, &other] {
            session
                .send(outbound(&bytes, route, destination))
                .unwrap()
                .validate_exact(&bytes)
                .unwrap();
        }

        assert_eq!(counts.fallbacks.load(Ordering::SeqCst), 3);
        assert_eq!(counts.opens.load(Ordering::SeqCst), 0);
        assert!(counts.frames.lock().unwrap().is_empty());
    }

    #[test]
    fn unsupported_binding_fallback_releases_socket() {
        let counts = Arc::new(Counts::default());
        counts.unsupported.store(true, Ordering::SeqCst);
        let session = session(&counts);
        let (bytes, destination) = ipv4();
        let route = decision(LOOPBACK_IFINDEX, destination);
        session.send(outbound(&bytes, &route, destination)).unwrap();
        assert_eq!(counts.opens.load(Ordering::SeqCst), 1);
        assert_eq!(counts.fallbacks.load(Ordering::SeqCst), 1);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 0);

        counts.unsupported.store(false, Ordering::SeqCst);
        session
            .send(outbound(&bytes, &route, destination))
            .unwrap()
            .validate_exact(&bytes)
            .unwrap();
        assert_eq!(counts.opens.load(Ordering::SeqCst), 2);
        assert_eq!(counts.fallbacks.load(Ordering::SeqCst), 1);
        drop(session);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn interface_change_during_open_prevents_transmission() {
        let counts = Arc::new(Counts::default());
        counts
            .change_interface_on_open
            .store(true, Ordering::SeqCst);
        let session = session(&counts);
        let (bytes, destination) = ipv4();
        let route = decision(LOOPBACK_IFINDEX, destination);

        assert!(session.send(outbound(&bytes, &route, destination)).is_err());
        assert!(counts.frames.lock().unwrap().is_empty());
        assert_eq!(counts.opens.load(Ordering::SeqCst), 1);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
        assert_eq!(counts.fallbacks.load(Ordering::SeqCst), 0);

        counts
            .change_interface_on_open
            .store(false, Ordering::SeqCst);
        counts.bad_interface.store(false, Ordering::SeqCst);
        session
            .send(outbound(&bytes, &route, destination))
            .unwrap()
            .validate_exact(&bytes)
            .unwrap();
        assert_eq!(counts.opens.load(Ordering::SeqCst), 2);
        assert_eq!(counts.frames.lock().unwrap().as_slice(), &[bytes]);
        drop(session);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 2);
    }
}
