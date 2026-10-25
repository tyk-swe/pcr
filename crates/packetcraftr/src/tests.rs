// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    clock::{Clock, SystemClock},
    route,
    target::{Error as TargetError, Hostname, Resolver, Target},
};
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    frame::LinkType,
    packet::Packet,
};
use packetcraftr_netio::{
    interface,
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

fn decision() -> Decision {
    Decision {
        interface: interface::Id {
            name: "test0".into(),
            index: 1,
        },
        source_mac: None,
        selected_source: Some("127.0.0.1".parse().unwrap()),
        preferred_source: None,
        next_hop: None,
        selection_reason: SelectionReason::Local,
        destination_scope: Scope::Host,
        mtu: 1500,
        capability: Capability::Layer3,
        link_type: LinkType::RAW,
    }
}
fn info(id: interface::Id) -> interface::Info {
    interface::Info {
        id,
        description: None,
        mac_address: None,
        addresses: vec![],
        flags: Default::default(),
        mtu: Some(1500),
        capability: Capability::Layer3,
        link_type: LinkType::RAW,
    }
}
struct Routes {
    unavailable: AtomicBool,
    cancel: Option<Cancellation>,
    invalid: bool,
}
impl packetcraftr_netio::route::Provider for Routes {
    type Error = packetcraftr_netio::route::Error;
    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Self::Error> {
        assert!(
            !self.unavailable.load(Ordering::SeqCst),
            "disabled provider must not be queried"
        );
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        let mut answer = decision();
        if self.invalid {
            answer.interface.index = 0;
        }
        Ok(answer)
    }
}
struct Interfaces {
    values: Vec<interface::Id>,
    cancel: Option<Cancellation>,
}
impl interface::Provider for Interfaces {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        Ok(self.values.iter().cloned().map(info).collect())
    }
}
#[test]
fn absolute_hostname_and_resolver_spelling() {
    struct Recording;
    impl Resolver for Recording {
        fn resolve(&self, host: &Hostname, _: usize) -> Result<Vec<IpAddr>, TargetError> {
            assert_eq!(host.as_str(), "example.test.");
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }
    let absolute: Hostname = "Example.TEST.".parse().unwrap();
    assert_eq!(absolute.to_string(), "example.test.");
    assert_eq!(
        serde_json::to_string(&absolute).unwrap(),
        "\"example.test.\""
    );
    assert_ne!(absolute, "example.test".parse::<Hostname>().unwrap());
    let policy = crate::policy::Policy {
        allow_hostname_resolution: true,
        ..Default::default()
    };
    let resolved = policy
        .resolve_target(
            &Target::Hostname(absolute),
            &Recording,
            &Deadline::new(Duration::from_secs(1)),
        )
        .unwrap();
    assert_eq!(
        resolved.addresses(),
        ["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        resolved.declared(),
        &Target::Hostname("example.test.".parse().unwrap())
    );
}
#[test]
fn clock_stops_at_spent_deadline() {
    let not_before = Instant::now() + Duration::from_millis(10);
    SystemClock
        .sleep(
            not_before.saturating_duration_since(Instant::now()),
            &Deadline::new(Duration::from_secs(1)),
        )
        .unwrap();
    assert!(Instant::now() >= not_before);
    let (started, beginning) = mpsc::sync_channel(1);
    let (finished, completion) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        let result = SystemClock.sleep(Duration::from_secs(10), &Deadline::immediate(None));
        finished.send(result).unwrap();
    });
    beginning.recv_timeout(Duration::from_secs(5)).unwrap();
    completion
        .recv_timeout(Duration::from_secs(5))
        .expect("spent control must interrupt sleep")
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn client_accessors_preserve_supplied_registry_policy_and_runtime() {
    let allowed = "127.0.0.2".parse().unwrap();
    let policy = crate::policy::Policy {
        allowed_destinations: vec![crate::policy::DestinationConstraint::Exact(allowed)],
        ..Default::default()
    };
    let client = crate::Client::new(packetcraftr_core::protocol::builtin::registry(), policy, ())
        .with_runtime(crate::runtime::Runtime::new(0).unwrap());
    assert_eq!(
        client
            .registry()
            .protocol_named("IPv6")
            .map(packetcraftr_core::layer::Id::as_str),
        Some("ipv6")
    );
    client.policy().authorize_destination(allowed).unwrap();
    assert!(matches!(
        client
            .policy()
            .authorize_destination("127.0.0.1".parse().unwrap()),
        Err(crate::policy::Error::DestinationNotAllowed { .. })
    ));
    assert_eq!(client.runtime().capacity(), 0);
}

#[test]
fn identification_hard_byte_ceiling_accepts_the_boundary_and_refuses_excess() {
    let mut request = crate::identify::Request::new(
        vec![crate::identify::Endpoint {
            address: "127.0.0.1:80".parse().unwrap(),
            transport: crate::identify::Transport::Tcp,
        }],
        crate::identify::builtin_corpus().unwrap(),
        crate::identify::builtin_exclusions().unwrap(),
    );
    let policy = crate::policy::Policy {
        max_bytes_per_operation: u64::MAX,
        max_packets_per_operation: u64::MAX,
        ..Default::default()
    };
    request.limits.operation.read_bytes = 64 * 1024 * 1024;
    request.validate(&policy).unwrap();
    request.limits.operation.read_bytes += 1;
    assert!(matches!(
        request.validate(&policy),
        Err(crate::identify::Error::Request { .. })
    ));
}

#[test]
fn os_hard_evidence_ceiling_accepts_the_boundary_and_refuses_excess() {
    let mut request = crate::os::Request::new(
        "127.0.0.1".parse().unwrap(),
        80,
        81,
        crate::os::builtin_corpus().unwrap(),
    );
    request.limits.evidence.max_bytes = 1024 * 1024;
    request.validate().unwrap();
    request.limits.evidence.max_bytes += 1;
    assert!(matches!(
        request.validate(),
        Err(crate::os::Error::Invalid(_))
    ));
}
#[test]
fn interface_ambiguity_and_late_enumeration() {
    let selector = route::Interface::Name("test0".into());
    let first = decision().interface;
    let second = interface::Id {
        name: first.name.clone(),
        index: 2,
    };
    let resolve = route::ResolvedInterface::default();
    assert!(matches!(
        resolve.resolve(
            &selector,
            &Interfaces {
                values: vec![first.clone(), second],
                cancel: None
            },
            &Deadline::new(Duration::from_secs(1))
        ),
        Err(route::Error::AmbiguousInterface { .. })
    ));
    let index = route::Interface::Index(std::num::NonZeroU32::new(1).unwrap());
    assert!(matches!(
        resolve.resolve(
            &index,
            &Interfaces {
                values: vec![
                    first.clone(),
                    interface::Id {
                        name: "other".into(),
                        index: 1
                    }
                ],
                cancel: None
            },
            &Deadline::new(Duration::from_secs(1))
        ),
        Err(route::Error::AmbiguousInterface { .. })
    ));
    let cancel = Cancellation::default();
    assert!(matches!(
        resolve.resolve(
            &selector,
            &Interfaces {
                values: vec![first],
                cancel: Some(cancel.clone())
            },
            &Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancel))
        ),
        Err(route::Error::Interrupted(_))
    ));
}
#[test]
fn route_deadline_cache_and_identity() {
    use packetcraftr_netio::route::Provider;
    let provider = Routes {
        unavailable: AtomicBool::new(false),
        cancel: None,
        invalid: false,
    };
    let cached = route::CachedProvider::new(&provider);
    let address = "127.0.0.2".parse().unwrap();
    let first = cached
        .lookup_with_preferences(address, None, None, &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(first.interface, decision().interface);
    assert_eq!(first.selected_source, decision().selected_source);
    provider.unavailable.store(true, Ordering::SeqCst);
    let reused = cached
        .lookup_with_preferences(address, None, None, &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(reused.interface, first.interface);
    assert_eq!(reused.selected_source, first.selected_source);
    assert!(matches!(
        cached.lookup_with_preferences(address, None, None, &Deadline::immediate(None)),
        Err(route::Error::Interrupted(_))
    ));
    let cancel = Cancellation::default();
    let late = Routes {
        unavailable: AtomicBool::new(false),
        cancel: Some(cancel.clone()),
        invalid: false,
    };
    let options = route::Options {
        link_mode: Mode::Layer3,
        ..Default::default()
    };
    assert!(matches!(
        route::plan(
            &Packet::new(),
            Some(address),
            &options,
            &late,
            &Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancel))
        ),
        Err(route::Error::Interrupted(_))
    ));
    let invalid = Routes {
        unavailable: AtomicBool::new(false),
        cancel: None,
        invalid: true,
    };
    assert!(matches!(
        route::plan(
            &Packet::new(),
            Some(address),
            &options,
            &invalid,
            &Deadline::new(Duration::from_secs(1))
        ),
        Err(route::Error::InvalidRouteIdentity { .. })
    ));
    assert!(matches!(
        route::plan(
            &Packet::new(),
            Some(address),
            &options,
            &provider,
            &Deadline::immediate(None)
        ),
        Err(route::Error::Interrupted(_))
    ));
}
#[test]
fn numeric_and_custom_resolution_boundaries() {
    struct Late(Cancellation);
    impl Resolver for Late {
        fn resolve(&self, _: &Hostname, _: usize) -> Result<Vec<IpAddr>, TargetError> {
            unreachable!()
        }
        fn resolve_controlled(
            &self,
            _: &Hostname,
            _: usize,
            _: &Deadline,
        ) -> Result<Vec<IpAddr>, TargetError> {
            self.0.cancel();
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }
    let policy = crate::policy::Policy {
        allow_hostname_resolution: true,
        ..Default::default()
    };
    let cancel = Cancellation::default();
    let resolver = Late(cancel.clone());
    let numeric = policy
        .resolve_target(
            &"127.0.0.1".parse().unwrap(),
            &resolver,
            &Deadline::new(Duration::from_secs(1)),
        )
        .unwrap();
    assert_eq!(
        numeric.addresses(),
        ["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
    assert!(matches!(
        policy.resolve_target(
            &"127.0.0.1".parse().unwrap(),
            &resolver,
            &Deadline::immediate(None)
        ),
        Err(crate::policy::ResolutionError::Target(
            TargetError::Control(_)
        ))
    ));
    let parent = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancel));
    let deadline = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
    assert!(matches!(
        policy.resolve_target(&"example.test".parse().unwrap(), &resolver, &deadline),
        Err(crate::policy::ResolutionError::Target(
            TargetError::Control(_)
        ))
    ));
}
#[test]
fn distinct_resolver_order_and_limit() {
    let hostname = "test.local".parse().unwrap();
    let a = "127.0.0.1".parse().unwrap();
    let b = "127.0.0.2".parse().unwrap();
    assert_eq!(
        crate::target::distinct_addresses(&hostname, [b, a, b, a], 2).unwrap(),
        [b, a]
    );
    assert!(matches!(
        crate::target::distinct_addresses(&hostname, [b, a, b], 1),
        Err(TargetError::AddressLimit { .. })
    ));
}

mod audit {
    use crate::{
        Client, ProviderSet, audit,
        clock::Clock,
        policy::{DestinationConstraint, Policy},
    };
    use packetcraftr_core::{
        budget::{Cancellation, Deadline},
        protocol::builtin,
    };
    use packetcraftr_netio::{tcp, tls};
    use std::{
        collections::BTreeSet,
        convert::Infallible,
        io::{self, Cursor, Read, Write},
        net::SocketAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    #[derive(Clone)]
    struct AuditClock(Arc<Mutex<Instant>>);

    impl AuditClock {
        fn advance(&self, duration: Duration) {
            *self.0.lock().unwrap() += duration;
        }
    }

    impl Clock for AuditClock {
        type Error = Infallible;
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
        fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
            self.advance(delay);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum Ending {
        Eof,
        ReadFailure,
        FlushFailure,
        TimeoutBoundary,
        Expire,
        Cancel,
    }

    enum AuditResponse {
        Bytes(Cursor<Vec<u8>>),
        Tls {
            session: Box<rustls::ServerConnection>,
            application: Arc<Mutex<Vec<u8>>>,
        },
    }

    struct AuditStream {
        peer: Arc<Mutex<SocketAddr>>,
        response: AuditResponse,
        written: Arc<Mutex<Vec<u8>>>,
        clock: AuditClock,
        cancellation: Cancellation,
        ending: Ending,
    }

    impl Read for AuditStream {
        fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
            let count = match &mut self.response {
                AuditResponse::Bytes(response) => response.read(bytes)?,
                AuditResponse::Tls { session, .. } => session.write_tls(&mut bytes)?,
            };
            if matches!(self.ending, Ending::TimeoutBoundary) {
                self.clock.advance(Duration::from_secs(5));
            }
            if matches!(self.ending, Ending::Expire) {
                self.clock.advance(Duration::from_secs(3601));
            }
            if matches!(self.ending, Ending::Cancel) {
                self.cancellation.cancel();
            }
            if count > 0 {
                return Ok(count);
            }
            match self.ending {
                Ending::Eof | Ending::FlushFailure => Ok(0),
                Ending::ReadFailure => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled read failure",
                )),
                Ending::TimeoutBoundary | Ending::Expire => Err(io::ErrorKind::TimedOut.into()),
                Ending::Cancel => Err(io::ErrorKind::Interrupted.into()),
            }
        }
    }

    impl Write for AuditStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = match &mut self.response {
                AuditResponse::Bytes(_) => bytes.len(),
                AuditResponse::Tls {
                    session,
                    application,
                } => {
                    let count = session.read_tls(&mut Cursor::new(bytes))?;
                    let available = session
                        .process_new_packets()
                        .map_err(io::Error::other)?
                        .plaintext_bytes_to_read();
                    if available > 0 {
                        let mut received = vec![0; available];
                        session.reader().read_exact(&mut received)?;
                        application.lock().unwrap().extend(received);
                        session
                            .writer()
                            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")?;
                    }
                    count
                }
            };
            self.written
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            if matches!(self.ending, Ending::FlushFailure) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled flush failure",
                ));
            }
            Ok(())
        }
    }

    impl tcp::Stream for AuditStream {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(*self.peer.lock().unwrap())
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:50000".parse().unwrap())
        }
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    struct AuditTcp {
        stream: Mutex<Option<AuditStream>>,
        forbidden: Arc<AtomicBool>,
    }

    impl tcp::Provider for AuditTcp {
        type Stream = AuditStream;
        fn connect(&self, endpoint: SocketAddr, _: &Deadline) -> Result<Self::Stream, tcp::Error> {
            assert!(
                !self.forbidden.load(Ordering::SeqCst),
                "audit must refuse before connecting"
            );
            assert_eq!(endpoint, endpoint_fixture());
            Ok(self
                .stream
                .lock()
                .unwrap()
                .take()
                .expect("one connection per audit"))
        }
    }

    type AuditClient = Client<ProviderSet<(), (), (), (), AuditTcp, ()>, AuditClock>;
    struct Fixture {
        client: AuditClient,
        written: Arc<Mutex<Vec<u8>>>,
        peer: Arc<Mutex<SocketAddr>>,
        forbidden: Arc<AtomicBool>,
    }

    fn endpoint_fixture() -> SocketAddr {
        "127.0.0.1:8443".parse().unwrap()
    }
    fn policy() -> Policy {
        Policy {
            allowed_destinations: vec![DestinationConstraint::Exact(endpoint_fixture().ip())],
            max_packets_per_operation: 2,
            max_bytes_per_operation: 1_048_576,
            ..Policy::default()
        }
    }
    fn fixture(policy: Policy, response: &[u8], ending: Ending) -> Fixture {
        response_fixture(
            policy,
            AuditResponse::Bytes(Cursor::new(response.to_vec())),
            ending,
        )
    }
    fn response_fixture(policy: Policy, response: AuditResponse, ending: Ending) -> Fixture {
        let clock = AuditClock(Arc::new(Mutex::new(Instant::now())));
        let cancellation = Cancellation::default();
        let written = Arc::new(Mutex::new(Vec::new()));
        let peer = Arc::new(Mutex::new(endpoint_fixture()));
        let forbidden = Arc::new(AtomicBool::new(false));
        let stream = AuditStream {
            peer: Arc::clone(&peer),
            response,
            written: Arc::clone(&written),
            clock: clock.clone(),
            cancellation: cancellation.clone(),
            ending,
        };
        let provider = AuditTcp {
            stream: Mutex::new(Some(stream)),
            forbidden: Arc::clone(&forbidden),
        };
        let client = Client::new(builtin::registry(), policy, ProviderSet::tcp(provider, ()))
            .with_clock(clock)
            .with_cancellation(cancellation);
        Fixture {
            client,
            written,
            peer,
            forbidden,
        }
    }

    fn http_request() -> audit::HttpRequest {
        let mut request = audit::HttpRequest::new(endpoint_fixture());
        request.host = "example.test".into();
        request.path = "/audit?kind=headers".into();
        request
    }

    fn expected_request(request: &audit::HttpRequest) -> Vec<u8> {
        // https://www.rfc-editor.org/rfc/rfc9112.html#section-3 checked 2026-10-25.
        format!("HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: PacketcraftR-audit\r\n\r\n", request.path, request.host).into_bytes()
    }

    #[test]
    fn audit_validation_refuses_invalid_requests_before_connecting() {
        let setup = fixture(policy(), b"", Ending::Eof);
        setup.forbidden.store(true, Ordering::SeqCst);
        let base = audit::TlsRequest::new(endpoint_fixture());
        for request in [
            audit::TlsRequest {
                endpoint: "127.0.0.1:0".parse().unwrap(),
                ..base.clone()
            },
            audit::TlsRequest {
                timeout: Duration::ZERO,
                ..base.clone()
            },
            audit::TlsRequest {
                timeout: Duration::from_secs(3601),
                ..base.clone()
            },
        ] {
            assert!(matches!(
                setup.client.audit_tls(&request),
                Err(audit::Error::Invalid(_))
            ));
        }
        let invalid_name = audit::TlsRequest {
            server_name: Some("bad name".into()),
            ..base.clone()
        };
        assert!(matches!(
            setup.client.audit_tls(&invalid_name),
            Err(audit::Error::Tls(tls::Error::InvalidServerName))
        ));
        let invalid_limits = audit::TlsRequest {
            limits: tls::Limits {
                max_steps: 0,
                ..base.limits
            },
            ..base
        };
        assert!(matches!(
            setup.client.audit_tls(&invalid_limits),
            Err(audit::Error::Tls(tls::Error::InvalidLimits))
        ));
        for host in [
            String::new(),
            "example test".into(),
            "éxample.test".into(),
            "example\r\nInjected: yes".into(),
            "a".repeat(1025),
            "example/test".into(),
            "example\\test".into(),
            "example@test".into(),
            "example#test".into(),
            "example?test".into(),
        ] {
            let request = audit::HttpRequest {
                host,
                ..http_request()
            };
            assert!(matches!(
                setup.client.audit_http(&request),
                Err(audit::Error::Invalid(_))
            ));
        }
        for path in [
            "relative".into(),
            "/line\r\nInjected: yes".into(),
            "/nul\0".into(),
            "/é".into(),
            format!("/{}", "a".repeat(8192)),
        ] {
            let request = audit::HttpRequest {
                path,
                ..http_request()
            };
            assert!(matches!(
                setup.client.audit_http(&request),
                Err(audit::Error::Invalid(_))
            ));
        }
        for max_response_bytes in [0, 65_536] {
            let request = audit::HttpRequest {
                max_response_bytes,
                ..http_request()
            };
            assert!(matches!(
                setup.client.audit_http(&request),
                Err(audit::Error::Invalid(_))
            ));
        }
        assert!(setup.written.lock().unwrap().is_empty());
    }

    #[test]
    fn audit_http_writes_one_head_and_uses_the_final_response() {
        let response = b"HTTP/1.1 100 Continue\r\nSet-Cookie: interim=discard-me\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Security-Policy: frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nSet-Cookie: sid=redacted-secret; Secure; HttpOnly; SameSite=Strict\r\n\r\n";
        let setup = fixture(policy(), response, Ending::ReadFailure);
        let request = http_request();
        let report = setup.client.audit_http(&request).unwrap();
        assert_eq!(*setup.written.lock().unwrap(), expected_request(&request));
        assert_eq!(report.kind, "audit-http");
        assert!(report.completeness.complete);
        assert!(report.findings.is_empty());
        assert_eq!(report.measurements["status"], 200);
        assert_eq!(report.measurements["https"], false);
        assert_eq!(report.measurements["host"], request.host);
        assert_eq!(report.measurements["path"], request.path);
        assert_eq!(
            report.measurements["bytes_sent"],
            expected_request(&request).len()
        );
        assert_eq!(report.measurements["bytes_read"], response.len());
        assert_eq!(
            report.measurements["cookies"],
            serde_json::json!([{"index":0,"name":"sid","value":"[redacted]","secure":true,"http_only":true,"same_site":"strict"}])
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("redacted-secret")
        );
    }

    #[test]
    fn audit_http_accepts_request_and_response_boundaries() {
        let response = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut request = http_request();
        request.connection.timeout = Duration::from_secs(3600);
        request.host = "a".repeat(1024);
        request.path = format!("/{}", "b".repeat(8191));
        request.max_response_bytes = 65_535;
        let setup = fixture(policy(), response, Ending::ReadFailure);
        let report = setup.client.audit_http(&request).unwrap();
        assert_eq!(*setup.written.lock().unwrap(), expected_request(&request));
        assert_eq!(report.measurements["status"], 204);
        let request = audit::HttpRequest {
            max_response_bytes: response.len(),
            ..http_request()
        };
        let report = fixture(policy(), response, Ending::ReadFailure)
            .client
            .audit_http(&request)
            .unwrap();
        assert_eq!(report.measurements["bytes_read"], response.len());
        let request = audit::HttpRequest {
            max_response_bytes: response.len() - 1,
            ..request
        };
        assert!(matches!(
            fixture(policy(), response, Ending::Eof)
                .client
                .audit_http(&request),
            Err(audit::Error::IncompleteResponse)
        ));
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\r\n";
        let report = fixture(policy(), response, Ending::ReadFailure)
            .client
            .audit_http(&http_request())
            .unwrap();
        assert_eq!(report.measurements["status"], 101);
    }

    #[test]
    fn audit_policy_and_peer_refusals_precede_request_bytes() {
        let request = http_request();
        let setup = fixture(policy(), b"", Ending::Eof);
        setup.forbidden.store(true, Ordering::SeqCst);
        let stopped = setup.client.with_deadline(Deadline::immediate(None));
        assert!(matches!(
            stopped.audit_http(&request),
            Err(audit::Error::Interrupted(_))
        ));
        for selected in [
            Policy {
                max_packets_per_operation: 1,
                ..policy()
            },
            Policy {
                max_bytes_per_operation: expected_request(&request).len() as u64 - 1,
                ..policy()
            },
            Policy {
                allowed_destinations: vec![DestinationConstraint::Exact(
                    "127.0.0.2".parse().unwrap(),
                )],
                ..policy()
            },
        ] {
            let setup = fixture(selected, b"", Ending::Eof);
            setup.forbidden.store(true, Ordering::SeqCst);
            assert!(matches!(
                setup.client.audit_http(&request),
                Err(audit::Error::Policy(_))
            ));
            assert!(setup.written.lock().unwrap().is_empty());
        }
        let tls_request = audit::TlsRequest::new(endpoint_fixture());
        let selected = Policy {
            max_bytes_per_operation: tls_request.limits.max_wire_bytes_sent as u64 - 1,
            ..policy()
        };
        let setup = fixture(selected, b"", Ending::Eof);
        setup.forbidden.store(true, Ordering::SeqCst);
        assert!(matches!(
            setup.client.audit_tls(&tls_request),
            Err(audit::Error::Policy(_))
        ));
        for use_tls in [false, true] {
            let setup = fixture(policy(), b"", Ending::Eof);
            *setup.peer.lock().unwrap() = "127.0.0.1:8444".parse().unwrap();
            let error = if use_tls {
                setup.client.audit_tls(&tls_request)
            } else {
                setup.client.audit_http(&request)
            }
            .unwrap_err();
            assert!(
                matches!(error, audit::Error::Io(source) if source.kind() == io::ErrorKind::InvalidData)
            );
            assert!(setup.written.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn audit_http_retains_distinct_io_and_control_failures() {
        for ending in [Ending::ReadFailure, Ending::FlushFailure] {
            let setup = fixture(policy(), b"HTTP/1.1 200 OK\r\nIncomplete:", ending);
            assert!(
                matches!(setup.client.audit_http(&http_request()), Err(audit::Error::Io(source)) if source.kind() == io::ErrorKind::BrokenPipe)
            );
        }
        for ending in [Ending::Expire, Ending::Cancel] {
            for response in [b"".as_slice(), b"HTTP/1.1 200 OK\r\n\r\n"] {
                let setup = fixture(policy(), response, ending);
                let error = setup.client.audit_http(&http_request()).unwrap_err();
                match ending {
                    Ending::Expire => assert!(matches!(
                        error,
                        audit::Error::Interrupted(
                            packetcraftr_core::budget::Interrupted::Exceeded(_)
                        )
                    )),
                    Ending::Cancel => assert!(matches!(
                        error,
                        audit::Error::Interrupted(
                            packetcraftr_core::budget::Interrupted::Cancelled(_)
                        )
                    )),
                    _ => unreachable!(),
                }
            }
        }
        let mut request = http_request();
        request.connection.timeout = Duration::from_secs(5);
        for response in [b"".as_slice(), b"HTTP/1.1 200 OK\r\n\r\n"] {
            let setup = fixture(policy(), response, Ending::TimeoutBoundary);
            assert!(matches!(
                setup.client.audit_http(&request),
                Err(audit::Error::Tcp(tcp::Error::DeadlineExceeded))
            ));
        }
        for response in [
            b"".as_slice(),
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nIncomplete:",
        ] {
            assert!(matches!(
                fixture(policy(), response, Ending::Eof)
                    .client
                    .audit_http(&http_request()),
                Err(audit::Error::IncompleteResponse)
            ));
        }
        for response in [
            b"GET / HTTP/1.1\r\n\r\n".as_slice(),
            b"not an HTTP response\r\n\r\n",
        ] {
            assert!(matches!(
                fixture(policy(), response, Ending::Eof)
                    .client
                    .audit_http(&http_request()),
                Err(audit::Error::Http(_))
            ));
        }
    }

    #[test]
    fn audit_tls_does_not_publish_a_report_after_handshake_eof() {
        let setup = fixture(policy(), b"", Ending::Eof);
        let error = setup
            .client
            .audit_tls(&audit::TlsRequest::new(endpoint_fixture()))
            .unwrap_err();
        assert!(
            matches!(error, audit::Error::Tls(tls::Error::Io(source)) if source.kind() == io::ErrorKind::UnexpectedEof)
        );
        assert!(!setup.written.lock().unwrap().is_empty());
    }

    #[test]
    fn audit_https_withholds_request_when_certificate_evidence_is_unavailable() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["example.test".into()]).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], signing_key.into())
        .unwrap();
        let session = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let application = Arc::new(Mutex::new(Vec::new()));
        let setup = response_fixture(
            policy(),
            AuditResponse::Tls {
                session: Box::new(session),
                application: Arc::clone(&application),
            },
            Ending::Eof,
        );
        let mut request = http_request();
        request.tls = true;
        request.connection.server_name = Some(request.host.clone());
        request.connection.limits.max_certificate_bytes = 0;

        let report = setup.client.audit_http(&request).unwrap();

        assert!(application.lock().unwrap().is_empty());
        assert_eq!(report.kind, "audit-http");
        assert!(!report.completeness.complete);
        assert_eq!(
            report
                .completeness
                .reasons
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "certificate evidence truncated",
                "HTTP request withheld because TLS certificate verification failed"
            ])
        );
        assert!(report.measurements["protocol"].is_string());
        assert!(report.measurements["cipher"].is_string());
        assert_eq!(
            report.measurements["certificate_sha256"],
            serde_json::json!([])
        );
        assert_eq!(
            report.measurements["verification"],
            serde_json::json!({
                "chain": {"valid": null, "reason": "certificate evidence truncated"},
                "name": {"valid": null, "reason": "certificate evidence truncated"}
            })
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["tls.chain_invalid", "tls.name_mismatch"])
        );
        for finding in report.findings {
            assert!(!finding.complete);
            assert_eq!(finding.subject, request.connection.endpoint.to_string());
        }
    }
}

mod capture {
    use super::Interfaces;
    use crate::{
        Client, ProviderSet,
        capture::{Control, Event, StopReason},
        clock::Clock,
        policy::Policy,
    };
    use packetcraftr_core::{
        budget::Deadline,
        error::Classified,
        frame::{Frame, LinkType},
        protocol::builtin,
    };
    use packetcraftr_netio::{capture as native, interface};
    use std::{
        collections::VecDeque,
        convert::Infallible,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    #[derive(Clone)]
    struct CaptureClock(Arc<Mutex<Instant>>);

    impl CaptureClock {
        fn advance(&self, elapsed: Duration) {
            *self.0.lock().unwrap() += elapsed;
        }
    }

    impl Clock for CaptureClock {
        type Error = Infallible;

        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }

        fn sleep(&self, elapsed: Duration, _: &Deadline) -> Result<(), Self::Error> {
            self.advance(elapsed);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Frames,
        Late,
        Forbidden,
        Failure,
    }

    struct Provider {
        clock: CaptureClock,
        mode: Mode,
    }

    struct Session {
        metadata: native::Metadata,
        clock: CaptureClock,
        mode: Mode,
        frames: VecDeque<Frame>,
        statistics: native::Stats,
    }

    impl native::Provider for Provider {
        type Capture = Session;

        fn arm_capture(
            &self,
            request: &native::Request,
            _: &Deadline,
        ) -> Result<Session, packetcraftr_netio::Error> {
            Ok(Session {
                metadata: native::Metadata {
                    interface: request.interface.clone(),
                    link_type: LinkType::RAW,
                    snap_length: request.limits.snap_length,
                    native: Default::default(),
                },
                clock: self.clock.clone(),
                mode: self.mode,
                frames: (1_u8..=3)
                    .map(|value| {
                        Frame::without_timestamp(LinkType::RAW, vec![value; usize::from(value) + 1])
                            .unwrap()
                    })
                    .collect(),
                statistics: native::Stats::default(),
            })
        }
    }

    impl native::Session for Session {
        fn metadata(&self) -> &native::Metadata {
            &self.metadata
        }

        fn wait_ready(&mut self, _: &Deadline) -> Result<(), packetcraftr_netio::Error> {
            Ok(())
        }

        fn next_captured_frame(
            &mut self,
            _: &Deadline,
        ) -> Result<Option<native::Captured>, packetcraftr_netio::Error> {
            match self.mode {
                Mode::Forbidden => panic!("a started-event stop must precede capture reads"),
                Mode::Failure => {
                    return Err(packetcraftr_netio::Error::Capture {
                        message: "fixture receive failure".into(),
                        source: None,
                    });
                }
                Mode::Frames | Mode::Late => {}
            }
            let Some(frame) = self.frames.pop_front() else {
                self.clock.advance(Duration::from_secs(2));
                return Ok(None);
            };
            if matches!(self.mode, Mode::Late) {
                self.clock.advance(Duration::from_secs(2));
            }
            self.statistics.received_frames += 1;
            self.statistics.received_bytes += u64::from(frame.captured_length());
            Ok(Some(native::Captured::new(frame, self.clock.now())))
        }

        fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
            if matches!(self.mode, Mode::Failure) {
                return Err(packetcraftr_netio::Error::Capture {
                    message: "fixture shutdown failure".into(),
                    source: None,
                });
            }
            Ok(())
        }

        fn stats(&self) -> native::Stats {
            self.statistics
        }
    }

    type CaptureClient = Client<ProviderSet<(), Interfaces, Provider>, CaptureClock>;

    fn fixture(mode: Mode) -> (CaptureClient, crate::capture::Request) {
        let clock = CaptureClock(Arc::new(Mutex::new(Instant::now())));
        let id = interface::Id {
            name: "capture0".into(),
            index: 7,
        };
        let client = Client::new(
            builtin::registry(),
            Policy {
                max_packets_per_operation: 16,
                max_bytes_per_operation: 1024,
                ..Default::default()
            },
            ProviderSet::capture(
                Interfaces {
                    values: vec![id.clone()],
                    cancel: None,
                },
                Provider {
                    clock: clock.clone(),
                    mode,
                },
            ),
        )
        .with_clock(clock);
        let request = crate::capture::Request::new(
            native::GroupRequest {
                interfaces: vec![id],
                limits: native::Limits {
                    max_frames: 8,
                    max_bytes: 512,
                    snap_length: 64,
                    overflow_policy: native::OverflowPolicy::Fail,
                },
                filter: None,
                promiscuous: false,
                native: Default::default(),
            },
            Duration::from_secs(1),
        );
        (client, request)
    }

    #[test]
    fn selected_capture_frames_obey_stop_before_and_stop_after() {
        for stop in [Control::StopBefore, Control::StopAfter] {
            let (client, request) = fixture(Mode::Frames);
            let emitted = Arc::new(Mutex::new(Vec::new()));
            let output = Arc::clone(&emitted);
            let report = client
                .capture(
                    request.with_selector(|number, _| Ok(number != 1)),
                    move |event| {
                        let Event::Frame {
                            source_frame,
                            frame,
                            ..
                        } = event
                        else {
                            return Ok(Control::Continue);
                        };
                        assert_eq!(frame.interface, Some(0));
                        if source_frame == 3 && stop == Control::StopBefore {
                            return Ok(stop);
                        }
                        output
                            .lock()
                            .unwrap()
                            .push((source_frame, frame.bytes().to_vec()));
                        Ok(if source_frame == 3 {
                            stop
                        } else {
                            Control::Continue
                        })
                    },
                )
                .unwrap();
            let expected = if stop == Control::StopBefore {
                vec![(2, vec![2; 3])]
            } else {
                vec![(2, vec![2; 3]), (3, vec![3; 4])]
            };
            assert_eq!(*emitted.lock().unwrap(), expected);
            assert_eq!(report.stop, StopReason::Sink);
            assert_eq!(report.frames_delivered, 3);
            assert_eq!(report.stats.packets_attempted, 3);
            assert_eq!(report.stats.packets_completed, expected.len() as u64);
            assert_eq!(report.stats.bytes, 9);
            let source = &report.sources[0];
            assert_eq!(
                (
                    source.delivered_frames,
                    source.admitted_frames,
                    source.matched_frames,
                    source.emitted_frames,
                    source.late_frames
                ),
                (3, 3, 2, expected.len() as u64, 0)
            );
            assert!(report.capture_statistics_complete);
        }
    }

    #[test]
    fn started_capture_stop_prevents_reads() {
        let (client, request) = fixture(Mode::Forbidden);
        let report = client
            .capture(request, |event| {
                assert!(matches!(event, Event::Started { .. }));
                Ok(Control::StopBefore)
            })
            .unwrap();
        assert_eq!(report.stop, StopReason::Sink);
        assert_eq!(report.frames_delivered, 0);
        assert_eq!(report.stats.bytes, 0);
    }

    #[test]
    fn late_capture_frame_is_reported_without_admission_or_publication() {
        let (client, request) = fixture(Mode::Late);
        let report = client
            .capture(request, |event| {
                assert!(matches!(event, Event::Started { .. }));
                Ok(Control::Continue)
            })
            .unwrap();
        assert_eq!(report.stop, StopReason::Window);
        assert_eq!(report.frames_delivered, 1);
        assert_eq!(report.sources[0].late_frames, 1);
        assert_eq!(report.sources[0].admitted_frames, 0);
        assert_eq!(report.stats.packets_completed, 0);
        assert_eq!(report.stats.bytes, 0);
    }

    #[test]
    fn capture_read_failure_survives_incomplete_cleanup_statistics() {
        let (client, request) = fixture(Mode::Failure);
        let error = client
            .capture(request, |_: Event| Ok(Control::Continue))
            .unwrap_err();
        assert_eq!(error.classification().code, "io.capture");
        let causes = error.causes();
        assert!(
            causes
                .iter()
                .any(|cause| cause.contains("fixture receive failure"))
        );
        assert!(
            causes
                .iter()
                .any(|cause| cause.contains("fixture shutdown failure"))
        );
        assert!(!error.report.capture_statistics_complete);
        assert_eq!(error.report.stop, StopReason::Failure);
    }
}
