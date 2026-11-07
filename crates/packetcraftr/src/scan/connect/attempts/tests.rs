// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::scan::{adaptive, inference};

#[test]
fn local_deadline_prevents_control_and_port_inference() {
    let mut probe = ProbeEvidence {
        sequence: 7,
        stage: Stage::Scan,
        endpoint: "192.0.2.1:80".parse().unwrap(),
        scope: None,
        attempt: 1,
        attempted: true,
        connect_succeeded: None,
        outcome: Outcome::DeadlineExpired,
        scheduled_at: SystemTime::now(),
        finished_at: None,
        elapsed: Duration::from_secs(1),
        local: None,
        error: None,
    };
    for outcome in [Outcome::DeadlineExpired, Outcome::LocalError] {
        probe.outcome = outcome;
        assert!(matches!(
            connect_outcome(&probe),
            adaptive::Outcome::Aborted
        ));
        let inference = inference::connect([(probe.sequence, outcome)]);
        assert!(inference.state.is_none());
        assert_eq!(inference.failed, [7]);
        assert!(inference.supporting.is_empty());
    }
    probe.outcome = Outcome::TimedOut;
    assert!(matches!(connect_outcome(&probe), adaptive::Outcome::Silent));
    assert_eq!(
        inference::connect([(7, probe.outcome)]).rule,
        inference::Rule::ConnectTimedOut
    );
    probe.attempted = false;
    assert!(matches!(
        connect_outcome(&probe),
        adaptive::Outcome::Omitted
    ));
}

#[derive(Clone, Copy)]
struct Peer(Option<SocketAddr>);

impl tcp::Provider for Peer {
    type Stream = Self;

    fn connect(&self, _: SocketAddr, _: &Deadline) -> Result<Self, tcp::Error> {
        Ok(*self)
    }
}

impl io::Read for Peer {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl io::Write for Peer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl tcp::Stream for Peer {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.ok_or_else(|| io::ErrorKind::NotConnected.into())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("192.0.2.2:40000".parse().unwrap())
    }

    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

fn completed_peer(endpoint: SocketAddr, peer: Option<SocketAddr>) -> Result<ProbeEvidence, Error> {
    let deadline = Deadline::new(Duration::from_secs(2));
    let mut pending = tcp::start_connect(Arc::new(Peer(peer)), endpoint, &deadline).unwrap();
    let result = pending.wait(&deadline).unwrap().unwrap();
    let entry = Active {
        pending,
        sequence: 7,
        stage: Stage::Scan,
        endpoint,
        scope: None,
        attempt: 1,
        started: Instant::now(),
        scheduled_at: SystemTime::now(),
        timeout: Duration::from_secs(2),
        selection: None,
    };
    finish_probe(&entry, result)
}

#[test]
fn equivalent_peer_forms_preserve_successful_connect_evidence() {
    let native = "192.0.2.1:443".parse().unwrap();
    let mapped = "[::ffff:192.0.2.1]:443".parse().unwrap();
    let ip = "2001:db8::1".parse().unwrap();
    let global = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 443, 0, 0));
    let decorated = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 443, 17, 9));
    for (endpoint, peer) in [(native, mapped), (mapped, native), (global, decorated)] {
        let evidence = completed_peer(endpoint, Some(peer)).unwrap();
        assert_eq!(evidence.outcome, Outcome::Connected);
        assert_eq!(evidence.endpoint, endpoint);
        assert_eq!(evidence.connect_succeeded, Some(true));
    }
    let reset = completed_peer(native, None).unwrap();
    assert_eq!(reset.outcome, Outcome::Connected);
    assert_eq!(reset.connect_succeeded, Some(true));
    assert!(reset.local.is_none());
}

#[test]
fn changed_peer_identity_is_invalid_connect_evidence() {
    for (endpoint, peer) in [
        ("192.0.2.1:443", "192.0.2.1:444"),
        ("192.0.2.1:443", "192.0.2.2:443"),
        ("[fe80::1%1]:443", "[fe80::1%2]:443"),
    ] {
        assert!(matches!(
            completed_peer(endpoint.parse().unwrap(), Some(peer.parse().unwrap())),
            Err(Error::InvalidEvidence { sequence: 7, .. })
        ));
    }
}
