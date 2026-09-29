// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{
    Client, ProviderSet,
    policy::Policy,
    probe::Transport,
    scan::{self, connect},
    target::{Family, SystemResolver, Target},
};
use packetcraftr_core::{budget::Deadline, document::tcp_profiles};
use packetcraftr_netio::tcp::{Provider, Stream};
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Scripted(Arc<Mutex<Vec<u8>>>);
struct Socket {
    peer: SocketAddr,
    writes: Arc<Mutex<Vec<u8>>>,
    reads: u32,
}
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        match self.reads {
            1 => {
                bytes[..4].copy_from_slice(b"HTTP");
                Ok(4)
            }
            _ => Err(io::Error::new(io::ErrorKind::TimedOut, "partial banner")),
        }
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(2);
        self.writes
            .lock()
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Stream for Socket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:49152".parse().unwrap())
    }
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}
impl Provider for Scripted {
    type Stream = Socket;
    fn connect(
        &self,
        peer: SocketAddr,
        _: &Deadline,
    ) -> Result<Socket, packetcraftr_netio::tcp::Error> {
        Ok(Socket {
            peer,
            writes: Arc::clone(&self.0),
            reads: 0,
        })
    }
}
fn request() -> scan::Request {
    let doc=br#"{"schema":"packetcraftr.tcp-profiles/v1","profiles":[{"ports":[8080],"profile":{"name":"HTTP prefix","request":{"type":"bytes","data":"48454144"},"response":{"type":"bytes","min_length":4,"max_length":4096,"checks":[{"offset":0,"data":"48545450"}]}}}]}"#;
    scan::Request {
        targets: Target::Address("127.0.0.1".parse().unwrap()).into(),
        transport: Transport::Tcp,
        tcp_mode: Default::default(),
        shuffle_seed: None,
        tcp_profiles: scan::profile::compile_tcp(tcp_profiles::parse(doc).unwrap()).unwrap(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        ports: vec![8080],
        attempts: 1,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        max_in_flight: 1,
        limits: Default::default(),
        route: Default::default(),
        collection: Default::default(),
    }
}
#[test]
fn bounded_banner_retains_partial_io_and_exact_written_request() {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(Scripted(Arc::clone(&writes)), SystemResolver),
    );
    let collector = connect::Collector::default();
    let report = client.scan_connect(request(), collector.clone()).unwrap();
    let aggregate = collector.finish(report).unwrap();
    let probe = &aggregate.endpoints[0].probes[0];
    assert_eq!(probe.outcome, connect::Outcome::Connected);
    let banner = probe.banner.as_ref().unwrap();
    assert_eq!(banner.request_bytes_written, 4);
    assert_eq!(&*writes.lock().unwrap(), b"HEAD");
    assert_eq!(banner.response.as_ref(), b"HTTP");
    assert_eq!(banner.application.status, scan::profile::Status::Confirmed);
    assert_eq!(
        banner.error.as_ref().unwrap().kind(),
        io::ErrorKind::TimedOut
    );
}
#[test]
fn complete_banner_traffic_is_authorized_before_connect() {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let policy = Policy {
        max_bytes_per_operation: 4099,
        ..Default::default()
    };
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        ProviderSet::tcp(Scripted(Arc::clone(&writes)), SystemResolver),
    );
    assert!(
        client
            .scan_connect(request(), connect::Collector::default())
            .is_err()
    );
    assert!(writes.lock().unwrap().is_empty());
}

#[test]
fn profile_peer_recheck_rejects_changed_peer_before_application_io() {
    struct Changed(Arc<Mutex<Vec<u8>>>);
    struct ChangedSocket {
        inner: Socket,
        queries: std::sync::atomic::AtomicUsize,
    }
    impl Read for ChangedSocket {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.inner.read(bytes)
        }
    }
    impl Write for ChangedSocket {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.inner.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Stream for ChangedSocket {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            if self
                .queries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                Ok(self.inner.peer)
            } else {
                Ok("127.0.0.2:8080".parse().unwrap())
            }
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.inner.set_read_timeout(timeout)
        }
        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.inner.set_write_timeout(timeout)
        }
    }
    impl Provider for Changed {
        type Stream = ChangedSocket;
        fn connect(
            &self,
            peer: SocketAddr,
            _: &Deadline,
        ) -> Result<ChangedSocket, packetcraftr_netio::tcp::Error> {
            Ok(ChangedSocket {
                inner: Socket {
                    peer,
                    writes: Arc::clone(&self.0),
                    reads: 0,
                },
                queries: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }
    let writes = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(Changed(Arc::clone(&writes)), SystemResolver),
    );
    assert!(matches!(
        client.scan_connect(request(), connect::Collector::default()),
        Err(scan::Error::InvalidEvidence { .. })
    ));
    assert!(writes.lock().unwrap().is_empty());
}
