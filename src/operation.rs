// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared operation identity, cancellation, completion, and event delivery.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::error::{Category, Classification, Classified, Kind};

/// A 128-bit identifier generated before an operation performs active work.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Id([u8; 16]);

impl Id {
    /// Generates an identifier directly from operating-system entropy.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(|bytes| getrandom::fill(bytes).map_err(|source| source.to_string()))
    }

    fn generate_with(
        fill: impl FnOnce(&mut [u8; 16]) -> Result<(), String>,
    ) -> Result<Self, Error> {
        let mut bytes = [0_u8; 16];
        fill(&mut bytes).map_err(|message| Error::Entropy { message })?;
        Ok(Self(bytes))
    }

    /// Builds an identifier from exact bytes, primarily for reproducible runs.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Stable, domain-separated mixing for generated packet fields.
    pub fn derive_u64(self, domain: &str, index: u64) -> u64 {
        // FNV-1a supplies a stable byte fold; SplitMix64's finalizer removes
        // the linear structure. This is correlation mixing, not encryption.
        let mut value = 0xcbf2_9ce4_8422_2325_u64;
        for byte in self
            .0
            .iter()
            .copied()
            .chain(domain.as_bytes().iter().copied())
            .chain(index.to_le_bytes())
        {
            value ^= u64::from(byte);
            value = value.wrapping_mul(0x0000_0100_0000_01b3);
        }
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub fn derive_u32(self, domain: &str, index: u64) -> u32 {
        self.derive_u64(domain, index) as u32
    }

    pub fn derive_u16(self, domain: &str, index: u64) -> u16 {
        self.derive_u64(domain, index) as u16
    }

    pub fn derive_nonzero_u16(self, domain: &str, index: u64) -> u16 {
        let value = self.derive_u16(domain, index);
        if value == 0 { 1 } else { value }
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::InvalidId);
        }
        let mut bytes = [0_u8; 16];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *output =
                u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| Error::InvalidId)?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Signal or caller reason that requested cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationReason {
    Requested,
    Interrupt,
    Terminate,
}

impl CancellationReason {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Terminate => 143,
            Self::Requested | Self::Interrupt => 130,
        }
    }

    const fn encoded(self) -> u8 {
        match self {
            Self::Requested => 1,
            Self::Interrupt => 2,
            Self::Terminate => 3,
        }
    }

    const fn from_encoded(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Requested),
            2 => Some(Self::Interrupt),
            3 => Some(Self::Terminate),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct CancellationState {
    reason: AtomicU8,
    lock: Mutex<()>,
    changed: Condvar,
}

/// Cloneable cancellation primitive used by waits and workflow boundaries.
#[derive(Clone, Debug, Default)]
pub struct Cancellation {
    state: Arc<CancellationState>,
}

impl Cancellation {
    pub fn cancel(&self, reason: CancellationReason) {
        if self
            .state
            .reason
            .compare_exchange(0, reason.encoded(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.state.changed.notify_all();
        }
    }

    pub fn reason(&self) -> Option<CancellationReason> {
        CancellationReason::from_encoded(self.state.reason.load(Ordering::Acquire))
    }

    pub fn is_cancelled(&self) -> bool {
        self.reason().is_some()
    }

    pub fn check(&self) -> Result<(), Error> {
        match self.reason() {
            Some(reason) => Err(Error::Cancelled { reason }),
            None => Ok(()),
        }
    }

    /// Waits until the delay expires or cancellation is requested.
    pub fn wait(&self, delay: Duration) -> Result<(), Error> {
        self.check()?;
        if delay.is_zero() {
            return Ok(());
        }
        let guard = self
            .state
            .lock
            .lock()
            .map_err(|_| Error::CancellationState)?;
        let _ = self
            .state
            .changed
            .wait_timeout_while(guard, delay, |_| !self.is_cancelled())
            .map_err(|_| Error::CancellationState)?;
        self.check()
    }
}

/// Terminal reason shared by aggregate and streaming operation contracts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionReason {
    #[default]
    Completed,
    EndOfInput,
    Timeout,
    LimitReached,
    DestinationReached,
    Cancelled,
}

/// Minimal generic event-delivery boundary used by streaming workflows.
pub trait EventSink<E> {
    fn emit(&mut self, event: E) -> Result<(), EventError>;
}

/// Complete shared state for one active or passive operation.
#[derive(Clone, Debug)]
pub struct Context {
    id: Id,
    cancellation: Cancellation,
    reservations: Arc<Mutex<Vec<PortReservation>>>,
}

impl Context {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::new(Id::generate()?))
    }

    pub fn new(id: Id) -> Self {
        Self {
            id,
            cancellation: Cancellation::default(),
            reservations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub const fn id(&self) -> Id {
        self.id
    }

    pub fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }

    /// Reserves a generated port and retains its socket until every clone of
    /// this operation context is dropped.
    pub fn reserve_port(&self, domain: &str, transport: Transport) -> Result<u16, Error> {
        self.reserve_port_for_family(domain, transport, PortFamily::Ipv4)
    }

    /// Reserves a generated port in every address-family namespace that the
    /// operation may use and retains the sockets for the operation lifetime.
    pub fn reserve_port_for_family(
        &self,
        domain: &str,
        transport: Transport,
        family: PortFamily,
    ) -> Result<u16, Error> {
        self.cancellation.check()?;
        let reservation = PortReservation::reserve_for_family(self.id, domain, transport, family)?;
        let port = reservation.port();
        self.reservations
            .lock()
            .map_err(|_| Error::PortReservationState)?
            .push(reservation);
        Ok(port)
    }
}

impl<E, F> EventSink<E> for F
where
    F: FnMut(E) -> Result<(), EventError>,
{
    fn emit(&mut self, event: E) -> Result<(), EventError> {
        self(event)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("event sink failed: {message}")]
pub struct EventError {
    pub message: String,
}

impl EventError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Classified for EventError {
    fn classification(&self) -> Classification {
        Classification::new(
            "io.event_sink",
            Kind::Io,
            Some("restore the output consumer and retry the operation"),
        )
    }
}

/// Transport namespace used when reserving a generated source port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// IP namespaces in which a generated source port must remain reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortFamily {
    Ipv4,
    Ipv6,
    Both,
}

enum Reservation {
    Tcp(socket2::Socket),
    Udp(socket2::Socket),
}

impl Reservation {
    fn port(&self) -> u16 {
        let address = match self {
            Self::Tcp(socket) | Self::Udp(socket) => socket.local_addr(),
        }
        .expect("bound reservation address")
        .as_socket()
        .expect("IP reservation address");
        address.port()
    }
}

/// Holds generated source-port reservations for the complete operation lifetime.
pub struct PortReservation {
    reservations: Vec<Reservation>,
}

impl fmt::Debug for PortReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortReservation")
            .field("port", &self.port())
            .finish()
    }
}

impl PortReservation {
    pub fn reserve(id: Id, domain: &str, transport: Transport) -> Result<Self, Error> {
        Self::reserve_for_family(id, domain, transport, PortFamily::Ipv4)
    }

    pub fn reserve_for_family(
        id: Id,
        domain: &str,
        transport: Transport,
        family: PortFamily,
    ) -> Result<Self, Error> {
        Self::reserve_with(id, domain, transport, family, bind_reservation)
    }

    fn reserve_with(
        id: Id,
        domain: &str,
        transport: Transport,
        family: PortFamily,
        mut bind: impl FnMut(Transport, SocketAddr) -> std::io::Result<Reservation>,
    ) -> Result<Self, Error> {
        const FIRST: u16 = 49_152;
        const WIDTH: u64 = u16::MAX as u64 - FIRST as u64 + 1;
        let start = id.derive_u64(domain, 0) % WIDTH;
        let mut last_error = None;
        for attempt in 0..128_u64 {
            let offset = (start + attempt) % WIDTH;
            let port = FIRST + offset as u16;
            let addresses = match family {
                PortFamily::Ipv4 => vec![SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    port,
                ))],
                PortFamily::Ipv6 => vec![SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    port,
                    0,
                    0,
                ))],
                PortFamily::Both => vec![
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)),
                ],
            };
            let required = addresses.len();
            let mut reservations = Vec::with_capacity(required);
            for address in addresses {
                match bind(transport, address) {
                    Ok(reservation) => reservations.push(reservation),
                    Err(error) => {
                        last_error = Some(error);
                        break;
                    }
                }
            }
            if reservations.len() == required {
                return Ok(Self { reservations });
            }
        }
        Err(Error::PortReservation {
            attempts: 128,
            message: last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no candidate was attempted".to_owned()),
        })
    }

    pub fn port(&self) -> u16 {
        self.reservations
            .first()
            .expect("port reservation contains at least one socket")
            .port()
    }
}

fn bind_reservation(transport: Transport, address: SocketAddr) -> std::io::Result<Reservation> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let (socket_type, protocol) = match transport {
        Transport::Tcp => (Type::STREAM, Protocol::TCP),
        Transport::Udp => (Type::DGRAM, Protocol::UDP),
    };
    let socket = Socket::new(domain, socket_type, Some(protocol))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&SockAddr::from(address))?;
    match transport {
        Transport::Tcp => {
            socket.listen(1)?;
            Ok(Reservation::Tcp(socket))
        }
        Transport::Udp => Ok(Reservation::Udp(socket)),
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("operating-system entropy is unavailable: {message}")]
    Entropy { message: String },
    #[error("operation ID must contain exactly 32 hexadecimal characters")]
    InvalidId,
    #[error("operation was cancelled ({reason:?})")]
    Cancelled { reason: CancellationReason },
    #[error("operation cancellation state is unavailable")]
    CancellationState,
    #[error("could not reserve a generated source port after {attempts} candidates: {message}")]
    PortReservation { attempts: u16, message: String },
    #[error("operation source-port reservation state is unavailable")]
    PortReservationState,
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidId => Classification::new(
                "cli.operation_id",
                Kind::Cli,
                Some("supply exactly 32 hexadecimal characters"),
            ),
            Self::Entropy { .. } => Classification::new(
                "capability.entropy",
                Kind::Capability,
                Some("restore the operating system random source before retrying active work"),
            ),
            Self::PortReservation { .. } => Classification::new(
                "capability.port_reservation",
                Kind::Capability,
                Some("free an ephemeral source port and retry"),
            ),
            Self::Cancelled { .. } => Classification::new(
                "operation.cancelled",
                Kind::Io,
                Some("confirm cleanup before deciding whether to restart the operation"),
            )
            .with_category(Category::Io),
            Self::CancellationState | Self::PortReservationState => Classification::new(
                "internal.cancellation_state",
                Kind::Internal,
                Some("restart the process before beginning another active operation"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_parse_render_and_mix_reproducibly_by_domain() {
        let id: Id = "00112233445566778899aabbccddeeff".parse().unwrap();
        assert_eq!(id.to_string(), "00112233445566778899aabbccddeeff");
        assert_eq!(
            id.derive_u64("tcp.sequence", 7),
            id.derive_u64("tcp.sequence", 7)
        );
        assert_ne!(id.derive_u64("tcp.sequence", 7), id.derive_u64("dns.id", 7));
        assert_ne!(
            id.derive_u64("tcp.sequence", 7),
            id.derive_u64("tcp.sequence", 8)
        );
    }

    #[test]
    fn cancellation_interrupts_waits_and_preserves_first_reason() {
        let cancellation = Cancellation::default();
        cancellation.cancel(CancellationReason::Terminate);
        cancellation.cancel(CancellationReason::Interrupt);
        assert_eq!(cancellation.reason(), Some(CancellationReason::Terminate));
        assert!(matches!(
            cancellation.wait(Duration::from_secs(1)),
            Err(Error::Cancelled {
                reason: CancellationReason::Terminate
            })
        ));
    }

    #[test]
    fn cancellation_interrupts_a_long_wait_within_one_second() {
        let cancellation = Cancellation::default();
        let requester = cancellation.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            requester.cancel(CancellationReason::Interrupt);
        });
        let started = std::time::Instant::now();
        let error = cancellation.wait(Duration::from_secs(30)).unwrap_err();
        worker.join().unwrap();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            error,
            Error::Cancelled {
                reason: CancellationReason::Interrupt
            }
        ));
    }

    #[test]
    fn a_generated_udp_port_is_reserved_until_drop() {
        let id = Id::from_bytes([7; 16]);
        let reservation = PortReservation::reserve(id, "test.udp", Transport::Udp).unwrap();
        assert!(reservation.port() >= 49_152);
        assert!(std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, reservation.port())).is_err());
    }

    #[test]
    fn a_dual_family_port_is_reserved_in_both_namespaces() {
        let reservation = PortReservation::reserve_for_family(
            Id::from_bytes([8; 16]),
            "test.dual.udp",
            Transport::Udp,
            PortFamily::Both,
        )
        .unwrap();
        let port = reservation.port();

        assert!(std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_err());
        assert!(std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)).is_err());
    }

    #[test]
    fn entropy_and_port_allocation_failures_are_typed_before_active_work() {
        let entropy =
            Id::generate_with(|_| Err("test entropy source failed".to_owned())).unwrap_err();
        assert!(matches!(entropy, Error::Entropy { .. }));
        assert_eq!(entropy.classification().code, "capability.entropy");

        let mut attempts = 0_u16;
        let port = PortReservation::reserve_with(
            Id::from_bytes([5; 16]),
            "test.failure",
            Transport::Tcp,
            PortFamily::Ipv4,
            |_, _| {
                attempts += 1;
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "test candidate occupied",
                ))
            },
        )
        .unwrap_err();
        assert!(matches!(port, Error::PortReservation { attempts: 128, .. }));
        assert_eq!(attempts, 128);
        assert_eq!(port.classification().code, "capability.port_reservation");
    }
}
