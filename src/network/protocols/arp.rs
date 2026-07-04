// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::time::{Duration, Instant};

use log::{debug, trace};
use pnet::datalink::{self, Channel, Config, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use thiserror::Error;

const ARP_PACKET_LEN: usize = 28;
const ETHERNET_HEADER_LEN: usize = 14;
const ARP_RETRY_INTERVAL: Duration = Duration::from_millis(250);

type ArpResult<T> = std::result::Result<T, ArpResolutionError>;

#[derive(Debug, Error)]
pub(crate) enum ArpResolutionError {
    #[error("interface {interface} has no MAC address")]
    MissingInterfaceMac { interface: String },
    #[error("open ARP channel failed: interface={interface}")]
    ChannelOpen {
        interface: String,
        #[source]
        source: io::Error,
    },
    #[error("interface {interface} does not support Ethernet channel operations")]
    ChannelUnsupported { interface: String },
    #[error("failed to allocate {component}")]
    AllocationFailed { component: &'static str },
    #[error("failed to queue ARP frame for transmit")]
    TransmitQueue,
    #[error("transmit ARP request failed: target={target} frame_len={frame_len} bytes")]
    Transmit {
        target: std::net::Ipv4Addr,
        frame_len: usize,
        #[source]
        source: io::Error,
    },
    #[error("receive ARP reply failed on interface {interface}")]
    Receive {
        interface: String,
        #[source]
        source: io::Error,
    },
    #[error("ARP timeout duration is too large: {timeout:?}")]
    TimeoutConfiguration { timeout: Duration },
    #[error(
        "failed to resolve MAC address for {target} via {interface} after {attempts} attempt(s)"
    )]
    ResolutionTimeout {
        target: std::net::Ipv4Addr,
        interface: String,
        attempts: u32,
    },
}

/// Attempt to resolve the MAC address for a target IPv4 address by issuing an ARP request
/// on the supplied interface.
pub(crate) fn resolve_mac(
    interface: &NetworkInterface,
    source_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    timeout: Duration,
) -> ArpResult<MacAddr> {
    let mut scanner = ArpScanner::new(interface, source_ip, timeout)?;
    scanner.resolve(target_ip, timeout)
}

/// A reusable ARP scanner that maintains an open datalink channel.
pub(crate) struct ArpScanner {
    channel: DatalinkArpChannel,
    interface_name: String,
    source_mac: MacAddr,
    source_ip: std::net::Ipv4Addr,
}

impl ArpScanner {
    /// Create a new ARP scanner on the specified interface.
    pub(crate) fn new(
        interface: &NetworkInterface,
        source_ip: std::net::Ipv4Addr,
        timeout: Duration,
    ) -> ArpResult<Self> {
        let source_mac = interface
            .mac
            .ok_or_else(|| ArpResolutionError::MissingInterfaceMac {
                interface: interface.name.clone(),
            })?;

        let channel = DatalinkArpChannel::open(interface, timeout)?;

        Ok(Self {
            channel,
            interface_name: interface.name.clone(),
            source_mac,
            source_ip,
        })
    }

    /// Resolve the MAC address for a target IPv4 address.
    pub(crate) fn resolve(
        &mut self,
        target_ip: std::net::Ipv4Addr,
        timeout: Duration,
    ) -> ArpResult<MacAddr> {
        resolve_with_channel(
            &mut self.channel,
            &self.interface_name,
            self.source_mac,
            self.source_ip,
            target_ip,
            timeout,
        )
    }
}

trait ArpChannel {
    fn send(&mut self, target: std::net::Ipv4Addr, frame: &[u8]) -> ArpResult<()>;
    fn receive(&mut self, interface: &str) -> ArpResult<Option<Vec<u8>>>;
}

struct DatalinkArpChannel {
    tx: Box<dyn datalink::DataLinkSender>,
    rx: Box<dyn datalink::DataLinkReceiver>,
}

impl DatalinkArpChannel {
    fn open(interface: &NetworkInterface, timeout: Duration) -> ArpResult<Self> {
        let config = Config {
            read_timeout: Some(timeout.min(ARP_RETRY_INTERVAL)),
            write_buffer_size: 1024,
            read_buffer_size: 1024,
            ..Default::default()
        };

        let channel = datalink::channel(interface, config).map_err(|source| {
            ArpResolutionError::ChannelOpen {
                interface: interface.name.clone(),
                source,
            }
        })?;

        match channel {
            Channel::Ethernet(tx, rx) => Ok(Self { tx, rx }),
            _ => Err(ArpResolutionError::ChannelUnsupported {
                interface: interface.name.clone(),
            }),
        }
    }
}

impl ArpChannel for DatalinkArpChannel {
    fn send(&mut self, target: std::net::Ipv4Addr, frame: &[u8]) -> ArpResult<()> {
        self.tx
            .send_to(frame, None)
            .ok_or(ArpResolutionError::TransmitQueue)?
            .map_err(|source| ArpResolutionError::Transmit {
                target,
                frame_len: frame.len(),
                source,
            })?;
        Ok(())
    }

    fn receive(&mut self, interface: &str) -> ArpResult<Option<Vec<u8>>> {
        match self.rx.next() {
            Ok(packet) => Ok(Some(packet.to_vec())),
            Err(err) if err.kind() == io::ErrorKind::TimedOut => Ok(None),
            Err(source) => Err(ArpResolutionError::Receive {
                interface: interface.to_string(),
                source,
            }),
        }
    }
}

fn resolve_with_channel<C: ArpChannel>(
    channel: &mut C,
    interface_name: &str,
    source_mac: MacAddr,
    source_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    timeout: Duration,
) -> ArpResult<MacAddr> {
    resolve_with_channel_with_retry(
        channel,
        interface_name,
        source_mac,
        source_ip,
        target_ip,
        timeout,
        ARP_RETRY_INTERVAL,
    )
}

fn resolve_with_channel_with_retry<C: ArpChannel>(
    channel: &mut C,
    interface_name: &str,
    source_mac: MacAddr,
    source_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    timeout: Duration,
    retry_interval: Duration,
) -> ArpResult<MacAddr> {
    let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    {
        let mut ethernet =
            MutableEthernetPacket::new(&mut frame).ok_or(ArpResolutionError::AllocationFailed {
                component: "ARP ethernet frame",
            })?;
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(source_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let payload = ethernet.payload_mut();
        let mut arp =
            MutableArpPacket::new(payload).ok_or(ArpResolutionError::AllocationFailed {
                component: "ARP payload",
            })?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        arp.set_sender_proto_addr(source_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    let now = Instant::now();
    let deadline = now
        .checked_add(timeout)
        .ok_or(ArpResolutionError::TimeoutConfiguration { timeout })?;
    let mut attempts = 0u32;

    while Instant::now() < deadline {
        attempts += 1;
        debug!(
            "Sending ARP request for {} on {} (attempt {})",
            target_ip, interface_name, attempts
        );
        channel.send(target_ip, &frame)?;

        let attempt_start = Instant::now();
        let mut attempt_deadline = attempt_start.checked_add(retry_interval).ok_or(
            ArpResolutionError::TimeoutConfiguration {
                timeout: retry_interval,
            },
        )?;
        if attempt_deadline > deadline {
            attempt_deadline = deadline;
        }

        loop {
            if Instant::now() >= attempt_deadline {
                break;
            }
            match channel.receive(interface_name)? {
                Some(packet) => {
                    if let Some(mac) = parse_arp_reply(&packet, target_ip) {
                        trace!(
                            "Resolved MAC {} for {} via {}",
                            mac,
                            target_ip,
                            interface_name
                        );
                        return Ok(mac);
                    }
                }
                None => break,
            }
        }
    }

    Err(ArpResolutionError::ResolutionTimeout {
        target: target_ip,
        interface: interface_name.to_string(),
        attempts,
    })
}

fn parse_arp_reply(packet: &[u8], expected_target: std::net::Ipv4Addr) -> Option<MacAddr> {
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    // RFC 826: Ethernet ARP uses hw_addr_len=6, proto_addr_len=4
    if arp.get_hw_addr_len() != 6 || arp.get_proto_addr_len() != 4 {
        return None;
    }
    if arp.get_sender_proto_addr() != expected_target {
        return None;
    }
    Some(arp.get_sender_hw_addr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const TARGET_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const OTHER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

    struct MockArpChannel {
        receives: Vec<std::result::Result<Option<Vec<u8>>, io::Error>>,
    }

    impl MockArpChannel {
        fn new(receives: Vec<std::result::Result<Option<Vec<u8>>, io::Error>>) -> Self {
            Self { receives }
        }
    }

    impl ArpChannel for MockArpChannel {
        fn send(&mut self, _target: Ipv4Addr, _frame: &[u8]) -> ArpResult<()> {
            Ok(())
        }

        fn receive(&mut self, interface: &str) -> ArpResult<Option<Vec<u8>>> {
            match self.receives.pop() {
                Some(Ok(packet)) => Ok(packet),
                Some(Err(source)) => Err(ArpResolutionError::Receive {
                    interface: interface.to_string(),
                    source,
                }),
                None => Ok(None),
            }
        }
    }

    fn interface(mac: Option<MacAddr>) -> NetworkInterface {
        NetworkInterface {
            name: "eth-test".to_string(),
            description: String::new(),
            index: 1,
            mac,
            ips: Vec::new(),
            flags: libc::IFF_UP as u32,
        }
    }

    fn arp_frame(operation: pnet::packet::arp::ArpOperation) -> Vec<u8> {
        let sender_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(sender_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(operation);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(TARGET_IP);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(Ipv4Addr::new(192, 0, 2, 5));

        frame
    }

    #[test]
    fn parse_arp_reply_returns_sender_mac_for_matching_reply() {
        assert_eq!(
            parse_arp_reply(&arp_frame(ArpOperations::Reply), TARGET_IP),
            Some(MacAddr::new(0x02, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn parse_arp_reply_rejects_non_arp_ethertype() {
        let mut frame = arp_frame(ArpOperations::Reply);
        MutableEthernetPacket::new(&mut frame)
            .unwrap()
            .set_ethertype(EtherTypes::Ipv4);

        assert_eq!(parse_arp_reply(&frame, TARGET_IP), None);
    }

    #[test]
    fn parse_arp_reply_rejects_requests() {
        assert_eq!(
            parse_arp_reply(&arp_frame(ArpOperations::Request), TARGET_IP),
            None
        );
    }

    #[test]
    fn parse_arp_reply_rejects_wrong_hardware_or_protocol_lengths() {
        let mut bad_hw_len = arp_frame(ArpOperations::Reply);
        MutableArpPacket::new(
            MutableEthernetPacket::new(&mut bad_hw_len)
                .unwrap()
                .payload_mut(),
        )
        .unwrap()
        .set_hw_addr_len(5);

        let mut bad_proto_len = arp_frame(ArpOperations::Reply);
        MutableArpPacket::new(
            MutableEthernetPacket::new(&mut bad_proto_len)
                .unwrap()
                .payload_mut(),
        )
        .unwrap()
        .set_proto_addr_len(16);

        assert_eq!(parse_arp_reply(&bad_hw_len, TARGET_IP), None);
        assert_eq!(parse_arp_reply(&bad_proto_len, TARGET_IP), None);
    }

    #[test]
    fn parse_arp_reply_rejects_wrong_sender_ip() {
        assert_eq!(
            parse_arp_reply(&arp_frame(ArpOperations::Reply), OTHER_IP),
            None
        );
    }

    #[test]
    fn parse_arp_reply_rejects_truncated_ethernet_frame() {
        assert_eq!(
            parse_arp_reply(&arp_frame(ArpOperations::Reply)[..10], TARGET_IP),
            None
        );
    }

    #[test]
    fn parse_arp_reply_rejects_truncated_arp_payload() {
        let frame = arp_frame(ArpOperations::Reply);

        assert_eq!(
            parse_arp_reply(&frame[..ETHERNET_HEADER_LEN + 10], TARGET_IP),
            None
        );
    }

    #[test]
    fn arp_scanner_rejects_missing_mac_with_typed_error() {
        let result = ArpScanner::new(
            &interface(None),
            Ipv4Addr::new(192, 0, 2, 1),
            Duration::from_millis(1),
        );

        assert!(matches!(
            result,
            Err(ArpResolutionError::MissingInterfaceMac { .. })
        ));
    }

    #[test]
    fn arp_resolve_receive_errors_are_typed() {
        let mut channel = MockArpChannel::new(vec![Err(io::Error::other("receive failed"))]);
        let err = resolve_with_channel_with_retry(
            &mut channel,
            "eth-test",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            TARGET_IP,
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .unwrap_err();

        assert!(matches!(err, ArpResolutionError::Receive { .. }));
    }

    #[test]
    fn arp_unsupported_channel_error_is_typed() {
        let err = ArpResolutionError::ChannelUnsupported {
            interface: "eth-test".to_string(),
        };

        assert!(matches!(err, ArpResolutionError::ChannelUnsupported { .. }));
    }

    #[test]
    fn arp_resolve_timeout_is_typed() {
        let mut channel = MockArpChannel::new(vec![Ok(None)]);
        let err = resolve_with_channel_with_retry(
            &mut channel,
            "eth-test",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            TARGET_IP,
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .unwrap_err();

        assert!(matches!(err, ArpResolutionError::ResolutionTimeout { .. }));
    }

    #[test]
    fn arp_huge_timeout_deadline_overflow_returns_error() {
        let mut channel = MockArpChannel::new(vec![]);
        let err = resolve_with_channel_with_retry(
            &mut channel,
            "eth-test",
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            TARGET_IP,
            Duration::MAX,
            Duration::from_millis(1),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ArpResolutionError::TimeoutConfiguration { .. }
        ));
    }
}
