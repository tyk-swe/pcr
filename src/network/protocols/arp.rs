// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, trace};
use pnet::datalink::{self, Channel, Config, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};

use crate::util::error::operation_failed;

const ARP_PACKET_LEN: usize = 28;
const ETHERNET_HEADER_LEN: usize = 14;
const ARP_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// Attempt to resolve the MAC address for a target IPv4 address by issuing an ARP request
/// on the supplied interface.
pub fn resolve_mac(
    interface: &NetworkInterface,
    source_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    timeout: Duration,
) -> Result<MacAddr> {
    let mut scanner = ArpScanner::new(interface, source_ip, timeout)?;
    scanner.resolve(target_ip, timeout)
}

/// A reusable ARP scanner that maintains an open datalink channel.
pub struct ArpScanner {
    channel: DatalinkArpChannel,
    interface_name: String,
    source_mac: MacAddr,
    source_ip: std::net::Ipv4Addr,
}

impl ArpScanner {
    /// Create a new ARP scanner on the specified interface.
    pub fn new(
        interface: &NetworkInterface,
        source_ip: std::net::Ipv4Addr,
        timeout: Duration,
    ) -> Result<Self> {
        let source_mac = interface
            .mac
            .ok_or_else(|| anyhow!("interface {} has no MAC address", interface.name))?;

        let channel = DatalinkArpChannel::open(interface, timeout)?;

        Ok(Self {
            channel,
            interface_name: interface.name.clone(),
            source_mac,
            source_ip,
        })
    }

    /// Resolve the MAC address for a target IPv4 address.
    pub fn resolve(&mut self, target_ip: std::net::Ipv4Addr, timeout: Duration) -> Result<MacAddr> {
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
    fn send(&mut self, frame: &[u8]) -> Result<()>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>>;
}

struct DatalinkArpChannel {
    tx: Box<dyn datalink::DataLinkSender>,
    rx: Box<dyn datalink::DataLinkReceiver>,
}

impl DatalinkArpChannel {
    fn open(interface: &NetworkInterface, timeout: Duration) -> Result<Self> {
        let config = Config {
            read_timeout: Some(timeout.min(ARP_RETRY_INTERVAL)),
            write_buffer_size: 1024,
            read_buffer_size: 1024,
            ..Default::default()
        };

        let channel = datalink::channel(interface, config).with_context(|| {
            operation_failed("open ARP channel", format!("interface={}", interface.name))
        })?;

        match channel {
            Channel::Ethernet(tx, rx) => Ok(Self { tx, rx }),
            _ => bail!(
                "interface {} does not support Ethernet channel operations",
                interface.name
            ),
        }
    }
}

impl ArpChannel for DatalinkArpChannel {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.tx
            .send_to(frame, None)
            .ok_or_else(|| anyhow!("failed to queue ARP frame for transmit"))?
            .context(operation_failed(
                "transmit ARP request",
                format!("frame_len={} bytes", frame.len()),
            ))?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        match self.rx.next() {
            Ok(packet) => Ok(Some(packet.to_vec())),
            Err(err) if err.kind() == io::ErrorKind::TimedOut => Ok(None),
            Err(err) => Err(err.into()),
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
) -> Result<MacAddr> {
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
) -> Result<MacAddr> {
    let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    {
        let mut ethernet = MutableEthernetPacket::new(&mut frame)
            .ok_or_else(|| anyhow!("failed to allocate ARP ethernet frame"))?;
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(source_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let payload = ethernet.payload_mut();
        let mut arp = MutableArpPacket::new(payload)
            .ok_or_else(|| anyhow!("failed to allocate ARP payload"))?;
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

    let deadline = Instant::now() + timeout;
    let mut attempts = 0u32;

    while Instant::now() < deadline {
        attempts += 1;
        debug!(
            "Sending ARP request for {} on {} (attempt {})",
            target_ip, interface_name, attempts
        );
        channel.send(&frame)?;

        let mut attempt_deadline = Instant::now() + retry_interval;
        if attempt_deadline > deadline {
            attempt_deadline = deadline;
        }

        loop {
            if Instant::now() >= attempt_deadline {
                break;
            }
            match channel.receive()? {
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

    bail!(
        "failed to resolve MAC address for {} via {} after {} attempt(s)",
        target_ip,
        interface_name,
        attempts
    )
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
    use std::collections::VecDeque;
    use std::time::Duration;

    struct MockChannel {
        frames: Vec<Vec<u8>>,
        responses: VecDeque<Result<Option<Vec<u8>>>>,
    }

    impl MockChannel {
        fn new(responses: VecDeque<Result<Option<Vec<u8>>>>) -> Self {
            Self {
                frames: Vec::new(),
                responses,
            }
        }

        fn frames_sent(&self) -> usize {
            self.frames.len()
        }
    }

    impl ArpChannel for MockChannel {
        fn send(&mut self, frame: &[u8]) -> Result<()> {
            self.frames.push(frame.to_vec());
            Ok(())
        }

        fn receive(&mut self) -> Result<Option<Vec<u8>>> {
            self.responses.pop_front().unwrap_or_else(|| Ok(None))
        }
    }

    fn build_reply(
        sender_mac: MacAddr,
        sender_ip: std::net::Ipv4Addr,
        target_mac: MacAddr,
        target_ip: std::net::Ipv4Addr,
    ) -> Result<Vec<u8>> {
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
        let mut ethernet = MutableEthernetPacket::new(&mut frame)
            .ok_or_else(|| anyhow!("failed to build mock ethernet frame"))?;
        ethernet.set_destination(target_mac);
        ethernet.set_source(sender_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let payload = ethernet.payload_mut();
        let mut arp = MutableArpPacket::new(payload)
            .ok_or_else(|| anyhow!("failed to build mock ARP payload"))?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(target_mac);
        arp.set_target_proto_addr(target_ip);

        Ok(frame)
    }

    #[test]
    fn arp_resolve_with_mock_channel() {
        let source_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let target_mac = MacAddr::new(10, 11, 12, 13, 14, 15);
        let source_ip = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);

        let reply = build_reply(target_mac, target_ip, source_mac, source_ip)
            .expect("failed to build mock reply");
        let responses = VecDeque::from(vec![Ok(Some(reply))]);
        let mut channel = MockChannel::new(responses);

        let result = resolve_with_channel_with_retry(
            &mut channel,
            "mock0",
            source_mac,
            source_ip,
            target_ip,
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .expect("mock resolution failed");

        assert_eq!(result, target_mac);
        assert!(channel.frames_sent() >= 1);
    }

    #[test]
    fn parse_arp_reply_requires_matching_target() {
        let source_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let target_mac = MacAddr::new(10, 11, 12, 13, 14, 15);
        let expected_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);
        let unexpected_ip = std::net::Ipv4Addr::new(192, 168, 0, 99);

        let frame = build_reply(target_mac, unexpected_ip, source_mac, expected_ip)
            .expect("failed to build mock reply");
        assert!(parse_arp_reply(&frame, expected_ip).is_none());
    }

    #[test]
    fn parse_arp_reply_ignores_non_arp_frames() {
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
        let mut ethernet =
            MutableEthernetPacket::new(&mut frame).expect("failed to build ethernet frame");
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(MacAddr::new(0, 1, 2, 3, 4, 5));
        ethernet.set_ethertype(EtherTypes::Ipv4);
        // Payload contents are irrelevant for non-ARP frames.
        assert!(parse_arp_reply(&frame, target_ip).is_none());
    }

    #[test]
    fn parse_arp_reply_returns_none_for_arp_request() {
        let source_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let target_mac = MacAddr::new(10, 11, 12, 13, 14, 15);
        let source_ip = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);

        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(source_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let payload = ethernet.payload_mut();
        let mut arp = MutableArpPacket::new(payload).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request); // Request, not Reply
        arp.set_sender_hw_addr(source_mac);
        arp.set_sender_proto_addr(source_ip);
        arp.set_target_hw_addr(target_mac);
        arp.set_target_proto_addr(target_ip);

        assert!(parse_arp_reply(&frame, target_ip).is_none());
    }

    #[test]
    fn parse_arp_reply_returns_sender_hw_addr() {
        let sender_mac = MacAddr::new(10, 11, 12, 13, 14, 15);
        let target_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let sender_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 1);

        let frame = build_reply(sender_mac, sender_ip, target_mac, target_ip).unwrap();
        let result = parse_arp_reply(&frame, sender_ip);

        assert_eq!(result, Some(sender_mac));
    }

    #[test]
    fn arp_resolve_times_out_when_no_response() {
        let source_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let source_ip = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 99);

        let responses = VecDeque::from(vec![Ok(None), Ok(None), Ok(None)]);
        let mut channel = MockChannel::new(responses);

        let result = resolve_with_channel_with_retry(
            &mut channel,
            "mock0",
            source_mac,
            source_ip,
            target_ip,
            Duration::from_millis(10),
            Duration::from_millis(1),
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to resolve MAC address"));
    }

    #[test]
    fn parse_arp_reply_returns_none_for_empty_packet() {
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);
        let frame = vec![];
        assert!(parse_arp_reply(&frame, target_ip).is_none());
    }

    #[test]
    fn parse_arp_reply_returns_none_for_truncated_ethernet() {
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);
        let frame = vec![0u8; 10]; // Too small for ethernet header
        assert!(parse_arp_reply(&frame, target_ip).is_none());
    }

    #[test]
    fn arp_resolve_retries_on_timeout() {
        let source_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let target_mac = MacAddr::new(10, 11, 12, 13, 14, 15);
        let source_ip = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);

        let reply = build_reply(target_mac, target_ip, source_mac, source_ip)
            .expect("failed to build mock reply");

        // First two attempts timeout, third succeeds
        let responses = VecDeque::from(vec![Ok(None), Ok(None), Ok(Some(reply))]);
        let mut channel = MockChannel::new(responses);

        let result = resolve_with_channel_with_retry(
            &mut channel,
            "mock0",
            source_mac,
            source_ip,
            target_ip,
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .expect("mock resolution should eventually succeed");

        assert_eq!(result, target_mac);
        assert!(
            channel.frames_sent() >= 3,
            "expected at least 3 attempts, got {}",
            channel.frames_sent()
        );
    }

    #[test]
    fn arp_resolve_ignores_unrelated_replies() {
        let source_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let target_mac = MacAddr::new(10, 11, 12, 13, 14, 15);
        let source_ip = std::net::Ipv4Addr::new(192, 168, 0, 1);
        let target_ip = std::net::Ipv4Addr::new(192, 168, 0, 42);
        let unrelated_ip = std::net::Ipv4Addr::new(192, 168, 0, 99);

        // First an unrelated reply, then the correct reply
        let unrelated_reply = build_reply(target_mac, unrelated_ip, source_mac, source_ip)
            .expect("failed to build unrelated reply");
        let correct_reply = build_reply(target_mac, target_ip, source_mac, source_ip)
            .expect("failed to build correct reply");

        let responses = VecDeque::from(vec![Ok(Some(unrelated_reply)), Ok(Some(correct_reply))]);
        let mut channel = MockChannel::new(responses);

        let result = resolve_with_channel_with_retry(
            &mut channel,
            "mock0",
            source_mac,
            source_ip,
            target_ip,
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .expect("should find correct reply");

        assert_eq!(result, target_mac);
    }

    #[test]
    fn mock_channel_tracks_sent_frames() {
        let responses = VecDeque::new();
        let mut channel = MockChannel::new(responses);
        assert_eq!(channel.frames_sent(), 0);

        let frame = vec![0u8; 42];
        channel.send(&frame).unwrap();
        assert_eq!(channel.frames_sent(), 1);

        channel.send(&frame).unwrap();
        assert_eq!(channel.frames_sent(), 2);
    }
}
