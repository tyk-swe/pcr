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
pub(crate) fn resolve_mac(
    interface: &NetworkInterface,
    source_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    timeout: Duration,
) -> Result<MacAddr> {
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
    pub(crate) fn resolve(
        &mut self,
        target_ip: std::net::Ipv4Addr,
        timeout: Duration,
    ) -> Result<MacAddr> {
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
    use std::net::Ipv4Addr;

    const TARGET_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const OTHER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

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
}
