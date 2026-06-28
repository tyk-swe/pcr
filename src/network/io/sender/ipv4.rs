use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::checksum as ipv4_checksum;
use rand::random;

use crate::engine::spec::{FragmentSpec, PacketSpec};
use crate::network::sender::error::{Ipv4Error, Result};

use super::fragment::{
    determine_more_flag, ensure_fragment_alignment, extract_fragment_payload, plan_fragments,
    FragmentPlan,
};
use super::header::{initialize_ipv4_header, IpHeaderContext, Ipv4HeaderParams};

pub(crate) const IPV4_HEADER_LEN: usize = 20;

pub(crate) fn build_ipv4_packets(
    spec: &PacketSpec,
    transport: &[u8],
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
) -> Result<Vec<Vec<u8>>> {
    let context = Ipv4PacketContext::from_spec(spec);
    let fragment_plans = plan_fragments(context.fragment(), transport.len(), IPV4_HEADER_LEN, 0)?;
    let mut fragments: Vec<Vec<u8>> = Vec::new();

    for (index, plan) in fragment_plans.iter().enumerate() {
        ensure_fragment_alignment(plan)?;
        let payload_bytes = extract_fragment_payload(plan, transport);
        let buffer = assemble_ipv4_fragment(
            &context,
            Ipv4FragmentParams {
                plan,
                position: FragmentPosition {
                    index,
                    total: fragment_plans.len(),
                },
                payload: &payload_bytes,
                addresses: (source_ip, destination_ip),
                protocol,
            },
        )?;
        fragments.push(buffer);
    }

    if fragments.is_empty() {
        return Err(Ipv4Error::NoFragments.into());
    }

    Ok(fragments)
}

struct Ipv4PacketContext {
    header: IpHeaderContext,
    identification: u16,
}

impl Ipv4PacketContext {
    fn from_spec(spec: &PacketSpec) -> Self {
        let header = IpHeaderContext::from_spec(spec);
        let identification = spec
            .ip
            .as_ref()
            .and_then(|ip| ip.identification)
            .unwrap_or_else(random::<u16>);

        Self {
            header,
            identification,
        }
    }

    fn fragment(&self) -> &FragmentSpec {
        self.header.fragment()
    }

    fn base_offset(&self) -> u16 {
        self.header.fragment_offset()
    }

    fn dont_fragment(&self) -> bool {
        self.header.fragment().dont_fragment
    }

    fn header(&self) -> &IpHeaderContext {
        &self.header
    }

    fn identification(&self) -> u16 {
        self.identification
    }
}

#[derive(Copy, Clone)]
struct FragmentPosition {
    index: usize,
    total: usize,
}

struct Ipv4FragmentParams<'a> {
    plan: &'a FragmentPlan,
    position: FragmentPosition,
    payload: &'a [u8],
    addresses: (Ipv4Addr, Ipv4Addr),
    protocol: IpNextHeaderProtocol,
}

fn assemble_ipv4_fragment(
    context: &Ipv4PacketContext,
    params: Ipv4FragmentParams<'_>,
) -> Result<Vec<u8>> {
    let total_length_usize = IPV4_HEADER_LEN + params.payload.len();
    if total_length_usize > u16::MAX as usize {
        return Err(Ipv4Error::FragmentTooLarge {
            length: total_length_usize,
            max: u16::MAX as usize,
        }
        .into());
    }

    let total_length = total_length_usize as u16;
    let mut buffer = vec![0u8; total_length_usize];
    let more_flag = determine_more_flag(params.plan, params.position.index, params.position.total);
    let offset_units = context
        .base_offset()
        .checked_add((params.plan.start / 8) as u16)
        .ok_or(Ipv4Error::FragmentOffsetOverflow)?;
    if offset_units > 0x1FFF {
        return Err(Ipv4Error::FragmentOffsetTooLarge.into());
    }

    let (source_ip, destination_ip) = params.addresses;
    {
        let mut packet = initialize_ipv4_header(
            &mut buffer,
            context.header(),
            Ipv4HeaderParams {
                total_length,
                identification: context.identification(),
                protocol: params.protocol,
                source_ip,
                destination_ip,
                dont_fragment: context.dont_fragment(),
                more_flag,
                fragment_offset: offset_units,
            },
        )?;
        packet.set_payload(params.payload);
        // Checksum must reflect payload
        let checksum = ipv4_checksum(&packet.to_immutable());
        packet.set_checksum(checksum);
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::spec::{
        DestinationSpec, FragmentSpec, IpSpec, Ipv6Spec, Layer2Spec, ListenerSpec, LoggingSpec,
        PacketSpec, PayloadSource, PayloadSpec, TransmissionSpec, TransportSpec,
    };
    use pnet::packet::ip::IpNextHeaderProtocol;
    use pnet::packet::ipv4::Ipv4Packet;
    use std::net::Ipv4Addr;

    fn default_packet_spec() -> PacketSpec {
        PacketSpec {
            target: DestinationSpec::default(),
            layer2: Layer2Spec::default(),
            ip: None,
            ipv6: Ipv6Spec::default(),
            transport: TransportSpec::Auto,
            payload: PayloadSpec {
                source: PayloadSource::Empty,
            },
            transmit: TransmissionSpec::default(),
            listener: ListenerSpec::default(),
            rules_file: None,
            logging: LoggingSpec::default(),
        }
    }

    #[test]
    fn build_ipv4_packets_calculates_checksum() {
        let spec = default_packet_spec();
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let src = Ipv4Addr::new(127, 0, 0, 1);
        let dst = Ipv4Addr::new(127, 0, 0, 1);

        let packets = build_ipv4_packets(
            &spec,
            &payload,
            src,
            dst,
            IpNextHeaderProtocol::new(17), // UDP
        )
        .expect("build should succeed");

        assert_eq!(packets.len(), 1);
        let packet = Ipv4Packet::new(&packets[0]).expect("valid ipv4 packet");

        assert_ne!(packet.get_checksum(), 0, "checksum should be calculated");
        assert_eq!(
            packet.get_checksum(),
            ipv4_checksum(&packet.to_immutable()),
            "checksum should match pnet calculation"
        );
    }

    #[test]
    fn build_ipv4_packets_sets_dont_fragment_flag() {
        let mut spec = default_packet_spec();
        spec.ip = Some(IpSpec {
            fragmentation: FragmentSpec {
                dont_fragment: true,
                ..Default::default()
            },
            ..Default::default()
        });

        let payload = vec![0u8; 10];
        let src = Ipv4Addr::LOCALHOST;
        let dst = Ipv4Addr::LOCALHOST;

        let packets = build_ipv4_packets(
            &spec,
            &payload,
            src,
            dst,
            IpNextHeaderProtocol::new(6), // TCP
        )
        .expect("build should succeed");

        assert_eq!(packets.len(), 1);
        let packet = Ipv4Packet::new(&packets[0]).expect("valid ipv4 packet");
        assert!(packet.get_flags() & pnet::packet::ipv4::Ipv4Flags::DontFragment != 0);
    }

    #[test]
    fn build_ipv4_packets_sets_more_fragments_flag() {
        let mut spec = default_packet_spec();
        spec.ip = Some(IpSpec {
            fragmentation: FragmentSpec {
                mtu: Some(28), // 20 header + 8 payload
                ..Default::default()
            },
            ..Default::default()
        });

        let payload = vec![0u8; 16]; // Needs 2 fragments (8 + 8)
        let src = Ipv4Addr::LOCALHOST;
        let dst = Ipv4Addr::LOCALHOST;

        let packets = build_ipv4_packets(&spec, &payload, src, dst, IpNextHeaderProtocol::new(17))
            .expect("build should succeed");

        assert_eq!(packets.len(), 2);

        let first = Ipv4Packet::new(&packets[0]).expect("valid first fragment");
        assert!(first.get_flags() & pnet::packet::ipv4::Ipv4Flags::MoreFragments != 0);

        let second = Ipv4Packet::new(&packets[1]).expect("valid second fragment");
        assert_eq!(
            second.get_flags() & pnet::packet::ipv4::Ipv4Flags::MoreFragments,
            0
        );
    }

    #[test]
    fn build_ipv4_packets_validates_total_length() {
        let spec = default_packet_spec();
        // Max u16 is 65535. Header is 20. Max payload is 65515.
        // Try 65516.
        let payload = vec![0u8; 65516];
        let src = Ipv4Addr::LOCALHOST;
        let dst = Ipv4Addr::LOCALHOST;

        let result = build_ipv4_packets(&spec, &payload, src, dst, IpNextHeaderProtocol::new(17));

        assert!(result.is_err());
        match result.unwrap_err() {
            crate::network::sender::error::SenderError::Ipv4(Ipv4Error::FragmentTooLarge {
                length,
                max,
            }) => {
                assert_eq!(length, 20 + 65516);
                assert_eq!(max, 65535);
            }
            err => panic!("unexpected error: {:?}", err),
        }
    }
}
