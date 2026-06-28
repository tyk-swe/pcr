use std::net::{Ipv4Addr, Ipv6Addr};

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use crate::engine::spec::{FragmentSpec, PacketSpec};
use crate::network::sender::error::{HeaderError, Result};

#[derive(Clone)]
pub(crate) struct IpHeaderContext {
    ttl: u8,
    traffic_class: u8,
    fragment: FragmentSpec,
}

pub(crate) struct Ipv4HeaderParams {
    pub(crate) total_length: u16,
    pub(crate) identification: u16,
    pub(crate) protocol: IpNextHeaderProtocol,
    pub(crate) source_ip: Ipv4Addr,
    pub(crate) destination_ip: Ipv4Addr,
    pub(crate) dont_fragment: bool,
    pub(crate) more_flag: bool,
    pub(crate) fragment_offset: u16,
}

pub(crate) fn initialize_ipv4_header<'a>(
    buffer: &'a mut [u8],
    context: &IpHeaderContext,
    params: Ipv4HeaderParams,
) -> Result<MutableIpv4Packet<'a>> {
    let mut packet = MutableIpv4Packet::new(buffer).ok_or(HeaderError::Ipv4AllocationFailed)?;
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_total_length(params.total_length);
    packet.set_ttl(context.ttl());
    packet.set_dscp(context.dscp());
    packet.set_identification(params.identification);
    let mut flags = 0u8;
    if params.dont_fragment {
        flags |= pnet::packet::ipv4::Ipv4Flags::DontFragment;
    }
    if params.more_flag {
        flags |= pnet::packet::ipv4::Ipv4Flags::MoreFragments;
    }
    packet.set_flags(flags);
    packet.set_fragment_offset(params.fragment_offset);
    packet.set_next_level_protocol(params.protocol);
    packet.set_source(params.source_ip);
    packet.set_destination(params.destination_ip);
    packet.set_checksum(0);
    Ok(packet)
}

pub(crate) fn initialize_ipv6_header<'a>(
    buffer: &'a mut [u8],
    context: &IpHeaderContext,
    payload_length: u16,
    next_header: IpNextHeaderProtocol,
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
) -> Result<MutableIpv6Packet<'a>> {
    let mut packet = MutableIpv6Packet::new(buffer).ok_or(HeaderError::Ipv6AllocationFailed)?;
    packet.set_version(6);
    packet.set_traffic_class(context.traffic_class());
    packet.set_flow_label(0);
    packet.set_payload_length(payload_length);
    packet.set_next_header(next_header);
    packet.set_hop_limit(context.hop_limit());
    packet.set_source(source_ip);
    packet.set_destination(destination_ip);
    Ok(packet)
}

impl IpHeaderContext {
    pub(crate) fn from_spec(spec: &PacketSpec) -> Self {
        let ip_spec = spec.ip.as_ref();
        let ttl = ip_spec.and_then(|ip| ip.ttl).unwrap_or(64);
        let traffic_class = ip_spec.and_then(|ip| ip.tos).unwrap_or(0);
        let fragment = ip_spec
            .map(|ip| ip.fragmentation.clone())
            .unwrap_or_default();

        Self {
            ttl,
            traffic_class,
            fragment,
        }
    }

    pub(crate) fn ttl(&self) -> u8 {
        self.ttl
    }

    pub(crate) fn hop_limit(&self) -> u8 {
        self.ttl
    }

    pub(crate) fn dscp(&self) -> u8 {
        self.traffic_class
    }

    pub(crate) fn traffic_class(&self) -> u8 {
        self.traffic_class
    }

    pub(crate) fn fragment(&self) -> &FragmentSpec {
        &self.fragment
    }

    pub(crate) fn fragment_mut(&mut self) -> &mut FragmentSpec {
        &mut self.fragment
    }

    pub(crate) fn fragment_offset(&self) -> u16 {
        self.fragment.offset.unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::spec::{
        DestinationSpec, FragmentSpec, IpSpec, Ipv6Spec, Layer2Spec, ListenerSpec, LoggingSpec,
        PacketSpec, PayloadSource, PayloadSpec, TransmissionSpec, TransportSpec,
    };
    use crate::network::sender::error::SenderError;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;

    fn base_packet_spec() -> PacketSpec {
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
    fn ip_header_context_uses_defaults_when_ipv4_spec_missing() {
        let spec = base_packet_spec();
        let ctx = IpHeaderContext::from_spec(&spec);

        assert_eq!(ctx.ttl(), 64, "default TTL should match conventional value");
        assert_eq!(ctx.hop_limit(), 64);
        assert_eq!(ctx.dscp(), 0, "default DSCP should be zero");
        assert_eq!(ctx.traffic_class(), 0);
        assert!(
            ctx.fragment().is_default(),
            "no fragment directives expected"
        );
        assert_eq!(ctx.fragment_offset(), 0);
    }

    #[test]
    fn ip_header_context_inherits_ipv4_fragment_configuration() {
        let mut spec = base_packet_spec();
        let ip = IpSpec {
            ttl: Some(42),
            tos: Some(0x1c),
            fragmentation: FragmentSpec {
                mtu: Some(512),
                offset: Some(24),
                more_fragments: true,
                dont_fragment: true,
                ..Default::default()
            },
            ..Default::default()
        };
        spec.ip = Some(ip);

        let mut ctx = IpHeaderContext::from_spec(&spec);
        assert_eq!(ctx.ttl(), 42);
        assert_eq!(ctx.hop_limit(), 42);
        assert_eq!(ctx.dscp(), 0x1c);
        assert!(ctx.fragment().more_fragments);
        assert!(ctx.fragment().dont_fragment);
        assert_eq!(ctx.fragment_offset(), 24);

        ctx.fragment_mut().dont_fragment = false;
        assert!(
            !ctx.fragment().dont_fragment,
            "fragment_mut should allow mutation"
        );
    }

    #[test]
    fn initialize_ipv4_header_sets_expected_fields() {
        use pnet::packet::ipv4::Ipv4Flags;

        let mut spec = base_packet_spec();
        let ip = IpSpec {
            ttl: Some(60),
            tos: Some(0x2e),
            ..Default::default()
        };
        spec.ip = Some(ip);
        let ctx = IpHeaderContext::from_spec(&spec);

        let params = Ipv4HeaderParams {
            total_length: 60,
            identification: 0x1234,
            protocol: IpNextHeaderProtocols::Tcp,
            source_ip: Ipv4Addr::new(192, 0, 2, 1),
            destination_ip: Ipv4Addr::new(192, 0, 2, 2),
            dont_fragment: true,
            more_flag: true,
            fragment_offset: 32,
        };

        let mut buffer = [0u8; 60];
        initialize_ipv4_header(&mut buffer, &ctx, params).expect("ipv4 header");
        let view = Ipv4Packet::new(&buffer[..]).expect("ipv4 view");

        assert_eq!(view.get_version(), 4);
        assert_eq!(view.get_total_length(), 60);
        assert_eq!(view.get_ttl(), 60);
        assert_eq!(view.get_dscp(), 0x2e);
        assert_eq!(view.get_fragment_offset(), 32);
        assert_eq!(view.get_identification(), 0x1234);
        assert_eq!(view.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);

        let flags = view.get_flags();
        assert!(flags & Ipv4Flags::DontFragment != 0);
        assert!(flags & Ipv4Flags::MoreFragments != 0);
        assert_eq!(view.get_source(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(view.get_destination(), Ipv4Addr::new(192, 0, 2, 2));
    }

    #[test]
    fn initialize_ipv4_header_errors_when_buffer_too_small() {
        let spec = base_packet_spec();
        let ctx = IpHeaderContext::from_spec(&spec);
        let mut buffer = [0u8; 4];

        let params = Ipv4HeaderParams {
            total_length: 20,
            identification: 0,
            protocol: IpNextHeaderProtocols::Udp,
            source_ip: Ipv4Addr::UNSPECIFIED,
            destination_ip: Ipv4Addr::UNSPECIFIED,
            dont_fragment: false,
            more_flag: false,
            fragment_offset: 0,
        };

        let err = initialize_ipv4_header(&mut buffer, &ctx, params).expect_err("tiny buffer");
        assert!(matches!(
            err,
            SenderError::Header(HeaderError::Ipv4AllocationFailed)
        ));
    }

    #[test]
    fn initialize_ipv6_header_sets_expected_fields() {
        let spec = base_packet_spec();
        let ctx = IpHeaderContext::from_spec(&spec);
        let mut buffer = [0u8; 40];

        let packet = initialize_ipv6_header(
            &mut buffer,
            &ctx,
            1280,
            IpNextHeaderProtocols::Udp,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
        )
        .expect("ipv6 header");

        assert_eq!(packet.get_version(), 6);
        assert_eq!(packet.get_payload_length(), 1280);
        assert_eq!(packet.get_next_header(), IpNextHeaderProtocols::Udp);
        assert_eq!(packet.get_hop_limit(), ctx.hop_limit());
        assert_eq!(packet.get_traffic_class(), ctx.traffic_class());
        assert_eq!(packet.get_source(), Ipv6Addr::LOCALHOST);
        assert_eq!(packet.get_destination(), Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn initialize_ipv6_header_errors_when_buffer_too_small() {
        let spec = base_packet_spec();
        let ctx = IpHeaderContext::from_spec(&spec);
        let mut buffer = [0u8; 8];

        let err = initialize_ipv6_header(
            &mut buffer,
            &ctx,
            16,
            IpNextHeaderProtocols::Udp,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
        )
        .expect_err("tiny buffer");
        assert!(matches!(
            err,
            SenderError::Header(HeaderError::Ipv6AllocationFailed)
        ));
    }
}
