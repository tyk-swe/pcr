// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod http2;
pub mod ntp;
pub mod syslog;
pub mod tftp;
pub mod tls;

pub(crate) use dhcp::{Dhcpv4Codec, Dhcpv6Codec};
pub(crate) use dns::DnsCodec;
pub(crate) use http::HttpCodec;
pub(crate) use ntp::NtpCodec;
pub(crate) use syslog::SyslogCodec;
pub(crate) use tftp::TftpCodec;
pub(crate) use tls::TlsCodec;

/// Raw byte-string fields also accept text, taken as its UTF-8 bytes.
pub(crate) fn byte_string_field(
    schema: &'static crate::layer::Schema,
    value: crate::field::Value,
    name: &str,
) -> Result<bytes::Bytes, crate::field::Error> {
    match value {
        crate::field::Value::Bytes(value) => Ok(value),
        crate::field::Value::Text(value) => Ok(bytes::Bytes::from(value.into_bytes())),
        _ => Err(crate::protocol::common::wrong_type(
            schema,
            name,
            "bytes or text",
        )),
    }
}

pub mod mqtt;
mod text_message;
pub(crate) use mqtt::MqttCodec;
pub mod coap;
pub(crate) use coap::CoapCodec;
pub mod amqp;
pub(crate) use amqp::AmqpCodec;
pub mod resp;
pub(crate) use resp::RespCodec;
pub mod memcached;
pub(crate) use memcached::MemcachedCodec;
pub mod ssdp;
pub(crate) use ssdp::SsdpCodec;

pub mod bgp;
pub(crate) use bgp::BgpCodec;

mod ber;

pub mod radius;
pub(crate) use radius::RadiusCodec;

pub mod snmp;
pub(crate) use snmp::SnmpCodec;

pub mod ldap;
pub(crate) use ldap::LdapCodec;

pub mod netflowv5;
pub(crate) use netflowv5::Netflowv5Codec;

pub mod ipfix;
pub(crate) use ipfix::IpfixCodec;

pub mod sflow;
pub(crate) use sflow::SflowCodec;

pub mod sip;
pub(crate) use sip::SipCodec;

pub mod rtsp;
pub(crate) use rtsp::RtspCodec;

pub mod rtp;
pub(crate) use rtp::RtpCodec;

pub mod rtcp;
pub(crate) use rtcp::RtcpCodec;

pub mod stun;
pub(crate) use stun::StunCodec;

pub mod dtls;
pub(crate) use dtls::DtlsCodec;

pub mod modbus_tcp;
pub(crate) use modbus_tcp::ModbusTcpCodec;

pub mod bacnet_ip;
pub(crate) use bacnet_ip::BacnetIpCodec;

pub mod dnp3;
pub(crate) use dnp3::Dnp3Codec;

pub mod ethernet_ip;
pub(crate) use ethernet_ip::EthernetIpCodec;

pub mod iec104;
pub(crate) use iec104::Iec104Codec;

pub mod opcua_tcp;
pub(crate) use opcua_tcp::OpcuaTcpCodec;
