// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub mod dhcp;
pub mod dns;
pub mod http;
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
    value: crate::field::FieldValue,
    name: &str,
) -> Result<bytes::Bytes, crate::field::Error> {
    match value {
        crate::field::FieldValue::Bytes(value) => Ok(value),
        crate::field::FieldValue::Text(value) => Ok(bytes::Bytes::from(value.into_bytes())),
        _ => Err(crate::protocol::common::wrong_type(
            schema,
            name,
            "bytes or text",
        )),
    }
}
