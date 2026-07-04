// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::rr::{Name, RecordType};

use super::{DnsProtocolError, DnsProtocolResult};

pub(super) const DNS_HEADER_BYTES: usize = 12;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_TRUNCATED: u16 = 0x0200;
const DNS_RCODE_MASK: u16 = 0x000f;

pub(super) struct DnsHeaderSummary {
    pub(super) truncated: bool,
}

pub(super) fn inspect_dns_response_header(
    response: &[u8],
    expected_id: u16,
) -> DnsProtocolResult<DnsHeaderSummary> {
    if response.len() < DNS_HEADER_BYTES {
        return Err(DnsProtocolError::ResponseTooShort {
            actual: response.len(),
            minimum: DNS_HEADER_BYTES,
        });
    }

    let id = u16::from_be_bytes([response[0], response[1]]);
    let flags = u16::from_be_bytes([response[2], response[3]]);

    if flags & DNS_FLAG_RESPONSE == 0 {
        return Err(DnsProtocolError::MessageTypeMismatch {
            actual: "Query".to_string(),
        });
    }

    let response_code = ResponseCode::from_low((flags & DNS_RCODE_MASK) as u8);
    if response_code != ResponseCode::NoError {
        return Err(DnsProtocolError::ServerResponseCode {
            code: response_code.to_string(),
        });
    }

    if id != expected_id {
        return Err(DnsProtocolError::TransactionIdMismatch {
            expected: expected_id,
            actual: id,
        });
    }

    Ok(DnsHeaderSummary {
        truncated: flags & DNS_FLAG_TRUNCATED != 0,
    })
}

pub(super) fn validate_dns_response(
    response: &[u8],
    expected_id: u16,
    expected_domain: &str,
    expected_type: RecordType,
) -> DnsProtocolResult<Message> {
    let message = Message::from_vec(response)
        .map_err(|source| DnsProtocolError::ResponseDecode { source })?;

    if message.message_type() != MessageType::Response {
        return Err(DnsProtocolError::MessageTypeMismatch {
            actual: format!("{:?}", message.message_type()),
        });
    }

    if message.response_code() != ResponseCode::NoError {
        return Err(DnsProtocolError::ServerResponseCode {
            code: message.response_code().to_string(),
        });
    }

    if message.id() != expected_id {
        return Err(DnsProtocolError::TransactionIdMismatch {
            expected: expected_id,
            actual: message.id(),
        });
    }

    if message.queries().is_empty() {
        return Err(DnsProtocolError::MissingQuery);
    }

    let query = &message.queries()[0];
    let normalized_domain = if expected_domain.ends_with('.') {
        expected_domain.to_string()
    } else {
        format!("{}.", expected_domain)
    };
    let expected_name =
        Name::from_str(&normalized_domain).map_err(|source| DnsProtocolError::InvalidDomain {
            domain: normalized_domain,
            source,
        })?;

    if *query.name() != expected_name {
        return Err(DnsProtocolError::QueryNameMismatch {
            expected: expected_name.to_string(),
            actual: query.name().to_string(),
        });
    }

    if query.query_type() != expected_type {
        return Err(DnsProtocolError::QueryTypeMismatch {
            expected: expected_type.to_string(),
            actual: query.query_type().to_string(),
        });
    }

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::op::{OpCode, Query};
    use trust_dns_proto::rr::DNSClass;

    fn response_bytes(id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(id);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);
        let mut query = Query::new();
        query.set_name(Name::from_str(name).unwrap());
        query.set_query_type(record_type);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        message.to_vec().unwrap()
    }

    #[test]
    fn inspect_dns_response_header_accepts_response_and_reports_truncation() {
        let response = [0x12, 0x34, 0x82, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let summary = inspect_dns_response_header(&response, 0x1234).unwrap();

        assert!(summary.truncated);
    }

    #[test]
    fn inspect_dns_response_header_rejects_short_query_error_and_wrong_id() {
        assert!(inspect_dns_response_header(&[0; 2], 1).is_err());
        assert!(inspect_dns_response_header(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1).is_err());
        assert!(
            inspect_dns_response_header(&[0, 1, 0x80, 0x03, 0, 0, 0, 0, 0, 0, 0, 0], 1).is_err()
        );
        assert!(inspect_dns_response_header(&[0, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1).is_err());
    }

    #[test]
    fn validate_dns_response_accepts_matching_query() {
        let bytes = response_bytes(7, "example.test.", RecordType::AAAA);
        let message = validate_dns_response(&bytes, 7, "example.test", RecordType::AAAA).unwrap();

        assert_eq!(message.id(), 7);
        assert_eq!(message.queries()[0].query_type(), RecordType::AAAA);
    }

    #[test]
    fn validate_dns_response_rejects_query_name_type_and_id_mismatch() {
        let bytes = response_bytes(7, "example.test.", RecordType::A);

        assert!(validate_dns_response(&bytes, 8, "example.test", RecordType::A).is_err());
        assert!(validate_dns_response(&bytes, 7, "other.test", RecordType::A).is_err());
        assert!(validate_dns_response(&bytes, 7, "example.test", RecordType::AAAA).is_err());
    }

    #[test]
    fn validate_dns_response_rejects_response_without_queries() {
        let mut message = Message::new();
        message.set_id(1);
        message.set_message_type(MessageType::Response);
        let bytes = message.to_vec().unwrap();

        assert!(validate_dns_response(&bytes, 1, "example.test", RecordType::A).is_err());
    }

    #[test]
    fn response_validation_errors_are_typed() {
        assert!(matches!(
            inspect_dns_response_header(&[0; 2], 1),
            Err(DnsProtocolError::ResponseTooShort { .. })
        ));
        assert!(matches!(
            inspect_dns_response_header(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 1),
            Err(DnsProtocolError::MessageTypeMismatch { .. })
        ));

        let bytes = response_bytes(7, "example.test.", RecordType::A);
        assert!(matches!(
            validate_dns_response(&bytes, 8, "example.test", RecordType::A),
            Err(DnsProtocolError::TransactionIdMismatch { .. })
        ));
        assert!(matches!(
            validate_dns_response(&bytes, 7, "other.test", RecordType::A),
            Err(DnsProtocolError::QueryNameMismatch { .. })
        ));
        assert!(matches!(
            validate_dns_response(&bytes, 7, "example.test", RecordType::AAAA),
            Err(DnsProtocolError::QueryTypeMismatch { .. })
        ));
        assert!(matches!(
            validate_dns_response(&[0], 7, "example.test", RecordType::A),
            Err(DnsProtocolError::ResponseDecode { .. })
        ));
    }
}
