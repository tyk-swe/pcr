// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};

pub(crate) fn build_dns_query(
    domain: &str,
    record_type: &str,
    transaction_id: Option<u16>,
) -> Result<(Vec<u8>, u16)> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err(anyhow!("domain name must not be empty"));
    }
    let mut name = Name::from_str(domain).context("Invalid domain name")?;
    // Ensure fully qualified domain name
    if !domain.ends_with('.') {
        name = Name::from_str(&format!("{}.", domain)).context("Invalid domain name")?;
    }

    let record_type_enum = RecordType::from_str(&record_type.to_uppercase())
        .map_err(|_| anyhow::anyhow!("Unsupported DNS type: {}", record_type))?;

    let mut message = Message::new();
    // trust-dns-proto Message::new() initializes with a random ID if we don't set it,
    // but explicit setting is fine too.
    let id = transaction_id.unwrap_or_else(rand::random);
    message.set_id(id);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(record_type_enum);
    query.set_query_class(DNSClass::IN);

    message.add_query(query);

    let bytes = message.to_vec()?;
    Ok((bytes, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dns_query_uses_provided_transaction_id_and_fqdn() {
        let (bytes, id) = build_dns_query("example.test", "aaaa", Some(0x1234)).unwrap();
        let message = Message::from_vec(&bytes).unwrap();

        assert_eq!(id, 0x1234);
        assert_eq!(message.id(), 0x1234);
        assert_eq!(message.message_type(), MessageType::Query);
        assert!(message.recursion_desired());
        assert_eq!(message.queries().len(), 1);
        assert_eq!(message.queries()[0].name().to_string(), "example.test.");
        assert_eq!(message.queries()[0].query_type(), RecordType::AAAA);
        assert_eq!(message.queries()[0].query_class(), DNSClass::IN);
    }

    #[test]
    fn build_dns_query_preserves_existing_trailing_dot() {
        let (bytes, _) = build_dns_query("example.test.", "A", Some(1)).unwrap();
        let message = Message::from_vec(&bytes).unwrap();

        assert_eq!(message.queries()[0].name().to_string(), "example.test.");
    }

    #[test]
    fn build_dns_query_rejects_empty_domain_and_unknown_type() {
        assert!(build_dns_query(" ", "A", Some(1)).is_err());
        assert!(build_dns_query("example.test", "NOPE", Some(1)).is_err());
    }
}
