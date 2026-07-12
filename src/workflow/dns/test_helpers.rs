#[cfg(test)]
fn canonical_query_name_from_wire(query: &[u8]) -> Option<String> {
    if query.len() < DNS_HEADER_BYTES {
        return None;
    }
    decode_name(query, DNS_HEADER_BYTES, DnsLimits::default())
        .ok()
        .map(|(name, _)| name.to_string())
}

#[cfg(test)]
fn query_type_from_wire(query: &[u8]) -> Option<DnsQueryType> {
    let (_, offset) = decode_name(query, DNS_HEADER_BYTES, DnsLimits::default()).ok()?;
    let code = read_u16(query, offset, "question type").ok()?;
    match code {
        1 => Some(DnsQueryType::A),
        2 => Some(DnsQueryType::Ns),
        5 => Some(DnsQueryType::Cname),
        6 => Some(DnsQueryType::Soa),
        12 => Some(DnsQueryType::Ptr),
        15 => Some(DnsQueryType::Mx),
        16 => Some(DnsQueryType::Txt),
        28 => Some(DnsQueryType::Aaaa),
        33 => Some(DnsQueryType::Srv),
        255 => Some(DnsQueryType::Any),
        _ => None,
    }
}
