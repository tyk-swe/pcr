/// Canonicalizes a bounded ASCII DNS name for wire construction and
/// case-insensitive correlation. The returned form always has a trailing dot.
pub fn canonical_query_name(value: &str) -> Result<String, DnsWireError> {
    if value == "." {
        return Ok(".".to_owned());
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() {
        return Err(DnsWireError::InvalidName {
            message: "must not be empty".to_owned(),
        });
    }
    let mut wire_length = 1usize;
    for label in value.split('.') {
        if label.is_empty() {
            return Err(DnsWireError::InvalidName {
                message: "contains an empty label".to_owned(),
            });
        }
        if label.len() > 63 {
            return Err(DnsWireError::InvalidName {
                message: "contains a label longer than 63 bytes".to_owned(),
            });
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*'))
        {
            return Err(DnsWireError::InvalidName {
                message: "labels must use ASCII letters, digits, hyphens, underscores, or wildcard asterisks"
                    .to_owned(),
            });
        }
        wire_length = wire_length
            .checked_add(label.len() + 1)
            .ok_or(DnsWireError::NameTooLong)?;
    }
    if wire_length > 255 {
        return Err(DnsWireError::NameTooLong);
    }
    Ok(format!("{}.", value.to_ascii_lowercase()))
}

/// Constructs one standard IN-class DNS query without resolver or I/O side
/// effects.
pub fn encode_dns_query(
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    recursion_desired: bool,
) -> Result<Bytes, DnsWireError> {
    let query_name = canonical_query_name(query_name)?;
    let mut message = Vec::with_capacity(DNS_HEADER_BYTES + query_name.len() + 5);
    message.extend_from_slice(&transaction_id.to_be_bytes());
    let flags = if recursion_desired {
        DNS_FLAG_RECURSION_DESIRED
    } else {
        0
    };
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&query_name, &mut message)?;
    message.extend_from_slice(&query_type.code().to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(Bytes::from(message))
}

/// Decodes the length prefix of a single DNS-over-TCP frame, then applies the
/// same transaction, question, bounds, and relevance validation as UDP.
pub fn decode_dns_tcp_frame(
    frame: &[u8],
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    limits: DnsLimits,
) -> Result<ValidatedDnsResponse, DnsWireError> {
    let prefix = frame.get(..2).ok_or(DnsWireError::MessageTooShort {
        actual: frame.len(),
        minimum: 2,
    })?;
    let declared = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let payload = &frame[2..];
    if declared != payload.len() {
        return Err(DnsWireError::TcpFrameLength {
            declared,
            actual: payload.len(),
        });
    }
    decode_dns_response(payload, query_name, query_type, transaction_id, limits)
}

/// Decodes and validates one complete DNS response. Only records relevant to
/// the validated question are returned as accepted section data; all other
/// declared records contribute to a bounded rejected-record audit trail.
pub fn decode_dns_response(
    message: &[u8],
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    limits: DnsLimits,
) -> Result<ValidatedDnsResponse, DnsWireError> {
    let query_name = canonical_query_name(query_name)?;
    let expected_name = DnsName::from_canonical_ascii(&query_name);
    if message.len() < DNS_HEADER_BYTES {
        return Err(DnsWireError::MessageTooShort {
            actual: message.len(),
            minimum: DNS_HEADER_BYTES,
        });
    }
    if message.len() > limits.max_message_bytes {
        return Err(DnsWireError::MessageTooLarge {
            actual: message.len(),
            maximum: limits.max_message_bytes,
        });
    }

    let actual_id = read_u16(message, 0, "transaction ID")?;
    let flags = read_u16(message, 2, "flags")?;
    if flags & DNS_FLAG_RESPONSE == 0 {
        return Err(DnsWireError::NotResponse);
    }
    let opcode = ((flags & DNS_OPCODE_MASK) >> 11) as u8;
    if opcode != 0 {
        return Err(DnsWireError::UnsupportedOpcode { opcode });
    }
    if flags & DNS_RESERVED_MASK != 0 {
        return Err(DnsWireError::ReservedHeaderBits);
    }
    if actual_id != transaction_id {
        return Err(DnsWireError::TransactionIdMismatch {
            expected: transaction_id,
            actual: actual_id,
        });
    }
    let question_count = read_u16(message, 4, "question count")?;
    if question_count != 1 {
        return Err(DnsWireError::QuestionCount {
            actual: question_count,
        });
    }
    let answer_count = usize::from(read_u16(message, 6, "answer count")?);
    let authority_count = usize::from(read_u16(message, 8, "authority count")?);
    let additional_count = usize::from(read_u16(message, 10, "additional count")?);
    let (actual_name, mut offset) = decode_name(message, DNS_HEADER_BYTES, limits)?;
    if actual_name != expected_name {
        return Err(DnsWireError::QuestionNameMismatch {
            expected: query_name,
            actual: actual_name.to_string(),
        });
    }
    let actual_type = read_u16(message, offset, "question type")?;
    offset += 2;
    if actual_type != query_type.code() {
        return Err(DnsWireError::QuestionTypeMismatch {
            expected: query_type.code(),
            actual: actual_type,
        });
    }
    let actual_class = read_u16(message, offset, "question class")?;
    offset += 2;
    if actual_class != DNS_CLASS_IN {
        return Err(DnsWireError::QuestionClassMismatch {
            actual: actual_class,
        });
    }

    let truncated = flags & DNS_FLAG_TRUNCATED != 0;
    if truncated {
        // A UDP truncation may end at any byte after the complete question.
        // Do not decode or present possibly partial records as accepted facts.
        return Ok(ValidatedDnsResponse {
            transaction_id,
            response_code: flags & DNS_RCODE_MASK,
            edns: None,
            authoritative: flags & DNS_FLAG_AUTHORITATIVE != 0,
            truncated: true,
            recursion_desired: flags & DNS_FLAG_RECURSION_DESIRED != 0,
            recursion_available: flags & DNS_FLAG_RECURSION_AVAILABLE != 0,
            authenticated_data: flags & DNS_FLAG_AUTHENTICATED_DATA != 0,
            checking_disabled: flags & DNS_FLAG_CHECKING_DISABLED != 0,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: Vec::new(),
            rejected_record_count: 0,
        });
    }

    let record_count = answer_count
        .checked_add(authority_count)
        .and_then(|count| count.checked_add(additional_count))
        .ok_or(DnsWireError::RecordLimit {
            actual: usize::MAX,
            limit: limits.max_records,
        })?;
    if record_count > limits.max_records {
        return Err(DnsWireError::RecordLimit {
            actual: record_count,
            limit: limits.max_records,
        });
    }

    let (answers, next) = decode_records(message, offset, answer_count, limits)?;
    let (authorities, next) = decode_records(message, next, authority_count, limits)?;
    let (additionals, next) = decode_records(message, next, additional_count, limits)?;
    if next != message.len() {
        return Err(DnsWireError::TrailingBytes {
            remaining: message.len() - next,
        });
    }
    if answers
        .iter()
        .chain(&authorities)
        .any(|record| matches!(record.value, DnsRecordValue::Opt(_)))
    {
        return Err(DnsWireError::InvalidEdns {
            message: "OPT pseudo-record must appear only in the additional section".to_owned(),
        });
    }
    let mut edns = None;
    let mut non_opt_additionals = Vec::with_capacity(additionals.len());
    for record in additionals {
        match &record.value {
            DnsRecordValue::Opt(value) => {
                if !record.owner.is_root() {
                    return Err(DnsWireError::InvalidEdns {
                        message: "OPT owner name must be the root".to_owned(),
                    });
                }
                if edns.replace(value.clone()).is_some() {
                    return Err(DnsWireError::DuplicateEdns);
                }
            }
            _ => non_opt_additionals.push(record),
        }
    }
    let response_code = (edns
        .as_ref()
        .map_or(0, |edns| u16::from(edns.extended_response_code))
        << 4)
        | (flags & DNS_RCODE_MASK);
    let RelevantRecords {
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
    } = filter_relevant_records(
        &expected_name,
        query_type,
        answers,
        authorities,
        non_opt_additionals,
        limits.max_rejected_records,
    )?;
    Ok(ValidatedDnsResponse {
        transaction_id,
        response_code,
        edns,
        authoritative: flags & DNS_FLAG_AUTHORITATIVE != 0,
        truncated: false,
        recursion_desired: flags & DNS_FLAG_RECURSION_DESIRED != 0,
        recursion_available: flags & DNS_FLAG_RECURSION_AVAILABLE != 0,
        authenticated_data: flags & DNS_FLAG_AUTHENTICATED_DATA != 0,
        checking_disabled: flags & DNS_FLAG_CHECKING_DISABLED != 0,
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
    })
}

fn encode_name(name: &str, output: &mut Vec<u8>) -> Result<(), DnsWireError> {
    if name == "." {
        output.push(0);
        return Ok(());
    }
    for label in name.trim_end_matches('.').split('.') {
        output.push(u8::try_from(label.len()).map_err(|_| DnsWireError::NameTooLong)?);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

fn read_u16(message: &[u8], offset: usize, field: &'static str) -> Result<u16, DnsWireError> {
    let bytes = message
        .get(offset..offset.saturating_add(2))
        .ok_or(DnsWireError::TruncatedField { field, offset })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(message: &[u8], offset: usize, field: &'static str) -> Result<u32, DnsWireError> {
    let bytes = message
        .get(offset..offset.saturating_add(4))
        .ok_or(DnsWireError::TruncatedField { field, offset })?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn decode_name(
    message: &[u8],
    offset: usize,
    limits: DnsLimits,
) -> Result<(DnsName, usize), DnsWireError> {
    let mut cursor = offset;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut visited = Vec::new();
    let mut pointer_count = 0usize;
    let mut wire_length = 1usize;
    loop {
        let length = *message.get(cursor).ok_or(DnsWireError::TruncatedField {
            field: "name label length",
            offset: cursor,
        })?;
        if length & 0xc0 == 0xc0 {
            let second = *message
                .get(cursor + 1)
                .ok_or(DnsWireError::TruncatedPointer { offset: cursor })?;
            let pointer = usize::from((u16::from(length & 0x3f) << 8) | u16::from(second));
            if pointer >= message.len() {
                return Err(DnsWireError::PointerOutOfBounds {
                    pointer,
                    length: message.len(),
                });
            }
            if pointer == cursor {
                return Err(DnsWireError::PointerLoop { offset: pointer });
            }
            if pointer > cursor {
                return Err(DnsWireError::ForwardPointer {
                    offset: cursor,
                    pointer,
                });
            }
            pointer_count += 1;
            if pointer_count > limits.max_name_pointers {
                return Err(DnsWireError::PointerLimit {
                    limit: limits.max_name_pointers,
                });
            }
            if visited.contains(&pointer) {
                return Err(DnsWireError::PointerLoop { offset: pointer });
            }
            visited.push(pointer);
            resume.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsWireError::ReservedLabelLength { offset: cursor });
        }
        cursor += 1;
        if length == 0 {
            let next = resume.unwrap_or(cursor);
            return Ok((DnsName { labels }, next));
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(DnsWireError::LabelTooLong {
                offset: cursor - 1,
                actual: length,
            });
        }
        let label = message.get(cursor..cursor.saturating_add(length)).ok_or(
            DnsWireError::TruncatedField {
                field: "name label",
                offset: cursor,
            },
        )?;
        wire_length = wire_length
            .checked_add(length + 1)
            .ok_or(DnsWireError::NameTooLong)?;
        if wire_length > 255 {
            return Err(DnsWireError::NameTooLong);
        }
        labels.push(Bytes::copy_from_slice(label));
        cursor += length;
    }
}

fn decode_records(
    message: &[u8],
    mut offset: usize,
    count: usize,
    limits: DnsLimits,
) -> Result<(Vec<DnsRecord>, usize), DnsWireError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (owner, next) = decode_name(message, offset, limits)?;
        offset = next;
        let type_code = read_u16(message, offset, "record type")?;
        let class = read_u16(message, offset + 2, "record class")?;
        let ttl = read_u32(message, offset + 4, "record TTL")?;
        let rdata_length = usize::from(read_u16(message, offset + 8, "RDATA length")?);
        let rdata_offset = offset + 10;
        let rdata_end =
            rdata_offset
                .checked_add(rdata_length)
                .ok_or(DnsWireError::TruncatedField {
                    field: "RDATA",
                    offset: rdata_offset,
                })?;
        message
            .get(rdata_offset..rdata_end)
            .ok_or(DnsWireError::TruncatedField {
                field: "RDATA",
                offset: rdata_offset,
            })?;
        let value = decode_rdata(
            message,
            type_code,
            class,
            ttl,
            rdata_offset,
            rdata_end,
            limits,
        )?;
        records.push(DnsRecord {
            owner,
            class,
            ttl,
            value,
        });
        offset = rdata_end;
    }
    Ok((records, offset))
}

fn decode_rdata(
    message: &[u8],
    type_code: u16,
    class: u16,
    ttl: u32,
    offset: usize,
    end: usize,
    limits: DnsLimits,
) -> Result<DnsRecordValue, DnsWireError> {
    let rdata = message
        .get(offset..end)
        .ok_or(DnsWireError::TruncatedField {
            field: "RDATA",
            offset,
        })?;
    let invalid = |message: &str| DnsWireError::InvalidRdata {
        record_type: type_code,
        offset,
        message: message.to_owned(),
    };
    let exact_name = |start| -> Result<DnsName, DnsWireError> {
        let (name, next) = decode_name(message, start, limits)?;
        if next != end {
            return Err(invalid("name does not consume the declared RDATA"));
        }
        Ok(name)
    };
    match type_code {
        1 => {
            let bytes: [u8; 4] = rdata
                .try_into()
                .map_err(|_| invalid("A RDATA must be 4 bytes"))?;
            Ok(DnsRecordValue::A(Ipv4Addr::from(bytes)))
        }
        2 => Ok(DnsRecordValue::Ns(exact_name(offset)?)),
        5 => Ok(DnsRecordValue::Cname(exact_name(offset)?)),
        6 => {
            let (primary_name_server, next) = decode_name(message, offset, limits)?;
            let (responsible_mailbox, next) = decode_name(message, next, limits)?;
            if next.checked_add(20) != Some(end) {
                return Err(invalid("SOA RDATA must end with five 32-bit integers"));
            }
            Ok(DnsRecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial: read_u32(message, next, "SOA serial")?,
                refresh: read_u32(message, next + 4, "SOA refresh")?,
                retry: read_u32(message, next + 8, "SOA retry")?,
                expire: read_u32(message, next + 12, "SOA expire")?,
                minimum: read_u32(message, next + 16, "SOA minimum")?,
            })
        }
        12 => Ok(DnsRecordValue::Ptr(exact_name(offset)?)),
        15 => {
            if rdata.len() < 3 {
                return Err(invalid("MX RDATA is shorter than preference plus name"));
            }
            let preference = read_u16(message, offset, "MX preference")?;
            let (exchange, next) = decode_name(message, offset + 2, limits)?;
            if next != end {
                return Err(invalid("MX name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Mx {
                preference,
                exchange,
            })
        }
        16 => {
            let mut cursor = 0usize;
            let mut strings = Vec::new();
            let mut total = 0usize;
            while cursor < rdata.len() {
                if strings.len() >= limits.max_txt_strings {
                    return Err(DnsWireError::TxtStringLimit {
                        limit: limits.max_txt_strings,
                    });
                }
                let length = usize::from(rdata[cursor]);
                cursor += 1;
                let string = rdata
                    .get(cursor..cursor.saturating_add(length))
                    .ok_or_else(|| invalid("TXT character-string exceeds declared RDATA"))?;
                total = total
                    .checked_add(length)
                    .ok_or(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    })?;
                if total > limits.max_txt_bytes {
                    return Err(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    });
                }
                strings.push(Bytes::copy_from_slice(string));
                cursor += length;
            }
            Ok(DnsRecordValue::Txt(strings))
        }
        28 => {
            let bytes: [u8; 16] = rdata
                .try_into()
                .map_err(|_| invalid("AAAA RDATA must be 16 bytes"))?;
            Ok(DnsRecordValue::Aaaa(Ipv6Addr::from(bytes)))
        }
        33 => {
            if rdata.len() < 7 {
                return Err(invalid(
                    "SRV RDATA is shorter than priority, weight, port, and name",
                ));
            }
            let priority = read_u16(message, offset, "SRV priority")?;
            let weight = read_u16(message, offset + 2, "SRV weight")?;
            let port = read_u16(message, offset + 4, "SRV port")?;
            let (target, next) = decode_name(message, offset + 6, limits)?;
            if next != end {
                return Err(invalid("SRV name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        DNS_TYPE_OPT => decode_edns(class, ttl, rdata).map(DnsRecordValue::Opt),
        _ => Ok(DnsRecordValue::Unknown {
            type_code,
            rdata: Bytes::copy_from_slice(rdata),
        }),
    }
}

fn decode_edns(class: u16, ttl: u32, rdata: &[u8]) -> Result<DnsEdns, DnsWireError> {
    let extended_response_code = (ttl >> 24) as u8;
    let version = ((ttl >> 16) & 0xff) as u8;
    if version != 0 {
        return Err(DnsWireError::UnsupportedEdnsVersion { version });
    }
    let flags = ttl as u16;
    let mut options = Vec::new();
    let mut cursor = 0usize;
    while cursor < rdata.len() {
        let header = rdata.get(cursor..cursor.saturating_add(4)).ok_or_else(|| {
            DnsWireError::InvalidEdns {
                message: format!("option header is truncated at RDATA byte {cursor}"),
            }
        })?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        cursor += 4;
        let data = rdata
            .get(cursor..cursor.saturating_add(length))
            .ok_or_else(|| DnsWireError::InvalidEdns {
                message: format!("option {code} data is truncated"),
            })?;
        options.push(DnsEdnsOption {
            code,
            data: Bytes::copy_from_slice(data),
        });
        cursor += length;
    }
    Ok(DnsEdns {
        udp_payload_size: class,
        extended_response_code,
        version,
        dnssec_ok: flags & 0x8000 != 0,
        flags,
        options,
    })
}

struct RelevantRecords {
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
    rejected_records: Vec<DnsRejectedRecord>,
    rejected_record_count: usize,
}

#[cfg(test)]
thread_local! {
    static FILTER_WORK: std::cell::Cell<(usize, usize)> = const {
        std::cell::Cell::new((0, 0))
    };
}

#[cfg(test)]
pub(super) fn reset_filter_work() {
    FILTER_WORK.set((0, 0));
}

#[cfg(test)]
pub(super) fn filter_work() -> (usize, usize) {
    FILTER_WORK.get()
}

#[cfg(test)]
fn count_indexed_answer() {
    FILTER_WORK.with(|work| {
        let (indexed, inspected) = work.get();
        work.set((indexed + 1, inspected));
    });
}

#[cfg(test)]
fn count_reachable_inspection() {
    FILTER_WORK.with(|work| {
        let (indexed, inspected) = work.get();
        work.set((indexed, inspected + 1));
    });
}

/// Hashable DNS equality key. Label lengths make boundaries unambiguous;
/// ASCII letters are folded while all other wire octets remain unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct NameKey(Vec<u8>);

impl NameKey {
    fn from_name(name: &DnsName) -> Self {
        Self::from_labels(&name.labels)
    }

    fn from_labels(labels: &[Bytes]) -> Self {
        let mut key = Vec::with_capacity(labels.iter().fold(0usize, |length, label| {
            length.saturating_add(label.len() + 1)
        }));
        for label in labels {
            key.push(label.len() as u8);
            key.extend(label.iter().map(u8::to_ascii_lowercase));
        }
        Self(key)
    }
}

fn filter_relevant_records(
    query_name: &DnsName,
    query_type: DnsQueryType,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
    rejected_limit: usize,
) -> Result<RelevantRecords, DnsWireError> {
    let mut answer_owners: HashMap<NameKey, Vec<usize>> = HashMap::new();
    for (index, record) in answers.iter().enumerate() {
        #[cfg(test)]
        count_indexed_answer();
        answer_owners
            .entry(NameKey::from_name(&record.owner))
            .or_default()
            .push(index);
    }

    let query_key = NameKey::from_name(query_name);
    let mut relevant_names = HashSet::from([query_key.clone()]);
    let mut pending_names = VecDeque::from([query_key]);
    let mut accepted_answers = vec![false; answers.len()];
    while let Some(owner) = pending_names.pop_front() {
        let Some(indices) = answer_owners.get(&owner) else {
            continue;
        };
        for &index in indices {
            #[cfg(test)]
            count_reachable_inspection();
            let record = &answers[index];
            if record.class != DNS_CLASS_IN {
                continue;
            }
            let type_code = record.value.type_code();
            if type_code == DnsQueryType::Cname.code() {
                accepted_answers[index] = true;
                if let DnsRecordValue::Cname(ref target) = record.value {
                    let target = NameKey::from_name(target);
                    if relevant_names.insert(target.clone()) {
                        if relevant_names.len() > MAX_DNS_RELEVANT_NAMES {
                            return Err(DnsWireError::RelevantNameLimit {
                                actual: relevant_names.len(),
                                limit: MAX_DNS_RELEVANT_NAMES,
                            });
                        }
                        pending_names.push_back(target);
                    }
                }
            } else if query_type == DnsQueryType::Any || type_code == query_type.code() {
                accepted_answers[index] = true;
            }
        }
    }

    let mut relevant_ancestors = HashSet::new();
    relevant_ancestors.insert(NameKey(Vec::new()));
    for name in &relevant_names {
        // Each key is length-prefixed, so every label boundary is found
        // without reconstructing or comparing allocated DnsName values.
        let mut offset = 0usize;
        while offset < name.0.len() {
            relevant_ancestors.insert(NameKey(name.0[offset..].to_vec()));
            offset += 1 + usize::from(name.0[offset]);
        }
    }

    let mut references = HashSet::new();
    let mut accepted_authorities = vec![false; authorities.len()];
    for (index, record) in authorities.iter().enumerate() {
        if record.class == DNS_CLASS_IN
            && relevant_ancestors.contains(&NameKey::from_name(&record.owner))
            && matches!(
                record.value,
                DnsRecordValue::Ns(_) | DnsRecordValue::Soa { .. }
            )
        {
            accepted_authorities[index] = true;
        }
    }
    for (index, record) in answers.iter().enumerate() {
        if accepted_answers[index]
            && let Some(name) = record.value.referenced_name()
        {
            references.insert(NameKey::from_name(name));
        }
    }
    for (index, record) in authorities.iter().enumerate() {
        if accepted_authorities[index]
            && let Some(name) = record.value.referenced_name()
        {
            references.insert(NameKey::from_name(name));
        }
    }
    let accepted_additionals = additionals
        .iter()
        .map(|record| {
            record.class == DNS_CLASS_IN
                && references.contains(&NameKey::from_name(&record.owner))
                && matches!(record.value, DnsRecordValue::A(_) | DnsRecordValue::Aaaa(_))
        })
        .collect::<Vec<_>>();

    let mut rejected_records = Vec::new();
    let mut rejected_record_count = 0usize;
    let mut reject = |section: DnsSection, index: usize, record: &DnsRecord, reason: &str| {
        rejected_record_count += 1;
        if rejected_records.len() < rejected_limit {
            rejected_records.push(DnsRejectedRecord {
                section,
                index,
                owner: record.owner.to_string(),
                type_code: record.value.type_code(),
                reason: reason.to_owned(),
            });
        }
    };
    for (index, record) in answers.iter().enumerate() {
        if !accepted_answers[index] {
            reject(
                DnsSection::Answer,
                index,
                record,
                rejection_reason(
                    record,
                    "record owner/type is unrelated to the validated question or CNAME chain",
                ),
            );
        }
    }
    for (index, record) in authorities.iter().enumerate() {
        if !accepted_authorities[index] {
            reject(
                DnsSection::Authority,
                index,
                record,
                rejection_reason(
                    record,
                    "authority is not an IN-class SOA/NS ancestor of the validated question",
                ),
            );
        }
    }
    for (index, record) in additionals.iter().enumerate() {
        if !accepted_additionals[index] {
            reject(
                DnsSection::Additional,
                index,
                record,
                rejection_reason(
                    record,
                    "additional record is not IN-class address glue referenced by accepted data",
                ),
            );
        }
    }

    Ok(RelevantRecords {
        answers: answers
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_answers[index].then_some(record))
            .collect(),
        authorities: authorities
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_authorities[index].then_some(record))
            .collect(),
        additionals: additionals
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_additionals[index].then_some(record))
            .collect(),
        rejected_records,
        rejected_record_count,
    })
}

fn rejection_reason<'a>(record: &DnsRecord, default: &'a str) -> &'a str {
    if record.class != DNS_CLASS_IN {
        "record class is not IN"
    } else if record.value.type_code() == DNS_TYPE_OPT {
        "EDNS OPT metadata is not accepted as question data"
    } else {
        default
    }
}

pub const fn response_code_name(code: u16) -> &'static str {
    match code {
        0 => "no_error",
        1 => "format_error",
        2 => "server_failure",
        3 => "name_error",
        4 => "not_implemented",
        5 => "refused",
        6 => "yx_domain",
        7 => "yx_rrset",
        8 => "nx_rrset",
        9 => "not_authoritative",
        10 => "not_zone",
        16 => "bad_version",
        17 => "bad_key",
        18 => "bad_time",
        19 => "bad_mode",
        20 => "bad_name",
        21 => "bad_algorithm",
        22 => "bad_truncation",
        23 => "bad_cookie",
        _ => "unknown",
    }
}

/// Pure, protocol-aware classification of one decoded frame against an exact
/// DNS probe. `None` means the frame has no structural relationship to the
/// request. A reverse-tuple frame with invalid integrity remains typed decode
/// failure evidence, but can never become an accepted DNS response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsResponseClassification {
    Response(ValidatedDnsResponse),
    Unrelated { reason: String },
    DecodeFailure { reason: String },
    NetworkFailure { reason: String },
}

impl DnsResponseClassification {
    pub(super) fn rank(&self) -> u8 {
        match self {
            Self::Response(_) => 4,
            Self::NetworkFailure { .. } => 3,
            Self::DecodeFailure { .. } => 2,
            Self::Unrelated { .. } => 1,
        }
    }
}

pub fn classify_dns_response(
    registry: &ProtocolRegistry,
    probe: &DnsProbe,
    sent: &Packet,
    response: &DecodedPacket,
    limits: DnsLimits,
) -> Option<DnsResponseClassification> {
    if direct_udp_match(registry, sent, &response.packet) {
        if response.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum") && diagnostic.severity != DiagnosticSeverity::Info
        }) {
            return Some(DnsResponseClassification::DecodeFailure {
                reason: "correlated UDP response has an invalid checksum diagnostic".to_owned(),
            });
        }
        let Some(payload) = raw_payload(&response.packet) else {
            return Some(DnsResponseClassification::DecodeFailure {
                reason: "correlated UDP response has no complete DNS payload".to_owned(),
            });
        };
        return Some(
            match decode_dns_response(
                &payload,
                &probe.query_name,
                probe.query_type,
                probe.transaction_id,
                limits,
            ) {
                Ok(validated) => DnsResponseClassification::Response(validated),
                Err(error) if error.is_unrelated() => DnsResponseClassification::Unrelated {
                    reason: error.to_string(),
                },
                Err(error) => DnsResponseClassification::DecodeFailure {
                    reason: error.to_string(),
                },
            },
        );
    }

    probe::observe(registry, ProbeTransport::Udp, sent, response).and_then(|observation| {
        observation.correlation.is_network_failure().then(|| {
            DnsResponseClassification::NetworkFailure {
                reason: observation.reason.to_owned(),
            }
        })
    })
}

fn direct_udp_match(registry: &ProtocolRegistry, request: &Packet, response: &Packet) -> bool {
    let Some(udp) = request
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "udp")
    else {
        return false;
    };
    registry
        .matcher(&udp.protocol_id())
        .is_some_and(|matcher| matcher.matches(request, response).matched)
}

pub(super) fn raw_payload(packet: &Packet) -> Option<Bytes> {
    match packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "raw")?
        .field("bytes")?
    {
        FieldValue::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}
use std::collections::{HashMap, HashSet, VecDeque};

use super::{
    Bytes, DNS_CLASS_IN, DNS_FLAG_AUTHENTICATED_DATA, DNS_FLAG_AUTHORITATIVE,
    DNS_FLAG_CHECKING_DISABLED, DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED,
    DNS_FLAG_RESPONSE, DNS_FLAG_TRUNCATED, DNS_HEADER_BYTES, DNS_OPCODE_MASK, DNS_RCODE_MASK,
    DNS_RESERVED_MASK, DNS_TYPE_OPT, DecodedPacket, DiagnosticSeverity, DnsEdns, DnsEdnsOption,
    DnsLimits, DnsName, DnsProbe, DnsQueryType, DnsRecord, DnsRecordValue, DnsRejectedRecord,
    DnsSection, DnsWireError, FieldValue, Ipv4Addr, Ipv6Addr, MAX_DNS_RELEVANT_NAMES, Packet,
    ProbeTransport, ProtocolRegistry, ValidatedDnsResponse, probe,
};
