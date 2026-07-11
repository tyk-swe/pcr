fn prepare(
    request: &FuzzRequest,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
) -> Result<PreparedFuzz, FuzzError> {
    request.validate()?;
    let started = Instant::now();
    validate_base_shape(&packet, request.build.max_layers)?;
    packet_reflected_value_bytes(&packet, request.limits)?;
    let fields = resolve_fields(&packet, &request.targets)?;
    let pairs = request
        .strategies
        .iter()
        .copied()
        .flat_map(|strategy| {
            fields
                .iter()
                .enumerate()
                .filter(move |(_, field)| strategy_compatible(strategy, field))
                .map(move |(field_index, _)| (strategy, field_index))
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return Err(FuzzError::NoCompatibleTargets);
    }

    let builder = Builder::new(Arc::clone(&registry));
    let dissector = Dissector::new(registry);
    let mut cases = Vec::with_capacity(request.cases);
    let mut built_cases = 0_u64;
    let mut built_bytes = 0_u64;
    let mut retained_bytes = 0_u64;
    for offset in 0..request.cases {
        enforce_preparation_deadline(started, request.limits.max_duration)?;
        let index = request
            .first_case
            .checked_add(offset as u64)
            .ok_or(FuzzError::CaseIndexOverflow)?;
        let seed = case_seed(request.seed, index);
        let pair_index = (index % pairs.len() as u64) as usize;
        let round = index / pairs.len() as u64;
        let (strategy, field_index) = pairs[pair_index];
        let field = &fields[field_index];
        let mut recipe = packet.clone();
        let layer = recipe
            .layer(field.target.layer)
            .expect("resolved layer must remain present");
        let original = layer
            .field(&field.target.field)
            .expect("resolved field must remain readable");
        let value = mutation_value(strategy, field, &original, seed, round, request.limits);
        let mutation = FuzzMutation {
            layer: field.target.layer,
            protocol: field.protocol.clone(),
            field: field.target.field.clone(),
            strategy,
            original: original.clone(),
            value: value.clone(),
        };
        let reproduction = FuzzReproduction {
            operation_seed: request.seed,
            case_index: index,
            case_seed: seed,
        };
        let shrink_values = shrink_values(&value, request.limits.max_shrink_steps);
        let set_result = recipe
            .layer_mut(field.target.layer)
            .expect("resolved mutable layer must remain present")
            .set_field(&field.target.field, value);
        let case_value_bytes =
            retained_case_value_bytes(&mutation, &shrink_values, &recipe, request.limits)?;
        charge_retained_bytes(
            &mut retained_bytes,
            case_value_bytes,
            request.limits.max_total_bytes as u64,
        )?;
        let mut case = FuzzCase {
            index,
            seed,
            mutation,
            reproduction,
            shrink_values,
            recipe,
            built: None,
            decoded: None,
            outcome: FuzzCaseOutcome::Rejected,
            error: None,
            sent: None,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        };
        if let Err(source) = set_result {
            case.error = Some(FuzzCaseFailure::new(
                format!("mutation was rejected: {source}"),
                Classification::new(
                    "packet.fuzz_mutation",
                    Kind::Packet,
                    Some("select a type/range accepted by the target field or retain the rejected case as fuzz evidence"),
                ),
                Vec::new(),
            ));
            cases.push(case);
            continue;
        }

        match builder.build(
            case.recipe.clone(),
            BuildContext::default(),
            request.build.clone(),
        ) {
            Ok(built) => {
                let next_bytes = built_bytes.checked_add(built.bytes.len() as u64).ok_or(
                    FuzzError::ByteLimit {
                        actual: u64::MAX,
                        limit: request.limits.max_total_bytes as u64,
                    },
                )?;
                if next_bytes > request.limits.max_total_bytes as u64 {
                    return Err(FuzzError::ByteLimit {
                        actual: next_bytes,
                        limit: request.limits.max_total_bytes as u64,
                    });
                }
                charge_retained_bytes(
                    &mut retained_bytes,
                    built.bytes.len() as u64,
                    request.limits.max_total_bytes as u64,
                )?;
                case.diagnostics.extend(built.diagnostics.clone());
                case.decoded =
                    dissect_built(&dissector, &built, request.limits, &mut case.diagnostics);
                if let Some(decoded) = &case.decoded {
                    let decoded_bytes =
                        packet_reflected_value_bytes(&decoded.packet, request.limits)?;
                    charge_retained_bytes(
                        &mut retained_bytes,
                        decoded_bytes,
                        request.limits.max_total_bytes as u64,
                    )?;
                }
                case.built = Some(built);
                case.outcome = FuzzCaseOutcome::Built;
                built_cases += 1;
                built_bytes = next_bytes;
            }
            Err(source) => {
                case.error = Some(FuzzCaseFailure::new(
                    format!("mutated packet was rejected: {source}"),
                    Classification::new(
                        "packet.fuzz_build",
                        Kind::Packet,
                        Some("reproduce the case in permissive offline mode when malformed dependent fields are intentional"),
                    ),
                    Vec::new(),
                ));
            }
        }
        cases.push(case);
    }
    enforce_preparation_deadline(started, request.limits.max_duration)?;
    Ok(PreparedFuzz {
        cases,
        built_cases,
        built_bytes,
        preparation_elapsed: started.elapsed(),
    })
}

fn enforce_preparation_deadline(started: Instant, limit: Duration) -> Result<(), FuzzError> {
    let elapsed = started.elapsed();
    if elapsed > limit {
        return Err(FuzzError::DurationLimit {
            actual: elapsed,
            limit,
        });
    }
    Ok(())
}

fn enforce_operation_deadline(
    started: Instant,
    accounted_elapsed: Duration,
    limit: Duration,
) -> Result<(), FuzzError> {
    let actual = started.elapsed().max(accounted_elapsed);
    if actual > limit {
        return Err(FuzzError::DurationLimit { actual, limit });
    }
    Ok(())
}

fn validate_base_shape(packet: &Packet, max_layers: usize) -> Result<(), FuzzError> {
    if packet.len() > max_layers {
        return Err(FuzzError::InvalidBasePacket {
            message: format!(
                "packet has {} layers, exceeding build.max_layers={max_layers}",
                packet.len()
            ),
        });
    }
    let mut fields = 0_usize;
    for layer in packet.iter() {
        fields = fields
            .checked_add(layer.schema().fields.len())
            .ok_or_else(|| FuzzError::InvalidBasePacket {
                message: "reflected field-count arithmetic overflowed".to_owned(),
            })?;
        if fields > MAX_FUZZ_TARGET_FIELDS {
            return Err(FuzzError::InvalidBasePacket {
                message: format!(
                    "packet schema exposes {fields} fields, exceeding hard limit {MAX_FUZZ_TARGET_FIELDS}"
                ),
            });
        }
    }
    Ok(())
}

fn retained_case_value_bytes(
    mutation: &FuzzMutation,
    shrink_values: &[FieldValue],
    recipe: &Packet,
    limits: FuzzLimits,
) -> Result<u64, FuzzError> {
    let mut total = (mutation.protocol.len() as u64)
        .checked_add(mutation.field.len() as u64)
        .ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })?;
    for value in std::iter::once(&mutation.original)
        .chain(std::iter::once(&mutation.value))
        .chain(shrink_values)
    {
        let remaining = limits.max_total_bytes.saturating_sub(total as usize);
        let size = bounded_value_size(value, remaining, limits.max_list_items, 0).ok_or(
            FuzzError::ByteLimit {
                actual: limits.max_total_bytes as u64 + 1,
                limit: limits.max_total_bytes as u64,
            },
        )?;
        total = total.checked_add(size as u64).ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })?;
    }
    total
        .checked_add(packet_reflected_value_bytes(recipe, limits)?)
        .ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })
}

fn packet_reflected_value_bytes(packet: &Packet, limits: FuzzLimits) -> Result<u64, FuzzError> {
    let mut total = 0_u64;
    for layer in packet.iter() {
        for field in layer.schema().fields {
            let Some(value) = layer.field(field.name) else {
                continue;
            };
            let remaining = limits.max_total_bytes.saturating_sub(total as usize);
            let size = bounded_value_size(&value, remaining, limits.max_list_items, 0).ok_or(
                FuzzError::ByteLimit {
                    actual: limits.max_total_bytes as u64 + 1,
                    limit: limits.max_total_bytes as u64,
                },
            )?;
            total = total.checked_add(size as u64).ok_or(FuzzError::ByteLimit {
                actual: u64::MAX,
                limit: limits.max_total_bytes as u64,
            })?;
        }
    }
    Ok(total)
}

fn charge_retained_bytes(total: &mut u64, value: u64, limit: u64) -> Result<(), FuzzError> {
    let next = total.checked_add(value).ok_or(FuzzError::ByteLimit {
        actual: u64::MAX,
        limit,
    })?;
    if next > limit {
        return Err(FuzzError::ByteLimit {
            actual: next,
            limit,
        });
    }
    *total = next;
    Ok(())
}

fn resolve_fields(
    packet: &Packet,
    requested: &[FuzzTarget],
) -> Result<Vec<ResolvedField>, FuzzError> {
    if requested.is_empty() {
        let mut fields = Vec::new();
        for (layer_index, layer) in packet.iter().enumerate() {
            for field in layer.schema().fields {
                if layer.field(field.name).is_none() {
                    continue;
                }
                if fields.len() >= MAX_FUZZ_TARGET_FIELDS {
                    return Err(FuzzError::InvalidBasePacket {
                        message: format!(
                            "packet exposes more than {MAX_FUZZ_TARGET_FIELDS} reflected fields"
                        ),
                    });
                }
                fields.push(ResolvedField {
                    target: FuzzTarget {
                        layer: layer_index,
                        field: field.name.to_owned(),
                    },
                    protocol: layer.protocol_id().to_string(),
                    kind: field.kind,
                    derived: field.derived,
                });
            }
        }
        if fields.is_empty() {
            return Err(FuzzError::NoCompatibleTargets);
        }
        return Ok(fields);
    }

    if requested.len() > MAX_FUZZ_TARGET_FIELDS {
        return Err(FuzzError::InvalidBasePacket {
            message: format!(
                "request selects {} fields, exceeding hard limit {MAX_FUZZ_TARGET_FIELDS}",
                requested.len()
            ),
        });
    }
    let mut fields = Vec::with_capacity(requested.len());
    for target in requested {
        if fields
            .iter()
            .any(|field: &ResolvedField| field.target == *target)
        {
            continue;
        }
        let layer = packet
            .layer(target.layer)
            .ok_or_else(|| FuzzError::InvalidTarget {
                target: target.clone(),
                message: format!("layer index is outside packet length {}", packet.len()),
            })?;
        let schema = layer
            .schema()
            .fields
            .iter()
            .find(|field| field.name == target.field)
            .ok_or_else(|| FuzzError::InvalidTarget {
                target: target.clone(),
                message: format!("layer {} has no such reflected field", layer.protocol_id()),
            })?;
        if layer.field(schema.name).is_none() {
            return Err(FuzzError::InvalidTarget {
                target: target.clone(),
                message: "field is not reflectively readable".to_owned(),
            });
        }
        fields.push(ResolvedField {
            target: target.clone(),
            protocol: layer.protocol_id().to_string(),
            kind: schema.kind,
            derived: schema.derived,
        });
    }
    Ok(fields)
}

fn strategy_compatible(strategy: FuzzStrategy, field: &ResolvedField) -> bool {
    match strategy {
        FuzzStrategy::Boundary | FuzzStrategy::Random => true,
        FuzzStrategy::BitFlip => field.kind == FieldKind::Bytes,
        FuzzStrategy::Malformed => field.derived,
    }
}

fn mutation_value(
    strategy: FuzzStrategy,
    field: &ResolvedField,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    let mut random = SplitMix64::new(seed ^ round.rotate_left(17));
    match strategy {
        FuzzStrategy::Boundary => boundary_value(field.kind, original, seed, round, limits),
        FuzzStrategy::Random => random_value(field.kind, original, &mut random, limits),
        FuzzStrategy::BitFlip => bit_flip_value(original, &mut random, limits.max_field_bytes),
        FuzzStrategy::Malformed => {
            malformed_value(field.kind, original, &mut random, round, limits)
        }
    }
}

fn boundary_value(
    kind: FieldKind,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    let selector = seed.wrapping_add(round);
    match kind {
        FieldKind::Bool => FieldValue::Bool(!original.as_bool().unwrap_or(false)),
        FieldKind::Unsigned => {
            const VALUES: &[u64] = &[
                0,
                1,
                u8::MAX as u64,
                u16::MAX as u64,
                u32::MAX as u64,
                u64::MAX,
            ];
            FieldValue::Unsigned(VALUES[(selector % VALUES.len() as u64) as usize])
        }
        FieldKind::Signed => {
            const VALUES: &[i64] = &[0, 1, -1, i8::MIN as i64, i8::MAX as i64, i64::MIN, i64::MAX];
            FieldValue::Signed(VALUES[(selector % VALUES.len() as u64) as usize])
        }
        FieldKind::Text => {
            let values = [
                String::new(),
                "A".to_owned(),
                "\u{1b}[31mcontrol\u{1b}[0m".to_owned(),
                "x".repeat(limits.max_field_bytes.min(256)),
            ];
            FieldValue::Text(values[(selector % values.len() as u64) as usize].clone())
        }
        FieldKind::Bytes => {
            let lengths = [0, 1, limits.max_field_bytes.min(64), limits.max_field_bytes];
            let length = lengths[(selector % lengths.len() as u64) as usize];
            FieldValue::Bytes(Bytes::from(vec![
                if selector & 1 == 0 { 0 } else { 0xff };
                length
            ]))
        }
        FieldKind::Ipv4 => {
            const VALUES: &[Ipv4Addr] = &[
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::BROADCAST,
                Ipv4Addr::new(192, 0, 2, 1),
            ];
            FieldValue::Ipv4(VALUES[(selector % VALUES.len() as u64) as usize])
        }
        FieldKind::Ipv6 => {
            let values = [
                Ipv6Addr::UNSPECIFIED,
                Ipv6Addr::LOCALHOST,
                "2001:db8::1".parse().expect("constant IPv6 address"),
                Ipv6Addr::from(u128::MAX),
            ];
            FieldValue::Ipv6(values[(selector % values.len() as u64) as usize])
        }
        FieldKind::Mac => {
            let values = [[0; 6], [0xff; 6], [0x02, 0, 0, 0, 0, 1]];
            FieldValue::Mac(values[(selector % values.len() as u64) as usize])
        }
        FieldKind::List => match original {
            FieldValue::List(values) if selector & 1 == 1 => {
                let candidate = FieldValue::List(values.first().cloned().into_iter().collect());
                if bounded_value_size(&candidate, limits.max_field_bytes, limits.max_list_items, 0)
                    .is_some()
                {
                    candidate
                } else {
                    FieldValue::List(Vec::new())
                }
            }
            _ => FieldValue::List(Vec::new()),
        },
    }
}

fn random_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    limits: FuzzLimits,
) -> FieldValue {
    match kind {
        FieldKind::Bool => FieldValue::Bool(random.next_u64() & 1 != 0),
        FieldKind::Unsigned => FieldValue::Unsigned(random.next_u64()),
        FieldKind::Signed => FieldValue::Signed(random.next_u64() as i64),
        FieldKind::Text => {
            let length = bounded_length(random, limits.max_field_bytes.min(256));
            let mut value = String::with_capacity(length);
            for _ in 0..length {
                let character = match random.next_u64() % 20 {
                    0 => '\u{1b}',
                    1 => '\n',
                    _ => char::from(b' ' + (random.next_u64() % 95) as u8),
                };
                value.push(character);
            }
            FieldValue::Text(value)
        }
        FieldKind::Bytes => {
            let length = bounded_length(random, limits.max_field_bytes);
            FieldValue::Bytes(Bytes::from(random.bytes(length)))
        }
        FieldKind::Ipv4 => FieldValue::Ipv4(Ipv4Addr::from(random.next_u64() as u32)),
        FieldKind::Ipv6 => {
            let value = (u128::from(random.next_u64()) << 64) | u128::from(random.next_u64());
            FieldValue::Ipv6(Ipv6Addr::from(value))
        }
        FieldKind::Mac => {
            let mut value = [0_u8; 6];
            value.copy_from_slice(&random.bytes(6));
            FieldValue::Mac(value)
        }
        FieldKind::List => match original {
            FieldValue::List(values) if !values.is_empty() => {
                let count = bounded_length(random, limits.max_list_items.min(values.len()));
                let mut output = Vec::with_capacity(count);
                let mut bytes = 0_usize;
                for _ in 0..count {
                    let value = &values[index_below(random, values.len())];
                    let remaining = limits
                        .max_field_bytes
                        .saturating_sub(bytes)
                        .saturating_sub(1);
                    let Some(value_bytes) =
                        bounded_value_size(value, remaining, limits.max_list_items, 0)
                    else {
                        break;
                    };
                    let Some(next_bytes) = bytes
                        .checked_add(1)
                        .and_then(|total| total.checked_add(value_bytes))
                    else {
                        break;
                    };
                    if next_bytes > limits.max_field_bytes {
                        break;
                    }
                    output.push(value.clone());
                    bytes = next_bytes;
                }
                FieldValue::List(output)
            }
            _ => FieldValue::List(Vec::new()),
        },
    }
}

fn bounded_value_size(
    value: &FieldValue,
    remaining: usize,
    max_list_items: usize,
    depth: usize,
) -> Option<usize> {
    if depth > 64 {
        return None;
    }
    let size = match value {
        FieldValue::Bool(_) => 1,
        FieldValue::Unsigned(_) | FieldValue::Signed(_) => 8,
        FieldValue::Text(value) => value.len(),
        FieldValue::Bytes(value) => value.len(),
        FieldValue::Ipv4(_) => 4,
        FieldValue::Ipv6(_) => 16,
        FieldValue::Mac(_) => 6,
        FieldValue::List(values) => {
            if values.len() > max_list_items {
                return None;
            }
            // Charge every list node even when it contains an otherwise
            // zero-byte nested list. This bounds structural cloning as well
            // as scalar and byte payload retention.
            let mut total = values.len();
            if total > remaining {
                return None;
            }
            for value in values {
                let value_size = bounded_value_size(
                    value,
                    remaining.saturating_sub(total),
                    max_list_items,
                    depth + 1,
                )?;
                total = total.checked_add(value_size)?;
                if total > remaining {
                    return None;
                }
            }
            total
        }
    };
    (size <= remaining).then_some(size)
}

fn bit_flip_value(original: &FieldValue, random: &mut SplitMix64, maximum: usize) -> FieldValue {
    let FieldValue::Bytes(bytes) = original else {
        return original.clone();
    };
    if bytes.is_empty() {
        return FieldValue::Bytes(Bytes::from_static(&[1]));
    }
    if bytes.len() > maximum {
        // Replacing an oversized value with a bounded prefix keeps allocation
        // within the mutation budget and makes the reduction explicit.
        let mut value = bytes[..maximum].to_vec();
        let index = index_below(random, value.len());
        value[index] ^= 1 << (random.next_u64() % 8);
        return FieldValue::Bytes(Bytes::from(value));
    }
    let mut value = bytes.to_vec();
    let index = index_below(random, value.len());
    value[index] ^= 1 << (random.next_u64() % 8);
    FieldValue::Bytes(Bytes::from(value))
}

fn malformed_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    if kind == FieldKind::Unsigned {
        if round & 1 == 0 {
            return FieldValue::Unsigned(random.next_u64() & u16::MAX as u64);
        }
        let length = 1 + index_below(random, limits.max_field_bytes.min(4));
        return FieldValue::Bytes(Bytes::from(random.bytes(length)));
    }
    random_value(kind, original, random, limits)
}

fn bounded_length(random: &mut SplitMix64, maximum: usize) -> usize {
    if maximum == 0 {
        0
    } else {
        index_below(random, maximum + 1)
    }
}

fn index_below(random: &mut SplitMix64, exclusive_maximum: usize) -> usize {
    debug_assert!(exclusive_maximum != 0);
    (random.next_u64() % exclusive_maximum as u64) as usize
}

fn shrink_values(value: &FieldValue, maximum: usize) -> Vec<FieldValue> {
    let mut values = Vec::new();
    let mut push = |candidate: FieldValue| {
        if values.len() < maximum && &candidate != value && !values.contains(&candidate) {
            values.push(candidate);
        }
    };
    match value {
        FieldValue::Bool(_) => push(FieldValue::Bool(false)),
        FieldValue::Unsigned(value) => {
            push(FieldValue::Unsigned(0));
            if *value > 1 {
                push(FieldValue::Unsigned(1));
                push(FieldValue::Unsigned(*value / 2));
            }
        }
        FieldValue::Signed(value) => {
            push(FieldValue::Signed(0));
            if value.unsigned_abs() > 1 {
                push(FieldValue::Signed(value.signum()));
                push(FieldValue::Signed(*value / 2));
            }
        }
        FieldValue::Text(value) => {
            push(FieldValue::Text(String::new()));
            if value.len() > 1 {
                push(FieldValue::Text(
                    value.chars().take(value.chars().count() / 2).collect(),
                ));
            }
        }
        FieldValue::Bytes(value) => {
            push(FieldValue::Bytes(Bytes::new()));
            if value.len() > 1 {
                push(FieldValue::Bytes(value.slice(..value.len() / 2)));
            }
            if !value.is_empty() {
                push(FieldValue::Bytes(Bytes::from(vec![0; value.len()])))
            }
        }
        FieldValue::Ipv4(_) => push(FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED)),
        FieldValue::Ipv6(_) => push(FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED)),
        FieldValue::Mac(_) => push(FieldValue::Mac([0; 6])),
        FieldValue::List(value) => {
            push(FieldValue::List(Vec::new()));
            if value.len() > 1 {
                push(FieldValue::List(value[..value.len() / 2].to_vec()));
            }
        }
    }
    values
}

fn dissect_built(
    dissector: &Dissector,
    built: &BuiltPacket,
    limits: FuzzLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<DecodedPacket> {
    let Some(link_type) = packet_link_type(&built.packet) else {
        diagnostics.push(Diagnostic::info(
            "fuzz.decode_unavailable",
            "built root has no registered capture-link representation; exact bytes are retained",
        ));
        return None;
    };
    let frame = match Frame::new(std::time::UNIX_EPOCH, link_type, built.bytes.clone()) {
        Ok(frame) => frame,
        Err(source) => {
            diagnostics.push(Diagnostic::warning(
                "fuzz.decode_frame",
                format!("could not form bounded decode evidence: {source}"),
            ));
            return None;
        }
    };
    match dissector.decode(
        frame,
        DecodeOptions {
            max_packet_size: limits.max_packet_bytes,
            ..DecodeOptions::default()
        },
    ) {
        Ok(decoded) => {
            diagnostics.extend(decoded.diagnostics.clone());
            Some(decoded)
        }
        Err(source) => {
            diagnostics.push(Diagnostic::warning(
                "fuzz.decode_rejected",
                format!("bounded dissection rejected the built case: {source}"),
            ));
            None
        }
    }
}

fn packet_link_type(packet: &Packet) -> Option<LinkType> {
    let protocol = packet.layer(0)?.protocol_id();
    Some(match protocol.as_str() {
        "ethernet" => LinkType::ETHERNET,
        "bsd_null" => LinkType::NULL,
        "bsd_loop" => LinkType::LOOP,
        "linux_sll" => LinkType::LINUX_SLL,
        "linux_sll2" => LinkType::LINUX_SLL2,
        "ipv4" => LinkType::IPV4,
        "ipv6" => LinkType::IPV6,
        "raw_ip" => LinkType::RAW,
        _ => return None,
    })
}

fn has_link_root(packet: &Packet) -> bool {
    packet.layer(0).is_some_and(|layer| {
        matches!(
            layer.protocol_id().as_str(),
            "ethernet" | "bsd_null" | "bsd_loop" | "linux_sll" | "linux_sll2"
        )
    })
}
