// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Bounded recipe, file, and standard-input handling.

fn read_recipe(
    arguments: RecipeArgs,
    registry: &crate::packet::internal::ProtocolRegistry,
) -> Result<Packet, CliError> {
    let stdin = read_nonterminal_stdin_bounded(DEFAULT_MAX_DOCUMENT_BYTES)?;
    let RecipeArgs {
        packet,
        packet_file,
    } = arguments;
    let source_count = usize::from(packet.is_some())
        + usize::from(packet_file.is_some())
        + usize::from(stdin.is_some());
    if source_count != 1 {
        return Err(CliError::new(
            2,
            "exactly one of --packet, --packet-file, or non-empty stdin is required",
        ));
    }

    let (input, path) = match (packet, packet_file, stdin) {
        (Some(expression), None, None) => return parse_expression(&expression, registry),
        (None, Some(path), None) => {
            let bytes = read_bounded_file(&path, DEFAULT_MAX_DOCUMENT_BYTES)?;
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("packet document is not UTF-8: {source}"))
            })?;
            (input, Some(path))
        }
        (None, None, Some(bytes)) => {
            let input = String::from_utf8(bytes).map_err(|source| {
                CliError::new(2, format!("stdin recipe is not UTF-8: {source}"))
            })?;
            (input, None)
        }
        _ => unreachable!("source count was validated"),
    };
    let trimmed = input.trim_start();
    let format = path
        .as_deref()
        .and_then(document_format_from_path)
        .or_else(|| trimmed.starts_with('{').then_some(DocumentFormat::Json))
        .or_else(|| {
            (trimmed.starts_with("schema:") || trimmed.starts_with("---"))
                .then_some(DocumentFormat::Yaml)
        });
    if let Some(format) = format {
        return PacketDocument::parse_with_resource_limits(
            &input,
            format,
            DEFAULT_MAX_DOCUMENT_BYTES,
            DEFAULT_MAX_LAYERS,
            DEFAULT_MAX_DOCUMENT_NESTING,
        )
        .and_then(|document| document.to_packet(registry, DEFAULT_MAX_LAYERS))
        .map_err(|source| CliError::new(2, source.to_string()));
    }
    parse_expression(&input, registry)
}

fn parse_expression(
    input: &str,
    registry: &crate::packet::internal::ProtocolRegistry,
) -> Result<Packet, CliError> {
    parse_packet_expression(input, registry, ExpressionOptions::default())
        .map_err(|source| CliError::new(2, source.to_string()))
}

fn document_format_from_path(path: &Path) -> Option<DocumentFormat> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "json" => Some(DocumentFormat::Json),
        "yaml" | "yml" => Some(DocumentFormat::Yaml),
        _ => None,
    }
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    let file = File::open(path)
        .map_err(|source| CliError::new(2, format!("open {} failed: {source}", path.display())))?;
    read_bounded(file, maximum)
}

fn read_stdin_bounded(maximum: usize) -> Result<Vec<u8>, CliError> {
    read_bounded(io::stdin().lock(), maximum)
}

fn read_nonterminal_stdin_bounded(maximum: usize) -> Result<Option<Vec<u8>>, CliError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(None);
    }
    let bytes = read_bounded_allow_empty(stdin.lock(), maximum)?;
    Ok((!bytes.is_empty()).then_some(bytes))
}

fn read_bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>, CliError> {
    let bytes = read_bounded_allow_empty(reader, maximum)?;
    if bytes.is_empty() {
        return Err(CliError::new(
            2,
            "one of --packet, --packet-file, or non-empty stdin is required",
        ));
    }
    Ok(bytes)
}

fn read_bounded_allow_empty(reader: impl Read, maximum: usize) -> Result<Vec<u8>, CliError> {
    let read_limit = maximum
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| CliError::new(70, "packet input byte limit cannot be represented"))?;
    let mut bytes = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::new(2, format!("read packet input failed: {source}")))?;
    if bytes.len() > maximum {
        return Err(CliError::new(
            2,
            format!("packet input exceeds {maximum} byte limit"),
        ));
    }
    Ok(bytes)
}
