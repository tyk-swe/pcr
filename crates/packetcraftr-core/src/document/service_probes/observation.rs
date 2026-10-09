// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::{
    Field, MAX_FIELD_BYTES, MAX_RESPONSE_BYTES, Observation, ObservationOutcome, ObservedField,
    Probe, Protocol, Request,
};
use crate::{
    document::udp_profiles::Payload,
    protocol::application::{
        dns::{Dns, RecordValue},
        http,
    },
};

/// Parses bounded evidence only; the caller retains the response bytes and
/// transport context. A partial read never silently becomes a complete reply.
pub fn observe(probe: &Probe, bytes: &[u8], truncated: bool) -> Observation {
    let exceeded = bytes.len() > MAX_RESPONSE_BYTES;
    let bytes = &bytes[..bytes.len().min(MAX_RESPONSE_BYTES)];
    let mut observation = match &probe.request {
        Request::Banner {} => ssh(bytes),
        Request::HttpHead {} => http(bytes),
        Request::Dns { payload } => dns(bytes, payload),
    };
    if truncated || exceeded {
        observation.outcome = ObservationOutcome::Truncated;
        observation.diagnostic =
            Some("response collection reached its byte or time boundary".into());
    }
    observation
}

fn base(protocol: Option<Protocol>, outcome: ObservationOutcome) -> Observation {
    Observation {
        protocol,
        outcome,
        fields: Vec::new(),
        diagnostic: None,
    }
}

fn failure(
    protocol: Protocol,
    outcome: ObservationOutcome,
    message: impl Into<String>,
) -> Observation {
    let mut observation = base(Some(protocol), outcome);
    observation.diagnostic = Some(message.into());
    observation
}

fn field(observation: &mut Observation, name: Field, value: &[u8]) {
    if value.len() <= MAX_FIELD_BYTES {
        observation.fields.push(ObservedField {
            field: name,
            value: value.to_vec(),
        });
    } else {
        observation.outcome = ObservationOutcome::Truncated;
        observation.diagnostic = Some("observed field exceeds the bounded field limit".into());
    }
}

fn ssh(bytes: &[u8]) -> Observation {
    // RFC 4253 §4.2 permits pre-identification lines. Bound their processing
    // independently and preserve the complete identification line as a claim.
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if index >= 16 {
            return failure(
                Protocol::Ssh,
                ObservationOutcome::Malformed,
                "SSH preamble exceeds 16 lines",
            );
        }
        if !line.starts_with(b"SSH-") {
            if line.len() > MAX_FIELD_BYTES {
                return failure(
                    Protocol::Ssh,
                    ObservationOutcome::Malformed,
                    "SSH preamble line exceeds its limit",
                );
            }
            continue;
        }
        if !line.ends_with(b"\n") {
            return failure(
                Protocol::Ssh,
                ObservationOutcome::Truncated,
                "SSH identification line is incomplete",
            );
        }
        if line.len() > 255 || !line.ends_with(b"\r\n") {
            return failure(
                Protocol::Ssh,
                ObservationOutcome::Malformed,
                "SSH identification requires a bounded CRLF line",
            );
        }
        let banner = &line[..line.len() - 2];
        if !banner.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
            return failure(
                Protocol::Ssh,
                ObservationOutcome::Malformed,
                "SSH identification contains nonprintable bytes",
            );
        }
        let software = banner
            .strip_prefix(b"SSH-2.0-")
            .or_else(|| banner.strip_prefix(b"SSH-1.99-"));
        let Some(software) = software else {
            return failure(
                Protocol::Ssh,
                ObservationOutcome::Malformed,
                "unsupported or malformed SSH protocol claim",
            );
        };
        let software = software
            .split(|byte| *byte == b' ')
            .next()
            .unwrap_or_default();
        if software.is_empty() || software.contains(&b'-') {
            return failure(
                Protocol::Ssh,
                ObservationOutcome::Malformed,
                "SSH software token is invalid",
            );
        }
        let mut observation = base(Some(Protocol::Ssh), ObservationOutcome::Complete);
        field(&mut observation, Field::SshBanner, banner);
        field(&mut observation, Field::SshSoftware, software);
        return observation;
    }
    base(None, ObservationOutcome::Unknown)
}

fn http(bytes: &[u8]) -> Observation {
    if !bytes.starts_with(b"HTTP/") {
        return base(None, ObservationOutcome::Unknown);
    }
    match http::parse_head(&Bytes::copy_from_slice(bytes)) {
        Ok(Some((head, _))) => {
            let Some(status) = head.status() else {
                return failure(
                    Protocol::Http,
                    ObservationOutcome::Malformed,
                    "HTTP response has a request start line",
                );
            };
            let mut observation = base(Some(Protocol::Http), ObservationOutcome::Complete);
            field(
                &mut observation,
                Field::HttpStatus,
                status.to_string().as_bytes(),
            );
            for value in head.values("server") {
                field(&mut observation, Field::HttpServer, value);
            }
            observation
        }
        Ok(None) => failure(
            Protocol::Http,
            ObservationOutcome::Truncated,
            "HTTP response head is incomplete",
        ),
        Err(error) => failure(
            Protocol::Http,
            ObservationOutcome::Malformed,
            error.to_string(),
        ),
    }
}

fn dns(bytes: &[u8], payload: &Payload) -> Observation {
    let decoded = match Dns::try_from(bytes) {
        Ok(decoded) => decoded,
        Err(error) => {
            let outcome = if error.truncation_needed().is_some() {
                ObservationOutcome::Truncated
            } else {
                ObservationOutcome::Malformed
            };
            return failure(Protocol::Dns, outcome, error.to_string());
        }
    };
    let Payload::Dns {
        name,
        query_type,
        class,
        ..
    } = payload
    else {
        return failure(
            Protocol::Dns,
            ObservationOutcome::Malformed,
            "probe has no DNS question",
        );
    };
    let expected_name = name.parse().ok();
    if !decoded.response
        || decoded.opcode != 0
        || decoded.questions.len() != 1
        || !decoded.questions.iter().all(|question| {
            Some(&question.name) == expected_name.as_ref()
                && question.query_type == *query_type
                && question.class == *class
        })
    {
        return failure(
            Protocol::Dns,
            ObservationOutcome::Malformed,
            "DNS reply does not echo the read-only question",
        );
    }
    let outcome = if decoded.truncated {
        ObservationOutcome::Truncated
    } else {
        ObservationOutcome::Complete
    };
    let mut observation = base(Some(Protocol::Dns), outcome);
    if decoded.truncated {
        observation.diagnostic = Some("DNS response has its truncation flag set".into());
    }
    field(
        &mut observation,
        Field::DnsRcode,
        decoded.rcode.to_string().as_bytes(),
    );
    for record in &decoded.answers {
        // TXT claims belong only to the question's name and class; unrelated
        // additional records are not product evidence.
        if Some(&record.owner) == expected_name.as_ref()
            && record.class == *class
            && let RecordValue::Txt(strings) = &record.value
        {
            for value in strings {
                field(&mut observation, Field::DnsTxt, value);
            }
        }
    }
    observation
}
