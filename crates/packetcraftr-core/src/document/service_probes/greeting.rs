// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded connection greetings. Reading these replies sends no application
//! commands, credentials, mail, file transfers, or protocol upgrades.

use super::{
    Field, MAX_FIELD_BYTES, MAX_GREETING_LINES, MAX_RESPONSE_BYTES, Observation,
    ObservationOutcome, ObservedField, Protocol,
};

/// Stops on a complete SMTP greeting or a definitive parser/resource boundary.
pub fn smtp_collection_complete(bytes: &[u8]) -> bool {
    collection_complete(bytes, Protocol::Smtp)
}

/// Stops on a complete FTP greeting or a definitive parser/resource boundary.
pub fn ftp_collection_complete(bytes: &[u8]) -> bool {
    collection_complete(bytes, Protocol::Ftp)
}

fn collection_complete(bytes: &[u8], protocol: Protocol) -> bool {
    bytes.len() > MAX_RESPONSE_BYTES
        || progress(&bytes[..bytes.len().min(MAX_RESPONSE_BYTES)], protocol).1
}

pub(super) fn observe(bytes: &[u8], protocol: Protocol) -> Observation {
    progress(bytes, protocol).0
}

fn initial() -> Observation {
    Observation {
        protocol: None,
        outcome: ObservationOutcome::Unknown,
        fields: Vec::new(),
        diagnostic: None,
    }
}

fn stop(
    mut observation: Observation,
    outcome: ObservationOutcome,
    diagnostic: &'static str,
    complete: bool,
) -> (Observation, bool) {
    observation.outcome = outcome;
    observation.diagnostic = Some(diagnostic.into());
    (observation, complete)
}

fn progress(bytes: &[u8], protocol: Protocol) -> (Observation, bool) {
    let mut observation = initial();
    let line_limit = if protocol == Protocol::Smtp {
        // RFC 5321 §4.5.3.1.5, including the reply code and CRLF.
        512
    } else {
        MAX_FIELD_BYTES
    };
    let mut multiline = false;
    for (index, line) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if index >= MAX_GREETING_LINES || line.len() > line_limit {
            return stop(
                observation,
                ObservationOutcome::Truncated,
                "connection greeting exceeds its line or line-count limit",
                true,
            );
        }
        if !line.ends_with(b"\n") {
            return stop(
                observation,
                ObservationOutcome::Truncated,
                "connection greeting line is incomplete",
                false,
            );
        }
        if !line.ends_with(b"\r\n")
            || !line[..line.len() - 2]
                .iter()
                .all(|byte| matches!(byte, 0x20..=0x7e))
        {
            return stop(
                observation,
                ObservationOutcome::Malformed,
                "connection greeting requires printable ASCII and CRLF",
                true,
            );
        }
        let reply = &line[..line.len() - 2];
        // RFC 5321 §4.2 permits a terminal reply code without a text string.
        let code_only = protocol == Protocol::Smtp && reply == b"220";
        let coded = reply.starts_with(b"220 ") || reply.starts_with(b"220-") || code_only;
        if index == 0 {
            if !coded {
                return (observation, true);
            }
            multiline = reply.starts_with(b"220-");
        } else if protocol == Protocol::Smtp && !coded {
            return stop(
                observation,
                ObservationOutcome::Malformed,
                "SMTP multiline greeting requires a consistent 220 reply code",
                true,
            );
        }
        match protocol {
            Protocol::Smtp => smtp_fields(&mut observation, reply),
            Protocol::Ftp => {
                observation.fields.push(ObservedField {
                    field: Field::FtpGreeting,
                    value: reply.to_vec(),
                });
                // A numeric 220 greeting alone also occurs in SMTP. Require
                // an explicit FTP marker before describing it as FTP evidence.
                // FTP continuation lines need not repeat the reply code.
                let text = if coded { &reply[4..] } else { reply };
                if smtp_claim(text).is_none()
                    && text
                        // Hostname punctuation belongs to the token: an FTP
                        // label inside a hostname is not a protocol marker.
                        .split(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-'))
                        .any(|token| {
                            token.eq_ignore_ascii_case(b"ftp")
                                || token.eq_ignore_ascii_case(b"vsftpd")
                                || token.eq_ignore_ascii_case(b"proftpd")
                        })
                {
                    observation.protocol = Some(Protocol::Ftp);
                }
            }
            _ => unreachable!("greeting parser has a closed protocol set"),
        }
        if !multiline || reply.starts_with(b"220 ") || code_only {
            observation.outcome = if observation.protocol.is_some() {
                ObservationOutcome::Complete
            } else {
                ObservationOutcome::Unknown
            };
            return (observation, true);
        }
        if index + 1 == MAX_GREETING_LINES {
            return stop(
                observation,
                ObservationOutcome::Truncated,
                "multiline connection greeting reached its line-count limit",
                true,
            );
        }
    }
    if multiline {
        stop(
            observation,
            ObservationOutcome::Truncated,
            "multiline connection greeting has no terminating 220 line",
            false,
        )
    } else {
        (observation, false)
    }
}

fn smtp_fields(observation: &mut Observation, reply: &[u8]) {
    observation.fields.push(ObservedField {
        field: Field::SmtpGreeting,
        value: reply.to_vec(),
    });
    let Some((hostname, software)) = reply.get(4..).and_then(smtp_claim) else {
        return;
    };
    observation.protocol = Some(Protocol::Smtp);
    observation.fields.push(ObservedField {
        field: Field::SmtpHostname,
        value: hostname.to_vec(),
    });
    observation.fields.push(ObservedField {
        field: Field::SmtpSoftware,
        value: software.to_vec(),
    });
}

fn smtp_claim(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let space = text.iter().position(|byte| *byte == b' ')?;
    let (hostname, rest) = (&text[..space], &text[space + 1..]);
    let software = rest.strip_prefix(b"ESMTP ")?;
    (valid_hostname(hostname) && !software.is_empty()).then_some((hostname, software))
}

pub(super) fn valid_hostname(value: &[u8]) -> bool {
    let value = value.strip_suffix(b".").unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label[0].is_ascii_alphanumeric()
                && label[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}
