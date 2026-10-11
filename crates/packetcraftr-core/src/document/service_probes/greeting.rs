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
        let coded = reply.starts_with(b"220 ") || reply.starts_with(b"220-");
        if index == 0 {
            if !coded {
                return (observation, true);
            }
            multiline = reply[3] == b'-';
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
                if text
                    .split(|byte| !byte.is_ascii_alphanumeric())
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
        if !multiline || reply.starts_with(b"220 ") {
            observation.outcome = if observation.protocol.is_some() {
                ObservationOutcome::Complete
            } else {
                ObservationOutcome::Unknown
            };
            return (observation, true);
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
    let Some(text) = reply.get(4..) else {
        return;
    };
    let Some(space) = text.iter().position(|byte| *byte == b' ') else {
        return;
    };
    let (hostname, rest) = (&text[..space], &text[space + 1..]);
    let Some(software) = rest.strip_prefix(b"ESMTP ") else {
        return;
    };
    if !valid_hostname(hostname) || software.is_empty() {
        return;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::service_probes::{
        Corpus, MatchOutcome, MatchRule, Metadata, Probe, ReadOnlyReview, Request,
        SERVICE_PROBES_SCHEMA_V1, Transport, VersionExtraction,
    };

    #[test]
    fn uncoded_ftp_continuations_preserve_markers_and_reply_boundaries() {
        for continuation in ["FTP", "vsFTPd 3.0.5", "ProFTPD 1.3.8"] {
            let wire = format!("220-Welcome\r\n{continuation}\r\n220 Ready\r\n");
            for end in 0..wire.len() {
                assert!(!ftp_collection_complete(&wire.as_bytes()[..end]));
            }
            assert!(ftp_collection_complete(wire.as_bytes()));
            let observation = observe(wire.as_bytes(), Protocol::Ftp);
            assert_eq!(observation.protocol, Some(Protocol::Ftp));
            assert_eq!(observation.outcome, ObservationOutcome::Complete);
            assert_eq!(observation.diagnostic, None);
            assert_eq!(
                observation.fields,
                ["220-Welcome", continuation, "220 Ready"].map(|line| ObservedField {
                    field: Field::FtpGreeting,
                    value: line.as_bytes().to_vec(),
                })
            );
        }
    }

    #[test]
    fn custom_rule_matches_exact_uncoded_ftp_continuation_and_version() {
        let metadata = Metadata {
            source: "project-authored test fixture".into(),
            reference: "isolated greeting fixture".into(),
            license: "AGPL-3.0-only".into(),
            maintainer: "tyk-swe".into(),
            updated: "2026-10-11".into(),
        };
        let probe = Probe {
            id: "ftp-greeting".into(),
            transport: Transport::Tcp,
            intensity: 1,
            request: Request::FtpGreeting {},
            metadata: metadata.clone(),
            read_only_review: ReadOnlyReview {
                reviewed_by: "tyk-swe".into(),
                reviewed: "2026-10-11".into(),
                statement: "Reads the connection greeting without sending commands".into(),
            },
        };
        let corpus = Corpus {
            schema: SERVICE_PROBES_SCHEMA_V1.into(),
            name: "ftp-continuation-fixture".into(),
            version: "1".into(),
            probes: vec![probe.clone()],
            matches: vec![MatchRule {
                id: "vsftpd-claim".into(),
                probe: probe.id.clone(),
                field: Field::FtpGreeting,
                prefix: "vsFTPd ".into(),
                product: "vsftpd".into(),
                version: Some(VersionExtraction {
                    max_bytes: 64,
                    stop_at: " ;()".into(),
                }),
                hostname_field: None,
                device_type: None,
                cpe: None,
                metadata,
            }],
        };
        corpus.validate().unwrap();
        let observation = crate::document::service_probes::observe(
            &probe,
            b"220-Welcome\r\nvsFTPd 3.0.5\r\n220 Ready\r\n",
            false,
        );
        let identification = corpus.identify(&probe, &observation);
        assert_eq!(identification.outcome, MatchOutcome::Matched);
        assert_eq!(identification.candidates.len(), 1);
        let candidate = &identification.candidates[0];
        assert_eq!(candidate.product, "vsftpd");
        assert_eq!(candidate.version.as_deref(), Some("3.0.5"));
        assert_eq!(candidate.provenance.field_indices, [1]);
    }

    #[test]
    fn smtp_rejects_uncoded_continuation_before_terminating_line() {
        let wire = b"220-mail.example.test ESMTP Postfix 3.10.1\r\nvsFTPd 3.0.5\r\n220 Ready\r\n";
        assert!(smtp_collection_complete(wire));
        let observation = observe(wire, Protocol::Smtp);
        assert_eq!(observation.outcome, ObservationOutcome::Malformed);
        assert_eq!(observation.fields.len(), 3);
        assert_eq!(observation.fields[0].field, Field::SmtpGreeting);
        assert_eq!(
            observation.fields[0].value,
            b"220-mail.example.test ESMTP Postfix 3.10.1"
        );
    }
}
