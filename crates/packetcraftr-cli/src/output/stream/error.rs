// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How encoding or publishing an NDJSON stream fails.

use std::io;

use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("NDJSON {phase} exceeded the operation publication deadline")]
    Deadline {
        phase: &'static str,
        #[source]
        source: packetcraftr_core::budget::DeadlineExceeded,
    },
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error(
        "NDJSON record at sequence {sequence} exceeds {limit} encoded bytes; operation is incomplete"
    )]
    RecordLimit { sequence: u64, limit: usize },
    #[error("data records must declare a nonterminal event kind")]
    ReservedEvent,
    #[error("NDJSON stream is already terminated")]
    Terminal,
    #[error("NDJSON stream output has already failed")]
    Failed,
    #[error("NDJSON stream state lock was poisoned")]
    Poisoned,
    #[error("NDJSON sequence overflowed")]
    SequenceOverflow,
    #[error("NDJSON record at sequence {sequence} failed to serialize")]
    Serialize {
        sequence: u64,
        #[source]
        source: serde_json::Error,
    },
    #[error("NDJSON stream is incomplete: record at sequence {sequence} failed to write")]
    Write {
        sequence: u64,
        #[source]
        source: io::Error,
    },
}

impl Classified for EncodeError {
    fn classification(&self) -> Classification {
        match self {
            Self::Deadline { .. } => Classification::new(
                "io.output_deadline",
                Kind::Io,
                Some(
                    "treat the operation as incomplete; serialization and publication share the remaining duration budget",
                ),
            ),
            Self::Cancelled(source) => source.classification(),
            Self::RecordLimit { .. } => Classification::new(
                "io.output_record_limit",
                Kind::Io,
                Some(
                    "reduce record contents or select a smaller input; account for earlier records",
                ),
            ),
            Self::Write { .. } => Classification::new(
                "io.stdout",
                Kind::Io,
                Some("inspect the output sink and account for records already written"),
            ),
            _ => Classification::new(
                "internal.ndjson_stream",
                Kind::Internal,
                Some("treat the structured stream as incomplete"),
            ),
        }
    }
}
