// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use packetcraftr_core::error::Kind;

pub(super) fn charge(
    value: &impl serde::Serialize,
    used: &mut usize,
    limit: usize,
) -> Result<(), CliError> {
    struct Counter {
        remaining: usize,
        count: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(std::io::Error::other("application output limit"));
            }
            self.remaining -= bytes.len();
            self.count += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        remaining: limit.saturating_sub(*used),
        count: 0,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| {
        CliError::new(
            Kind::Policy,
            "application output exceeds --max-application-output-bytes",
        )
    })?;
    *used += counter.count;
    Ok(())
}
