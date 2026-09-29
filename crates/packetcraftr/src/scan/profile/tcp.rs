// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Error, Evidence, Status};
use bytes::Bytes;
use packetcraftr_core::document::tcp_profiles::{Assignment, Config, Payload, ResponseCheck};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpProfile {
    config: Config,
}
impl TcpProfile {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.name.is_empty()
            || config.name.chars().count() > 128
            || config.name.chars().any(char::is_control)
        {
            return Err(Error::Invalid(
                "TCP profile name must contain 1..=128 non-control characters",
            ));
        }
        let Payload::Bytes { data } = &config.request;
        if data.len() > 65_536 {
            return Err(Error::Invalid("TCP request exceeds 64 KiB"));
        }
        if let ResponseCheck::Bytes {
            checks,
            min_length,
            max_length,
        } = &config.response
        {
            if checks.is_empty()
                || checks.len() > 64
                || min_length > max_length
                || *max_length == 0
                || *max_length > 65_536
            {
                return Err(Error::Invalid(
                    "TCP response checks require bounded lengths within 1..=65536",
                ));
            }
            for check in checks {
                if check.data.is_empty()
                    || check.data.len() > 1024
                    || check
                        .offset
                        .checked_add(check.data.len())
                        .is_none_or(|end| end > *max_length)
                    || check
                        .mask
                        .as_ref()
                        .is_some_and(|mask| mask.len() != check.data.len())
                {
                    return Err(Error::Invalid("TCP byte check exceeds response bounds"));
                }
            }
        }
        Ok(Self { config })
    }
    pub fn request(&self) -> &Bytes {
        let Payload::Bytes { data } = &self.config.request;
        data
    }
    pub fn max_response(&self) -> usize {
        match &self.config.response {
            ResponseCheck::Any {} => 4096,
            ResponseCheck::Bytes { max_length, .. } => *max_length,
        }
    }
    pub fn storage_bytes(&self) -> usize {
        self.request().len()
            + self.config.name.len()
            + match &self.config.response {
                ResponseCheck::Any {} => 0,
                ResponseCheck::Bytes { checks, .. } => checks
                    .iter()
                    .map(|check| check.data.len() + check.mask.as_ref().map_or(0, Bytes::len) + 64)
                    .sum::<usize>(),
            }
    }
    pub fn evaluate(&self, response: &[u8]) -> Evidence {
        let status = match &self.config.response {
            ResponseCheck::Any {} => Status::Unchecked,
            ResponseCheck::Bytes {
                checks,
                min_length,
                max_length,
            } => {
                if response.len() >= *min_length
                    && response.len() <= *max_length
                    && checks.iter().all(|check| {
                        response
                            .get(check.offset..check.offset + check.data.len())
                            .is_some_and(|actual| {
                                actual.iter().zip(&check.data).enumerate().all(
                                    |(index, (actual, expected))| {
                                        let mask =
                                            check.mask.as_ref().map_or(255, |mask| mask[index]);
                                        actual & mask == expected & mask
                                    },
                                )
                            })
                    })
                {
                    Status::Confirmed
                } else {
                    Status::Rejected
                }
            }
        };
        Evidence {
            profile: self.config.name.clone(),
            status,
            reason: match status {
                Status::Confirmed => "configured TCP response checks matched",
                Status::Unchecked => "TCP banner retained without response checks",
                _ => "TCP response checks did not match",
            }
            .to_owned(),
        }
    }
}
pub fn compile_tcp(assignments: Vec<Assignment>) -> Result<BTreeMap<u16, Arc<TcpProfile>>, Error> {
    let mut profiles = BTreeMap::new();
    let mut charged = 0usize;
    for assignment in assignments {
        if assignment.ports.is_empty() || assignment.ports.len() > 4096 {
            return Err(Error::PortCount {
                count: assignment.ports.len(),
            });
        }
        let profile = Arc::new(TcpProfile::new(assignment.profile)?);
        charged = charged.saturating_add(profile.storage_bytes());
        if charged > 1024 * 1024 {
            return Err(Error::Storage);
        }
        for port in assignment.ports {
            if profiles.contains_key(&port) {
                return Err(Error::ConflictingPort { port });
            }
            profiles.insert(port, Arc::clone(&profile));
            if profiles.len() > 4096 {
                return Err(Error::MappedPorts);
            }
        }
    }
    Ok(profiles)
}
