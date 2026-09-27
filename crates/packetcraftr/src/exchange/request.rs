// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::template::{DEFAULT_MAX_TEMPLATE_PACKETS, Template};
use packetcraftr_netio::capture::{Limits as CaptureQueueLimits, MAX_CAPTURE_QUEUE_FRAMES};
use packetcraftr_netio::deadline::MAX_WAIT;

use super::Error;

pub const DEFAULT_MAX_UNMATCHED_FRAMES: usize = MAX_CAPTURE_QUEUE_FRAMES;
pub const DEFAULT_MAX_RESPONSES: usize = MAX_CAPTURE_QUEUE_FRAMES;

#[derive(Clone, Debug)]
pub struct Request {
    pub template: Template,
    pub send: crate::send::Options,
    /// The collection window, from the start of the exchange.
    pub timeout: Duration,
    pub max_template_packets: usize,
    pub collection: Collection,
}

impl Request {
    #[must_use]
    pub fn new(template: Template, send: crate::send::Options) -> Self {
        Self {
            template,
            send,
            timeout: Duration::from_secs(3),
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
            collection: Collection::default(),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.timeout > MAX_WAIT {
            return Err(Error::InvalidRequest {
                field: "timeout",
                message: format!("must not exceed {MAX_WAIT:?}"),
            });
        }
        if self.max_template_packets == 0 {
            return Err(Error::InvalidRequest {
                field: "max_template_packets",
                message: "must be greater than zero".to_owned(),
            });
        }
        self.collection.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    /// One aggregate queue bound shared by matched, unsolicited, and undecodable traffic.
    pub capture: CaptureQueueLimits,
    pub decode: packetcraftr_core::decode::Options,
    pub max_responses: usize,
    pub max_unmatched_frames: usize,
}

impl Default for Collection {
    fn default() -> Self {
        Self {
            capture: CaptureQueueLimits::default(),
            decode: packetcraftr_core::decode::Options::default(),
            max_responses: DEFAULT_MAX_RESPONSES,
            max_unmatched_frames: DEFAULT_MAX_UNMATCHED_FRAMES,
        }
    }
}

impl Collection {
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_responses", self.max_responses),
            ("max_unmatched_frames", self.max_unmatched_frames),
        ] {
            if value > self.capture.max_frames {
                return Err(Error::InvalidRequest {
                    field,
                    message: format!(
                        "{value} exceeds aggregate capture frame ceiling {}",
                        self.capture.max_frames
                    ),
                });
            }
        }
        self.capture
            .validate()
            .map_err(|source| Error::from(crate::Error::from(source)))
    }
}
