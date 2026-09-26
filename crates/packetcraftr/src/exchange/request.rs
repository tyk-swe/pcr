// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::template::{DEFAULT_MAX_TEMPLATE_PACKETS, Template};
use packetcraftr_netio::capture::{
    Limits as CaptureQueueLimits, MAX_CAPTURE_QUEUE_FRAMES, MAX_TIMEOUT,
};

use super::Error;

pub const DEFAULT_MAX_UNMATCHED_FRAMES: usize = MAX_CAPTURE_QUEUE_FRAMES;
pub const DEFAULT_MAX_RESPONSES: usize = MAX_CAPTURE_QUEUE_FRAMES;

/// One exchange: capture is armed, every packet `template` expands to is
/// sent once, and frames are collected until `timeout`.
#[derive(Clone, Debug)]
pub struct Request {
    pub template: Template,
    /// How each packet is prepared.
    pub send: crate::send::Options,
    /// The collection window, from the start of the exchange.
    pub timeout: Duration,
    /// Template-expansion ceiling checked before packets materialize.
    pub max_template_packets: usize,
    pub collection: Collection,
}

impl Request {
    /// Exchanges every packet `template` expands to under the default window
    /// and collection bounds.
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

    /// Validates the finite window and retention bounds before any provider
    /// runs.
    ///
    /// # Errors
    ///
    /// Returns the first invalid bound.
    pub fn validate(&self) -> Result<(), Error> {
        if self.timeout > MAX_TIMEOUT {
            return Err(Error::InvalidRequest {
                field: "timeout",
                message: format!("must not exceed {MAX_TIMEOUT:?}"),
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

/// How an exchange's capture is armed and what it retains: shared by every
/// workflow that runs its steps as exchanges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    /// The one aggregate backend queue bound shared by matched, unsolicited,
    /// and undecodable capture traffic, including the explicit per-frame
    /// snapshot length the capture session is armed with.
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
    /// Validates the retention bounds against the capture queue.
    ///
    /// Once this returns, [`capture`](Self::capture) is exactly the bounded
    /// queue configuration a capture provider may be armed with, and every
    /// retention ceiling fits inside it.
    ///
    /// # Errors
    ///
    /// Returns the first invalid bound.
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
