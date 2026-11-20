// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::template::{DEFAULT_MAX_TEMPLATE_PACKETS, Template};
use packetcraftr_netio::capture::{Limits as CaptureQueueLimits, MAX_CAPTURE_QUEUE_FRAMES};
use packetcraftr_netio::deadline::MAX_WAIT;

use super::Error;
use crate::deadline::duration_violation;

pub const DEFAULT_MAX_UNMATCHED_FRAMES: usize = MAX_CAPTURE_QUEUE_FRAMES;
pub const DEFAULT_MAX_RESPONSES: usize = MAX_CAPTURE_QUEUE_FRAMES;

/// When an exchange stops collecting before its window closes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StopCondition {
    /// Collect until the window closes.
    #[default]
    Window,
    /// End the collection as soon as every request of the packet set has at least one retained
    /// response. Duplicate responses to one request count once, and a request that has not been
    /// sent cannot be answered, so the set is never cut short before its last send.
    AllAnswered,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub template: Template,
    pub send: crate::send::Options,
    /// The collection window, from the start of the exchange.
    pub timeout: Duration,
    pub max_template_packets: usize,
    pub collection: Collection,
    /// Honored by [`Client::exchange`](crate::Client::exchange); workflows that hook an
    /// exchange supply their own stop predicate.
    pub stop: StopCondition,
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
            stop: StopCondition::Window,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        validate_window(self.timeout, self.max_template_packets, &self.collection)
    }
}

/// One workflow step's exchange, without the public request's stop condition.
/// Workflows stop through their own predicate passed to the hooked exchange.
pub(crate) struct Step {
    pub(crate) template: Template,
    pub(crate) send: crate::send::Options,
    pub(crate) timeout: Duration,
    pub(crate) max_template_packets: usize,
    pub(crate) collection: Collection,
}

impl Step {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        validate_window(self.timeout, self.max_template_packets, &self.collection)
    }
}

fn validate_window(
    timeout: Duration,
    max_template_packets: usize,
    collection: &Collection,
) -> Result<(), Error> {
    if duration_violation(timeout, MAX_WAIT) {
        return Err(Error::InvalidRequest {
            field: "timeout",
            message: format!("must be greater than zero and not exceed {MAX_WAIT:?}"),
        });
    }
    if max_template_packets == 0 {
        return Err(Error::InvalidRequest {
            field: "max_template_packets",
            message: "must be greater than zero".to_owned(),
        });
    }
    collection.validate()
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
    /// Caps this exchange's responses, narrowing its unmatched frames so they
    /// can never exceed the response ceiling.
    #[must_use]
    pub fn with_max_responses(mut self, max_responses: usize) -> Self {
        self.max_responses = max_responses;
        self.max_unmatched_frames = self.max_unmatched_frames.min(max_responses);
        self
    }

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

#[derive(Clone, Debug)]
pub struct Parameters {
    timeout: Duration,
    max_template_packets: usize,
    collection: Collection,
    stop: StopCondition,
}

impl Parameters {
    pub fn new(
        timeout: Duration,
        max_template_packets: usize,
        collection: Collection,
        stop: StopCondition,
    ) -> Result<Self, Error> {
        validate_window(timeout, max_template_packets, &collection)?;
        Ok(Self {
            timeout,
            max_template_packets,
            collection,
            stop,
        })
    }

    pub fn into_request(self, template: Template, send: crate::send::Options) -> Request {
        Request {
            template,
            send,
            timeout: self.timeout,
            max_template_packets: self.max_template_packets,
            collection: self.collection,
            stop: self.stop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_preflight_precedes_collection_validation() {
        let collection = Collection {
            max_responses: usize::MAX,
            ..Collection::default()
        };
        assert!(matches!(
            Parameters::new(Duration::ZERO, 0, collection, StopCondition::Window),
            Err(Error::InvalidRequest {
                field: "timeout",
                ..
            })
        ));
    }

    #[test]
    fn with_max_responses_narrows_unmatched_frames() {
        let collection = Collection {
            max_responses: 100,
            max_unmatched_frames: 40,
            ..Collection::default()
        };
        let narrowed = collection.clone().with_max_responses(10);
        assert_eq!(narrowed.max_responses, 10);
        assert_eq!(narrowed.max_unmatched_frames, 10);

        let widened = collection.with_max_responses(200);
        assert_eq!(widened.max_responses, 200);
        assert_eq!(widened.max_unmatched_frames, 40);
    }

    #[test]
    fn validated_window_constructs_the_requested_operation() {
        let timeout = Duration::from_millis(123);
        let parameters = Parameters::new(
            timeout,
            2,
            Collection::default(),
            StopCondition::AllAnswered,
        )
        .unwrap();
        let request = parameters.into_request(
            Template::new(packetcraftr_core::packet::Packet::default()),
            crate::send::Options::default(),
        );
        request.validate().unwrap();
        assert_eq!(request.timeout, timeout);
        assert_eq!(request.max_template_packets, 2);
        assert_eq!(request.stop, StopCondition::AllAnswered);
    }
}
