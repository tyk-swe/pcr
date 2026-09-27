// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Selected-message entity-span delivery to a caller's synchronous sink.

use crate::error::BoundaryError;

/// Receives one selected message's entity spans while it parses.
///
/// `write` is invoked synchronously inside
/// [`Collector::observe`](super::Collector::observe) for each nonempty span
/// of Content-Length, close-delimited, or chunk-data bytes in parse order —
/// never chunk framing, trailers, or another message's body, and never
/// decoded content. The slice borrows the delivery and is valid only for
/// the call; implementations stage or forward the bytes immediately. A
/// `write` error is terminal: it aborts the run as
/// `application::Error::Output` and no further call reaches the sink.
pub trait BodySink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError>;
}

/// The one selected message and the sink borrowing its entity spans.
pub(super) struct Target<'a> {
    /// The one-based message index in parse-start order whose body `sink`
    /// receives.
    pub message: u64,
    pub sink: &'a mut dyn BodySink,
}
