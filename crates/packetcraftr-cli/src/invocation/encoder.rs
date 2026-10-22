// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The invocation's output stream: the published wire encoder together with
//! human presentation preferences.

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;

use crate::output;

/// Immutable human presentation preferences, independent of published schemas.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Presentation {
    pub(crate) verbose: bool,
}

/// Carries presentation through the same bounded command and worker lifetimes
/// as the publisher. The public wire encoder remains presentation-independent.
#[derive(Clone)]
pub(crate) struct StreamEncoder {
    encoder: output::stream::StreamEncoder,
    presentation: Presentation,
}

impl StreamEncoder {
    pub(crate) fn terminal(mut self) -> Self {
        self.encoder = self.encoder.terminal();
        self
    }

    pub(crate) fn new(
        command: output::contract::Command,
        writer: impl std::io::Write + Send + 'static,
    ) -> Self {
        output::stream::StreamEncoder::new(command, writer).into()
    }

    pub(crate) fn presentation(&self) -> Presentation {
        self.presentation
    }

    pub(crate) fn with_presentation(mut self, presentation: Presentation) -> Self {
        self.presentation = presentation;
        self
    }

    pub(crate) fn with_control(mut self, control: Arc<Deadline>) -> Self {
        self.encoder = self.encoder.with_control(control);
        self
    }

    pub(crate) fn with_resource_diagnostics(
        mut self,
        observe: impl Fn() -> output::resources::Report + Send + Sync + 'static,
    ) -> Self {
        self.encoder = self.encoder.with_resource_diagnostics(observe);
        self
    }

    pub(crate) fn with_terminal_error_timeout(mut self, timeout: Duration) -> Self {
        self.encoder = self.encoder.with_terminal_error_timeout(timeout);
        self
    }
}

impl From<output::stream::StreamEncoder> for StreamEncoder {
    fn from(encoder: output::stream::StreamEncoder) -> Self {
        Self {
            encoder,
            presentation: Presentation::default(),
        }
    }
}

impl Deref for StreamEncoder {
    type Target = output::stream::StreamEncoder;
    fn deref(&self) -> &Self::Target {
        &self.encoder
    }
}
