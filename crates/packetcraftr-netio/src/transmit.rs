// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod evidence;
mod frame;

use crate::Error;

pub use evidence::{Report, SendEvidenceFault, Submission, TimeMarker, Timing};
pub use frame::{Layer2Frame, Layer3Frame, Outbound, Route};

pub trait Provider: Send + Sync {
    fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error>;

    /// Creates an operation-scoped provider without sending or opening a transmission handle.
    /// Existing providers default to one-shot sends.
    fn session(&self) -> Box<dyn Provider + '_> {
        Box::new(DirectProvider(self))
    }
}

struct DirectProvider<'a, P: ?Sized>(&'a P);

impl<P: Provider + ?Sized> Provider for DirectProvider<'_, P> {
    fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        self.0.send(outbound)
    }

    fn session(&self) -> Box<dyn Provider + '_> {
        Box::new(DirectProvider(self.0))
    }
}

/// The native one-shot transmission provider.
///
/// On Linux a session can retain one compatible libpcap handle and one raw IP
/// socket for the namespace's built-in loopback interface. Concurrent sends are
/// rejected, and incompatible traffic uses one-shot dispatch. Sends are rejected
/// if the session's network namespace, user namespace or credentials change or
/// cannot be verified. A failed native submission invalidates its handle and its
/// error is returned for later compatible sends. Dropping the session closes its
/// handles.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    fn send(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        crate::platform::transmit::send(outbound)
    }

    fn session(&self) -> Box<dyn Provider + '_> {
        crate::platform::transmit::session()
    }
}
