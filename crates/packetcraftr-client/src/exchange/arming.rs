// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture arming after all packet preparation and authorization gates pass.

use packetcraftr_net::{
    capture::CaptureProvider,
    route::{NeighborResolver, RouteProvider},
    transmit::PacketIo,
};

use crate::Client;
use crate::exchange::deadline::ensure_preparation_deadline;
use crate::exchange::{ExchangeTransaction, PreparedExchange};
use crate::send::ClientError;

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo + CaptureProvider,
{
    pub(super) fn arm_capture(
        &self,
        prepared: PreparedExchange,
    ) -> Result<ExchangeTransaction<<I as CaptureProvider>::Capture>, ClientError> {
        let first_route = &prepared
            .packets
            .first()
            .expect("non-empty prepared exchange")
            .route
            .plan;
        ensure_preparation_deadline(prepared.deadline)?;
        let capture = self.io.arm_capture(first_route, prepared.capture_limits)?;
        Ok(ExchangeTransaction::new(
            std::sync::Arc::clone(&self.registry),
            capture,
            prepared,
        ))
    }
}
