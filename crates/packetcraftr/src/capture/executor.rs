// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::failure;
use super::{Cause, Error, Report};
use crate::{Client, clock::Clock, providers::CaptureProviders};
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::capture::{self as native, Group, GroupRequest, Session as _};
use std::time::Duration;

impl<P: CaptureProviders, K: Clock> Client<P, K> {
    pub(super) fn arm_capture_group(
        &self,
        request: &GroupRequest,
        window: Duration,
        deadline: &Deadline,
        report: Report,
    ) -> Result<Armed<<P::Capture as native::Provider>::Capture>, Error> {
        // A zero window still arms its sources, then stops without waiting.
        let unbounded;
        let arming = if window.is_zero() {
            unbounded = self.deadline(packetcraftr_netio::deadline::MAX_WAIT);
            &unbounded
        } else {
            deadline
        };
        let mut group = match Group::new(request) {
            Ok(group) => group,
            Err(error) => return Err(failure(Cause::Native(error), report, None)),
        };
        let mut primary = group
            .arm(self.providers.capture(), arming)
            .err()
            .map(Cause::Native);
        if primary.is_none() && !window.is_zero() {
            if deadline
                .remaining()
                .map_or(true, |remaining| remaining.is_zero())
            {
                primary = Some(Cause::Invalid("capture window expired during activation"));
            } else if let Err(error) = group.wait_ready(deadline) {
                primary = Some(Cause::Native(error));
            }
        }
        Ok(Armed {
            group,
            report,
            primary,
        })
    }
}

pub(super) struct Armed<C: native::Session> {
    pub(super) group: Group<C>,
    pub(super) report: Report,
    pub(super) primary: Option<Cause>,
}
