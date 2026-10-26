// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! WINDOW_UPDATE handling and reconciliation of closed-stream credit.

use super::super::super::model::{Certainty, IssueScope, Status};
use super::super::super::stream::Phase as StreamPhase;
use super::super::super::{Error, settings};
use super::super::{ConnectionState, Context, Evidence, Fault};
use crate::analysis::http2::budget;
use crate::analysis::http2::side::{PerSide, Side};

impl ConnectionState {
    pub(crate) fn window_update(
        &mut self,
        side: Side,
        stream_id: u32,
        increment: u32,
        evidence: Evidence,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let grant = side.peer();
        if stream_id == 0 {
            self.send_window[grant] = self.send_window[grant].saturating_add(i64::from(increment));
            if self.send_window[grant] > settings::WINDOW_MAX {
                let confirmed = self.dirs[grant]
                    .as_ref()
                    .is_some_and(|dir| dir.closed && dir.buffer.is_empty());
                self.issue(
                    context,
                    Fault {
                        flow: self.dir_flow(side),
                        http2_stream_id: Some(0),
                        scope: IssueScope::Connection,
                        certainty: if confirmed {
                            Certainty::Confirmed
                        } else {
                            Certainty::ObservedOrder
                        },
                        status: if confirmed {
                            Status::Malformed
                        } else {
                            Status::Incomplete
                        },
                        code: "connection_window_overflow",
                        detail: "connection flow window exceeds 2^31-1".into(),
                        wire: evidence.wire,
                        sources: evidence.sources,
                    },
                )?;
                if confirmed {
                    self.fail(context, Status::Malformed)?;
                }
            }
            return Ok(());
        }
        if let Some(debt) = self.closed_credit.get_mut(&stream_id) {
            if let Some(window) = debt[grant].as_mut() {
                *window = window.saturating_add(i64::from(increment));
                if *window >= 0 {
                    debt[grant] = None;
                }
            }
            self.release_credit(stream_id, context)?;
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            let owner = if Side::initiator_of(stream_id) == Side::Server {
                Side::Server
            } else {
                Side::Client
            };
            if self.closed.contains_key(&stream_id) || stream_id <= self.max_initiated[owner] {
                return Ok(());
            }
            let confirmed_idle =
                self.clean_start && (side == owner || self.opener_exhausted(owner));
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Connection,
                    certainty: if confirmed_idle {
                        Certainty::Confirmed
                    } else {
                        Certainty::ObservedOrder
                    },
                    status: Status::Malformed,
                    code: "window_update_unknown_stream",
                    detail: "WINDOW_UPDATE on a stream that is not open".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            if confirmed_idle {
                self.fail(context, Status::Malformed)?;
            } else {
                self.retain_pending_opener(stream_id, "window_update_unknown_stream", context)?;
            }
            return Ok(());
        };
        if stream.phase == StreamPhase::Closed {
            return Ok(());
        }
        stream.window_granted[grant] =
            stream.window_granted[grant].saturating_add(i64::from(increment));
        stream.send_window[grant] = stream.send_window[grant].saturating_add(i64::from(increment));
        if stream.send_window[grant] >= 0 {
            stream.credit_exceeded[grant] = false;
        }
        if stream.send_window[grant] > settings::WINDOW_MAX {
            let confirmed =
                stream.ended[grant] && self.stream_window_overflows(grant, stream_id, context)?;
            self.issue(
                context,
                Fault {
                    flow: self.dir_flow(side),
                    http2_stream_id: Some(stream_id),
                    scope: IssueScope::Stream,
                    certainty: if confirmed {
                        Certainty::Confirmed
                    } else {
                        Certainty::ObservedOrder
                    },
                    status: if confirmed {
                        Status::Malformed
                    } else {
                        Status::Incomplete
                    },
                    code: "stream_window_overflow",
                    detail: "stream flow window exceeds 2^31-1".into(),
                    wire: evidence.wire,
                    sources: evidence.sources,
                },
            )?;
            if confirmed {
                self.close_stream(stream_id, Status::Malformed, None, context)?;
            }
        }
        Ok(())
    }

    /// A clean, fully consumed granting direction cannot hide later credit.
    pub(crate) fn reconcile_closed_credit(
        &mut self,
        side: Side,
        only_stream: Option<u32>,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        if self.phase != super::super::Phase::H2
            || !self.clean_start
            || !self.dirs[side.peer()]
                .as_ref()
                .is_some_and(|dir| dir.closed && dir.buffer.is_empty() && dir.chain.is_none())
        {
            return Ok(false);
        }
        if self.send_window[side] < 0 {
            self.issue(context, Fault {
                flow: self.dir_flow(side), http2_stream_id: Some(0),
                scope: IssueScope::Connection, certainty: Certainty::Confirmed,
                status: Status::Malformed, code: "connection_window_exceeded",
                detail: "DATA exhausted connection credit after the granting direction ended; prior DATA evidence is retained".into(),
                wire: bytes::Bytes::new(), sources: None,
            })?;
            self.fail(context, Status::Malformed)?;
            return Ok(true);
        }
        // A not-yet-ACKed SETTINGS increase may already have supplied credit.
        let mut delta = 0i64;
        let mut extra = 0i64;
        for pending in &self.settings[side.peer()].pending {
            context.check_deadline()?;
            delta += pending.window_delta;
            extra = extra.max(delta);
        }
        let mut cursor = 0;
        loop {
            context.check_deadline()?;
            let id = match only_stream {
                Some(id) if cursor == 0 => Some(id),
                Some(_) => None,
                None => self
                    .streams
                    .range((
                        std::ops::Bound::Excluded(cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(id, _)| *id),
            };
            let Some(id) = id else {
                break;
            };
            cursor = id;
            if self.streams.get(&id).is_some_and(|stream| {
                stream.credit_exceeded[side] && stream.send_window[side] + extra < 0
            }) {
                self.issue(context, Fault {
                    flow: self.dir_flow(side), http2_stream_id: Some(id),
                    scope: IssueScope::Stream, certainty: Certainty::Confirmed,
                    status: Status::Malformed, code: "stream_window_exceeded",
                    detail: "DATA exhausted stream credit after the granting direction ended; prior DATA evidence is retained".into(),
                    wire: bytes::Bytes::new(), sources: None,
                })?;
                self.streams
                    .get_mut(&id)
                    .ok_or(Error::Invariant("stream"))?
                    .credit_exceeded[side] = false;
                self.close_stream(id, Status::Malformed, None, context)?;
                if only_stream.is_some() {
                    return Ok(true);
                }
            }
        }
        let mut cursor = 0;
        loop {
            context.check_deadline()?;
            let id = match only_stream {
                Some(id) if cursor == 0 => Some(id),
                Some(_) => None,
                None => self
                    .closed_credit
                    .range((
                        std::ops::Bound::Excluded(cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(id, _)| *id),
            };
            let Some(id) = id else {
                break;
            };
            cursor = id;
            if self
                .closed_credit
                .get(&id)
                .and_then(|debt| debt[side])
                .is_some_and(|window| window + extra < 0)
            {
                self.issue(context, Fault {
                    flow: self.dir_flow(side), http2_stream_id: Some(id),
                    scope: IssueScope::Stream, certainty: Certainty::Confirmed,
                    status: Status::Malformed, code: "stream_window_exceeded",
                    detail: "completed stream DATA exhausted credit before the granting direction ended; earlier DATA evidence is retained".into(),
                    wire: bytes::Bytes::new(), sources: None,
                })?;
                self.closed_credit
                    .get_mut(&id)
                    .ok_or(Error::Invariant("debt"))?[side] = None;
                self.release_credit(id, context)?;
            }
        }
        Ok(false)
    }

    pub(crate) fn retain_closed_credit(
        &mut self,
        id: u32,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let stream = self.streams.get(&id).ok_or(Error::Invariant("stream"))?;
        let debt_at = |side| {
            (stream.credit_exceeded[side] && stream.send_window[side] < 0)
                .then_some(stream.send_window[side])
        };
        let debt = PerSide::new(debt_at(Side::Client), debt_at(Side::Server));
        if debt.iter().any(Option::is_some) && !self.closed_credit.contains_key(&id) {
            context.charge(&mut self.charge, budget::CLOSED_CREDIT_OVERHEAD)?;
            self.closed_credit.insert(id, debt);
        }
        Ok(())
    }

    fn release_credit(&mut self, id: u32, context: &mut Context<'_>) -> Result<(), Error> {
        if self
            .closed_credit
            .get(&id)
            .is_some_and(|debt| debt.iter().all(Option::is_none))
        {
            self.closed_credit.remove(&id);
            context.release(&mut self.charge, budget::CLOSED_CREDIT_OVERHEAD)?;
        }
        Ok(())
    }

    pub(super) fn release_resolved_credit(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let before = self.closed_credit.len();
        self.closed_credit
            .retain(|_, debt| debt.iter().any(Option::is_some));
        context.release(
            &mut self.charge,
            (before - self.closed_credit.len()) * budget::CLOSED_CREDIT_OVERHEAD,
        )
    }
}
