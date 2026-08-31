// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The shared charging policy for one packet-document parse.
//!
//! Counts and byte widths are charged here before the bounded item is
//! allocated, pushed, or inserted, and the first breach records which [`Limit`]
//! tripped so the parser can report it as a classified error instead of a
//! format message.

use std::cell::Cell;

use serde::de;

use crate::document::types::{DocumentLimits, Limit};

/// Retained width charged for fixed-size scalars, in payload bytes.
pub(super) const BOOL_PAYLOAD_BYTES: usize = 1;
pub(super) const INTEGER_PAYLOAD_BYTES: usize = 8;
pub(super) const IPV4_PAYLOAD_BYTES: usize = 4;
pub(super) const IPV6_PAYLOAD_BYTES: usize = 16;
pub(super) const MAC_PAYLOAD_BYTES: usize = 6;

/// Shared parse budget. Cheap interior mutability is enough: serde drives
/// one document on one thread.
pub(super) struct Budget<'l> {
    pub(super) limits: &'l DocumentLimits,
    nodes: Cell<usize>,
    list_items: Cell<usize>,
    payload_bytes: Cell<usize>,
    breach: Cell<Option<Limit>>,
}

impl<'l> Budget<'l> {
    pub(super) fn new(limits: &'l DocumentLimits) -> Self {
        Self {
            limits,
            nodes: Cell::new(0),
            list_items: Cell::new(0),
            payload_bytes: Cell::new(0),
            breach: Cell::new(None),
        }
    }

    /// The first limit this budget rejected, if any.
    pub(super) fn breach(&self) -> Option<Limit> {
        self.breach.get()
    }

    pub(super) fn exceeded<E: de::Error>(&self, limit: Limit) -> E {
        if self.breach.get().is_none() {
            self.breach.set(Some(limit));
        }
        E::custom(format_args!(
            "packet document exceeds configured limit {limit}={}",
            self.limits.maximum(limit)
        ))
    }

    pub(super) fn charge<E: de::Error>(
        &self,
        counter: &Cell<usize>,
        amount: usize,
        limit: Limit,
    ) -> Result<(), E> {
        let next = counter
            .get()
            .checked_add(amount)
            .filter(|next| *next <= self.limits.maximum(limit))
            .ok_or_else(|| self.exceeded(limit))?;
        counter.set(next);
        Ok(())
    }

    pub(super) fn charge_node<E: de::Error>(&self) -> Result<(), E> {
        self.charge(&self.nodes, 1, Limit::TotalNodes)
    }

    /// Which list budget is already full before another item is read, so the
    /// caller can probe for the item without allocating it.
    pub(super) fn list_budget_full(&self, in_list: usize) -> Option<Limit> {
        if in_list >= self.limits.max_list_items {
            Some(Limit::ListItems)
        } else if self.list_items.get() >= self.limits.max_total_list_items {
            Some(Limit::TotalListItems)
        } else {
            None
        }
    }

    /// Charges one aggregate list item ahead of reading it; a read that finds
    /// the end of the list hands the charge back.
    pub(super) fn charge_list_item<E: de::Error>(&self) -> Result<(), E> {
        self.charge(&self.list_items, 1, Limit::TotalListItems)
    }

    pub(super) fn refund_list_item(&self) {
        self.list_items.set(self.list_items.get().saturating_sub(1));
    }

    pub(super) fn charge_payload<E: de::Error>(&self, bytes: usize) -> Result<(), E> {
        self.charge(&self.payload_bytes, bytes, Limit::TotalPayloadBytes)
    }

    pub(super) fn check_width<E: de::Error>(&self, actual: usize, limit: Limit) -> Result<(), E> {
        if actual > self.limits.maximum(limit) {
            return Err(self.exceeded(limit));
        }
        Ok(())
    }

    /// Entering a list at `depth` enclosing lists.
    pub(super) fn enter_list<E: de::Error>(&self, depth: usize) -> Result<(), E> {
        if depth >= self.limits.max_nesting {
            return Err(self.exceeded(Limit::Nesting));
        }
        Ok(())
    }

    /// Reserves capacity for a sequence without trusting its size hint beyond
    /// the remaining budget.
    pub(super) fn bounded_capacity(&self, hint: Option<usize>, limit: Limit) -> usize {
        hint.unwrap_or(0).min(self.limits.maximum(limit))
    }
}
