// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::Cell;

use serde::de;

use crate::document::types::{DocumentLimits, Limit};

/// Retained width charged for fixed-size scalars, in payload bytes.
pub(super) const BOOL_PAYLOAD_BYTES: usize = 1;
pub(super) const INTEGER_PAYLOAD_BYTES: usize = 8;
pub(super) const IPV4_PAYLOAD_BYTES: usize = 4;
pub(super) const IPV6_PAYLOAD_BYTES: usize = 16;
pub(super) const MAC_PAYLOAD_BYTES: usize = 6;

/// Cheap interior mutability is enough: serde drives one document on one thread.
pub(super) struct Budget<'l> {
    pub(super) limits: &'l DocumentLimits,
    nodes: Cell<usize>,
    list_items: Cell<usize>,
    payload_bytes: Cell<usize>,
    breach: Cell<Option<Limit>>,
    temporary: Cell<usize>,
}

impl<'l> Budget<'l> {
    pub(super) fn new(limits: &'l DocumentLimits) -> Self {
        Self {
            limits,
            nodes: Cell::new(0),
            list_items: Cell::new(0),
            payload_bytes: Cell::new(0),
            breach: Cell::new(None),
            temporary: Cell::new(0),
        }
    }

    pub(super) fn temporary_scope(&self) -> TemporaryScope<'_, 'l> {
        TemporaryScope {
            budget: self,
            previous: self.temporary.get(),
        }
    }

    /// The factor two covers geometric container growth and conversion overlap.
    pub(super) fn charge_temporary<E: de::Error>(&self, amount: usize) -> Result<(), E> {
        let maximum = self
            .limits
            .max_input_bytes
            .saturating_mul(2 * std::mem::size_of::<crate::field::FieldValue>());
        let next = self
            .temporary
            .get()
            .checked_add(amount)
            .filter(|value| *value <= maximum)
            .ok_or_else(|| self.exceeded(Limit::InputBytes))?;
        self.temporary.set(next);
        Ok(())
    }

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

    pub(super) fn list_budget_full(&self, in_list: usize) -> Option<Limit> {
        if in_list >= self.limits.max_list_items {
            Some(Limit::ListItems)
        } else if self.list_items.get() >= self.limits.max_total_list_items {
            Some(Limit::TotalListItems)
        } else {
            None
        }
    }

    pub(super) fn charge_list_item<E: de::Error>(&self) -> Result<(), E> {
        self.charge(&self.list_items, 1, Limit::TotalListItems)
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

    pub(super) fn enter_list<E: de::Error>(&self, depth: usize) -> Result<(), E> {
        if depth >= self.limits.max_nesting {
            return Err(self.exceeded(Limit::Nesting));
        }
        Ok(())
    }

    pub(super) fn bounded_capacity(&self, hint: Option<usize>, limit: Limit) -> usize {
        hint.unwrap_or(0).min(self.limits.maximum(limit))
    }
}

pub(super) struct TemporaryScope<'b, 'l> {
    budget: &'b Budget<'l>,
    previous: usize,
}

impl Drop for TemporaryScope<'_, '_> {
    fn drop(&mut self) {
        self.budget.temporary.set(self.previous);
    }
}
