// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core as core;

pub(crate) struct Retained<T> {
    maximum: usize,
    items: Vec<T>,
    omitted: u64,
}

impl<T> Retained<T> {
    pub(crate) const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            items: Vec::new(),
            omitted: 0,
        }
    }

    pub(crate) fn push(&mut self, convert: impl FnOnce() -> T) {
        if self.items.len() >= self.maximum {
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        self.items.push(convert());
    }

    pub(crate) const fn omitted(&self) -> u64 {
        self.omitted
    }

    pub(crate) fn into_items(self) -> Vec<T> {
        self.items
    }
}

pub(crate) fn omitted_diagnostic(
    code: &'static str,
    subject: &str,
    omitted: u64,
    ceiling: &str,
) -> Vec<core::diagnostic::Diagnostic> {
    if omitted == 0 {
        return Vec::new();
    }
    vec![core::diagnostic::Diagnostic::warning(
        code,
        format!("{omitted} {subject} omitted from this document by the {ceiling} ceiling"),
    )]
}
