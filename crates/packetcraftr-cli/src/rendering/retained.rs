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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn retention_skips_conversion_for_items_the_ceiling_keeps_out() {
        let mut conversions = 0;
        let mut retained = Retained::new(2);
        for value in 0..5_u8 {
            retained.push(|| {
                conversions += 1;
                value
            });
        }
        assert_eq!(conversions, 2);
        assert_eq!(retained.omitted(), 3);
        assert_eq!(retained.into_items(), vec![0, 1]);

        let mut empty = Retained::new(0);
        empty.push(|| {
            conversions += 1;
            1_u8
        });
        assert_eq!(conversions, 2);
        assert_eq!(empty.omitted(), 1);
        assert!(empty.into_items().is_empty());
    }

    #[test]
    fn a_complete_document_carries_no_omission_diagnostic() {
        assert!(
            omitted_diagnostic("expert.findings_omitted", "finding(s)", 0, "--max-frames")
                .is_empty()
        );

        let diagnostics =
            omitted_diagnostic("expert.findings_omitted", "finding(s)", 4, "--max-frames");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "expert.findings_omitted");
        assert_eq!(
            diagnostics[0].message,
            "4 finding(s) omitted from this document by the --max-frames ceiling",
        );
    }
}
