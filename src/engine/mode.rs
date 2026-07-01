// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionMode {
    Plan,
    Live,
}

impl ExecutionMode {
    pub(crate) fn is_plan(self) -> bool {
        matches!(self, Self::Plan)
    }
}
