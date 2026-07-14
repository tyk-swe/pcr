// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

mod arguments;
mod commands;
mod errors;
mod input;
mod rendering;
mod runtime;

pub(crate) use runtime::run_entrypoint;

#[cfg(test)]
mod tests;
