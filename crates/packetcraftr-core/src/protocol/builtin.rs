// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod assembly;
mod bindings;
mod filter_fields;

pub use assembly::{registry, registry_with};

#[cfg(test)]
mod tests;
