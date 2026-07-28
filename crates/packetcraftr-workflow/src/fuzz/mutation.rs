// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Internal fuzz mutation façade.

pub(super) use decode::{dissect_built, has_link_root};
pub(super) use preparation::prepare;
#[cfg(test)]
pub(super) use value::{bounded_value_size, random_value};

mod decode;
mod preparation;
mod value;
