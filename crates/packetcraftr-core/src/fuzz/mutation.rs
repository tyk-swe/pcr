// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Internal fuzz mutation façade.

pub(super) use preparation::prepare_with_events;

mod decode;
mod preparation;
mod value;
