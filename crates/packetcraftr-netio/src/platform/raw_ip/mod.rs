// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target-native raw IP transmission after upstream authorization, route, MTU,
//! and capture-readiness checks.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(not(windows), forbid(unsafe_code))]

mod preparation;
mod submission;

pub(super) use submission::send_layer3;
