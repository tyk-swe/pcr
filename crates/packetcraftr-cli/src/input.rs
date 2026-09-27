// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded acquisition of recipe, frame, document, and capture input.
//! Argument validation belongs to `command_options`; capture readers retain
//! source bytes, scope, timestamps, and invocation limits.

mod bounded;
mod capture;
mod fingerprint;
mod recipe;

pub(crate) use bounded::{
    InputKind, read_bounded_file, read_bounded_file_allow_empty, read_bounded_json_document,
    read_stdin_bounded,
};
pub(crate) use capture::{open_capture, open_capture_file, open_capture_hashed, snapshot_capture};
pub(crate) use recipe::read_recipe;
