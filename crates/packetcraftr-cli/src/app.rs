// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The application shell: process entry, argument parsing and help, and
//! launching the selected command.

pub(crate) mod cli;
mod startup;

pub(crate) use startup::run;
