// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub mod config;
pub mod engine;

pub use config::{FuzzConfig, FuzzProtocol, FuzzStrategy};
pub use engine::run_fuzz;
