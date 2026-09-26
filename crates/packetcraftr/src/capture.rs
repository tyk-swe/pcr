// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture: passive live capture from one or more interfaces under one
//! operation budget and readiness barrier.
//!
//! [`Client::capture`](crate::Client::capture) arms every requested interface
//! as one capture group, publishes [`Event::Started`] once every source is
//! ready, then publishes each selected frame as an [`Event::Frame`] until the
//! window closes, the budget is spent, or the sink asks it to stop. It
//! returns the terminal [`Report`], which keeps each source's completion
//! evidence. Native session ownership stays in the capture provider; this
//! workflow numbers frames, applies the budget before selection, and keeps
//! per-source accounting.

mod engine;
mod error;
mod report;
mod request;

pub use error::{Cause, Error};
pub use report::{Control, Event, Report, Source, StopReason};
pub use request::Request;
