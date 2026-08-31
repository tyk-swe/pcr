// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned, render-neutral CLI output. Its types are separate from workflow
//! results so both can evolve independently.
//!
//! Everything here serializes into `schemas/packetcraftr.output.v1.schema.json`,
//! which is frozen: 121 of its 122 `additionalProperties` declarations are
//! `false` (the one exception carries arbitrary field names), so one added
//! `pub` field breaks every consumer.
//! `crates/packetcraftr/tests/aggregate_schema_conformance.rs` serializes a real
//! value of every aggregate payload and validates it, so drift fails there
//! rather than in the field.
//!
//! # Where an output type comes from
//!
//! A domain type becomes an output type one of three ways, and the choice is
//! not free:
//!
//! - **Re-export** ([`scan::Classification`], [`dns::Section`],
//!   [`replay::Timing`], …) when the domain type's own serialization *is* the
//!   frozen v1 vocabulary. Renaming a variant in the domain module is then a
//!   wire break with nothing in between, so every re-exported enum is pinned
//!   against the vocabulary the schema declares by
//!   `every_frozen_enum_serializes_exactly_the_vocabulary_the_schema_declares`.
//! - **`mirror_enum!`** when the output name should be free to differ from the
//!   domain name, or when output must not inherit the domain type's derives.
//!   The generated `match` is exhaustive, so a new domain variant is a compile
//!   error rather than a silent omission.
//! - **A hand-written twin** when the shapes genuinely differ — when the domain
//!   type is `#[non_exhaustive]` and the conversion must therefore be fallible
//!   ([`protocols::FieldKind`]), or when output adds, drops, or renames fields.
//!
//! # NDJSON record conventions
//!
//! Most commands emit `{"event": ..., ...}`: an externally visible
//! discriminator names the record kind. Three v1 exceptions exist and are not
//! being changed, because inconsistency is not brokenness and a consumer can
//! dispatch on field presence today:
//!
//! - `tls` flattens its payload under the tag, so a session record carries the
//!   session's own keys beside `"event": "session"` rather than nesting them.
//! - `expert`, `follow` and `replay` emit bare untagged records — a finding, a
//!   chunk, a transmitted frame — which are interleaved in the same stream with
//!   the *tagged* `ip_datagram_completed` / `ip_datagram_incomplete` /
//!   `ip_overlap_resolved` events from [`reassembly::Event`]. An NDJSON consumer
//!   of `follow` must therefore dispatch on field presence, not on `event`.
//!
//! Unifying these is the v2 change: give `expert`, `follow` and `replay` an
//! `Event` enum with the same `event` discriminator and un-flatten
//! [`tls::Event`], revising `$defs.expertStreamResult`,
//! `$defs.followStreamResult`, `$defs.replayStreamResult`,
//! `$defs.tlsSessionEvent` and `$defs.tlsCompleteEvent` together.

#[macro_use]
mod mirror;

pub mod build;
pub mod capture;
pub mod contract;
pub mod dissect;
pub mod dns;
pub mod envelope;
pub mod exchange;
pub mod expert;
pub mod follow;
pub mod frame;
pub mod fuzz;
mod hex;
pub mod interfaces;
pub mod network;
pub mod plan;
pub mod protocols;
pub mod read;
pub mod reassembly;
pub mod replay;
pub mod routes;
pub mod scan;
pub mod send;
pub mod stats;
pub mod tls;
pub mod traceroute;
