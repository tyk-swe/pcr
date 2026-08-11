// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded packet templates.

mod model;

pub use model::{
    DEFAULT_MAX_TEMPLATE_PACKETS, PacketTemplate as Template, PacketTemplateIter as Iter,
    TemplateError as Error,
};
