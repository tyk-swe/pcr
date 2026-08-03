// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured conversation-following output.

mod model;
pub use model::{
    FollowChunk as Chunk, FollowCommandResult as Result, FollowDirection as Direction,
    FollowEndpoint as Endpoint,
};
