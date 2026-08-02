// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-statistics output.

mod model;
pub use crate::frame::Timestamp;
pub use model::{
    StatsCommandResult as Result, StatsConversationOutput as Conversation,
    StatsEndpointOutput as Endpoint, StatsIoBucketOutput as IoBucket, StatsIoOutput as Io,
    StatsPortOutput as Port, StatsProtocolOutput as Protocol, StatsTableName as Table,
    StatsTransport as Transport,
};
