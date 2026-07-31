// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-statistics output.

mod model;
pub use model::{
    StatsCommandResult as Result, StatsConversationOutput as Conversation,
    StatsEndpointOutput as Endpoint, StatsIoBucketOutput as IoBucket, StatsIoOutput as Io,
    StatsLengthBucketOutput as LengthBucket, StatsLengthsOutput as Lengths,
    StatsPortOutput as Port, StatsProtocolOutput as Protocol,
    StatsServiceResponseTimeBucketOutput as ServiceResponseTimeBucket,
    StatsServiceResponseTimeOutput as ServiceResponseTime, StatsTableName as Table,
    StatsTransport as Transport,
};
