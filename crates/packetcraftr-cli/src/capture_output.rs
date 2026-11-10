// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod spool;
mod writer;

pub(crate) use spool::{stream_capture_error, stream_limits, write_capture_file};
pub(crate) use writer::{SourceCaptureWriter, finish_compressed_output};
