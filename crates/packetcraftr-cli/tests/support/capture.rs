// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;

pub(crate) fn append_truncated_record(file: &mut tempfile::NamedTempFile) {
    file.write_all(&[0; 8])
        .expect("truncated record header must write");
    file.flush().expect("truncated capture must flush");
}
