// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) const AFTER_LONG_HELP: &str = r#"Live transmission is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr send --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)'"#;
