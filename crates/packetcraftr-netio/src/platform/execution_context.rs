// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A Linux thread keeps its creator's network namespace, so pooled work reuses a matching thread.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ExecutionContext {
    #[cfg(target_os = "linux")]
    namespace: (u64, u64),
}

#[cfg(target_os = "linux")]
pub(in crate::platform) const NAMESPACE_PATH: &str = "/proc/thread-self/ns/net";

#[cfg(target_os = "linux")]
impl ExecutionContext {
    pub(in crate::platform) fn of_namespace(file: &std::fs::File) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(Self {
            namespace: (metadata.dev(), metadata.ino()),
        })
    }
}

pub(crate) fn current() -> Option<ExecutionContext> {
    #[cfg(target_os = "linux")]
    {
        let file = std::fs::File::open(NAMESPACE_PATH).ok()?;
        ExecutionContext::of_namespace(&file).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(ExecutionContext {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threads_in_one_context_match() {
        let here = current();
        let there = std::thread::spawn(current).join().unwrap();
        assert!(here.is_some());
        assert_eq!(here, there);
    }
}
