// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! What a pooled worker thread inherits from the thread that spawned it.
//!
//! A Linux thread stays in the network namespace it was created in, and
//! sockets, route netlink, and capture handles open in the namespace of the
//! thread that opens them. Pooled work therefore only reuses a thread whose
//! namespace matches its caller's. Other targets have no per-thread network
//! context, so every thread matches.

/// The identity of a thread's network context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ExecutionContext {
    /// The device and inode of the thread's network namespace.
    #[cfg(target_os = "linux")]
    namespace: (u64, u64),
}

/// The procfs entry naming the calling thread's network namespace.
#[cfg(target_os = "linux")]
pub(in crate::platform) const NAMESPACE_PATH: &str = "/proc/thread-self/ns/net";

#[cfg(target_os = "linux")]
impl ExecutionContext {
    /// The context a network-namespace file identifies.
    pub(in crate::platform) fn of_namespace(file: &std::fs::File) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(Self {
            namespace: (metadata.dev(), metadata.ino()),
        })
    }
}

/// The calling thread's context, or `None` when it cannot be identified;
/// such work then runs on a thread of its own.
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
