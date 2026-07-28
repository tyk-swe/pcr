// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux route and interface adapter backed by route netlink.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use self::{
    query::{query_interfaces, query_route},
    worker::with_netlink,
};
use super::{find_interface, interface_decision, validate_preferred_source_family};
use crate::{
    interface::InterfaceInfo,
    route::{InterfaceId, NativeRouteError, RouteDecision},
};

mod query;
mod worker;

pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    with_netlink(|handle| async move { query_interfaces(&handle).await })
}

pub(super) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    validate_preferred_source_family(destination, preferred_source)?;
    let interface_hint = interface_hint.cloned();
    with_netlink(move |handle| query_route(handle, destination, interface_hint, preferred_source))
}

pub(super) fn interface_route(requested: &InterfaceId) -> Result<RouteDecision, NativeRouteError> {
    interface_decision(find_interface(interfaces()?, requested)?)
}

fn os_error(operation: &'static str, error: impl std::fmt::Display) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        thread,
    };

    use super::{
        interfaces,
        worker::{
            NETLINK_WORKER, NetlinkCommand, NetlinkExecutionError, NetlinkWorker,
            NetworkNamespaceId, current_network_namespace, with_netlink,
            with_netlink_for_namespace, with_netlink_in_namespace,
        },
    };
    use crate::route::{
        NativeRouteError, Provider as RouteProvider, RouteSelectionReason, SystemProvider,
    };

    fn worker_thread_id() -> thread::ThreadId {
        with_netlink(|_| async { Ok(thread::current().id()) }).unwrap()
    }

    #[test]
    fn native_linux_provider_finds_loopback_routes_and_interfaces() {
        let interfaces = interfaces().unwrap();
        assert!(interfaces.iter().any(|interface| interface.flags.loopback));

        let provider = SystemProvider;
        let ipv4 = provider
            .lookup_with_preferences(IpAddr::V4(Ipv4Addr::LOCALHOST), None, None)
            .unwrap();
        assert_eq!(ipv4.selection_reason, RouteSelectionReason::Local);
        assert!(ipv4.selected_address.is_some_and(|source| source.is_ipv4()));

        let ipv6 = provider
            .lookup_with_preferences(IpAddr::V6(Ipv6Addr::LOCALHOST), None, None)
            .unwrap();
        assert_eq!(ipv6.selection_reason, RouteSelectionReason::Local);
        assert!(ipv6.selected_address.is_some_and(|source| source.is_ipv6()));
    }

    #[test]
    fn repeated_lookups_reuse_the_calling_threads_netlink_worker() {
        let first_worker = worker_thread_id();
        SystemProvider
            .lookup_with_preferences(IpAddr::V4(Ipv4Addr::LOCALHOST), None, None)
            .unwrap();
        let second_worker = worker_thread_id();

        assert_eq!(first_worker, second_worker);
        assert_ne!(first_worker, thread::current().id());
    }

    #[test]
    fn network_namespace_change_restarts_the_calling_threads_netlink_worker() {
        let first_namespace = NetworkNamespaceId {
            device: 1,
            inode: 1,
        };
        let second_namespace = NetworkNamespaceId {
            device: 1,
            inode: 2,
        };
        let first_worker =
            with_netlink_in_namespace(first_namespace, |_| async { Ok(thread::current().id()) })
                .unwrap();
        let old_commands = NETLINK_WORKER.with(|worker| {
            worker
                .borrow()
                .as_ref()
                .expect("the first worker was initialized above")
                .commands
                .clone()
        });

        let reused_worker =
            with_netlink_in_namespace(first_namespace, |_| async { Ok(thread::current().id()) })
                .unwrap();
        assert_eq!(first_worker, reused_worker);

        with_netlink_in_namespace(second_namespace, |_| async {
            Ok::<_, NativeRouteError>(())
        })
        .unwrap();
        assert!(old_commands.send(NetlinkCommand::Shutdown).is_err());
        NETLINK_WORKER.with(|worker| {
            assert_eq!(
                worker
                    .borrow()
                    .as_ref()
                    .expect("the replacement worker was initialized above")
                    .namespace,
                second_namespace
            );
        });
    }

    #[test]
    fn unavailable_namespace_metadata_uses_uncached_netlink_workers() {
        let namespace = NetworkNamespaceId {
            device: 1,
            inode: 1,
        };
        let cached_worker =
            with_netlink_in_namespace(namespace, |_| async { Ok(thread::current().id()) }).unwrap();

        let first_uncached_worker =
            with_netlink_for_namespace(None, |_| async { Ok(thread::current().id()) }).unwrap();
        let second_uncached_worker =
            with_netlink_for_namespace(None, |_| async { Ok(thread::current().id()) }).unwrap();

        assert_ne!(cached_worker, first_uncached_worker);
        assert_ne!(first_uncached_worker, second_uncached_worker);
        NETLINK_WORKER.with(|worker| assert!(worker.borrow().is_none()));
    }

    #[test]
    fn synchronous_lookup_is_safe_inside_tokio() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        runtime.block_on(async {
            let caller = thread::current().id();
            let worker = tokio::spawn(async {
                let worker = worker_thread_id();
                SystemProvider
                    .lookup_with_preferences(IpAddr::V4(Ipv4Addr::LOCALHOST), None, None)
                    .unwrap();
                worker
            })
            .await
            .unwrap();
            assert_ne!(worker, caller);
        });
    }

    #[test]
    fn concurrent_caller_threads_get_independent_netlink_workers() {
        let mut worker_threads = HashSet::new();
        std::thread::scope(|scope| {
            let workers = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        let caller = thread::current().id();
                        let worker = worker_thread_id();
                        SystemProvider
                            .lookup_with_preferences(IpAddr::V4(Ipv4Addr::LOCALHOST), None, None)
                            .unwrap();
                        (caller, worker)
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                let (caller, worker) = worker.join().unwrap();
                assert_ne!(caller, worker);
                assert!(worker_threads.insert(worker));
            }
        });
        assert_eq!(worker_threads.len(), 4);
    }

    #[test]
    fn explicit_worker_shutdown_sends_shutdown_and_joins() {
        let mut worker = NetlinkWorker::start(current_network_namespace().unwrap()).unwrap();
        let worker_thread = worker
            .execute(|_| async { Ok::<_, NativeRouteError>(thread::current().id()) })
            .unwrap();
        assert_ne!(worker_thread, thread::current().id());

        worker.shutdown().unwrap();
        assert!(worker.thread.is_none());
        assert!(matches!(
            worker.execute(|_| async { Ok::<_, NativeRouteError>(()) }),
            Err(NetlinkExecutionError::Worker(
                NativeRouteError::InvalidResponse { .. }
            ))
        ));
    }

    async fn panic_operation() -> Result<(), NativeRouteError> {
        panic!("scripted netlink operation panic")
    }

    #[test]
    fn panicked_operation_is_typed_and_does_not_kill_the_worker() {
        let mut worker = NetlinkWorker::start(current_network_namespace().unwrap()).unwrap();
        assert_eq!(
            match worker.execute(|_| panic_operation()) {
                Err(NetlinkExecutionError::Operation(error)) => error,
                result => panic!("expected a typed operation panic, got {result:?}"),
            },
            NativeRouteError::InvalidResponse {
                message: "Linux netlink worker panicked".to_owned(),
            }
        );
        worker
            .execute(|_| async { Ok::<_, NativeRouteError>(()) })
            .unwrap();
        worker.shutdown().unwrap();
    }
}
