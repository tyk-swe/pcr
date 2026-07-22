// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Linux route and interface adapter backed by route netlink.

#![forbid(unsafe_code)]

#[cfg(feature = "native-route")]
use std::{
    any::Any,
    cell::RefCell,
    collections::BTreeMap,
    fs,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::mpsc::{self, Receiver, Sender, SyncSender},
    thread::{self, JoinHandle},
};

#[cfg(feature = "native-route")]
use futures_util::TryStreamExt;
#[cfg(feature = "native-route")]
use rtnetlink::packet_route::{
    address::AddressAttribute,
    link::{LinkAttribute, LinkFlags, LinkLayerType},
    route::{RouteAddress, RouteAttribute, RouteMetric, RouteNextHopFlags, RouteType},
};
#[cfg(feature = "native-route")]
use rtnetlink::{Handle, RouteMessageBuilder, new_connection};

#[cfg(feature = "native-route")]
use super::{
    NativeRouteSnapshot, find_interface, finish_route, interface_decision,
    validate_preferred_source_family,
};
#[cfg(feature = "native-route")]
use crate::capture::LinkType;
#[cfg(feature = "native-route")]
use crate::net::{
    interface::{InterfaceAddress, InterfaceFlags, InterfaceInfo},
    link::{LinkCapability, MacAddress},
    route::{InterfaceId, NativeRouteError, RouteDecision, RouteSelectionReason},
};

#[cfg(feature = "native-route")]
pub(super) fn interfaces() -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    with_netlink(|handle| async move { query_interfaces(&handle).await })
}

#[cfg(feature = "native-route")]
pub(super) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    validate_preferred_source_family(destination, preferred_source)?;
    let interface_hint = interface_hint.cloned();
    with_netlink(move |handle| async move {
        let message = route_request(destination, interface_hint.as_ref(), preferred_source);
        let mut replies = handle.route().get(message).execute();
        let reply = replies
            .try_next()
            .await
            .map_err(|error| os_error("RTM_GETROUTE", error))?
            .ok_or(NativeRouteError::RouteNotFound { destination })?;

        let mut output_index = None;
        let mut selected_address = None;
        let mut next_hop = None;
        let mut route_mtu = None;
        let mut multipath = None;
        for attribute in &reply.attributes {
            match attribute {
                RouteAttribute::Oif(index) => output_index = Some(*index),
                RouteAttribute::PrefSource(address) => selected_address = route_address(address),
                RouteAttribute::Gateway(address) => next_hop = route_address(address),
                RouteAttribute::Metrics(metrics) => {
                    route_mtu = metrics.iter().find_map(|metric| match metric {
                        RouteMetric::Mtu(mtu) => Some(*mtu),
                        _ => None,
                    });
                }
                RouteAttribute::MultiPath(next_hops) => {
                    multipath = next_hops.iter().find(|next_hop| {
                        !next_hop
                            .flags
                            .intersects(RouteNextHopFlags::Dead | RouteNextHopFlags::Linkdown)
                    });
                }
                _ => {}
            }
        }
        if let Some(next_hop_entry) = multipath {
            output_index.get_or_insert(next_hop_entry.interface_index);
            if next_hop.is_none() {
                next_hop = next_hop_entry.attributes.iter().find_map(|attribute| {
                    if let RouteAttribute::Gateway(address) = attribute {
                        route_address(address)
                    } else {
                        None
                    }
                });
            }
        }
        let output_index = output_index
            .or_else(|| interface_hint.as_ref().map(|interface| interface.index))
            .ok_or_else(|| NativeRouteError::InvalidResponse {
                message: "Linux route response omitted its output interface".to_owned(),
            })?;
        let interfaces = query_interfaces(&handle).await?;
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.id.index == output_index)
            .ok_or_else(|| NativeRouteError::InterfaceNotFound {
                name: interface_hint
                    .as_ref()
                    .map_or_else(|| format!("index-{output_index}"), |hint| hint.name.clone()),
                index: output_index,
            })?;
        let selection_reason = match reply.header.kind {
            RouteType::Local => RouteSelectionReason::Local,
            RouteType::Unicast | RouteType::Broadcast | RouteType::Anycast => {
                if next_hop.is_some() {
                    RouteSelectionReason::Gateway
                } else {
                    RouteSelectionReason::OnLink
                }
            }
            _ => return Err(NativeRouteError::RouteNotFound { destination }),
        };
        finish_route(
            destination,
            interface_hint.as_ref(),
            preferred_source,
            NativeRouteSnapshot {
                interface,
                selected_address,
                next_hop: next_hop.filter(|address| !address.is_unspecified()),
                route_mtu,
                selection_reason,
            },
        )
    })
}

#[cfg(feature = "native-route")]
pub(super) fn interface_route(requested: &InterfaceId) -> Result<RouteDecision, NativeRouteError> {
    interface_decision(find_interface(interfaces()?, requested)?)
}

#[cfg(feature = "native-route")]
fn with_netlink<F, Fut, T>(operation: F) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    with_netlink_for_namespace(current_network_namespace(), operation)
}

#[cfg(feature = "native-route")]
fn with_netlink_for_namespace<F, Fut, T>(
    namespace: Option<NetworkNamespaceId>,
    operation: F,
) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    match namespace {
        Some(namespace) => with_netlink_in_namespace(namespace, operation),
        None => {
            // Namespace metadata is only needed to cache workers safely. A
            // fresh thread inherits the caller's current network namespace,
            // so netlink remains usable when procfs is not mounted.
            NETLINK_WORKER.with(|worker| worker.borrow_mut().take());
            with_uncached_netlink(operation)
        }
    }
}

#[cfg(feature = "native-route")]
fn with_netlink_in_namespace<F, Fut, T>(
    namespace: NetworkNamespaceId,
    operation: F,
) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    NETLINK_WORKER.with(|worker| {
        let mut worker = worker.borrow_mut();
        if worker
            .as_ref()
            .is_none_or(|worker| worker.namespace != namespace)
        {
            // Linux network namespaces are selected per calling thread. Drop
            // and join a worker inherited from an earlier namespace before
            // opening a netlink socket in the caller's current namespace.
            worker.take();
            *worker = Some(NetlinkWorker::start(namespace)?);
        }
        let result = worker
            .as_ref()
            .expect("the netlink worker was initialized above")
            .execute(operation);
        match result {
            Ok(value) => Ok(value),
            Err(NetlinkExecutionError::Operation(error)) => Err(error),
            Err(NetlinkExecutionError::Worker(error)) => {
                // A broken command or response channel means this worker can
                // no longer make progress. Joining it here lets the next call
                // initialize a fresh worker instead of retaining a dead one.
                worker.take();
                Err(error)
            }
        }
    })
}

#[cfg(feature = "native-route")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NetworkNamespaceId {
    device: u64,
    inode: u64,
}

#[cfg(feature = "native-route")]
fn current_network_namespace() -> Option<NetworkNamespaceId> {
    let metadata = fs::metadata("/proc/thread-self/ns/net").ok()?;
    Some(NetworkNamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(feature = "native-route")]
fn with_uncached_netlink<F, Fut, T>(operation: F) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .map_err(|error| os_error("create Tokio netlink runtime", error))?;
            runtime.block_on(async move {
                let (connection, handle, _) = new_connection()
                    .map_err(|error| os_error("open route netlink socket", error))?;
                let connection = tokio::spawn(connection);
                let result = operation(handle).await;
                connection.abort();
                result
            })
        })
        .map_err(|error| os_error("spawn netlink worker", error))?
        .join()
        .map_err(|_| netlink_worker_panicked())?
}

#[cfg(feature = "native-route")]
thread_local! {
    static NETLINK_WORKER: RefCell<Option<NetlinkWorker>> = const { RefCell::new(None) };
}

#[cfg(feature = "native-route")]
type ErasedNetlinkResult = Result<Box<dyn Any + Send>, NativeRouteError>;

#[cfg(feature = "native-route")]
type NetlinkFuture = Pin<Box<dyn Future<Output = ErasedNetlinkResult> + Send>>;

#[cfg(feature = "native-route")]
type NetlinkOperation = Box<dyn FnOnce(Handle) -> NetlinkFuture + Send>;

#[cfg(feature = "native-route")]
enum NetlinkCommand {
    Execute {
        operation: NetlinkOperation,
        response: SyncSender<ErasedNetlinkResult>,
    },
    Shutdown,
}

#[cfg(feature = "native-route")]
struct NetlinkWorker {
    namespace: NetworkNamespaceId,
    commands: Sender<NetlinkCommand>,
    thread: Option<JoinHandle<()>>,
}

#[cfg(feature = "native-route")]
impl NetlinkWorker {
    fn start(namespace: NetworkNamespaceId) -> Result<Self, NativeRouteError> {
        let (commands, command_receiver) = mpsc::channel();
        let (setup_sender, setup_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("packetcraftr-netlink".to_owned())
            .spawn(move || netlink_worker(command_receiver, setup_sender))
            .map_err(|error| os_error("spawn netlink worker", error))?;

        match setup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                namespace,
                commands,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                if thread.join().is_err() {
                    Err(netlink_worker_panicked())
                } else {
                    Err(netlink_channel_error("setup response channel closed"))
                }
            }
        }
    }

    fn execute<F, Fut, T>(&self, operation: F) -> Result<T, NetlinkExecutionError>
    where
        F: FnOnce(Handle) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
        T: Send + 'static,
    {
        let operation = Box::new(move |handle| {
            Box::pin(async move {
                operation(handle)
                    .await
                    .map(|value| Box::new(value) as Box<dyn Any + Send>)
            }) as NetlinkFuture
        });
        let (response, receiver) = mpsc::sync_channel(1);
        self.commands
            .send(NetlinkCommand::Execute {
                operation,
                response,
            })
            .map_err(|_| {
                NetlinkExecutionError::Worker(netlink_channel_error("command channel closed"))
            })?;
        let response = receiver.recv().map_err(|_| {
            NetlinkExecutionError::Worker(netlink_channel_error("response channel closed"))
        })?;
        let value = response.map_err(NetlinkExecutionError::Operation)?;
        value.downcast::<T>().map(|value| *value).map_err(|_| {
            NetlinkExecutionError::Worker(netlink_channel_error(
                "returned an unexpected response type",
            ))
        })
    }

    fn shutdown(&mut self) -> Result<(), NativeRouteError> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let send_result = self.commands.send(NetlinkCommand::Shutdown);
        if thread.join().is_err() {
            return Err(netlink_worker_panicked());
        }
        send_result.map_err(|_| netlink_channel_error("shutdown command channel closed"))
    }
}

#[cfg(feature = "native-route")]
impl Drop for NetlinkWorker {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(feature = "native-route")]
#[derive(Debug)]
enum NetlinkExecutionError {
    Operation(NativeRouteError),
    Worker(NativeRouteError),
}

#[cfg(feature = "native-route")]
fn netlink_worker(
    commands: Receiver<NetlinkCommand>,
    setup: SyncSender<Result<(), NativeRouteError>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = setup.send(Err(os_error("create Tokio netlink runtime", error)));
            return;
        }
    };
    let (connection, handle, _) = match runtime.block_on(async { new_connection() }) {
        Ok(parts) => parts,
        Err(error) => {
            let _ = setup.send(Err(os_error("open route netlink socket", error)));
            return;
        }
    };
    let connection = runtime.spawn(connection);
    if setup.send(Ok(())).is_err() {
        connection.abort();
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            NetlinkCommand::Execute {
                operation,
                response,
            } => {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(operation(handle.clone()))
                }))
                .unwrap_or_else(|_| Err(netlink_worker_panicked()));
                let _ = response.send(result);
            }
            NetlinkCommand::Shutdown => break,
        }
    }
    connection.abort();
}

#[cfg(feature = "native-route")]
fn netlink_worker_panicked() -> NativeRouteError {
    NativeRouteError::InvalidResponse {
        message: "Linux netlink worker panicked".to_owned(),
    }
}

#[cfg(feature = "native-route")]
fn netlink_channel_error(message: &'static str) -> NativeRouteError {
    NativeRouteError::InvalidResponse {
        message: format!("Linux netlink worker {message}"),
    }
}

#[cfg(feature = "native-route")]
async fn query_interfaces(handle: &Handle) -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    let mut links = handle.link().get().execute();
    let mut interfaces = BTreeMap::new();
    while let Some(message) = links
        .try_next()
        .await
        .map_err(|error| os_error("RTM_GETLINK", error))?
    {
        let mut name = None;
        let mut description = None;
        let mut mac_address = None;
        let mut mtu = None;
        for attribute in message.attributes {
            match attribute {
                LinkAttribute::IfName(value) => name = Some(value),
                LinkAttribute::IfAlias(value) if !value.is_empty() => description = Some(value),
                LinkAttribute::Address(value) if value.len() == 6 => {
                    let mut address = [0_u8; 6];
                    address.copy_from_slice(&value);
                    mac_address = Some(MacAddress(address));
                }
                LinkAttribute::Mtu(value) => mtu = Some(value),
                _ => {}
            }
        }
        let name = name.ok_or_else(|| NativeRouteError::InvalidResponse {
            message: format!("Linux link {} has no interface name", message.header.index),
        })?;
        let loopback = message.header.flags.contains(LinkFlags::Loopback)
            || message.header.link_layer_type == LinkLayerType::Loopback;
        let ethernet = message.header.link_layer_type == LinkLayerType::Ether;
        interfaces.insert(
            message.header.index,
            InterfaceInfo {
                id: InterfaceId {
                    name,
                    index: message.header.index,
                },
                description,
                mac_address,
                addresses: Vec::new(),
                flags: InterfaceFlags {
                    up: message.header.flags.contains(LinkFlags::Up),
                    broadcast: message.header.flags.contains(LinkFlags::Broadcast),
                    loopback,
                    point_to_point: message.header.flags.contains(LinkFlags::Pointopoint),
                    multicast: message.header.flags.contains(LinkFlags::Multicast),
                },
                mtu,
                capability: if ethernet && mac_address.is_some() {
                    LinkCapability::Layer2And3
                } else {
                    LinkCapability::Layer3
                },
                link_type: if ethernet {
                    LinkType::ETHERNET
                } else {
                    LinkType::RAW
                },
            },
        );
    }

    let mut addresses = handle.address().get().execute();
    while let Some(message) = addresses
        .try_next()
        .await
        .map_err(|error| os_error("RTM_GETADDR", error))?
    {
        let Some(interface) = interfaces.get_mut(&message.header.index) else {
            continue;
        };
        let address = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(address) => Some(*address),
                _ => None,
            })
            .or_else(|| {
                message
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        AddressAttribute::Address(address) => Some(*address),
                        _ => None,
                    })
            });
        if let Some(address) = address {
            let assigned = InterfaceAddress {
                address,
                prefix_length: message.header.prefix_len,
            };
            if !interface.addresses.contains(&assigned) {
                interface.addresses.push(assigned);
            }
        }
    }
    Ok(interfaces.into_values().collect())
}

#[cfg(feature = "native-route")]
fn route_request(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> rtnetlink::packet_route::route::RouteMessage {
    match destination {
        IpAddr::V4(destination) => {
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(destination, u32::BITS as u8);
            if let Some(interface) = interface_hint {
                builder = builder.output_interface(interface.index);
            }
            if let Some(IpAddr::V4(source)) = preferred_source {
                builder = builder.source_prefix(source, u32::BITS as u8);
            }
            builder.build()
        }
        IpAddr::V6(destination) => {
            let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(destination, u128::BITS as u8);
            if let Some(interface) = interface_hint {
                builder = builder.output_interface(interface.index);
            }
            if let Some(IpAddr::V6(source)) = preferred_source {
                builder = builder.source_prefix(source, u128::BITS as u8);
            }
            builder.build()
        }
    }
}

#[cfg(feature = "native-route")]
fn route_address(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

#[cfg(feature = "native-route")]
fn os_error(operation: &'static str, error: impl std::fmt::Display) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: error.to_string(),
    }
}

#[cfg(all(test, feature = "native-route"))]
mod tests {
    use super::*;
    use crate::net::route::Provider as RouteProvider;
    use std::collections::HashSet;

    fn worker_thread_id() -> thread::ThreadId {
        with_netlink(|_| async { Ok(thread::current().id()) }).unwrap()
    }

    #[test]
    fn native_linux_provider_finds_loopback_routes_and_interfaces() {
        let interfaces = interfaces().unwrap();
        assert!(interfaces.iter().any(|interface| interface.flags.loopback));

        let provider = crate::net::route::SystemProvider;
        let ipv4 = provider
            .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
            .unwrap();
        assert_eq!(ipv4.selection_reason, RouteSelectionReason::Local);
        assert!(ipv4.selected_address.is_some_and(|source| source.is_ipv4()));

        let ipv6 = provider
            .lookup(IpAddr::V6(Ipv6Addr::LOCALHOST), None)
            .unwrap();
        assert_eq!(ipv6.selection_reason, RouteSelectionReason::Local);
        assert!(ipv6.selected_address.is_some_and(|source| source.is_ipv6()));
    }

    #[test]
    fn repeated_lookups_reuse_the_calling_threads_netlink_worker() {
        let first_worker = worker_thread_id();
        crate::net::route::SystemProvider
            .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
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
                crate::net::route::SystemProvider
                    .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
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
                        crate::net::route::SystemProvider
                            .lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
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
