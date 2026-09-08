// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live workflow executor shared by the probe-driven commands. It resolves
//! the deferred interface once, then delegates to the library exchange.

use super::registry;
use crate::command_options::{HostnamePolicyArgs, RouteSelectionArgs};
use crate::system::{client, exchange};
use packetcraftr_core as core;
use packetcraftr_netio as net;
use std::sync::Arc;
use std::time::Duration;

use crate::errors::CliError;
use crate::system::{Client, Exchange, InterfaceSelector, resolve};

pub(super) struct Executor {
    pub(super) client: Client,
    pub(super) exchange: packetcraftr::exchange::Options,
    /// Resolved against the system provider on first execution.
    ///
    /// The lookup is deferred so interface enumeration never precedes target
    /// authorization: a denied target must be refused before the process
    /// touches the platform's interface list.
    pub(super) interface: Option<InterfaceSelector>,
}

impl Executor {
    /// Binds the deferred `--interface` selector, once.
    ///
    /// The selector is cleared only after the lookup succeeds, so a failed
    /// lookup never leaves a later attempt unconstrained.
    fn bind_interface<P: packetcraftr_netio::interface::Provider>(
        &mut self,
        provider: &P,
    ) -> Result<(), CliError> {
        let Some(selector) = self.interface.clone() else {
            return Ok(());
        };
        self.exchange.send.plan.interface = Some(resolve(selector, provider)?);
        self.interface = None;
        Ok(())
    }

    fn prepared(&mut self) -> Result<Exchange<'_>, CliError> {
        self.bind_interface(&packetcraftr_netio::interface::SystemProvider)?;
        Ok(packetcraftr::probe::ExchangeExecutor::new(
            &self.client,
            self.exchange.clone(),
        ))
    }
}

/// Every live workflow request the library's exchange executor accepts is
/// served the same way: bind the interface once, then delegate.
impl<Req> packetcraftr::probe::Executor<Req> for Executor
where
    Req: packetcraftr::probe::Request,
    for<'a> Exchange<'a>: packetcraftr::probe::Executor<Req>,
{
    fn execute(
        &mut self,
        request: &Req,
    ) -> Result<Req::Execution, packetcraftr_core::error::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(request)
    }
}

impl packetcraftr::dns::TcpExecutor for Executor {
    fn execute_tcp(
        &mut self,
        exchange: &packetcraftr::dns::TcpExchange,
    ) -> Result<packetcraftr::dns::TcpExecution, packetcraftr::dns::tcp::Error> {
        // TCP only continues a truncated UDP answer, so the UDP execution has
        // already bound the interface; the kernel socket cannot honour it.
        Exchange::new(&self.client, self.exchange.clone())
            .with_dns_tcp(net::tcp::SystemProvider)
            .execute_tcp(exchange)
    }
}

/// The providers the three commands compose identically once their request is
/// built.
pub(super) struct Providers {
    pub(super) policy: Arc<packetcraftr::policy::Policy>,
    pub(super) registry: Arc<core::registry::Registry>,
    pub(super) executor: Executor,
    /// Admits the one callback worker NDJSON streaming publishes through.
    pub(super) runtime: packetcraftr::progress::Runtime,
}

/// Validates the policy and interface selector, then binds an executor to the
/// requested route.
///
/// `max_template_packets` is how many packets one exchange may hold: one query
/// for `dns`, one probe for `scan`, one attempt per hop for `traceroute`.
pub(super) fn prepare(
    route: RouteSelectionArgs,
    policy: HostnamePolicyArgs,
    timeout: Duration,
    max_template_packets: usize,
    queue_limits: net::capture::Limits,
) -> Result<Providers, CliError> {
    let policy = Arc::new(policy.into_policy());
    policy.validate().map_err(CliError::classified)?;
    let interface = InterfaceSelector::parse_optional(route.interface.as_deref())?;
    let registry = registry()?;
    let exchange = exchange::options(
        packetcraftr::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: route.link_mode.into(),
                interface: None,
                preferred_source: route.source,
            },
            build: core::build::Options::default(),
            allow_permissive_live: false,
        },
        timeout,
        max_template_packets,
        queue_limits,
    )?;
    let executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface,
    };
    Ok(Providers {
        policy,
        registry,
        executor,
        runtime: packetcraftr::progress::Runtime::default(),
    })
}

#[cfg(test)]
mod tests {
    use packetcraftr_netio as net;

    use super::*;
    use crate::system::client;

    /// Fails the first enumeration, then reports one interface.
    #[derive(Default)]
    struct FlakyProvider {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl net::interface::Provider for FlakyProvider {
        fn interfaces(&self) -> Result<Vec<net::interface::Info>, net::Error> {
            let call = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if call == 0 {
                return Err(net::Error::InterfaceDiscovery {
                    message: "fixture enumeration failure".to_owned(),
                    source: None,
                });
            }
            Ok(vec![net::interface::Info {
                id: net::interface::Id {
                    name: "fixture0".to_owned(),
                    index: 9,
                },
                description: None,
                mac_address: None,
                addresses: Vec::new(),
                flags: net::interface::Flags::default(),
                mtu: None,
                capability: net::link::Capability::Layer2AndLayer3,
                link_type: packetcraftr_core::frame::LinkType::ETHERNET,
            }])
        }
    }

    fn executor() -> Executor {
        let registry = packetcraftr_core::protocol::builtin::registry();
        let policy = packetcraftr::policy::Policy::default();
        Executor {
            client: client(registry, policy),
            exchange: packetcraftr::exchange::Options::default(),
            interface: Some(InterfaceSelector::parse("fixture0").expect("fixture selector")),
        }
    }

    #[test]
    fn a_failed_interface_lookup_keeps_the_selector_pending() {
        let provider = FlakyProvider::default();
        let mut executor = executor();

        let error = executor
            .bind_interface(&provider)
            .expect_err("the first enumeration fails");
        assert_eq!(error.exit_code(), 5);
        assert!(
            executor.interface.is_some(),
            "a failed lookup must not discard the selector",
        );
        assert!(
            executor.exchange.send.plan.interface.is_none(),
            "a failed lookup must not leave an unconstrained plan",
        );

        executor
            .bind_interface(&provider)
            .expect("the second enumeration succeeds");
        assert!(executor.interface.is_none());
        assert_eq!(
            executor
                .exchange
                .send
                .plan
                .interface
                .as_ref()
                .map(|id| id.index),
            Some(9),
        );
    }
}
