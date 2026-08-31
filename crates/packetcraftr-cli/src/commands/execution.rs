// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live workflow executor shared by the probe-driven commands. Each workflow
//! trait resolves the deferred interface once, then delegates to the exchange.

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
    /// The selector is cleared only after the lookup succeeds. Clearing it
    /// first would let a second attempt run with no interface constraint at
    /// all and transmit on whatever the route provider picked — the opposite
    /// of what `--interface` asked for.
    fn bind_interface<P: packetcraftr::netio::interface::Provider>(
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
        self.bind_interface(&packetcraftr::netio::interface::SystemProvider)?;
        Ok(packetcraftr::ExchangeExecutor::new(
            &self.client,
            self.exchange.clone(),
        ))
    }
}

impl packetcraftr::dns::Executor for Executor {
    fn execute(
        &mut self,
        exchange: &packetcraftr::dns::Exchange,
    ) -> Result<packetcraftr::dns::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(exchange)
    }

    fn execute_tcp(
        &mut self,
        exchange: &packetcraftr::dns::TcpExchange,
    ) -> Result<packetcraftr::dns::TcpExecution, packetcraftr::netio::dns_tcp::Error> {
        let mut executor = packetcraftr::ExchangeExecutor::new(&self.client, self.exchange.clone());
        packetcraftr::dns::Executor::execute_tcp(&mut executor, exchange)
    }
}

impl packetcraftr::scan::Executor<packetcraftr::scan::Probe> for Executor {
    fn execute(
        &mut self,
        batch: &packetcraftr::scan::Batch,
    ) -> Result<packetcraftr::scan::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(batch)
    }
}

impl packetcraftr::traceroute::Executor<packetcraftr::traceroute::Probe> for Executor {
    fn execute(
        &mut self,
        batch: &packetcraftr::traceroute::Batch,
    ) -> Result<packetcraftr::traceroute::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(batch)
    }
}

impl packetcraftr::fuzz::Executor for Executor {
    fn execute(
        &mut self,
        case: &packetcraftr::fuzz::ExecutionCase,
        timeout: Duration,
    ) -> Result<packetcraftr::fuzz::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(case, timeout)
    }
}

#[cfg(test)]
mod tests {
    use packetcraftr::netio as net;

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
                link_type: packetcraftr::core::frame::LinkType::ETHERNET,
            }])
        }
    }

    fn executor() -> Executor {
        let registry = packetcraftr::core::protocol::builtin::registry();
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
