// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The optional trace stage of a scan: every scanned host, traced under one
//! plan with the probes the scan saw it answer.

use std::time::Duration;

use packetcraftr::probe::Transport;
use packetcraftr::scan::followup;
use packetcraftr::traceroute::hosts;

use crate::commands::traceroute::arguments::Strategy;
use crate::errors::CliError;
use crate::output;
use packetcraftr_core::error::Kind;

/// The `--traceroute-*` options.
pub(super) struct Options {
    pub(super) strategy: Option<Strategy>,
    pub(super) port: Option<u16>,
    pub(super) first_hop: u8,
    pub(super) max_hops: u8,
    pub(super) attempts: u32,
    pub(super) max_probes: usize,
    pub(super) reuse_max_age: Option<Duration>,
}

/// The trace request every scanned host shares, validated before any probe.
pub(super) struct Stage {
    trace: followup::Trace,
    plan: output::traceroute::hosts::Plan,
}

impl Stage {
    pub(super) fn new(
        options: &Options,
        scan: &packetcraftr::scan::Request,
    ) -> Result<Self, CliError> {
        let strategy = match (options.strategy, options.port) {
            (None, Some(_)) => {
                return Err(CliError::new(
                    Kind::Usage,
                    "--traceroute-port requires --traceroute-strategy",
                ));
            }
            (None, None) => None,
            (Some(strategy), port) => {
                let transport = Transport::from(strategy);
                let destination_port = match transport {
                    Transport::Udp => {
                        Some(port.unwrap_or(packetcraftr::traceroute::DEFAULT_UDP_PORT))
                    }
                    Transport::Tcp => {
                        Some(port.unwrap_or(packetcraftr::traceroute::DEFAULT_TCP_PORT))
                    }
                    Transport::Icmp | Transport::Sctp | Transport::Ip => {
                        if port.is_some() {
                            return Err(CliError::new(
                                Kind::Usage,
                                "--traceroute-port does not apply to portless ICMP",
                            ));
                        }
                        None
                    }
                };
                Some(hosts::Strategy {
                    transport,
                    destination_port,
                })
            }
        };
        let trace = followup::Trace {
            strategy,
            first_hop: options.first_hop,
            max_hops: options.max_hops,
            attempts: options.attempts,
            max_probes: options.max_probes,
            reuse: options
                .reuse_max_age
                .map(|max_age| hosts::Reuse { max_age }),
            runtime: None,
        };
        trace.validate(scan).map_err(super::followup_error)?;
        let plan = output::traceroute::hosts::Plan {
            first_hop: options.first_hop,
            max_hops: options.max_hops,
            attempts: options.attempts,
            max_probes: options.max_probes,
            strategy: strategy.map(|strategy| output::traceroute::hosts::StrategyPlan {
                strategy: strategy.transport,
                destination_port: strategy.destination_port,
            }),
            reuse: options
                .reuse_max_age
                .map(|max_age| output::traceroute::hosts::ReusePlan { max_age }),
        };
        Ok(Self { trace, plan })
    }

    pub(super) const fn plan(&self) -> output::traceroute::hosts::Plan {
        self.plan
    }

    /// The trace request, publishing through its own registered runtime.
    pub(super) fn trace(&self, invocation: &crate::invocation::Invocation) -> followup::Trace {
        followup::Trace {
            runtime: Some(crate::system::runtime(
                invocation,
                crate::system::Runtime::Workflow,
            )),
            ..self.trace.clone()
        }
    }

    /// Revalidates the trace against the finalized scan request, which
    /// carries the route and collection the prepared workflow selected: a
    /// queue or evidence configuration the trace cannot run under fails
    /// before the scan sends a probe.
    pub(super) fn revalidate(&self, scan: &packetcraftr::scan::Request) -> Result<(), CliError> {
        self.trace.validate(scan).map_err(super::followup_error)
    }
}
