// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live workflow orchestration shared by the probe-driven commands:
//! provider composition ([`prepare`]/[`Providers`]), the per-invocation
//! [`WorkflowSession`], and [`run_workflow`], the one driver deciding between
//! the streaming and collecting engine entry points under the negotiated
//! output format. The deferred interface resolves once inside [`Executor`],
//! then delegates to the library exchange.

use crate::command_options::{FuzzPolicyArgs, HostnamePolicyArgs, RouteSelectionArgs};
use crate::system::{client, exchange};
use packetcraftr_cli::output;
use packetcraftr_core as core;
use packetcraftr_netio as net;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::errors::CliError;
use crate::rendering::StreamEncoder;
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
    fn pipeline_capacity(&self) -> usize {
        // A throwaway exchange, not `self.prepared()`: capacity is intrinsic
        // to the request type, and binding the deferred interface here would
        // touch the platform's interface list before target authorization.
        <Exchange<'_> as packetcraftr::probe::Executor<Req>>::pipeline_capacity(&Exchange::new(
            &self.client,
            self.exchange.clone(),
        ))
    }
    fn execute_pipeline(
        &mut self,
        requests: &[Req],
        options: packetcraftr::probe::PipelineOptions,
        emit: &mut dyn FnMut(
            packetcraftr::probe::PipelineEvent<Req::Execution>,
        ) -> Result<(), core::error::BoundaryError>,
    ) -> Result<packetcraftr::Stats, core::error::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute_pipeline(requests, options, emit)
    }
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
        // Direct TCP reaches this path without preparing any UDP exchange.
        // CLI admission rejects packet-oriented overrides before execution;
        // the socket adapter independently validates materialized options.
        Exchange::new(&self.client, self.exchange.clone())
            .with_dns_tcp(net::tcp::SystemProvider)
            .execute_tcp(exchange)
    }
}

pub(super) struct Providers<P = Executor> {
    policy: Arc<packetcraftr::policy::Policy>,
    /// The resolver the session authorizer resolves declared targets with.
    resolver: packetcraftr::target::SystemResolver,
    registry: Arc<core::registry::Registry>,
    /// Packet exchange executor, or socket provider for connect-only scans.
    executor: P,
    /// Admits the one callback worker NDJSON streaming publishes through.
    runtime: packetcraftr::progress::Runtime,
}

impl Providers<Executor> {
    /// Vends the live-run session the workflow commands drive: the authorizer
    /// over the composed policy and the system resolver, the clock sharing
    /// the installed cancellation signal, and the registry, executor, and
    /// callback worker the engines drive.
    pub(super) fn session(&mut self) -> WorkflowSession<'_> {
        WorkflowSession {
            authorizer: packetcraftr::policy::PolicyAuthorizer::new(&self.policy, &self.resolver),
            clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
            registry: &self.registry,
            executor: &mut self.executor,
            runtime: &self.runtime,
        }
    }

    /// A packet campaign has no hostname to resolve. Keep this authorizer
    /// distinct so a live fuzz case cannot gain hostname-based admission.
    fn packet_session(&mut self) -> WorkflowSession<'_> {
        WorkflowSession {
            authorizer: packetcraftr::policy::PolicyAuthorizer::for_packets(&self.policy),
            clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
            registry: &self.registry,
            executor: &mut self.executor,
            runtime: &self.runtime,
        }
    }
}

impl Providers<Arc<net::tcp::SystemProvider>> {
    pub(super) fn connect_session(&mut self) -> ConnectSession<'_> {
        ConnectSession {
            authorizer: packetcraftr::policy::PolicyAuthorizer::new(&self.policy, &self.resolver),
            clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
            provider: Arc::clone(&self.executor),
            runtime: &self.runtime,
        }
    }
}

/// The per-invocation run context [`Providers::session`] vends to a workflow
/// command. Commands lend it to [`run_workflow`], which borrows the pieces
/// each engine entry point needs.
pub(super) struct WorkflowSession<'a> {
    /// Authorizes declared targets and the operation budget.
    pub(super) authorizer: packetcraftr::policy::PolicyAuthorizer<'a>,
    /// Pacing clock sharing the installed interrupt signal.
    pub(super) clock: packetcraftr::clock::CancellableClock,
    /// The protocol registry the engines decode evidence with.
    pub(super) registry: &'a core::registry::Registry,
    /// The exchange executor probe requests run through.
    pub(super) executor: &'a mut Executor,
    /// The bounded callback worker NDJSON streaming publishes through.
    pub(super) runtime: &'a packetcraftr::progress::Runtime,
}

/// Socket-only scan session: authorization still precedes TCP connection and
/// no packet exchange/interface discovery is needed.
pub(super) struct ConnectSession<'a> {
    pub(super) authorizer: packetcraftr::policy::PolicyAuthorizer<'a>,
    pub(super) clock: packetcraftr::clock::CancellableClock,
    pub(super) provider: Arc<net::tcp::SystemProvider>,
    pub(super) runtime: &'a packetcraftr::progress::Runtime,
}

/// Live fuzz options and the providers that prepare its packet executor.
pub(super) struct FuzzLive {
    providers: Providers,
    pub(super) options: packetcraftr::fuzz::LiveOptions,
}

impl FuzzLive {
    pub(super) fn registry(&self) -> Arc<core::registry::Registry> {
        Arc::clone(&self.providers.registry)
    }

    pub(super) fn session(&mut self) -> WorkflowSession<'_> {
        self.providers.packet_session()
    }
}

pub(super) struct FuzzSettings {
    pub(super) route: RouteSelectionArgs,
    pub(super) policy: FuzzPolicyArgs,
    pub(super) build: core::build::Options,
    pub(super) timeout: Duration,
    pub(super) rate: Option<u32>,
    pub(super) destination: Option<IpAddr>,
    pub(super) allow_permissive_live: bool,
    pub(super) queue_limits: net::capture::Limits,
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
    Ok(compose_packet(
        policy,
        exchange,
        interface,
        "workflow_progress",
    ))
}

/// Connect uses the same authorizer, clock and callback runtime as the other
/// live workflows, without preparing an unused packet route or binding any
/// interface before its target is authorized.
pub(super) fn prepare_connect(
    policy: HostnamePolicyArgs,
) -> Result<Providers<Arc<net::tcp::SystemProvider>>, CliError> {
    let policy = Arc::new(policy.into_policy());
    policy.validate().map_err(CliError::classified)?;
    Ok(compose(
        policy,
        packetcraftr_core::protocol::builtin::registry(),
        Arc::new(net::tcp::SystemProvider),
        "scan_connect",
    ))
}

/// Prepare packet-oriented fuzz under the same deferred executor as scan/DNS.
/// No interface is enumerated until the campaign has authorized its packets.
pub(super) fn prepare_fuzz_live(settings: FuzzSettings) -> Result<FuzzLive, CliError> {
    let options = packetcraftr::fuzz::LiveOptions {
        timeout: settings.timeout,
        cases_per_second: settings.rate,
        destination: settings.destination,
        allow_malformed_live: settings.allow_permissive_live,
        limits: packetcraftr::fuzz::LiveLimits {
            max_evidence_frames: settings.queue_limits.max_frames,
            max_evidence_bytes: settings.queue_limits.max_bytes,
        },
    };
    options.validate().map_err(CliError::classified)?;
    let policy = Arc::new(settings.policy.into_policy());
    policy.validate().map_err(CliError::classified)?;
    let interface = InterfaceSelector::parse_optional(settings.route.interface.as_deref())?;
    let exchange = exchange::options(
        packetcraftr::send::Options {
            destination: settings.destination,
            plan: net::route::Options {
                link_mode: settings.route.link_mode.into(),
                interface: None,
                preferred_source: settings.route.source,
            },
            build: settings.build,
            allow_permissive_live: settings.allow_permissive_live,
        },
        settings.timeout,
        1,
        settings.queue_limits,
    )?;
    Ok(FuzzLive {
        providers: compose_packet(policy, exchange, interface, "fuzz_progress"),
        options,
    })
}

fn compose_packet(
    policy: Arc<packetcraftr::policy::Policy>,
    exchange: packetcraftr::exchange::Options,
    interface: Option<InterfaceSelector>,
    runtime_name: &'static str,
) -> Providers {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface,
    };
    compose(policy, registry, executor, runtime_name)
}

fn compose<P>(
    policy: Arc<packetcraftr::policy::Policy>,
    registry: Arc<core::registry::Registry>,
    executor: P,
    runtime_name: &'static str,
) -> Providers<P> {
    Providers {
        policy,
        resolver: packetcraftr::target::SystemResolver,
        registry,
        executor,
        runtime: crate::resources::runtime(
            runtime_name,
            packetcraftr::progress::MAX_WORKER_CAPACITY,
        ),
    }
}

/// The event sink a streaming engine entry point receives. Engines publish
/// through a runtime-budgeted worker, so the sink is `Send` and `'static`.
pub(super) type Emit<E> = Box<dyn FnMut(E) -> Result<(), core::error::BoundaryError> + Send>;

/// The collecting engine entry point: runs the workflow into a report.
type Collect<'a, S, R> = Box<dyn FnOnce(&mut S) -> Result<R, CliError> + 'a>;

/// The streaming engine entry point: publishes each event through the sink.
type Publish<'a, S, E, U> = Box<dyn FnOnce(&mut S, Emit<E>) -> Result<U, CliError> + 'a>;

/// The render dispatch for text or exchange capture formats. All of these
/// formats receive the same converted report as the JSON envelope.
type Render<'a, T, F> =
    Box<dyn FnOnce(output::workflow::Converted<T>, F) -> Result<(), CliError> + 'a>;

/// A workflow command supplies only its identity, two engine entry points,
/// output conversion owner, and renderer over the already converted report.
/// `S` is the invocation session or `()` for a self-contained provider.
pub(super) struct Hooks<'a, S, C, F>
where
    C: output::workflow::Conversion,
{
    pub(super) command: output::contract::Command,
    pub(super) conversion: C,
    pub(super) run: Collect<'a, S, C::EngineReport>,
    pub(super) run_with_events: Publish<'a, S, C::EngineEvent, C::EngineSummary>,
    pub(super) render_text: Render<'a, C::Result, F>,
}

/// Drives one workflow under the negotiated `format`.
///
/// NDJSON converts each event and the terminal summary through `C`; all
/// other formats convert the collected report exactly once before rendering.
/// Every streamed emission passes the same cancellation/deadline guard.
pub(super) fn run_workflow<S, C, F>(
    session: &mut S,
    format: F,
    stream: &StreamEncoder,
    cancellation: &core::budget::Cancellation,
    hooks: Hooks<'_, S, C, F>,
) -> Result<(), CliError>
where
    C: output::workflow::Conversion,
    C::EngineEvent: 'static,
    F: Copy + Into<output::contract::Format>,
{
    let Hooks {
        command,
        conversion: _conversion,
        run,
        run_with_events,
        render_text,
    } = hooks;
    match format.into() {
        output::contract::Format::Ndjson => {
            let events = stream.clone();
            let cancellation = cancellation.clone();
            let summary = run_with_events(
                session,
                Box::new(move |event| {
                    emission_check(&cancellation).map_err(CliError::into_boundary_error)?;
                    let (record, diagnostics) = C::event(event)
                        .map_err(CliError::classified)
                        .map_err(CliError::into_boundary_error)?;
                    events
                        .emit_data(record, diagnostics)
                        .map_err(CliError::from)
                        .map_err(CliError::into_boundary_error)
                }),
            )?;
            let (record, diagnostics, stats) = C::summary(summary).map_err(CliError::classified)?;
            match stats {
                Some(stats) => stream.complete_with_stats(record, diagnostics, stats)?,
                None => stream.complete(record, diagnostics)?,
            }
            Ok(())
        }
        wide => {
            let report = run(session)?;
            emission_check(cancellation)?;
            let converted = C::report(report).map_err(CliError::classified)?;
            if wide == output::contract::Format::Json {
                let output::workflow::Converted {
                    result,
                    diagnostics,
                    stats,
                    ..
                } = converted;
                match stats {
                    Some(stats) => crate::rendering::emit_aggregate_with_stats(
                        command,
                        result,
                        diagnostics,
                        stats,
                    ),
                    None => crate::rendering::emit_aggregate(command, result, diagnostics),
                }
            } else {
                render_text(converted, format)
            }
        }
    }
}

/// The emission guard: the workflow's cancellation token plus the installed
/// invocation deadline — the same coverage `cancellation::check` gives the
/// process signal, with the token injectable for tests.
fn emission_check(cancellation: &core::budget::Cancellation) -> Result<(), CliError> {
    cancellation.check().map_err(CliError::classified)?;
    crate::invocation::check()
}

#[cfg(test)]
mod tests {
    use packetcraftr_netio as net;

    use super::*;
    use crate::system::client;

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

    mod workflow {
        use std::cell::RefCell;

        use super::*;
        use crate::test_support::{TestRecord, assert_contiguous, stream};
        use packetcraftr_cli::output::contract::{ExchangeFormat, ToolFormat};
        use packetcraftr_core::budget::Cancellation;

        /// A terminal record the scripted `complete` hook publishes.
        #[derive(serde::Serialize)]
        struct Complete(u64);

        impl output::stream::StreamRecord for Complete {
            fn event_name(&self) -> &'static str {
                "complete"
            }
        }

        struct Script<'a>(std::marker::PhantomData<&'a ()>);

        impl<'a> output::workflow::Conversion for Script<'a> {
            type EngineEvent = u64;
            type EngineSummary = u64;
            type EngineReport = (u64, &'a RefCell<Vec<String>>);
            type Event = TestRecord<u64>;
            type Terminal = Complete;
            type Result = u64;

            fn event(
                event: u64,
            ) -> Result<(TestRecord<u64>, Vec<core::diagnostic::Diagnostic>), output::contract::Error>
            {
                if event == 99 {
                    return Err(output::contract::Error::IncoherentFuzzEvents {
                        message: "adapter refused".to_owned(),
                    });
                }
                Ok((TestRecord(event), Vec::new()))
            }

            fn summary(
                summary: u64,
            ) -> Result<
                (
                    Complete,
                    Vec<core::diagnostic::Diagnostic>,
                    Option<packetcraftr::Stats>,
                ),
                output::contract::Error,
            > {
                Ok((Complete(summary), Vec::new(), None))
            }

            fn report(
                (report, log): Self::EngineReport,
            ) -> Result<output::workflow::Converted<u64>, output::contract::Error> {
                log.borrow_mut().push("converted".to_owned());
                Ok(output::workflow::Converted::new(report, Vec::new(), None))
            }
        }

        /// Scripted hooks recording the entry points and adapters the driver
        /// invokes; the wire buffer records what the stream adapters publish.
        fn hooks<'a>(
            log: &'a RefCell<Vec<String>>,
            stream_engine: impl FnOnce(&mut (), Emit<u64>) -> Result<u64, CliError> + 'a,
        ) -> Hooks<'a, (), Script<'a>, ToolFormat> {
            Hooks {
                command: output::contract::Command::Scan,
                conversion: Script(std::marker::PhantomData),
                run: Box::new(|_| {
                    log.borrow_mut().push("run".to_owned());
                    Ok((41_u64, log))
                }),
                run_with_events: Box::new(stream_engine),
                render_text: Box::new(|converted, format| {
                    log.borrow_mut()
                        .push(format!("render_text:{}:{format:?}", converted.result));
                    Ok(())
                }),
            }
        }

        #[test]
        fn ndjson_streams_events_then_the_terminal_record() {
            let (stream, output) = stream(output::contract::Command::Scan);
            let log = RefCell::new(Vec::new());
            run_workflow(
                &mut (),
                ToolFormat::Ndjson,
                &stream,
                &Cancellation::default(),
                hooks(&log, |_, mut emit| {
                    emit(10).map_err(CliError::classified)?;
                    emit(11).map_err(CliError::classified)?;
                    Ok(7_u64)
                }),
            )
            .expect("the scripted stream run succeeds");

            let records = output.records();
            assert_contiguous(&records);
            assert_eq!(records.len(), 3, "two events plus the terminal record");
            assert_eq!(records[0]["event"], "frame");
            assert_eq!(records[0]["result"], 10);
            assert_eq!(records[1]["result"], 11);
            assert_eq!(records[2]["event"], "complete");
            assert_eq!(records[2]["result"], 7);
            assert!(stream.is_complete());
            assert_eq!(*log.borrow(), Vec::<String>::new());
        }

        #[test]
        fn aggregate_text_collects_and_renders() {
            let (stream, output) = stream(output::contract::Command::Scan);
            let log = RefCell::new(Vec::new());
            run_workflow(
                &mut (),
                ToolFormat::Text,
                &stream,
                &Cancellation::default(),
                hooks(&log, |_, _| unreachable!("aggregate never streams")),
            )
            .expect("the scripted aggregate run succeeds");

            assert_eq!(
                *log.borrow(),
                vec![
                    "run".to_owned(),
                    "converted".to_owned(),
                    "render_text:41:Text".to_owned()
                ]
            );
            assert!(
                output.bytes().is_empty(),
                "aggregate formats write no stream records"
            );
        }

        #[test]
        fn aggregate_json_collects_converts_and_emits() {
            let (stream, output) = stream(output::contract::Command::Scan);
            let log = RefCell::new(Vec::new());
            run_workflow(
                &mut (),
                ToolFormat::Json,
                &stream,
                &Cancellation::default(),
                hooks(&log, |_, _| unreachable!("aggregate never streams")),
            )
            .expect("the scripted aggregate run succeeds");

            assert_eq!(
                *log.borrow(),
                vec!["run".to_owned(), "converted".to_owned()]
            );
            assert!(
                output.bytes().is_empty(),
                "aggregate formats write no stream records"
            );
        }

        #[test]
        fn other_render_formats_reach_render_text_with_the_format() {
            let (stream, _output) = stream(output::contract::Command::Exchange);
            let log = RefCell::new(Vec::new());
            let hooks = Hooks {
                command: output::contract::Command::Exchange,
                conversion: Script(std::marker::PhantomData),
                run: Box::new(|_: &mut ()| Ok((41_u64, &log))),
                run_with_events: Box::new(|_: &mut (), _: Emit<u64>| {
                    unreachable!("aggregate never streams")
                }),
                render_text: Box::new(
                    |converted: output::workflow::Converted<u64>, format: ExchangeFormat| {
                        log.borrow_mut()
                            .push(format!("render_text:{}:{format:?}", converted.result));
                        Ok(())
                    },
                ),
            };
            run_workflow(
                &mut (),
                ExchangeFormat::PcapNg,
                &stream,
                &Cancellation::default(),
                hooks,
            )
            .expect("the scripted capture run succeeds");

            assert_eq!(
                *log.borrow(),
                vec!["converted".to_owned(), "render_text:41:PcapNg".to_owned()]
            );
        }

        #[test]
        fn cancellation_during_emission_fails_before_the_terminal_record() {
            let (stream, output) = stream(output::contract::Command::Scan);
            let cancellation = Cancellation::default();
            let injector = cancellation.clone();
            let log = RefCell::new(Vec::new());
            let error = run_workflow(
                &mut (),
                ToolFormat::Ndjson,
                &stream,
                &cancellation,
                hooks(&log, move |_, mut emit| {
                    emit(10).map_err(CliError::classified)?;
                    injector.cancel();
                    emit(11).map_err(CliError::classified)?;
                    Ok(0_u64)
                }),
            )
            .expect_err("the cancelled emission fails the run");

            assert_eq!(error.exit_code(), 5, "io.cancelled keeps the I/O exit code");
            let records = output.records();
            assert_eq!(records.len(), 1, "the cancelled second event never emits");
            assert_eq!(records[0]["result"], 10);
            assert!(stream.is_open(), "a cancelled run emits no terminal record");
        }

        #[test]
        fn an_event_adapter_failure_aborts_the_stream() {
            let (stream, output) = stream(output::contract::Command::Scan);
            let log = RefCell::new(Vec::new());
            let hooks = hooks(&log, |_, mut emit| {
                emit(10).map_err(CliError::classified)?;
                emit(99).map_err(CliError::classified)?;
                Ok(0_u64)
            });
            let error = run_workflow(
                &mut (),
                ToolFormat::Ndjson,
                &stream,
                &Cancellation::default(),
                hooks,
            )
            .expect_err("the adapter failure propagates");

            assert_eq!(error.exit_code(), 70);
            let records = output.records();
            assert_eq!(records.len(), 1, "only the first event emitted");
            assert!(stream.is_open());
        }
    }
}
