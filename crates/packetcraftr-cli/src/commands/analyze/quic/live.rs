use super::{arguments::Args, keylog, rendering::State};
use crate::{errors::CliError, invocation::Invocation, output, system};
use packetcraftr::Sink as _;
use packetcraftr_core::{
    analysis::{self, quic},
    capture_file,
    error::{BoundaryError, Kind},
};
use packetcraftr_netio as net;
use std::sync::{Arc, Mutex};

struct Context {
    pipeline: analysis::FramePipeline,
    collector: quic::Collector,
    secrets: keylog::Input,
    state: State,
    interfaces: Vec<capture_file::Interface>,
}
pub(super) struct Outcome {
    pub run: analysis::Summary,
    pub capture: output::capture::Snapshot,
    pub collector: quic::Collector,
    pub secrets: keylog::Input,
    pub state: State,
}
pub(super) fn run(
    args: &Args,
    setup: &crate::commands::offline_analysis::AnalysisSetup,
    collector: quic::Collector,
    secrets: keylog::Input,
    state: State,
    invocation: &Invocation,
) -> Result<Outcome, CliError> {
    let interfaces = system::resolve_unique(invocation, &args.interface, 256)?;
    let request = packetcraftr::capture::Request::new(
        net::capture::GroupRequest {
            interfaces,
            settings: net::capture::Settings {
                filter: args.capture_filter.clone(),
                promiscuous: args.promiscuous,
                ..net::capture::Settings::new(args.capture.clone().into_limits())
            },
        },
        args.timeout.timeout(),
    );
    let mut options = setup.options(invocation);
    options.track_sources = true;
    let pipeline = analysis::FramePipeline::new(setup.registry.clone(), options)
        .map_err(CliError::classified)?;
    let context = Context {
        pipeline,
        collector,
        secrets,
        state,
        interfaces: Vec::new(),
    };
    let policy = packetcraftr::policy::Policy {
        max_packets_per_operation: setup.limits.max_frames,
        max_bytes_per_operation: setup.limits.max_bytes,
        ..packetcraftr::policy::Policy::default()
    };
    let client = system::client(
        invocation,
        setup.registry.clone(),
        policy,
        system::Runtime::Capture,
    );
    drive(&client, request, context, args, invocation)
}
fn drive<P: packetcraftr::CaptureProviders, K: packetcraftr::clock::Clock>(
    client: &packetcraftr::Client<P, K>,
    request: packetcraftr::capture::Request,
    context: Context,
    args: &Args,
    invocation: &Invocation,
) -> Result<Outcome, CliError> {
    let context = Arc::new(Mutex::new(Some(context)));
    let sink_context = Arc::clone(&context);
    let sink_args = args.clone();
    let sink_invocation = invocation.clone();
    let mut emit = crate::commands::execution::emitter(
        invocation,
        move |event: packetcraftr::capture::Event, encoder| -> Result<(), CliError> {
            let mut guard = sink_context
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let context = guard
                .as_mut()
                .ok_or_else(|| CliError::new(Kind::Internal, "live QUIC state unavailable"))?;
            let Context {
                pipeline,
                collector,
                secrets,
                state,
                interfaces,
            } = context;
            let args = &sink_args;
            let invocation = &sink_invocation;
            match event {
                packetcraftr::capture::Event::Started { sources } => {
                    *interfaces = sources
                        .iter()
                        .map(|source| {
                            crate::capture_output::source_interface(
                                source,
                                capture_file::Format::PcapNg,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(CliError::classified)?;
                }
                packetcraftr::capture::Event::Frame {
                    source_frame,
                    frame,
                    ..
                } => {
                    secrets.poll(collector, invocation, false)?;
                    collector
                        .refresh(&invocation.control.io_control(), |event| {
                            state
                                .event(event, args, invocation, encoder)
                                .map_err(CliError::into_boundary_error)
                        })
                        .map_err(CliError::classified)?;
                    pipeline
                        .push(
                            source_frame,
                            frame,
                            |_| Ok(()),
                            |record| {
                                for event in collector
                                    .observe(&record)
                                    .map_err(BoundaryError::from_error)?
                                {
                                    state
                                        .event(event, args, invocation, encoder)
                                        .map_err(CliError::into_boundary_error)?;
                                }
                                Ok(())
                            },
                        )
                        .map_err(CliError::classified)?;
                }
            }
            Ok(())
        },
    )?;
    let sink = packetcraftr::forwarding(move |event, control| {
        match control {
            Some(control) => emit.publish_controlled(event, control),
            None => emit.publish(event),
        }
        .map(|()| packetcraftr::capture::Control::Continue)
    });
    let result = client.capture(request, sink);
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            let snapshot = output::capture::Snapshot::from((error.report.as_ref(), None));
            return Err(CliError::classified(error).with_capture(snapshot));
        }
    };
    let snapshot = output::capture::Snapshot::from((&report, None));
    let context = context
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .ok_or_else(|| CliError::new(Kind::Internal, "live QUIC state unavailable"))?;
    let run = context
        .pipeline
        .finish(context.interfaces, |_| Ok(()))
        .map_err(|e| CliError::classified(e).with_capture(snapshot.clone()))?;
    Ok(Outcome {
        run,
        capture: snapshot,
        collector: context.collector,
        secrets: context.secrets,
        state: context.state,
    })
}

#[cfg(test)]
mod tests;
