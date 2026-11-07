use super::{arguments::Args, keylog, rendering::State};
use crate::{errors::CliError, invocation::Invocation, output, system};
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
    if args.interface.len() > 256 {
        return Err(CliError::new(
            Kind::Usage,
            "QUIC capture supports at most 256 interface selectors",
        ));
    }
    let interfaces = args
        .interface
        .iter()
        .map(|selector| system::resolve(invocation, selector.get()?))
        .collect::<Result<Vec<_>, CliError>>()?;
    let interfaces = interfaces
        .into_iter()
        .map(|id| (id.index, id))
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_values()
        .collect();
    let request = packetcraftr::capture::Request::new(
        net::capture::GroupRequest {
            interfaces,
            limits: args.capture.clone().into_limits(),
            filter: args.capture_filter.clone(),
            promiscuous: args.promiscuous,
            native: net::capture::NativeSettings::default(),
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
    let result = client.capture(
        request,
        move |event| -> Result<packetcraftr::capture::Control, BoundaryError> {
            let mut guard = sink_context
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let context = guard.as_mut().ok_or_else(|| {
                CliError::new(Kind::Internal, "live QUIC state unavailable").into_boundary_error()
            })?;
            let Context {
                pipeline,
                collector,
                secrets,
                state,
                interfaces,
            } = context;
            let args = &sink_args;
            let invocation = &sink_invocation;
            let encoder = &invocation.output;
            match event {
                packetcraftr::capture::Event::Started { sources } => {
                    *interfaces = sources
                        .iter()
                        .map(|source| capture_file::Interface {
                            link_type: source.metadata.link_type,
                            snap_len: u32::try_from(source.metadata.snap_length)
                                .unwrap_or(u32::MAX),
                            timestamp_resolution: capture_file::TimestampResolution::Decimal(
                                match source.metadata.native.timestamp_precision.effective {
                                    Some(net::capture::TimestampPrecision::Micro) => 6,
                                    _ => 9,
                                },
                            ),
                            timestamp_offset: 0,
                        })
                        .collect();
                }
                packetcraftr::capture::Event::Frame {
                    source_frame,
                    frame,
                    ..
                } => {
                    secrets
                        .poll(collector, invocation, false)
                        .map_err(CliError::into_boundary_error)?;
                    collector.refresh(&invocation.control.io_control(), |event| {
                        state
                            .event(event, args, invocation, encoder)
                            .map_err(CliError::into_boundary_error)
                    })?;
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
                        .map_err(BoundaryError::from_error)?;
                }
            }
            Ok(packetcraftr::capture::Control::Continue)
        },
    );
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
