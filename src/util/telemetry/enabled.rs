// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{info, warn};
use prometheus::{Encoder, IntCounter, IntCounterVec, Registry, TextEncoder};
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

use crate::util::sync::LockResultExt;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);
static FRAMES_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_frames_sent_total",
        "Total number of frames transmitted",
        &["link_type", "transport"],
    )
});
static BYTES_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_bytes_sent_total",
        "Total number of bytes transmitted",
        &["link_type", "transport"],
    )
});
static LISTENER_PACKETS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_listener_packets_total",
        "Packets observed by listener mode",
        &["protocol"],
    )
});
static RULE_ACTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_rule_actions_total",
        "Rule action outcomes",
        &["action", "outcome"],
    )
});
static RULE_ACTION_DROPS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_rule_executor_dropped_total",
        "Rule executor drop reasons",
        &["action", "reason"],
    )
});
static LISTENER_DROPPED_PACKETS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_listener_dropped_packets_total",
        "Packets dropped by listener due to queue capacity",
        &["reason"],
    )
});

pub(crate) type Result<T> = std::result::Result<T, TelemetryError>;

#[derive(Debug)]
pub(crate) struct PrometheusExporterHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) shutdown_tx: oneshot::Sender<()>,
    pub(crate) join_handle: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Error)]
pub(crate) enum TelemetryError {
    #[error("parse prometheus bind address failed: addr='{addr}'")]
    ParseAddress {
        addr: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("bind prometheus exporter failed: addr='{addr}'")]
    BindExporter {
        addr: SocketAddr,
        #[source]
        source: hyper::Error,
    },
}

struct MetricsCache {
    last_update: Instant,
    data: Vec<u8>,
}

pub(crate) fn get_frame_sent_counters(
    link_type: &str,
    transport: &str,
) -> (IntCounter, IntCounter) {
    let link = normalise_label(link_type);
    let transport = normalise_label(transport);
    (
        FRAMES_SENT.with_label_values(&[link, transport]),
        BYTES_SENT.with_label_values(&[link, transport]),
    )
}

#[allow(dead_code)]
pub(crate) fn record_listener_packet(protocol: &str) {
    let proto = normalise_label(protocol);
    LISTENER_PACKETS.with_label_values(&[proto]).inc();
}

pub(crate) fn record_rule_action(action: &str, outcome: &str) {
    let action = normalise_label(action);
    let outcome = normalise_label(outcome);
    RULE_ACTIONS.with_label_values(&[action, outcome]).inc();
}

pub(crate) fn record_rule_executor_drop(action: &str, reason: &str) {
    let action = normalise_label(action);
    let reason = normalise_label(reason);
    RULE_ACTION_DROPS.with_label_values(&[action, reason]).inc();
}

#[allow(dead_code)]
pub(crate) fn record_listener_dropped_packet(reason: &str) {
    let reason = normalise_label(reason);
    LISTENER_DROPPED_PACKETS.with_label_values(&[reason]).inc();
}

pub(crate) fn spawn_prometheus_exporter(
    handle: &Handle,
    addr: &str,
) -> Result<PrometheusExporterHandle> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|source| TelemetryError::ParseAddress {
            addr: addr.to_string(),
            source,
        })?;

    if !socket.ip().is_loopback() {
        warn!(
            "Prometheus exporter binding to non-loopback address: {}",
            socket
        );
    }

    let builder = Server::try_bind(&socket).map_err(|source| TelemetryError::BindExporter {
        addr: socket,
        source,
    })?;
    let local_addr = builder.local_addr();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let cache = Arc::new(Mutex::new(MetricsCache {
        last_update: Instant::now() - Duration::from_secs(10),
        data: Vec::new(),
    }));

    let service = make_service_fn(move |_| {
        let cache = cache.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let cache = cache.clone();
                handle_metrics_request(req, cache)
            }))
        }
    });

    let server = builder.serve(service);
    let graceful = server.with_graceful_shutdown(async {
        shutdown_rx.await.ok();
    });

    let join_handle = handle.spawn(async move {
        info!("Prometheus exporter listening on http://{local_addr}/metrics");
        if let Err(err) = graceful.await {
            warn!("prometheus exporter terminated with error: {err}");
        } else {
            info!("prometheus exporter shut down gracefully");
        }
    });

    Ok(PrometheusExporterHandle {
        addr: local_addr,
        shutdown_tx,
        join_handle,
    })
}

async fn handle_metrics_request(
    req: Request<Body>,
    cache: Arc<Mutex<MetricsCache>>,
) -> std::result::Result<Response<Body>, Infallible> {
    if req.method() != Method::GET || req.uri().path() != "/metrics" {
        return Ok(response(StatusCode::NOT_FOUND, "not found"));
    }

    let mut cache_guard = cache.lock().ignore_poison();

    if cache_guard.last_update.elapsed() < Duration::from_secs(1) && !cache_guard.data.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", TextEncoder::new().format_type())
            .body(Body::from(cache_guard.data.clone()))
            .unwrap_or_else(|_| response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")));
    }

    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
        warn!("failed to encode prometheus metrics: {err}");
        return Ok(response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to encode metrics",
        ));
    }

    cache_guard.data = buffer.clone();
    cache_guard.last_update = Instant::now();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .unwrap_or_else(|_| {
            response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build response",
            )
        }))
}

fn response(status: StatusCode, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from(body)))
}

fn register_metric(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let opts = prometheus::Opts::new(name, help);
    let metric = IntCounterVec::new(opts, labels).expect("metric definition is valid");
    let _ = REGISTRY.register(Box::new(metric.clone()));
    metric
}

fn normalise_label(value: &str) -> &str {
    if value.is_empty() {
        "unknown"
    } else {
        value
    }
}
