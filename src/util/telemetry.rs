// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "metrics")]
use std::convert::Infallible;
#[cfg(feature = "metrics")]
use std::net::SocketAddr;
#[cfg(feature = "metrics")]
use std::sync::{Arc, LazyLock, Mutex};
#[cfg(feature = "metrics")]
use std::time::{Duration, Instant};

#[cfg(feature = "metrics")]
use hyper::service::{make_service_fn, service_fn};
#[cfg(feature = "metrics")]
use hyper::{Body, Method, Request, Response, Server, StatusCode};
#[cfg(feature = "metrics")]
use log::{info, warn};
#[cfg(feature = "metrics")]
use prometheus::{Encoder, IntCounter, IntCounterVec, Registry, TextEncoder};
#[cfg(feature = "metrics")]
use thiserror::Error;
#[cfg(feature = "metrics")]
use tokio::runtime::Handle;
#[cfg(feature = "metrics")]
use tokio::sync::oneshot;

#[cfg(feature = "metrics")]
use crate::util::sync::LockResultExt;

#[cfg(feature = "metrics")]
static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);
#[cfg(feature = "metrics")]
static FRAMES_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_frames_sent_total",
        "Total number of frames transmitted",
        &["link_type", "transport"],
    )
});
#[cfg(feature = "metrics")]
static BYTES_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_bytes_sent_total",
        "Total number of bytes transmitted",
        &["link_type", "transport"],
    )
});
#[cfg(feature = "metrics")]
static LISTENER_PACKETS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_listener_packets_total",
        "Packets observed by listener mode",
        &["protocol"],
    )
});
#[cfg(feature = "metrics")]
static RULE_ACTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_rule_actions_total",
        "Rule action outcomes",
        &["action", "outcome"],
    )
});
#[cfg(feature = "metrics")]
static RULE_ACTION_DROPS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_rule_executor_dropped_total",
        "Rule executor drop reasons",
        &["action", "reason"],
    )
});
#[cfg(feature = "metrics")]
static LISTENER_DROPPED_PACKETS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_metric(
        "packetcraftr_listener_dropped_packets_total",
        "Packets dropped by listener due to queue capacity",
        &["reason"],
    )
});

#[cfg(feature = "metrics")]
fn register_metric(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let opts = prometheus::Opts::new(name, help);
    let metric = IntCounterVec::new(opts, labels).expect("metric definition is valid");
    // Ignore duplicate-registration errors (can occur in tests or after process reload)
    let _ = REGISTRY.register(Box::new(metric.clone()));
    metric
}

#[cfg(feature = "metrics")]
fn normalise_label(value: &str) -> &str {
    if value.is_empty() {
        "unknown"
    } else {
        value
    }
}

#[cfg(feature = "metrics")]
pub fn record_frame_sent(link_type: &str, transport: &str, bytes: usize) {
    let link = normalise_label(link_type);
    let transport = normalise_label(transport);
    FRAMES_SENT.with_label_values(&[link, transport]).inc();
    BYTES_SENT
        .with_label_values(&[link, transport])
        .inc_by(bytes as u64);
}

#[cfg(feature = "metrics")]
pub fn get_frame_sent_counters(link_type: &str, transport: &str) -> (IntCounter, IntCounter) {
    let link = normalise_label(link_type);
    let transport = normalise_label(transport);
    (
        FRAMES_SENT.with_label_values(&[link, transport]),
        BYTES_SENT.with_label_values(&[link, transport]),
    )
}

#[cfg(feature = "metrics")]
pub fn record_listener_packet(protocol: &str) {
    let proto = normalise_label(protocol);
    LISTENER_PACKETS.with_label_values(&[proto]).inc();
}

#[cfg(feature = "metrics")]
pub fn record_rule_action(action: &str, outcome: &str) {
    let action = normalise_label(action);
    let outcome = normalise_label(outcome);
    RULE_ACTIONS.with_label_values(&[action, outcome]).inc();
}

#[cfg(feature = "metrics")]
pub fn record_rule_executor_drop(action: &str, reason: &str) {
    let action = normalise_label(action);
    let reason = normalise_label(reason);
    RULE_ACTION_DROPS.with_label_values(&[action, reason]).inc();
}

#[cfg(feature = "metrics")]
pub fn record_listener_dropped_packet(reason: &str) {
    let reason = normalise_label(reason);
    LISTENER_DROPPED_PACKETS.with_label_values(&[reason]).inc();
}

#[cfg(not(feature = "metrics"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopCounter;

#[cfg(not(feature = "metrics"))]
impl NoopCounter {
    pub fn inc(&self) {}

    pub fn inc_by(&self, _amount: u64) {}
}

#[cfg(not(feature = "metrics"))]
pub fn record_frame_sent(_link_type: &str, _transport: &str, _bytes: usize) {}

#[cfg(not(feature = "metrics"))]
pub fn get_frame_sent_counters(_link_type: &str, _transport: &str) -> (NoopCounter, NoopCounter) {
    (NoopCounter, NoopCounter)
}

#[cfg(not(feature = "metrics"))]
pub fn record_listener_packet(_protocol: &str) {}

#[cfg(not(feature = "metrics"))]
pub fn record_rule_action(_action: &str, _outcome: &str) {}

#[cfg(not(feature = "metrics"))]
pub fn record_rule_executor_drop(_action: &str, _reason: &str) {}

#[cfg(not(feature = "metrics"))]
pub fn record_listener_dropped_packet(_reason: &str) {}

#[cfg(feature = "metrics")]
#[derive(Debug)]
pub struct PrometheusExporterHandle {
    pub addr: SocketAddr,
    pub shutdown_tx: oneshot::Sender<()>,
    pub join_handle: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "metrics")]
struct MetricsCache {
    last_update: Instant,
    data: Vec<u8>,
}

#[cfg(feature = "metrics")]
pub fn spawn_prometheus_exporter(handle: &Handle, addr: &str) -> Result<PrometheusExporterHandle> {
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
        last_update: Instant::now() - Duration::from_secs(10), // Force immediate refresh
        data: Vec::new(),
    }));

    let service = make_service_fn(move |_| {
        let cache = cache.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let cache = cache.clone();
                async move {
                    if req.method() == Method::GET && req.uri().path() == "/metrics" {
                        let mut cache_guard = cache.lock().ignore_poison();

                        // Check cache (1 second TTL)
                        if cache_guard.last_update.elapsed() < Duration::from_secs(1)
                            && !cache_guard.data.is_empty()
                        {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", TextEncoder::new().format_type())
                                    .body(Body::from(cache_guard.data.clone()))
                                    .unwrap_or_else(|_| {
                                        Response::new(Body::from("internal error"))
                                    }),
                            );
                        }

                        let encoder = TextEncoder::new();
                        let metric_families = REGISTRY.gather();
                        let mut buffer = Vec::new();
                        if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
                            warn!("failed to encode prometheus metrics: {err}");
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from("unable to encode metrics"))
                                    .unwrap_or_else(|_| {
                                        Response::new(Body::from("internal error"))
                                    }),
                            );
                        }

                        // Update cache
                        cache_guard.data = buffer.clone();
                        cache_guard.last_update = Instant::now();

                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", encoder.format_type())
                                .body(Body::from(buffer))
                                .unwrap_or_else(|_| {
                                    Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("failed to build response"))
                                        .unwrap_or_else(|_| {
                                            Response::new(Body::from("internal error"))
                                        })
                                }),
                        )
                    } else {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::from("not found"))
                                .unwrap_or_else(|_| Response::new(Body::from("not found"))),
                        )
                    }
                }
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

#[cfg(feature = "metrics")]
#[derive(Debug, Error)]
pub enum TelemetryError {
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

#[cfg(feature = "metrics")]
pub type Result<T> = std::result::Result<T, TelemetryError>;
