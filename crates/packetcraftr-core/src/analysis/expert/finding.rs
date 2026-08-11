// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::diagnostic::Severity as DiagnosticSeverity;

use crate::analysis::adapter::Transports;
use crate::analysis::pipeline::FrameRecord;

use super::{Finding, StreamRef, tcp_stream_ref, udp_stream_ref};

#[derive(Clone, Copy)]
struct IndexedTransport {
    layer: usize,
    stream: StreamRef,
}

#[derive(Clone, Copy)]
struct DiagnosticStreams {
    tcp: Option<IndexedTransport>,
    udp: Option<IndexedTransport>,
    outermost: Option<usize>,
}

pub(super) fn from_diagnostics(
    record: &FrameRecord<'_>,
    transports: &Transports<'_>,
) -> Vec<Finding> {
    let streams = DiagnosticStreams {
        tcp: record
            .tcp_stream
            .zip(transports.tcp.as_ref())
            .map(|(stream, (layer, _, _))| IndexedTransport {
                layer: *layer,
                stream: tcp_stream_ref(stream),
            }),
        udp: record
            .udp_stream
            .zip(transports.udp.as_ref())
            .map(|(stream, (layer, _))| IndexedTransport {
                layer: *layer,
                stream: udp_stream_ref(stream),
            }),
        outermost: transports.outermost,
    };

    record
        .decoded
        .diagnostics
        .iter()
        .map(|diagnostic| {
            new(
                diagnostic.severity,
                diagnostic.code.clone(),
                record.number,
                diagnostic_stream(diagnostic.layer, streams),
                diagnostic.message.clone(),
            )
        })
        .collect()
}

fn diagnostic_stream(layer: Option<usize>, streams: DiagnosticStreams) -> Option<StreamRef> {
    let indexed_outer = [streams.tcp, streams.udp]
        .into_iter()
        .flatten()
        .map(|transport| transport.layer)
        .min();
    if streams
        .outermost
        .zip(indexed_outer)
        .is_some_and(|(outermost, indexed)| {
            outermost < indexed && layer.is_none_or(|layer| layer <= outermost)
        })
    {
        return None;
    }

    match (streams.tcp, streams.udp) {
        (Some(transport), None) | (None, Some(transport)) => Some(transport.stream),
        (Some(tcp), Some(udp)) => layer.map(|layer| {
            let (outer, inner) = if tcp.layer < udp.layer {
                (tcp, udp)
            } else {
                (udp, tcp)
            };
            if layer <= outer.layer {
                outer.stream
            } else {
                inner.stream
            }
        }),
        (None, None) => None,
    }
}

pub(super) fn new(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    number: u64,
    stream: Option<StreamRef>,
    message: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        code: code.into(),
        number,
        stream,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::expert::StreamTransport;

    const TCP: StreamRef = StreamRef {
        transport: StreamTransport::Tcp,
        index: 3,
    };
    const UDP: StreamRef = StreamRef {
        transport: StreamTransport::Udp,
        index: 5,
    };

    #[test]
    fn diagnostic_stream_attribution_covers_transport_shapes() {
        struct Case {
            name: &'static str,
            layer: Option<usize>,
            streams: DiagnosticStreams,
            expected: Option<StreamRef>,
        }

        let tcp = IndexedTransport {
            layer: 3,
            stream: TCP,
        };
        let udp = IndexedTransport {
            layer: 1,
            stream: UDP,
        };
        let cases = [
            Case {
                name: "single transport layerless",
                layer: None,
                streams: DiagnosticStreams {
                    tcp: Some(tcp),
                    udp: None,
                    outermost: Some(3),
                },
                expected: Some(TCP),
            },
            Case {
                name: "mixed outer transport",
                layer: Some(1),
                streams: DiagnosticStreams {
                    tcp: Some(tcp),
                    udp: Some(udp),
                    outermost: Some(1),
                },
                expected: Some(UDP),
            },
            Case {
                name: "mixed inner transport",
                layer: Some(2),
                streams: DiagnosticStreams {
                    tcp: Some(tcp),
                    udp: Some(udp),
                    outermost: Some(1),
                },
                expected: Some(TCP),
            },
            Case {
                name: "mixed layerless",
                layer: None,
                streams: DiagnosticStreams {
                    tcp: Some(tcp),
                    udp: Some(udp),
                    outermost: Some(1),
                },
                expected: None,
            },
            Case {
                name: "same-transport unindexed outer header",
                layer: Some(1),
                streams: DiagnosticStreams {
                    tcp: Some(tcp),
                    udp: None,
                    outermost: Some(1),
                },
                expected: None,
            },
            Case {
                name: "same-transport indexed inner header",
                layer: Some(2),
                streams: DiagnosticStreams {
                    tcp: Some(tcp),
                    udp: None,
                    outermost: Some(1),
                },
                expected: Some(TCP),
            },
            Case {
                name: "same-transport layerless",
                layer: None,
                streams: DiagnosticStreams {
                    tcp: Some(tcp),
                    udp: None,
                    outermost: Some(1),
                },
                expected: None,
            },
        ];

        for case in cases {
            assert_eq!(
                diagnostic_stream(case.layer, case.streams),
                case.expected,
                "{}",
                case.name
            );
        }
    }
}
