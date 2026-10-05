// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::build::Options;
use packetcraftr_core::codec::{
    DecodedLayer, EncodedLayer, Error as CodecError, LayerCodec, LayerDecodeContext,
    LayerEncodeContext, Mode,
};
use packetcraftr_core::diagnostic::{Diagnostic, Severity};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::fuzz::{
    Campaign, Error as FuzzError, Limits, Report, Request, Strategy, run as fuzz,
};
use packetcraftr_core::layer::{Id, Layer};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::reflective_layer;
use packetcraftr_core::registry::Registry;

const DRIFT_PORT: u16 = 9_999;

/// A two-byte layer whose `quirk` byte decides how decoding betrays encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Drift {
    value: u8,
    quirk: u8,
    unbuildable: bool,
}
/// Decoding flips the low bit of `value`, so the rebuild differs.
const QUIRK_DRIFT: u8 = 1;
/// Decoding yields a layer the encoder refuses.
const QUIRK_UNBUILDABLE: u8 = 2;

reflective_layer! {
    fn drift_schema() => { protocol: Id::new("drift"), name: "Drift" }
    impl Drift {
        "value" => {
            kind: Unsigned, derived: false, required: true,
            description: "Payload value",
            reflect: value,
            layout: (0, 1)
        },
        "quirk" => {
            kind: Unsigned, derived: false, required: true,
            description: "Decode behavior selector",
            reflect: quirk,
            layout: (1, 2)
        }
    }
    layout fn drift_layout();
}

#[derive(Clone, Copy, Debug)]
struct DriftCodec;

impl LayerCodec for DriftCodec {
    fn protocol_id(&self) -> &'static Id {
        &drift_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let drift = layer
            .downcast_ref::<Drift>()
            .ok_or_else(|| CodecError::WrongLayer {
                expected: *self.protocol_id(),
                actual: *layer.protocol_id(),
            })?;
        if drift.unbuildable {
            return Err(CodecError::Unsupported {
                protocol: *self.protocol_id(),
                message: "decoded drift layers cannot be re-encoded".to_owned(),
            });
        }
        Ok(
            EncodedLayer::header(vec![drift.value, drift.quirk], Box::new(drift.clone()))
                .with_fields(drift_layout()),
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, CodecError> {
        let [value, quirk, ..] = input[..] else {
            return Err(CodecError::Truncated {
                protocol: *self.protocol_id(),
                needed: 2,
                available: input.len(),
            });
        };
        let layer = Drift {
            value: if quirk == QUIRK_DRIFT {
                value ^ 1
            } else {
                value
            },
            quirk,
            unbuildable: quirk == QUIRK_UNBUILDABLE,
        };
        let mut decoded = DecodedLayer::terminal(Box::new(layer), 2);
        decoded.fields = drift_layout();
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        let mut layer = Drift::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

fn registry() -> Arc<Registry> {
    Arc::new(
        packetcraftr_core::protocol::builtin::registry_with(|builder| {
            builder.register_codec(DriftCodec, &[])?;
            builder.bind("udp", u64::from(DRIFT_PORT), "drift", 100)?;
            Ok(())
        })
        .expect("drift registry"),
    )
}

fn drift_packet(quirk: u8) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: DRIFT_PORT,
            ..Udp::default()
        })
        .push(Drift {
            value: 0x10,
            quirk,
            unbuildable: false,
        });
    packet
}

fn campaign(packet: Packet, request: Request) -> Report {
    fuzz(&request, packet, registry()).expect("campaign runs")
}

fn drift_request(mode: Mode) -> Request {
    Request {
        seed: 11,
        cases: 8,
        strategies: vec![Strategy::Boundary],
        targets: vec!["2.value".parse().unwrap()],
        build: Options {
            mode,
            ..Options::default()
        },
        ..Request::default()
    }
}

fn roundtrip(report: &Report) -> Vec<&Diagnostic> {
    report
        .cases
        .iter()
        .flat_map(|case| &case.diagnostics)
        .filter(|diagnostic| diagnostic.code.starts_with("fuzz.roundtrip"))
        .collect()
}

#[test]
fn rebuild_bounded_by_byte_budget_nothing() {
    let request = |max_total_bytes| Request {
        cases: 1,
        build: Options {
            mode: Mode::Permissive,
            limits: packetcraftr_core::packet::Limits {
                max_packet_size: 256,
                ..packetcraftr_core::packet::Limits::default()
            },
        },
        limits: Limits {
            max_packet_bytes: 256,
            max_total_bytes,
            ..Limits::default()
        },
        ..drift_request(Mode::Permissive)
    };
    let generous = campaign(drift_packet(QUIRK_DRIFT), request(1 << 20));
    assert_eq!(
        roundtrip(&generous)
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>(),
        ["fuzz.roundtrip_mismatch"]
    );

    // The smallest budget that still holds the case leaves no room to rebuild.
    let tightest = (256..4096)
        .find_map(|budget| fuzz(&request(budget), drift_packet(QUIRK_DRIFT), registry()).ok())
        .expect("some budget holds the case");
    let [skipped] = roundtrip(&tightest)[..] else {
        panic!("{:?}", roundtrip(&tightest));
    };
    assert_eq!(skipped.code, "fuzz.roundtrip_skipped");
    assert_eq!(skipped.severity, Severity::Info);
    // the skipped rebuild changed neither the retained bytes nor the totals
    assert_eq!(tightest.stats.bytes, generous.stats.bytes);
    assert_eq!(
        tightest.cases[0].built.as_ref().map(|built| &built.bytes),
        generous.cases[0].built.as_ref().map(|built| &built.bytes)
    );
}

/// Behaves like [`DriftCodec`], but cancels once it decodes a mutated case and
/// counts how often it encodes.
#[derive(Debug)]
struct CancelOnMutatedDecode(Cancellation, Arc<AtomicUsize>);

impl LayerCodec for CancelOnMutatedDecode {
    fn protocol_id(&self) -> &'static Id {
        DriftCodec.protocol_id()
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        DriftCodec.encode(layer, payload, context)
    }

    fn decode(
        &self,
        input: Bytes,
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, CodecError> {
        if input.first() != Some(&0x10) {
            self.0.cancel();
        }
        DriftCodec.decode(input, context)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        DriftCodec.make_layer(fields)
    }
}

#[test]
fn cancel_decode_stops_case_before_rebuilt() {
    let cancellation = Cancellation::default();
    let encodes = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(
        packetcraftr_core::protocol::builtin::registry_with(|builder| {
            builder.register_codec(
                CancelOnMutatedDecode(cancellation.clone(), Arc::clone(&encodes)),
                &[],
            )?;
            builder.bind("udp", u64::from(DRIFT_PORT), "drift", 100)?;
            Ok(())
        })
        .expect("cancelling registry"),
    );
    let mut deadline = Deadline::new(std::time::Duration::from_secs(60))
        .with_cancellation(Some(cancellation.clone()));
    // the campaign fails either way, so the encode count below is what shows
    // the cancelled case stopped before its rebuild
    let request = Request {
        cases: 1,
        ..drift_request(Mode::Permissive)
    };
    let Err(error) =
        Campaign::prepare(&request, drift_packet(QUIRK_DRIFT), registry, &mut deadline)
    else {
        panic!("a cancelled campaign stops");
    };
    assert!(matches!(error, FuzzError::Cancelled(_)), "{error:?}");
    assert!(cancellation.is_cancelled());
    // only the case's own build ran; the cancelled case was never rebuilt
    assert_eq!(encodes.load(Ordering::SeqCst), 1);
}
