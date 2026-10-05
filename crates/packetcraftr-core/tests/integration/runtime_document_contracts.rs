// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::field::FieldValue;
use packetcraftr_core::{packet::Packet, template};

#[test]
fn template_aliases_errors_reject_before_iteration() {
    use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
    let mut base = Packet::new();
    base.push(Udp::default());
    let repeated = template::Template::new(base.clone())
        .axis(0, "sport", vec![1_u16.into()])
        .axis(0, "source_port", vec![2_u16.into()]);
    assert!(matches!(
        repeated.expand(1),
        Err(template::Error::DuplicateAxis { layer: 0, .. })
    ));
    let invalid = template::Template::new(base).axis(
        0,
        "sport",
        vec![1_u16.into(), FieldValue::Unsigned(65_536)],
    );
    assert!(matches!(
        invalid.expand(2),
        Err(template::Error::Field { .. })
    ));

    let mut base = Packet::new();
    for _ in 0..usize::BITS {
        base.push(Ipv4::default());
    }
    let mut product = template::Template::new(base);
    for index in 0..usize::BITS as usize {
        product = product.axis(index, "ttl", vec![1_u8.into(), 2_u8.into()]);
    }
    assert!(matches!(
        product.expansion_len(),
        Err(template::Error::ExpansionOverflow)
    ));
    assert!(matches!(
        product.expand(usize::MAX),
        Err(template::Error::ExpansionOverflow)
    ));
    let empty = product.axis(0, "tos", vec![]);
    assert_eq!(
        empty.expansion_len().unwrap(),
        0,
        "an empty factor makes the entire product empty"
    );
}
