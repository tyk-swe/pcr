// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[test]
fn root_modules_preserve_component_type_identity() {
    let root_packet = packetcraftr::core::Packet::new();
    let component_packet: packetcraftr_core::core::Packet = root_packet;
    let root_packet_again: packetcraftr::Packet = component_packet;
    assert!(root_packet_again.is_empty());

    let root_link_type = packetcraftr::io::LinkType::ETHERNET;
    let component_link_type: packetcraftr_io::io::LinkType = root_link_type;
    assert_eq!(component_link_type, packetcraftr::LinkType::ETHERNET);

    let root_protocol = packetcraftr::protocols::Ethernet::default();
    let _: packetcraftr_protocols::protocols::Ethernet = root_protocol;

    let root_limits = packetcraftr::session::ReassemblyLimits::default();
    let component_limits: packetcraftr_session::session::ReassemblyLimits = root_limits;
    assert_eq!(component_limits.max_flows, 8_192);
}

#[test]
fn component_crates_share_the_root_registry_types() {
    let mut builder: packetcraftr_core::RegistryBuilder = packetcraftr::ProtocolRegistry::builder();
    builder
        .module(&packetcraftr_protocols::BuiltinProtocols)
        .unwrap();
    let registry: packetcraftr::ProtocolRegistry = builder.build().unwrap();
    assert!(registry.protocol_named("ethernet").is_some());
}
