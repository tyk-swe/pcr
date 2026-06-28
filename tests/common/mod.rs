use packetcraftr::engine::spec::{
    DestinationSpec, Ipv6Spec, Layer2Spec, ListenerSpec, LoggingSpec, PacketSpec, PayloadSource,
    PayloadSpec, TransmissionSpec, TransportSpec,
};
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
// This file will contain shared test utilities.

pub fn mock_interface(name: &str, mac: Option<MacAddr>, ips: Vec<IpNetwork>) -> NetworkInterface {
    NetworkInterface {
        name: name.to_string(),
        description: String::new(),
        index: 0,
        mac,
        ips,
        flags: 0,
    }
}

pub fn base_spec() -> PacketSpec {
    PacketSpec {
        target: DestinationSpec::default(),
        layer2: Layer2Spec::default(),
        ip: None,
        ipv6: Ipv6Spec::default(),
        transport: TransportSpec::default(),
        payload: PayloadSpec {
            source: PayloadSource::Empty,
        },
        transmit: TransmissionSpec::default(),
        listener: ListenerSpec::default(),
        rules_file: None,
        logging: LoggingSpec::default(),
    }
}
