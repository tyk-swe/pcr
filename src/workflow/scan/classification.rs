#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanResponseClassification {
    pub classification: ScanClassification,
    pub responder: IpAddr,
    pub reason: &'static str,
    pub(crate) correlation: Correlation,
}

/// Pure response classifier used by the workflow and deterministic tests. A
/// return value of `None` means the response is corrupt, unrelated, or not
/// protocol-consistent with the request and must not influence classification.
pub fn classify_scan_response(
    registry: &ProtocolRegistry,
    transport: ScanTransport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<ScanResponseClassification> {
    let observation =
        super::probe::observe(registry, transport.probe_transport(), request, response)?;
    let classification = match observation.correlation {
        Correlation::TcpReset | Correlation::PortUnreachable => ScanClassification::Closed,
        Correlation::TcpSynAck | Correlation::UdpReply | Correlation::IcmpReply => {
            ScanClassification::Open
        }
        Correlation::TcpOther => ScanClassification::Unknown,
        Correlation::TimeExceeded | Correlation::AdministrativelyProhibited => {
            ScanClassification::Filtered
        }
        Correlation::DestinationUnreachable => ScanClassification::Unreachable,
    };
    Some(ScanResponseClassification {
        classification,
        responder: observation.responder,
        reason: observation.reason,
        correlation: observation.correlation,
    })
}
