// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::request::{PacketRequest, TransportProtocolRequest};
use crate::rules::error::RuleError;
use crate::rules::model::PacketContext;
use crate::rules::template::{apply_template, render_option};

#[derive(Debug, Clone)]
pub(crate) struct RuleSendTemplate {
    request: PacketRequest,
}

impl RuleSendTemplate {
    pub(crate) fn new(request: PacketRequest) -> Self {
        Self { request }
    }

    pub(crate) fn render(&self, packet: Option<&PacketContext>) -> PacketRequest {
        let mut request = self.request.clone();
        render_option(&mut request.destination.destination, packet);
        render_option(&mut request.destination.destination_ip, packet);
        render_option(&mut request.destination.interface, packet);
        render_option(&mut request.layer2.source_mac, packet);
        render_option(&mut request.layer2.destination_mac, packet);
        render_option(&mut request.layer2.ethertype, packet);
        render_option(&mut request.ip.source_ip, packet);
        render_option(&mut request.ip.destination_ip, packet);
        render_vec(&mut request.ipv6.extensions, packet);
        render_option(&mut request.payload.data, packet);
        render_option(&mut request.payload.data_hex, packet);
        render_option(&mut request.payload.data_file, packet);
        render_option(&mut request.payload.dns_query, packet);
        render_option(&mut request.payload.dns_type, packet);
        render_option(&mut request.payload.http_method, packet);
        render_option(&mut request.payload.http_path, packet);
        render_option(&mut request.payload.http_host, packet);
        render_option(&mut request.payload.tls_client_hello, packet);
        render_option(&mut request.transmit.interval, packet);
        render_option(&mut request.listener.filter, packet);
        render_option(&mut request.listener.capture_file, packet);
        render_option(&mut request.rules_file, packet);
        render_option(&mut request.logging.log_file, packet);
        render_option(&mut request.logging.pcap_write, packet);
        render_option(&mut request.logging.metrics_json, packet);
        render_option(&mut request.logging.prometheus_bind, packet);

        if let Some(TransportProtocolRequest::Tcp(tcp)) = request.transport.command.as_mut() {
            render_option(&mut tcp.flags, packet);
            render_option(&mut tcp.timestamps, packet);
            render_option(&mut tcp.options_hex, packet);
        }

        request
    }
}

fn render_vec(fields: &mut [String], packet: Option<&PacketContext>) {
    for field in fields {
        *field = apply_template(field, packet);
    }
}

pub(crate) trait RuleSendDispatcher: std::fmt::Debug + Send + Sync {
    fn dispatch(
        &self,
        rule_name: &str,
        template: &RuleSendTemplate,
        packet: Option<&PacketContext>,
    ) -> std::result::Result<(), RuleError>;
}
