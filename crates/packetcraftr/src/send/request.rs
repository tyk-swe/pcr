// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::template::{DEFAULT_MAX_TEMPLATE_PACKETS, Template};

use super::Error;
use super::options::Options;

#[derive(Clone, Debug)]
pub struct Request {
    pub template: Template,
    pub send: Options,
    /// Must be at least one: repetition can never mean unbounded sending.
    pub repeat: u32,
    /// Transmission-start ceiling in packets per second; `None` is unpaced.
    pub rate: Option<u32>,
    pub max_template_packets: usize,
}

impl Request {
    #[must_use]
    pub fn new(template: Template, send: Options) -> Self {
        Self {
            template,
            send,
            repeat: 1,
            rate: None,
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.parameters().map(drop)
    }

    pub(super) fn parameters(&self) -> Result<Parameters, Error> {
        Parameters::new(self.repeat, self.rate, self.max_template_packets)
    }

    pub fn packet_count(&self) -> Result<u64, Error> {
        super::plan::Plan::try_from(self).map(|plan| plan.packet_count)
    }
}

pub(super) fn invalid(field: &'static str, message: &str) -> Error {
    Error::InvalidRequest {
        field,
        message: message.to_owned(),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    pub(super) repeat: u32,
    pub(super) rate: Option<u32>,
    pub(super) max_template_packets: usize,
}

impl Parameters {
    pub fn new(repeat: u32, rate: Option<u32>, max_template_packets: usize) -> Result<Self, Error> {
        if repeat == 0 {
            return Err(invalid("repeat", "must be at least one"));
        }
        if rate == Some(0) {
            return Err(invalid(
                "rate",
                "must be a positive packets-per-second ceiling",
            ));
        }
        if max_template_packets == 0 {
            return Err(invalid("max_template_packets", "must be greater than zero"));
        }
        Ok(Self {
            repeat,
            rate,
            max_template_packets,
        })
    }

    pub fn packet_count(&self, template: &Template) -> Result<u64, Error> {
        super::plan::Plan::new(self, template).map(|plan| plan.packet_count)
    }

    pub fn into_request(self, template: Template, send: Options) -> Request {
        Request {
            template,
            send,
            repeat: self.repeat,
            rate: self.rate,
            max_template_packets: self.max_template_packets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::{field::Value, packet::Packet};

    #[test]
    fn validated_scheduling_uses_the_complete_template() {
        let template = Template::new(Packet::default()).axis(
            0,
            "value",
            vec![Value::Unsigned(1), Value::Unsigned(2)],
        );
        let parameters = Parameters::new(3, None, 2).unwrap();
        assert_eq!(parameters.packet_count(&template).unwrap(), 6);
        let request = parameters.into_request(template, Options::default());
        assert_eq!(request.packet_count().unwrap(), 6);
    }

    #[test]
    fn validated_scheduling_rejects_excessive_pacing() {
        let repeat = u32::try_from(packetcraftr_netio::deadline::MAX_WAIT.as_secs() + 2).unwrap();
        let parameters = Parameters::new(repeat, Some(1), 1).unwrap();
        let error = parameters
            .packet_count(&Template::new(Packet::default()))
            .unwrap_err();
        assert!(matches!(error, Error::InvalidRequest { field: "rate", .. }));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn validated_scheduling_rejects_expansion_times_repeat_overflow() {
        let template = (0..63).fold(Template::new(Packet::default()), |template, index| {
            template.axis(index, "value", vec![Value::Unsigned(0), Value::Unsigned(1)])
        });
        let parameters = Parameters::new(3, None, usize::MAX).unwrap();
        assert!(matches!(
            parameters.packet_count(&template),
            Err(Error::InvalidRequest {
                field: "repeat",
                ..
            })
        ));
    }
}
