use std::path::PathBuf;
use std::time::Duration;

#[cfg(not(feature = "pcap"))]
use super::error::SpecError;
use super::error::SpecResult;

#[cfg(not(feature = "pcap"))]
use crate::engine::listener_config::ListenerPcapRequirement;
use crate::engine::listener_config::NormalizedListenerRequest;
use crate::engine::request::ListenerRequest;

#[derive(Debug, Clone, Default)]
pub struct ListenerSpec {
    pub enabled: bool,
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub show_reply: bool,
    pub timeout: Option<Duration>,
    pub capture_file: Option<PathBuf>,
    pub implicit: bool,
    pub queue_capacity: Option<usize>,
}

impl ListenerSpec {
    pub(crate) fn from_request(request: &ListenerRequest) -> SpecResult<Self> {
        #[cfg(not(feature = "pcap"))]
        if let Some(requirement) = crate::engine::listener_config::spec_pcap_requirement(request) {
            return Err(match requirement {
                ListenerPcapRequirement::Listen => SpecError::ListenReplyRequiresPcap,
                ListenerPcapRequirement::ShowReply => SpecError::ShowReplyRequiresPcap,
                ListenerPcapRequirement::Filter => SpecError::FilterRequiresPcap,
                ListenerPcapRequirement::Capture => SpecError::PcapSaveRequiresFeature,
            });
        }

        let normalized = NormalizedListenerRequest::from_request(request);

        Ok(Self {
            enabled: normalized.enabled,
            filter: normalized.filter,
            promiscuous: normalized.promiscuous,
            show_reply: normalized.show_reply,
            timeout: normalized.timeout,
            capture_file: normalized.capture_file,
            implicit: normalized.implicit,
            queue_capacity: normalized.queue_capacity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::request::ListenerRequest;
    #[cfg(feature = "pcap")]
    use std::path::PathBuf;
    #[cfg(feature = "pcap")]
    use std::time::Duration;

    #[cfg(feature = "pcap")]
    #[test]
    fn listener_explicitly_enabled() {
        let listen = ListenerRequest {
            listen: Some(true),
            ..Default::default()
        };

        let spec = ListenerSpec::from_request(&listen).expect("listener spec");
        assert!(spec.enabled, "explicit listen should enable listener");
        assert!(!spec.implicit, "explicit listen should NOT be implicit");
    }

    #[test]
    fn listener_disabled_by_default() {
        let listen = ListenerRequest::default();
        let spec = ListenerSpec::from_request(&listen).expect("listener spec");
        assert!(!spec.enabled);
        assert!(!spec.implicit);
    }

    #[test]
    fn listener_promiscuous_mode() {
        let listen = ListenerRequest {
            promiscuous: Some(true),
            ..Default::default()
        };

        let spec = ListenerSpec::from_request(&listen).expect("listener spec");
        assert!(
            !spec.enabled,
            "promiscuous mode alone should not enable listener"
        );
        assert!(spec.promiscuous, "promiscuous flag should be set");
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn listener_timeout_and_capacity() {
        let listen = ListenerRequest {
            listen: Some(true),
            timeout: Some(30),
            queue_capacity: Some(2048),
            ..Default::default()
        };

        let spec = ListenerSpec::from_request(&listen).expect("listener spec");
        assert!(spec.enabled);
        assert_eq!(spec.timeout, Some(Duration::from_secs(30)));
        assert_eq!(spec.queue_capacity, Some(2048));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn listener_implicit_logic_combinations() {
        // Case 1: Listen false, show_reply true -> Implicit
        let opts1 = ListenerRequest {
            listen: Some(false),
            show_reply: Some(true),
            ..Default::default()
        };
        let spec1 = ListenerSpec::from_request(&opts1).expect("spec1");
        assert!(spec1.enabled);
        assert!(spec1.implicit);

        // Case 2: Listen true, show_reply true -> Explicit
        let opts2 = ListenerRequest {
            listen: Some(true),
            show_reply: Some(true),
            ..Default::default()
        };
        let spec2 = ListenerSpec::from_request(&opts2).expect("spec2");
        assert!(spec2.enabled);
        assert!(!spec2.implicit);
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn listener_implicitly_enabled_by_filter() {
        let opts = ListenerRequest {
            filter: Some("tcp".to_string()),
            ..Default::default()
        };
        let spec = ListenerSpec::from_request(&opts).expect("spec");
        assert!(spec.enabled);
        assert!(spec.implicit);
        assert_eq!(spec.filter, Some("tcp".to_string()));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn listener_filter_error_without_pcap() {
        let opts = ListenerRequest {
            filter: Some("tcp".to_string()),
            ..Default::default()
        };
        let result = ListenerSpec::from_request(&opts);
        assert!(result.is_err());
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn listener_reply_requires_pcap_feature() {
        let opts = ListenerRequest {
            listen: Some(true),
            ..Default::default()
        };

        let result = ListenerSpec::from_request(&opts);
        assert!(matches!(result, Err(SpecError::ListenReplyRequiresPcap)));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn listener_show_reply_requires_pcap_feature() {
        let opts = ListenerRequest {
            show_reply: Some(true),
            ..Default::default()
        };

        let result = ListenerSpec::from_request(&opts);
        assert!(matches!(result, Err(SpecError::ShowReplyRequiresPcap)));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn listener_capture_enables_implicitly() {
        let opts = ListenerRequest {
            capture_file: Some("test.pcap".to_string()),
            ..Default::default()
        };
        let spec = ListenerSpec::from_request(&opts).expect("spec");
        assert!(spec.enabled);
        assert!(spec.implicit);
        assert_eq!(spec.capture_file, Some(PathBuf::from("test.pcap")));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn listener_capture_requires_pcap_feature() {
        let listen = ListenerRequest {
            capture_file: Some("out.pcap".to_string()),
            ..Default::default()
        };

        let result = ListenerSpec::from_request(&listen);
        assert!(result.is_err(), "pcap saving should require pcap feature");
    }

    #[test]
    fn listener_spec_logic_table() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct TestCase {
            listen: Option<bool>,
            show_reply: bool,
            filter: Option<String>,
            capture_file: Option<String>,
            expected_enabled: bool,
            expected_implicit: bool,
            name: &'static str,
            requires_pcap: bool,
        }

        let cases = vec![
            TestCase {
                listen: None,
                show_reply: false,
                filter: None,
                capture_file: None,
                expected_enabled: false,
                expected_implicit: false,
                name: "all default",
                requires_pcap: false,
            },
            TestCase {
                listen: Some(true),
                show_reply: false,
                filter: None,
                capture_file: None,
                expected_enabled: true,
                expected_implicit: false,
                name: "explicit listen",
                requires_pcap: true,
            },
            TestCase {
                listen: Some(false),
                show_reply: true,
                filter: None,
                capture_file: None,
                expected_enabled: true,
                expected_implicit: true,
                name: "implicit by show_reply",
                requires_pcap: true,
            },
            TestCase {
                listen: Some(false),
                show_reply: false,
                filter: Some("tcp".into()),
                capture_file: None,
                expected_enabled: true,
                expected_implicit: true,
                name: "implicit by filter",
                requires_pcap: true,
            },
            TestCase {
                listen: Some(false),
                show_reply: false,
                filter: None,
                capture_file: Some("out.pcap".into()),
                expected_enabled: true,
                expected_implicit: true,
                name: "implicit by capture file",
                requires_pcap: true,
            },
            TestCase {
                listen: Some(true),
                show_reply: true,
                filter: Some("tcp".into()),
                capture_file: Some("out.pcap".into()),
                expected_enabled: true,
                expected_implicit: false,
                name: "explicit listen overrides implicit even with others set",
                requires_pcap: true,
            },
        ];

        for tc in cases {
            #[cfg(not(feature = "pcap"))]
            if tc.requires_pcap {
                continue;
            }

            let opts = ListenerRequest {
                listen: tc.listen,
                show_reply: Some(tc.show_reply),
                filter: tc.filter,
                capture_file: tc.capture_file,
                ..Default::default()
            };

            let spec = ListenerSpec::from_request(&opts)
                .unwrap_or_else(|e| panic!("Test '{}' failed: {:?}", tc.name, e));
            assert_eq!(
                spec.enabled, tc.expected_enabled,
                "Test '{}' enabled mismatch",
                tc.name
            );
            assert_eq!(
                spec.implicit, tc.expected_implicit,
                "Test '{}' implicit mismatch",
                tc.name
            );
        }
    }
}
