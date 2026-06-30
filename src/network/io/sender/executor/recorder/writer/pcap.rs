// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;

use log::warn;

use crate::network::sender::error::{ExecutorError, Result};

use super::super::super::super::types::{LinkType, NetworkTransmissionPlan};

pub(crate) struct CaptureWriter {
    capture: Option<PacketCapture>,
}

impl CaptureWriter {
    pub(crate) fn for_plan(plan: &NetworkTransmissionPlan) -> Result<Self> {
        let capture = if let Some(path) = plan.logging.pcap_write.as_ref() {
            Some(PacketCapture::new(path.as_path(), &plan.link_type)?)
        } else {
            None
        };

        Ok(Self { capture })
    }

    pub(crate) fn record(&mut self, frame: &[u8]) -> Result<()> {
        if let Some(writer) = self.capture.as_mut() {
            writer.record(frame)?;
        }
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<()> {
        if let Some(writer) = self.capture.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

fn linktype_for_plan(link_type: &LinkType) -> pcap::Linktype {
    match link_type {
        LinkType::Ethernet => pcap::Linktype::ETHERNET,
        LinkType::Ipv4 => pcap::Linktype::IPV4,
        LinkType::Ipv6 => pcap::Linktype::IPV6,
    }
}

struct PacketCapture {
    writer: pcap::Savefile,
}

impl PacketCapture {
    fn new(path: &std::path::Path, link_type: &LinkType) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| {
                    ExecutorError::CreatePcapDirectory {
                        path: parent.to_path_buf(),
                        source,
                    }
                })?;
            }
        }

        let handle = pcap::Capture::dead(linktype_for_plan(link_type)).map_err(|source| {
            ExecutorError::CreatePcapHandle {
                link_type: link_type.clone(),
                source,
            }
        })?;
        let writer = handle
            .savefile(path)
            .map_err(|source| ExecutorError::OpenPcapOutput {
                path: path.to_path_buf(),
                source,
            })?;

        Ok(Self { writer })
    }

    fn record(&mut self, frame: &[u8]) -> Result<()> {
        let now = std::time::SystemTime::now();
        let duration = match now.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(err) => {
                warn!(
                    "system clock is before UNIX_EPOCH; using zero timestamp for capture record: {err}"
                );
                std::time::Duration::default()
            }
        };
        let frame_len =
            u32::try_from(frame.len()).map_err(|_| ExecutorError::FrameLengthTooLarge {
                length: frame.len(),
            })?;
        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: duration.as_secs() as libc::time_t,
                tv_usec: duration.subsec_micros() as libc::suseconds_t,
            },
            caplen: frame_len,
            len: frame_len,
        };
        let packet = pcap::Packet::new(&header, frame);
        self.writer.write(&packet);
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .map_err(|source| ExecutorError::FlushPcap { source })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linktype_mapping_covers_supported_link_types() {
        assert_eq!(
            linktype_for_plan(&LinkType::Ethernet),
            pcap::Linktype::ETHERNET
        );
        assert_eq!(linktype_for_plan(&LinkType::Ipv4), pcap::Linktype::IPV4);
        assert_eq!(linktype_for_plan(&LinkType::Ipv6), pcap::Linktype::IPV6);
    }

    #[test]
    fn packet_capture_creates_nested_parent_directories() {
        let root =
            std::env::temp_dir().join(format!("packetcraftr-recorder-test-{}", std::process::id()));
        let path = root.join("nested").join("capture.pcap");
        let _ = fs::remove_dir_all(&root);

        let mut capture = PacketCapture::new(&path, &LinkType::Ethernet).unwrap();
        capture.record(&[0, 1, 2, 3]).unwrap();
        capture.flush().unwrap();

        assert!(path.exists());

        let _ = fs::remove_dir_all(&root);
    }
}
