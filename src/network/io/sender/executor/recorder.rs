#[cfg(feature = "pcap")]
use std::fs;

#[cfg(feature = "pcap")]
use log::warn;

use crate::network::sender::error::{ExecutorError, Result};

#[cfg(feature = "pcap")]
use super::super::types::LinkType;
use super::super::types::TransmissionPlan;

pub(super) struct PacketRecorder {
    #[cfg(feature = "pcap")]
    capture: Option<PacketCapture>,
}

impl PacketRecorder {
    pub(super) fn for_plan(plan: &TransmissionPlan) -> Result<Self> {
        #[cfg(feature = "pcap")]
        {
            let capture = if let Some(path) = plan.logging.pcap_write.as_ref() {
                Some(PacketCapture::new(path.as_path(), &plan.link_type)?)
            } else {
                None
            };
            Ok(Self { capture })
        }

        #[cfg(not(feature = "pcap"))]
        {
            if let Some(path) = plan.logging.pcap_write.as_ref() {
                return Err(ExecutorError::PcapFeatureRequired { path: path.clone() }.into());
            }
            Ok(Self {})
        }
    }

    pub(super) fn record(&mut self, frame: &[u8]) -> Result<()> {
        #[cfg(feature = "pcap")]
        if let Some(writer) = self.capture.as_mut() {
            writer.record(frame)?;
        }
        #[cfg(not(feature = "pcap"))]
        let _ = frame;
        Ok(())
    }

    pub(super) fn flush(&mut self) -> Result<()> {
        #[cfg(feature = "pcap")]
        if let Some(writer) = self.capture.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

#[cfg(feature = "pcap")]
fn linktype_for_plan(link_type: &LinkType) -> pcap::Linktype {
    match link_type {
        LinkType::Ethernet => pcap::Linktype::ETHERNET,
        LinkType::Ipv4 => pcap::Linktype::IPV4,
        LinkType::Ipv6 => pcap::Linktype::IPV6,
    }
}

#[cfg(feature = "pcap")]
struct PacketCapture {
    writer: pcap::Savefile,
}

#[cfg(feature = "pcap")]
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
