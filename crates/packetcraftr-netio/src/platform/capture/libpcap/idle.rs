// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    io::{self, Write as _},
    os::{
        fd::{AsRawFd, RawFd},
        unix::net::UnixStream,
    },
};

use crate::{capture::live::CaptureInterrupt, platform::common::READ_TIMEOUT_MILLIS};

pub(super) struct Wake {
    capture: RawFd,
    receiver: UnixStream,
}

pub(super) struct Interrupt(UnixStream);

impl Wake {
    pub(super) fn pair(capture: RawFd) -> io::Result<(Self, Interrupt)> {
        let (receiver, sender) = UnixStream::pair()?;
        sender.set_nonblocking(true)?;
        Ok((Self { capture, receiver }, Interrupt(sender)))
    }

    #[expect(unsafe_code, reason = "waits on borrowed descriptors via poll")]
    pub(super) fn wait(&self) -> io::Result<bool> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.receiver.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.capture,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both entries are initialized, writable and valid for the call.
        // A negative descriptor disables device readiness when libpcap has no selectable FD.
        let status = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, READ_TIMEOUT_MILLIS) };
        if status < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(error)
            };
        }
        if descriptors[0].revents != 0 {
            return Ok(true);
        }
        if descriptors[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("libpcap readiness descriptor closed"));
        }
        Ok(false)
    }
}

impl CaptureInterrupt for Interrupt {
    fn interrupt(&self) {
        let _ = (&self.0).write(&[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_stop_without_a_capture_descriptor_is_sticky() {
        let (wait, interrupt) = Wake::pair(-1).unwrap();
        assert!(!wait.wait().unwrap());
        interrupt.interrupt();
        assert!(wait.wait().unwrap());
        assert!(wait.wait().unwrap());
    }
}
