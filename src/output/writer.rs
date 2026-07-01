// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
#[cfg(test)]
use std::sync::Mutex;

pub(crate) trait OutputWriter: Send + Sync {
    fn stdout(&self, bytes: &[u8]) -> io::Result<()>;
    fn stderr(&self, bytes: &[u8]) -> io::Result<()>;
}

#[derive(Debug, Default)]
pub(crate) struct StdOutputWriter;

impl OutputWriter for StdOutputWriter {
    fn stdout(&self, bytes: &[u8]) -> io::Result<()> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()
    }

    fn stderr(&self, bytes: &[u8]) -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        stderr.write_all(bytes)?;
        stderr.flush()
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct BufferOutputWriter {
    stdout: Mutex<Vec<u8>>,
    stderr: Mutex<Vec<u8>>,
}

#[cfg(test)]
#[allow(dead_code)]
impl BufferOutputWriter {
    pub(crate) fn stdout_string(&self) -> String {
        String::from_utf8(self.stdout.lock().unwrap().clone()).unwrap()
    }

    pub(crate) fn stderr_string(&self) -> String {
        String::from_utf8(self.stderr.lock().unwrap().clone()).unwrap()
    }
}

#[cfg(test)]
impl OutputWriter for BufferOutputWriter {
    fn stdout(&self, bytes: &[u8]) -> io::Result<()> {
        self.stdout.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }

    fn stderr(&self, bytes: &[u8]) -> io::Result<()> {
        self.stderr.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }
}
