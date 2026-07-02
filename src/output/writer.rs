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
        write_stdout_all_and_flush(&mut stdout, bytes)
    }

    fn stderr(&self, bytes: &[u8]) -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        stderr.write_all(bytes)?;
        stderr.flush()
    }
}

fn write_stdout_all_and_flush<W: Write + ?Sized>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    match writer.write_all(bytes).and_then(|()| writer.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestWriter {
        write_error: Option<io::ErrorKind>,
        flush_error: Option<io::ErrorKind>,
        written: Vec<u8>,
        flushed: bool,
    }

    impl TestWriter {
        fn with_write_error(kind: io::ErrorKind) -> Self {
            Self {
                write_error: Some(kind),
                ..Self::default()
            }
        }

        fn with_flush_error(kind: io::ErrorKind) -> Self {
            Self {
                flush_error: Some(kind),
                ..Self::default()
            }
        }
    }

    impl Write for TestWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.write_error {
                return Err(io::Error::from(kind));
            }

            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            if let Some(kind) = self.flush_error {
                return Err(io::Error::from(kind));
            }

            Ok(())
        }
    }

    #[test]
    fn stdout_write_treats_broken_pipe_during_write_as_success() {
        let mut writer = TestWriter::with_write_error(io::ErrorKind::BrokenPipe);

        let result = write_stdout_all_and_flush(&mut writer, b"payload");

        assert!(result.is_ok());
    }

    #[test]
    fn stdout_write_treats_broken_pipe_during_flush_as_success() {
        let mut writer = TestWriter::with_flush_error(io::ErrorKind::BrokenPipe);

        let result = write_stdout_all_and_flush(&mut writer, b"payload");

        assert!(result.is_ok());
        assert_eq!(writer.written, b"payload");
        assert!(writer.flushed);
    }

    #[test]
    fn stdout_write_returns_non_broken_pipe_write_errors() {
        let mut writer = TestWriter::with_write_error(io::ErrorKind::PermissionDenied);

        let result = write_stdout_all_and_flush(&mut writer, b"payload");

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn stdout_write_returns_non_broken_pipe_flush_errors() {
        let mut writer = TestWriter::with_flush_error(io::ErrorKind::PermissionDenied);

        let result = write_stdout_all_and_flush(&mut writer, b"payload");

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(writer.written, b"payload");
        assert!(writer.flushed);
    }

    #[test]
    fn stdout_write_writes_and_flushes_successfully() {
        let mut writer = TestWriter::default();

        write_stdout_all_and_flush(&mut writer, b"payload").unwrap();

        assert_eq!(writer.written, b"payload");
        assert!(writer.flushed);
    }
}
