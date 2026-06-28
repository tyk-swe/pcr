// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Default, Clone)]
pub struct CapturingOutputSink {
    stdout: Vec<String>,
    stderr: Vec<String>,
}

impl CapturingOutputSink {
    pub fn stdout_line(&mut self, line: impl Into<String>) {
        self.stdout.push(line.into());
    }

    pub fn stderr_line(&mut self, line: impl Into<String>) {
        self.stderr.push(line.into());
    }

    pub fn stdout(&self) -> String {
        self.stdout.join("\n")
    }

    pub fn stderr(&self) -> String {
        self.stderr.join("\n")
    }

    pub fn stdout_lines(&self) -> &[String] {
        &self.stdout
    }

    pub fn stderr_lines(&self) -> &[String] {
        &self.stderr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capturing_output_sink_records_stdout_and_stderr_separately() {
        let mut sink = CapturingOutputSink::default();

        sink.stdout_line("result");
        sink.stderr_line("diagnostic");

        assert_eq!(sink.stdout(), "result");
        assert_eq!(sink.stderr(), "diagnostic");
        assert_eq!(sink.stdout_lines(), &["result".to_string()]);
        assert_eq!(sink.stderr_lines(), &["diagnostic".to_string()]);
    }
}
