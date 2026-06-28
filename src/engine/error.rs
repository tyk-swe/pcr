use anyhow::Error as AnyhowError;
use thiserror::Error;

/// Result type for engine operations
pub type EngineResult<T> = std::result::Result<T, EngineError>;

/// Errors that can occur during engine operations
#[derive(Error, Debug)]
pub enum EngineError {
    #[error("failed to initialize rule engine: {0}")]
    RuleEngineInit(#[source] AnyhowError),

    #[error("failed to initialize rule send executor: {0}")]
    RuleSendExecutorInit(#[source] AnyhowError),

    #[error("failed to load rules from {path}: {source}")]
    RuleLoad {
        path: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("failed to build packet specification: {0}")]
    PacketSpecBuild(#[source] AnyhowError),

    #[error("failed to generate preflight summary: {0}")]
    PreflightSummary(#[source] AnyhowError),

    #[error("insufficient privileges for raw socket operations: {0}")]
    InsufficientPrivileges(#[source] AnyhowError),

    #[error("failed to plan transmission: {0}")]
    TransmissionPlan(#[source] AnyhowError),

    #[error("transmission execution failed: {0}")]
    TransmissionExecution(#[source] AnyhowError),

    #[error("listener operation failed: {0}")]
    Listener(#[from] crate::network::io::listener::ListenerError),

    #[error("daemon operation failed: {0}")]
    Daemon(#[source] AnyhowError),

    #[error("interactive shell failed: {0}")]
    Interactive(#[source] AnyhowError),

    #[error("traceroute operation failed: {0}")]
    Traceroute(#[source] AnyhowError),

    #[error("scan operation failed: {0}")]
    Scan(#[source] AnyhowError),

    #[error("tokio runtime construction failed: {0}")]
    RuntimeConstruction(#[source] AnyhowError),
}

impl EngineError {
    pub fn rule_engine_init<S: Into<String>>(msg: S) -> Self {
        Self::RuleEngineInit(AnyhowError::msg(msg.into()))
    }

    pub fn rule_send_executor_init<S: Into<String>>(msg: S) -> Self {
        Self::RuleSendExecutorInit(AnyhowError::msg(msg.into()))
    }

    pub fn rule_load<S: Into<String>>(path: S, source: anyhow::Error) -> Self {
        Self::RuleLoad {
            path: path.into(),
            source,
        }
    }

    pub fn preflight_summary<S: Into<String>>(msg: S) -> Self {
        Self::PreflightSummary(AnyhowError::msg(msg.into()))
    }

    pub fn insufficient_privileges<S: Into<String>>(msg: S) -> Self {
        Self::InsufficientPrivileges(AnyhowError::msg(msg.into()))
    }

    pub fn transmission_plan<S: Into<String>>(msg: S) -> Self {
        Self::TransmissionPlan(AnyhowError::msg(msg.into()))
    }

    pub fn transmission_execution<S: Into<String>>(msg: S) -> Self {
        Self::TransmissionExecution(AnyhowError::msg(msg.into()))
    }

    pub fn daemon<S: Into<String>>(msg: S) -> Self {
        Self::Daemon(AnyhowError::msg(msg.into()))
    }

    pub fn interactive<S: Into<String>>(msg: S) -> Self {
        Self::Interactive(AnyhowError::msg(msg.into()))
    }

    pub fn traceroute<S: Into<String>>(msg: S) -> Self {
        Self::Traceroute(AnyhowError::msg(msg.into()))
    }

    pub fn scan<S: Into<String>>(msg: S) -> Self {
        Self::Scan(AnyhowError::msg(msg.into()))
    }

    pub fn runtime_construction<S: Into<String>>(msg: S) -> Self {
        Self::RuntimeConstruction(AnyhowError::msg(msg.into()))
    }
}

// Note: Conversion from EngineError to anyhow::Error is provided automatically
// via thiserror's #[error] attribute and anyhow's blanket From implementation

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_constructors_build_expected_variants() {
        assert!(matches!(
            EngineError::rule_engine_init("oops"),
            EngineError::RuleEngineInit(_)
        ));
        assert!(matches!(
            EngineError::rule_send_executor_init("nope"),
            EngineError::RuleSendExecutorInit(_)
        ));
        let source = anyhow::anyhow!("missing");
        let err = EngineError::rule_load("rules.yml", source);
        match err {
            EngineError::RuleLoad { path, .. } => assert_eq!(path, "rules.yml"),
            _ => panic!("expected RuleLoad"),
        }
        assert!(matches!(
            EngineError::preflight_summary("summary"),
            EngineError::PreflightSummary(_)
        ));
        assert!(matches!(
            EngineError::insufficient_privileges("caps"),
            EngineError::InsufficientPrivileges(_)
        ));
        assert!(matches!(
            EngineError::transmission_plan("plan"),
            EngineError::TransmissionPlan(_)
        ));
        assert!(matches!(
            EngineError::transmission_execution("exec"),
            EngineError::TransmissionExecution(_)
        ));
        assert!(matches!(
            EngineError::daemon("daemon"),
            EngineError::Daemon(_)
        ));
        assert!(matches!(
            EngineError::interactive("repl"),
            EngineError::Interactive(_)
        ));
        assert!(matches!(
            EngineError::traceroute("trace"),
            EngineError::Traceroute(_)
        ));
        assert!(matches!(EngineError::scan("scan"), EngineError::Scan(_)));
        assert!(matches!(
            EngineError::runtime_construction("runtime"),
            EngineError::RuntimeConstruction(_)
        ));
    }

    #[test]
    fn engine_error_display_messages_include_context() {
        let err = EngineError::transmission_execution("failed");
        assert!(err.to_string().contains("transmission execution failed"));

        let err = EngineError::rule_engine_init("boom");
        assert!(err.to_string().contains("failed to initialize rule engine"));
    }
}
