/// Global configuration derived from CLI arguments.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub output_format: Option<crate::output::OutputFormat>,
    pub prometheus_bind: Option<String>,
    pub rule_workers: Option<usize>,
    pub rule_queue: Option<usize>,
    pub send_workers: Option<usize>,
    pub send_queue: Option<usize>,
    pub allow_unbounded_sends: bool,
    pub dry_run: bool,
}
