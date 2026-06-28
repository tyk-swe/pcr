use super::*;
use std::collections::HashSet;

#[test]
fn verify_tcp_scan_strategy_report_names_are_unique() {
    let strategies: Vec<Box<dyn TcpScanStrategy>> = vec![
        Box::new(GenericTcpScan::syn()),
        Box::new(GenericTcpScan::fin()),
        Box::new(GenericTcpScan::null()),
        Box::new(GenericTcpScan::xmas()),
        Box::new(GenericTcpScan::ack()),
    ];

    let mut names = HashSet::new();
    for strategy in strategies {
        let name = strategy.report_name();
        assert!(
            names.insert(name),
            "Duplicate report name found: '{}'. All strategies must have unique report names.",
            name
        );
    }
}
