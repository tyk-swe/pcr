// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetcraftr_core::{budget::Deadline, frame::LinkType};
use packetcraftr_netio::{
    Error,
    capture::{self, Captured, Group, GroupRequest, Metadata, Session, Stats},
    interface::Id,
};

#[derive(Default)]
struct Trace {
    stops: Vec<u32>,
    joins: Vec<u32>,
    completed: usize,
    expected: usize,
    fail_arm: Option<u32>,
    fail_stop: Option<u32>,
    time: Option<Instant>,
}

struct Provider(Arc<Mutex<Trace>>);
struct Capture {
    trace: Arc<Mutex<Trace>>,
    metadata: Metadata,
}

impl capture::Provider for Provider {
    type Capture = Capture;

    fn arm_capture(&self, request: &capture::Request, _: &Deadline) -> Result<Capture, Error> {
        if self.0.lock().unwrap().fail_arm == Some(request.interface.index) {
            return Err(Error::CaptureReadiness {
                message: "injected arm failure".to_owned(),
            });
        }
        Ok(Capture {
            trace: Arc::clone(&self.0),
            metadata: Metadata {
                interface: request.interface.clone(),
                link_type: LinkType(1),
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
        })
    }
}

impl Session for Capture {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), Error> {
        Ok(())
    }
    fn next_captured_frame(&mut self, _: &Deadline) -> Result<Option<Captured>, Error> {
        Ok(None)
    }
    fn stats(&self) -> Stats {
        Stats::default()
    }
    fn request_stop(&mut self) -> Result<(), Error> {
        let mut trace = self.trace.lock().unwrap();
        trace.stops.push(self.metadata.interface.index);
        if trace.fail_stop == Some(self.metadata.interface.index) {
            return Err(Error::CaptureReadiness {
                message: "injected stop failure".to_owned(),
            });
        }
        Ok(())
    }
    fn shutdown_until(&mut self, deadline: &Deadline) -> Result<(), Error> {
        let mut trace = self.trace.lock().unwrap();
        assert_eq!(
            trace.stops.len(),
            trace.expected,
            "every stop precedes the first join"
        );
        trace.joins.push(self.metadata.interface.index);
        drop(trace);
        if deadline.enforce().is_err() {
            return Err(Error::DeadlineExceeded {
                operation: "test capture cleanup",
            });
        }
        let mut trace = self.trace.lock().unwrap();
        trace.time = trace.time.map(|now| now + Duration::from_millis(600));
        drop(trace);
        if deadline.enforce().is_err() {
            return Err(Error::DeadlineExceeded {
                operation: "test capture cleanup",
            });
        }
        self.trace.lock().unwrap().completed += 1;
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        panic!("cooperative group cleanup must use the shared two-phase boundary")
    }
}

#[test]
fn all_sources_stop_before_join_and_share_one_cleanup_ceiling() {
    for count in [1, 4, 15] {
        let trace = Arc::new(Mutex::new(Trace {
            stops: Vec::with_capacity(count),
            expected: count,
            time: Some(Instant::now()),
            ..Trace::default()
        }));
        let mut group = Group::new(&GroupRequest {
            interfaces: (1..=count)
                .map(|index| Id {
                    index: index as u32,
                    name: format!("test{index}"),
                })
                .collect(),
            limits: capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        })
        .unwrap();
        group
            .arm(
                &Provider(Arc::clone(&trace)),
                &Deadline::new(Duration::from_secs(10)),
            )
            .unwrap();
        let clock = Arc::clone(&trace);
        let deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
            clock.lock().unwrap().time.unwrap()
        });
        let result = group.shutdown_until(&deadline);
        assert_eq!(result.is_ok(), count == 1);
        assert_eq!(trace.lock().unwrap().completed, 1);
        let joins = trace.lock().unwrap().joins.len();
        let _ = group.shutdown();
        drop(group);
        let trace = trace.lock().unwrap();
        assert_eq!(trace.stops.len(), count);
        assert_eq!(
            trace.joins.len(),
            joins,
            "shutdown/drop must not repeat joins"
        );
    }
}

#[test]
fn partial_arm_and_stop_failure_still_join_every_owned_source_once() {
    for partial in [true, false] {
        let trace = Arc::new(Mutex::new(Trace {
            expected: if partial { 1 } else { 4 },
            fail_arm: partial.then_some(2),
            fail_stop: (!partial).then_some(1),
            ..Trace::default()
        }));
        let mut group = Group::new(&GroupRequest {
            interfaces: (1..=4)
                .map(|index| Id {
                    index,
                    name: format!("test{index}"),
                })
                .collect(),
            limits: capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        })
        .unwrap();
        let arm = group.arm(
            &Provider(Arc::clone(&trace)),
            &Deadline::new(Duration::from_secs(10)),
        );
        assert_eq!(arm.is_err(), partial);
        let shutdown = group.shutdown();
        assert_eq!(shutdown.is_err(), !partial);
        if !partial {
            let sources = group.snapshot();
            assert!(!sources[0].shutdown_confirmed);
            assert!(sources[1..].iter().all(|source| source.shutdown_confirmed));
        }
        let _ = group.shutdown();
        drop(group);
        let trace = trace.lock().unwrap();
        assert_eq!(trace.stops.len(), trace.expected);
        assert_eq!(trace.joins.len(), trace.expected);
    }
}
