// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::clock::{Clock, SystemClock};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct ScriptedStream {
    read: ReadMode,
    write: WriteMode,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
enum ReadMode {
    IdlePoll,
    OneByte,
}

#[derive(Clone, Copy)]
enum WriteMode {
    WouldBlock,
}

impl Read for ScriptedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match self.read {
            ReadMode::IdlePoll => {
                std::thread::sleep(crate::deadline::POLL_INTERVAL + Duration::from_millis(2));
                Err(io::ErrorKind::WouldBlock.into())
            }
            ReadMode::OneByte => {
                bytes[0] = 0x17;
                Ok(1)
            }
        }
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        match self.write {
            WriteMode::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl crate::tcp::Stream for ScriptedStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:443".parse().unwrap())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:44444".parse().unwrap())
    }

    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

fn limits(max_steps: usize) -> Limits {
    Limits {
        max_steps,
        ..Limits::default()
    }
}

fn stream(
    read: ReadMode,
    write: WriteMode,
) -> (ScriptedStream, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    (
        ScriptedStream {
            read,
            write,
            reads: Arc::clone(&reads),
            writes: Arc::clone(&writes),
        },
        reads,
        writes,
    )
}

fn step_limit(error: io::Error) -> bool {
    error
        .into_inner()
        .and_then(|inner| inner.downcast::<Error>().ok())
        .is_some_and(|error| matches!(*error, Error::StepLimit { .. }))
}

#[test]
fn idle_poll_slices_survive_past_the_step_budget_duration() {
    let (inner, reads, _) = stream(ReadMode::IdlePoll, WriteMode::WouldBlock);
    let mut wire = Wire::new(
        inner,
        limits(1),
        Deadline::new(Duration::from_millis(250)),
        |_: &[u8]| Ok::<(), io::Error>(()),
    );
    let started = SystemClock.now();
    let mut buffer = [0_u8; 16];

    for _ in 0..2 {
        assert_eq!(
            wire.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    assert!(started.elapsed() > crate::deadline::POLL_INTERVAL);
    assert_eq!(wire.steps, 0);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn a_silent_peer_reaches_its_deadline_before_the_step_limit() {
    let (inner, reads, _) = stream(ReadMode::IdlePoll, WriteMode::WouldBlock);
    let mut wire = Wire::new(
        inner,
        limits(1),
        Deadline::new(crate::deadline::POLL_INTERVAL + Duration::from_millis(1)),
        |_: &[u8]| Ok::<(), io::Error>(()),
    );
    let mut buffer = [0_u8; 16];

    assert_eq!(
        wire.read(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let error = wire.enforce().unwrap_err();
    assert!(matches!(error, Error::Interrupted(_)));
    assert!(!matches!(error, Error::StepLimit { .. }));
    assert_eq!(wire.steps, 0);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[test]
fn one_byte_slow_loris_reads_consume_the_step_limit() {
    let (inner, reads, _) = stream(ReadMode::OneByte, WriteMode::WouldBlock);
    let mut wire = Wire::new(
        inner,
        limits(2),
        Deadline::new(Duration::from_secs(5)),
        |_: &[u8]| Ok::<(), io::Error>(()),
    );
    let mut buffer = [0_u8; 16];

    assert_eq!(wire.read(&mut buffer).unwrap(), 1);
    assert_eq!(wire.read(&mut buffer).unwrap(), 1);
    assert!(step_limit(wire.read(&mut buffer).unwrap_err()));
    assert_eq!(wire.steps, 2);
    assert_eq!(wire.bytes_read, 2);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn write_would_block_retries_consume_the_step_limit() {
    let (inner, _, writes) = stream(ReadMode::OneByte, WriteMode::WouldBlock);
    let mut wire = Wire::new(
        inner,
        limits(2),
        Deadline::new(Duration::from_secs(5)),
        |_: &[u8]| Ok::<(), io::Error>(()),
    );

    assert_eq!(
        wire.write(b"abc").unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        wire.write(b"abc").unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(step_limit(wire.write(b"abc").unwrap_err()));
    assert_eq!(wire.steps, 2);
    assert_eq!(wire.bytes_sent, 0);
    assert_eq!(writes.load(Ordering::SeqCst), 2);
}
