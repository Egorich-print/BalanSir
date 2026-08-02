//! D3: Stress testing for balansir-common
//!
//! - IPC: 10k messages round-trip over Unix socket pair
//! - EventBus: 100k event burst, overflow drop behavior
//! - EventBus: concurrent publishers

use balansir_common::event_bus::{BoundedEventBus, Event};
use balansir_common::ipc::{IpcConnection, IpcMessage, MsgType};
use std::time::Instant;
use tokio::net::UnixStream;

/// IPC burst: 10_000 messages sent and received in order
#[tokio::test]
async fn ipc_burst_10000_messages() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut sender = IpcConnection::new(a);
    let mut receiver = IpcConnection::new(b);

    const COUNT: u32 = 10_000;

    let start = Instant::now();
    let sender_task = tokio::spawn(async move {
        for i in 0..COUNT {
            let msg = IpcMessage::new(MsgType::HealthCheck, i as u64, vec![0xAB; 64]);
            sender.send(&msg).await.unwrap();
        }
    });

    let mut received = 0;
    for _ in 0..COUNT {
        let msg = receiver.recv().await.unwrap();
        assert_eq!(msg.msg_type, MsgType::HealthCheck);
        assert_eq!(msg.correlation_id, received);
        assert_eq!(msg.payload.len(), 64);
        assert!(msg.payload.iter().all(|&b| b == 0xAB));
        received += 1;
    }
    sender_task.await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(received, COUNT as u64);
    eprintln!(
        "ipc_burst_10000_messages: {} msgs in {:?} ({:.0} msgs/s)",
        COUNT,
        elapsed,
        COUNT as f64 / elapsed.as_secs_f64()
    );
}

/// EventBus burst: publish 100k events, verify drop-oldest semantics
#[test]
fn event_bus_burst_drop_oldest() {
    const CAPACITY: usize = 256;
    const COUNT: usize = 100_000;

    let bus = BoundedEventBus::new(CAPACITY);

    let start = Instant::now();
    for i in 0..COUNT {
        bus.publish(Event::ComponentStarted { id: i as u32 });
    }
    let publish_time = start.elapsed();

    // Only last CAPACITY events survive (drop-oldest)
    let mut received = 0;
    let mut last_id = 0;
    while let Some(envelope) = bus.try_recv() {
        received += 1;
        assert!(envelope.id > last_id, "IDs must be strictly monotonic");
        last_id = envelope.id;
    }

    assert_eq!(received, CAPACITY);
    assert_eq!(last_id, COUNT as u64, "last event must be the newest");

    let expected_first = (COUNT - CAPACITY + 1) as u64;
    eprintln!(
        "event_bus_burst_drop_oldest: {} events -> capacity {} kept, first_id={}, last_id={} (publish {:?})",
        COUNT, CAPACITY, expected_first, last_id, publish_time
    );
}

/// EventBus: concurrent publishers must not lose events or break monotonicity
#[test]
fn event_bus_concurrent_publishers() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 10_000;
    const COUNT: usize = THREADS * PER_THREAD;
    // Capacity >= COUNT so nothing is dropped
    let bus = BoundedEventBus::new(COUNT + 1);

    let start = Instant::now();
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let bus = bus.clone();
            scope.spawn(move || {
                for i in 0..PER_THREAD {
                    let event = Event::HighCpu {
                        usage: ((t + i) % 100) as u8,
                    };
                    bus.publish(event);
                }
            });
        }
    });
    let publish_time = start.elapsed();

    let mut received = 0;
    let mut last_id = 0;
    while let Some(envelope) = bus.try_recv() {
        received += 1;
        assert!(envelope.id > last_id, "IDs must be strictly monotonic");
        last_id = envelope.id;
    }

    assert_eq!(received, COUNT, "no events may be lost under concurrency");
    assert_eq!(last_id, COUNT as u64);
    eprintln!(
        "event_bus_concurrent_publishers: {} events from {} threads in {:?}",
        COUNT, THREADS, publish_time
    );
}

/// EventBus recv() with concurrent producer: waiter wakes up
#[tokio::test]
async fn event_bus_concurrent_recv() {
    let bus = BoundedEventBus::new(1024);

    let producer = tokio::spawn({
        let bus = bus.clone();
        async move {
            for i in 0..500u32 {
                bus.publish(Event::ComponentStarted { id: i });
            }
        }
    });

    let mut received = 0;
    loop {
        let envelope = bus.recv().await;
        received += 1;
        if envelope.id >= 500 {
            break;
        }
    }

    producer.await.unwrap();
    assert_eq!(received, 500);
}
