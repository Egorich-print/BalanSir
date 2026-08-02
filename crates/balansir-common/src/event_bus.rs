use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::Notify;

use crate::types::EventId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub id: EventId,
    pub timestamp_ms: i64,
    pub event: Event,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    ComponentStarted { id: u32 },
    ComponentStopped { id: u32, reason: u32 },
    ComponentFailed { id: u32, error: u32 },
    ComponentHealthChanged { id: u32, status: u8 },
    PolicyMatched { rule: u32, action: u8 },
    PolicyFailed { rule: u32, error: u32 },
    DecisionMade { trace_id: u64 },
    InterfaceUp { name_hash: u32 },
    InterfaceDown { name_hash: u32 },
    HighCpu { usage: u8 },
    HighMemory { usage: u8 },
    UpdateAvailable { component: u32, version: u32 },
}

pub struct BoundedEventBus {
    inner: Mutex<BoundedEventBusInner>,
    notify: Notify,
    capacity: usize,
    sequence: AtomicU64,
}

struct BoundedEventBusInner {
    queue: VecDeque<EventEnvelope>,
}

impl BoundedEventBus {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(BoundedEventBusInner {
                queue: VecDeque::with_capacity(capacity),
            }),
            notify: Notify::new(),
            capacity,
            sequence: AtomicU64::new(1),
        }
    }

    pub fn publish(&self, event: Event) {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let envelope = EventEnvelope {
            id,
            timestamp_ms,
            event,
        };

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.queue.len() >= self.capacity {
            inner.queue.pop_front();
        }
        inner.queue.push_back(envelope);
        drop(inner);
        self.notify.notify_waiters();
    }

    pub fn try_recv(&self) -> Option<EventEnvelope> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.queue.pop_front()
    }

    pub async fn recv(&self) -> EventEnvelope {
        loop {
            if let Some(event) = self.try_recv() {
                return event;
            }
            self.notify.notified().await;
        }
    }

    pub fn next_id(&self) -> EventId {
        self.sequence.load(Ordering::Relaxed)
    }
}

impl Clone for BoundedEventBus {
    fn clone(&self) -> Self {
        Self {
            inner: Mutex::new(BoundedEventBusInner {
                queue: VecDeque::with_capacity(self.capacity),
            }),
            notify: Notify::new(),
            capacity: self.capacity,
            sequence: AtomicU64::new(self.sequence.load(Ordering::Relaxed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_bus() {
        let bus = BoundedEventBus::new(16);

        bus.publish(Event::ComponentStarted { id: 1 });

        let envelope = bus.recv().await;
        assert_eq!(envelope.id, 1);
        assert!(envelope.timestamp_ms > 0);
        assert_eq!(envelope.event, Event::ComponentStarted { id: 1 });
    }

    #[tokio::test]
    async fn test_event_bus_overflow() {
        let bus = BoundedEventBus::new(2);

        for i in 0..3 {
            bus.publish(Event::ComponentStarted { id: i });
        }

        let envelope = bus.recv().await;
        assert_eq!(envelope.id, 2); // Second event (first was dropped)
    }

    #[tokio::test]
    async fn test_event_ids_monotonic() {
        let bus = BoundedEventBus::new(16);

        bus.publish(Event::ComponentStarted { id: 1 });
        bus.publish(Event::ComponentStarted { id: 2 });
        bus.publish(Event::ComponentStarted { id: 3 });

        let e1 = bus.recv().await;
        let e2 = bus.recv().await;
        let e3 = bus.recv().await;

        assert!(e1.id < e2.id);
        assert!(e2.id < e3.id);
    }
}
