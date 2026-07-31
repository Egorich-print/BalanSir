use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::Notify;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    ComponentStarted { id: u32, timestamp: i64 },
    ComponentStopped { id: u32, reason: u32 },
    ComponentFailed { id: u32, error: u32 },
    ComponentHealthChanged { id: u32, status: u8 },
    PolicyMatched { rule: u32, action: u8 },
    PolicyFailed { rule: u32, error: u32 },
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
}

struct BoundedEventBusInner {
    queue: VecDeque<Event>,
}

impl BoundedEventBus {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(BoundedEventBusInner {
                queue: VecDeque::with_capacity(capacity),
            }),
            notify: Notify::new(),
            capacity,
        }
    }

    pub fn publish(&self, event: Event) {
        let mut inner = self.inner.lock().unwrap();
        if inner.queue.len() >= self.capacity {
            inner.queue.pop_front();
        }
        inner.queue.push_back(event);
        drop(inner);
        self.notify.notify_waiters();
    }

    pub fn try_recv(&self) -> Option<Event> {
        let mut inner = self.inner.lock().unwrap();
        inner.queue.pop_front()
    }

    pub async fn recv(&self) -> Event {
        loop {
            if let Some(event) = self.try_recv() {
                return event;
            }
            self.notify.notified().await;
        }
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_bus() {
        let bus = BoundedEventBus::new(16);

        bus.publish(Event::ComponentStarted {
            id: 1,
            timestamp: 1000,
        });

        let event = bus.recv().await;
        match event {
            Event::ComponentStarted { id, timestamp } => {
                assert_eq!(id, 1);
                assert_eq!(timestamp, 1000);
            }
            _ => panic!("Unexpected event"),
        }
    }

    #[tokio::test]
    async fn test_event_bus_overflow() {
        let bus = BoundedEventBus::new(2);

        // Publish 3 events (overflow)
        for i in 0..3 {
            bus.publish(Event::ComponentStarted {
                id: i,
                timestamp: i as i64,
            });
        }

        // Should receive last 2 events
        let event = bus.recv().await;
        match event {
            Event::ComponentStarted { id, .. } => assert_eq!(id, 1),
            _ => panic!("Unexpected event"),
        }
    }
}
