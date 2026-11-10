//! Live fan-out for the relay: a registry of attached connections,
//! each with its own queue bounded by bytes rather than by slots.
//!
//! The publisher fans a stored event out after its commit. Every attached
//! connection of the event's partition gets one cheap clone (two `Arc`s); the
//! canonical JSON is built once per event, so a recipient only splices its
//! subscription id in front of it.
//!
//! Memory. A queued event is charged `json.len() + QUEUE_OVERHEAD_BYTES`
//! (the cost) twice over: to the queue that holds it, and, once however many
//! queues hold it, to a fan-out wide total. Two limits follow, both enforced
//! by the publisher and neither waiting on a connection task:
//!
//! * a queue over [`LIVE_QUEUE_BYTES`] (4 MiB) is dropped as a lag
//!   disconnect, and only that connection is;
//! * the distinct events held by all queues together never exceed
//!   [`LIVE_TOTAL_BYTES`] (16 MiB). An event that would pass it first evicts
//!   the queues holding the most (a stalled reader, not a healthy one), as a
//!   lag disconnect each.
//!
//! The queues live behind the publisher's reach (a locked deque per
//! connection, not a channel), so an evicted queue's buffer is freed by the
//! publisher at that moment, not when the connection task next runs; a
//! stalled socket pins nothing. The worst case is therefore a constant,
//! whatever the number of stalled or lagging connections.
//!
//! The bound is lower than the two limits suggest. A connection attaches to
//! one partition, and every queue of a partition is a suffix of that
//! partition's stream (everything published since it attached, less what its
//! reader has taken), so the queues' union is the longest of them, which the
//! per-queue limit caps at 4 MiB. Two partitions give at most
//! 2 x 4 MiB = 8 MiB charged in queues. On top of that each connection holds
//! at most one event it has taken off its queue and is writing out (32
//! connections, the `event_relay` route permits, times a 256 KiB event, 8 MiB
//! if every one is a different old event), and that stays charged until it
//! is sent. So at most 16 MiB is charged, which is [`LIVE_TOTAL_BYTES`]: the
//! total only binds if every one of those coincides, and then it evicts the
//! largest queue rather than failing. Charged bytes are roughly 1.5 to 2
//! times that as real heap, so about 24 to 32 MiB at worst on a phone
//! keeper, against up to 32 x 4 MiB charged (128 MiB, 200 MiB or more real)
//! when each overflowed queue stayed pinned until its connection noticed.
//!
//! With custom limits above those a total can bind sooner; eviction then
//! takes every queue's lock on each pass and may evict several queues in
//! turn, since the largest queue frees only the prefix it alone holds.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use nostr::event::Event;
use serde_json::Value;
use tokio::sync::Notify;

use crate::store::Visibility;

/// Bytes one connection may have queued before it is dropped as lagging.
pub const LIVE_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// Bytes of distinct events all queues may hold between them.
pub const LIVE_TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Charged on top of an event's JSON for its parsed copy and queue entry.
const QUEUE_OVERHEAD_BYTES: usize = 512;

/// One stored event on its way to the connections that subscribe to it.
#[derive(Clone)]
pub struct LiveEvent {
    pub visibility: Visibility,
    pub event: Arc<Event>,
    json: Arc<str>,
}

impl LiveEvent {
    /// An event with the JSON the store wrote for it (its `PreparedPut`
    /// form), so it is not serialised again and a spliced frame is byte for
    /// byte the frame a REQ sends for it.
    pub fn stored(visibility: Visibility, event: Arc<Event>, json: Arc<str>) -> Self {
        Self {
            visibility,
            event,
            json,
        }
    }

    /// Serialise the event as the store does. An event that cannot be
    /// serialised has no frame to send, so it is refused here rather than
    /// delivered as `null`.
    pub fn try_new(visibility: Visibility, event: Arc<Event>) -> Result<Self, serde_json::Error> {
        let json: Arc<str> = serde_json::to_string(&*event)?.into();
        Ok(Self::stored(visibility, event, json))
    }

    /// [`Self::try_new`] for tests, whose events always serialise.
    #[cfg(test)]
    pub fn new(visibility: Visibility, event: Arc<Event>) -> Self {
        Self::try_new(visibility, event).expect("a test event serialises")
    }

    /// The event's canonical JSON.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// `["EVENT","<subscription>",<canonical json>]`.
    pub fn frame_for(&self, subscription: &str) -> String {
        event_frame(subscription, &self.json)
    }

    fn cost(&self) -> usize {
        self.json.len() + QUEUE_OVERHEAD_BYTES
    }
}

/// `["EVENT","<subscription>",<json>]`, with the event's JSON spliced in as
/// it is and the subscription id escaped as a JSON string.
pub fn event_frame(subscription: &str, json: &str) -> String {
    let id = Value::from(subscription).to_string();
    let mut frame = String::with_capacity(json.len() + id.len() + 12);
    frame.push_str("[\"EVENT\",");
    frame.push_str(&id);
    frame.push(',');
    frame.push_str(json);
    frame.push(']');
    frame
}

/// The distinct bytes held by queues, released when the last queue holding
/// an event drops it.
struct Charge {
    bytes: usize,
    total: Arc<AtomicUsize>,
}

impl Charge {
    fn new(bytes: usize, total: &Arc<AtomicUsize>) -> Arc<Self> {
        total.fetch_add(bytes, Ordering::AcqRel);
        Arc::new(Self {
            bytes,
            total: Arc::clone(total),
        })
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.total.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct Queued {
    event: LiveEvent,
    cost: usize,
    _charge: Arc<Charge>,
}

#[derive(Default)]
struct Queue {
    events: VecDeque<Queued>,
    /// Sum of `cost` over `events`.
    bytes: usize,
    /// Set by the publisher when it drops this queue.
    lagged: bool,
}

/// One connection's queue, shared by the publisher and its receiver.
struct Shared {
    queue: Mutex<Queue>,
    wake: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        // The critical sections never panic; a poisoned lock still holds a
        // consistent deque.
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// Mark lagged and hand back the buffer, for the caller to free now, on
    /// its own thread. Dropping it releases the events' charges.
    fn evict(&self) -> VecDeque<Queued> {
        let freed = {
            let mut queue = self.lock();
            queue.lagged = true;
            queue.bytes = 0;
            std::mem::take(&mut queue.events)
        };
        self.wake.notify_one();
        freed
    }
}

struct Slot {
    id: u64,
    /// `None` takes every partition (tests and diagnostics).
    partition: Option<Visibility>,
    shared: Arc<Shared>,
}

/// The attached connections' queues. The publisher iterates this after each
/// commit; there is no subscription index yet.
pub struct LiveFanout {
    slots: Mutex<Vec<Slot>>,
    attached: AtomicUsize,
    next_id: AtomicU64,
    queue_bytes: usize,
    total_bytes: usize,
    /// Distinct bytes currently held by queues.
    held: Arc<AtomicUsize>,
}

impl LiveFanout {
    pub fn new(queue_bytes: usize, total_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(Vec::new()),
            attached: AtomicUsize::new(0),
            next_id: AtomicU64::new(0),
            queue_bytes,
            total_bytes,
            held: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// How many receivers are attached. A publisher that sees zero builds
    /// nothing: a receiver attaches before its REQ's stored query runs, so an
    /// event committed after that query began always finds it here.
    pub fn attached(&self) -> usize {
        self.attached.load(Ordering::Acquire)
    }

    /// Distinct bytes held by all queues now.
    #[cfg(test)]
    pub fn held_bytes(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    pub fn attach(self: &Arc<Self>, partition: Option<Visibility>) -> LiveReceiver {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::default()),
            wake: Notify::new(),
        });
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut slots) = self.slots.lock() {
            slots.push(Slot {
                id,
                partition,
                shared: Arc::clone(&shared),
            });
            self.attached.store(slots.len(), Ordering::Release);
        }
        LiveReceiver {
            shared,
            id,
            fanout: Arc::clone(self),
        }
    }

    /// Queue `live` on every attached connection of its partition. A queue
    /// that would pass its byte budget is dropped here, buffer freed, and its
    /// connection ends as a lag disconnect; the others are untouched. If the
    /// event would pass the total, the queues holding the most go first.
    pub fn publish(&self, live: &LiveEvent) {
        let cost = live.cost();
        let Ok(mut slots) = self.slots.lock() else {
            return;
        };
        let takes = |slot: &Slot| slot.partition.is_none_or(|p| p == live.visibility);
        if !slots.iter().any(takes) {
            return;
        }
        while self.held.load(Ordering::Acquire) + cost > self.total_bytes {
            let Some((index, held)) = slots
                .iter()
                .enumerate()
                .map(|(index, slot)| (index, slot.shared.bytes()))
                .max_by_key(|&(_, bytes)| bytes)
            else {
                break;
            };
            if held == 0 {
                break;
            }
            // Freed here, under `slots`: the loop's own test reads `held`,
            // which only falls as the charges drop. Only a custom total can
            // bind (see the module doc), so this is not the common path.
            drop(slots.swap_remove(index).shared.evict());
        }
        let charge = Charge::new(cost, &self.held);
        // Overflowed queues are freed after `slots` is released, so attach
        // and detach on connection tasks never wait on their deallocation.
        let mut overflowed = Vec::new();
        slots.retain(|slot| {
            if !takes(slot) {
                return true;
            }
            let mut queue = slot.shared.lock();
            if queue.bytes + cost > self.queue_bytes {
                drop(queue);
                overflowed.push(slot.shared.evict());
                return false;
            }
            queue.bytes += cost;
            queue.events.push_back(Queued {
                event: live.clone(),
                cost,
                _charge: Arc::clone(&charge),
            });
            drop(queue);
            slot.shared.wake.notify_one();
            true
        });
        self.attached.store(slots.len(), Ordering::Release);
        drop(slots);
        drop(overflowed);
    }

    fn detach(&self, id: u64) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.retain(|slot| slot.id != id);
            self.attached.store(slots.len(), Ordering::Release);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveRecvError {
    /// The queue passed its byte budget (or the fan-out's total) and was
    /// dropped.
    Lagged,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveTryRecvError {
    Empty,
    Lagged,
    Closed,
}

/// One connection's live queue. Dropping it detaches the connection.
pub struct LiveReceiver {
    shared: Arc<Shared>,
    id: u64,
    fanout: Arc<LiveFanout>,
}

impl LiveReceiver {
    fn take(&mut self) -> Result<LiveEvent, LiveTryRecvError> {
        let mut queue = self.shared.lock();
        if queue.lagged {
            return Err(LiveTryRecvError::Lagged);
        }
        match queue.events.pop_front() {
            Some(queued) => {
                queue.bytes -= queued.cost;
                Ok(queued.event)
            }
            None => Err(LiveTryRecvError::Empty),
        }
    }

    /// Cancel-safe. After an overflow it reports [`LiveRecvError::Lagged`]
    /// at once, without delivering what was already queued (the publisher
    /// has already freed it).
    pub async fn recv(&mut self) -> Result<LiveEvent, LiveRecvError> {
        loop {
            match self.take() {
                Ok(event) => return Ok(event),
                Err(LiveTryRecvError::Lagged) => return Err(LiveRecvError::Lagged),
                Err(LiveTryRecvError::Closed) => return Err(LiveRecvError::Closed),
                // `notify_one` keeps a permit if the publisher got here
                // between `take` and this wait, so no wake-up is lost.
                Err(LiveTryRecvError::Empty) => self.shared.wake.notified().await,
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<LiveEvent, LiveTryRecvError> {
        self.take()
    }

    /// Bytes currently charged to this queue.
    pub fn queued_bytes(&self) -> usize {
        self.shared.bytes()
    }
}

impl Drop for LiveReceiver {
    fn drop(&mut self) {
        self.fanout.detach(self.id);
        drop(self.shared.evict());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::key::Keys;

    fn live(keys: &Keys, size: usize, n: usize) -> LiveEvent {
        let event = EventBuilder::new(Kind::from(1), format!("{n:08}{}", "x".repeat(size)))
            .finalize(keys)
            .unwrap();
        LiveEvent::new(Visibility::Sheltered, Arc::new(event))
    }

    #[test]
    fn an_overflowing_queue_is_freed_by_the_publisher_at_once() {
        let keys = Keys::generate();
        let probe = live(&keys, 1000, 0);
        let cost = probe.cost();
        let fanout = LiveFanout::new(cost * 3, cost * 100);
        let mut stalled = fanout.attach(Some(Visibility::Sheltered));
        for n in 0..3 {
            fanout.publish(&live(&keys, 1000, n));
        }
        assert_eq!(stalled.queued_bytes(), cost * 3);
        assert_eq!(fanout.held_bytes(), cost * 3);
        // The fourth overflows it. Nothing has called `recv`: the buffer is
        // already gone and nothing is held for the slow connection.
        fanout.publish(&live(&keys, 1000, 3));
        assert_eq!(fanout.attached(), 0);
        assert_eq!(fanout.held_bytes(), 0, "freed by the publisher");
        assert_eq!(stalled.queued_bytes(), 0);
        assert_eq!(stalled.try_recv().err(), Some(LiveTryRecvError::Lagged));
    }

    #[tokio::test]
    async fn recv_wakes_on_publish_and_reports_a_lag_at_once() {
        let keys = Keys::generate();
        let cost = live(&keys, 100, 0).cost();
        let fanout = LiveFanout::new(cost * 2, cost * 100);
        let mut reader = fanout.attach(None);
        let waiting = tokio::spawn(async move {
            let first = reader.recv().await;
            let second = reader.recv().await;
            (
                first.map(|e| e.event.id),
                second.map(|e| e.event.id),
                reader,
            )
        });
        tokio::task::yield_now().await;
        let (a, b) = (live(&keys, 100, 1), live(&keys, 100, 2));
        fanout.publish(&a);
        fanout.publish(&b);
        let (first, second, mut reader) = waiting.await.unwrap();
        assert_eq!(first, Ok(a.event.id));
        assert_eq!(second, Ok(b.event.id));
        // Three queued with a budget of two: lagged, not delivered.
        for n in 3..6 {
            fanout.publish(&live(&keys, 100, n));
        }
        assert_eq!(reader.recv().await.err(), Some(LiveRecvError::Lagged));
    }

    #[test]
    fn the_total_is_a_constant_however_many_connections_stall() {
        let keys = Keys::generate();
        let cost = live(&keys, 10_000, 0).cost();
        // Per queue far above the total, so only the total can bind.
        let total = cost * 8;
        let fanout = LiveFanout::new(cost * 1000, total);
        let mut stalled: Vec<LiveReceiver> = (0..32).map(|_| fanout.attach(None)).collect();
        let mut keeping_up = fanout.attach(None);
        let mut worst = 0;
        for n in 0..400 {
            fanout.publish(&live(&keys, 10_000, n));
            worst = worst.max(fanout.held_bytes());
            assert!(fanout.held_bytes() <= total, "after event {n}");
            // The healthy reader takes every event as it arrives.
            keeping_up
                .try_recv()
                .expect("a reader that keeps up never lags");
        }
        assert!(worst > cost * 4, "the budget was actually used: {worst}");
        // Memory is now bounded and the stalled readers were dropped, each
        // with its buffer freed on the publisher's thread.
        assert_eq!(fanout.attached(), 1);
        for reader in &mut stalled {
            assert_eq!(reader.try_recv().err(), Some(LiveTryRecvError::Lagged));
            assert_eq!(reader.queued_bytes(), 0);
        }
        assert_eq!(fanout.held_bytes(), 0);
    }

    #[test]
    fn a_shared_event_is_charged_to_the_total_once() {
        let keys = Keys::generate();
        let cost = live(&keys, 1000, 0).cost();
        // Room for four distinct events across twenty queues that all hold
        // them: healthy fan-out costs one copy, not twenty.
        let fanout = LiveFanout::new(cost * 10, cost * 4);
        let mut readers: Vec<LiveReceiver> = (0..20).map(|_| fanout.attach(None)).collect();
        for n in 0..4 {
            fanout.publish(&live(&keys, 1000, n));
        }
        assert_eq!(fanout.held_bytes(), cost * 4);
        assert_eq!(fanout.attached(), 20);
        for reader in &mut readers {
            assert_eq!(reader.queued_bytes(), cost * 4);
            for _ in 0..4 {
                reader.try_recv().unwrap();
            }
        }
        assert_eq!(fanout.held_bytes(), 0, "released with the last holder");
    }

    #[test]
    fn the_stalled_reader_goes_first_when_the_total_is_reached() {
        let keys = Keys::generate();
        let cost = live(&keys, 1000, 0).cost();
        let fanout = LiveFanout::new(cost * 100, cost * 5);
        let mut stalled = fanout.attach(None);
        let mut slow = fanout.attach(None);
        for n in 0..4 {
            fanout.publish(&live(&keys, 1000, n));
        }
        // `slow` has read three of the four; `stalled` none.
        for _ in 0..3 {
            slow.try_recv().unwrap();
        }
        fanout.publish(&live(&keys, 1000, 4));
        fanout.publish(&live(&keys, 1000, 5));
        assert_eq!(stalled.try_recv().err(), Some(LiveTryRecvError::Lagged));
        assert!(slow.try_recv().is_ok(), "the reader nearer the head stays");
        assert!(fanout.held_bytes() <= cost * 5);
    }
}
