//! One writer thread with group commit for the durable event store.
//!
//! Connections prepare an event (parse, verify, size and shape checks) on
//! their own threads, then queue it here. The writer takes whatever is queued,
//! with no debounce, so a lone event commits at once, and hands it to
//! [`EventStore::put_prepared_batch`], which stores the batch in one
//! transaction. Only after that commit does it answer each caller, and only
//! then does it announce the committed events to live subscribers.
//!
//! Queueing is two steps. [`EventWriter::reserve_until`] takes a place in the queue
//! (waiting, in arrival order, while it is full) and hands back a
//! [`Reserved`]; [`Reserved::wait_until`] then waits for the answer. A
//! connection reserves on its own task, so its events enter the queue in the
//! order it sent them, and keeps only the receivers while they commit: no task
//! is left running for a write, so a connection that goes away holds nothing
//! but queue places, and [`Cancel`] gives those back.
//!
//! The queue is bounded in events and in bytes, and that bound covers
//! everything accepted from every connection. Waiting senders hold no work
//! permit: the writer serialises writes, so the permits stay for the work
//! that needs them.
//!
//! If the store runs out of time for a batch it hands the events it never
//! started back as [`EventStoreError::Deferred`]. They are not refused: they
//! go back to the front of the queue, in order, for the next batch.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nostr::event::Event;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use crate::store::{
    BATCH_BUDGET, EventStore, EventStoreError, PreparedPut, PutOutcome, PutResult, Visibility,
};

/// Events that may wait for the writer. The weight bound below is what holds
/// the queue's memory; this count is high enough that ordinary events (about
/// 1 KiB of weight each) reach a full batch before the count stops them.
pub const QUEUE_EVENTS: usize = 4096;
/// Weight that may wait for the writer. An event weighs twice its JSON (the
/// event and its stored text), so this is about 8 MiB of events.
pub const QUEUE_WEIGHT: usize = 16 * 1024 * 1024;
/// Most events in one transaction. Large batches share each changed index
/// page and each commit among more events: with 100 writers at 256 a batch
/// the store wrote about 10 WAL pages per event, at 2,048 about 3 (measured
/// on 6 November 2026, before the store left Bothy). On slow storage [`BATCH_BUDGET`],
/// not this count, is what ends a batch: events not started in time are
/// deferred to the next one, not refused.
pub const BATCH_EVENTS: usize = 2048;
/// Most weight in one transaction, about 2 MiB of events. A single heavier
/// event still goes alone.
pub const BATCH_WEIGHT: usize = 4 * 1024 * 1024;
/// What the commit itself (an fsync, which has no deadline of its own) may add
/// to a batch's time budget when sizing how long a caller waits.
pub const COMMIT_ALLOWANCE: Duration = Duration::from_secs(5);

/// The longest an event can honestly wait from asking for a place to hearing
/// its fate, with the queue full of other connections' work and every batch
/// using its whole time budget: the batch being written, the batches the
/// queue holds (by event count or by weight, whichever needs more), and its
/// own.
pub const fn worst_wait(
    queue_events: usize,
    batch_events: usize,
    queue_weight: usize,
    batch_weight: usize,
) -> Duration {
    let by_events = queue_events.div_ceil(if batch_events == 0 { 1 } else { batch_events });
    let by_weight = queue_weight.div_ceil(if batch_weight == 0 { 1 } else { batch_weight });
    let held = if by_events > by_weight {
        by_events
    } else {
        by_weight
    };
    let batches = held as u64 + 2;
    Duration::from_secs(batches * (BATCH_BUDGET.as_secs() + COMMIT_ALLOWANCE.as_secs()))
}

/// How long a caller waits to queue an event and then to hear its fate, at
/// the default bounds. It is sized from them ([`worst_wait`]), so an event
/// that waits its turn behind honest load is not refused and then stored.
pub const WRITE_WAIT: Duration = worst_wait(QUEUE_EVENTS, BATCH_EVENTS, QUEUE_WEIGHT, BATCH_WEIGHT);

#[derive(Clone, Copy, Debug)]
pub struct WriterLimits {
    pub queue_events: usize,
    pub queue_weight: usize,
    pub batch_events: usize,
    pub batch_weight: usize,
    /// How long a caller waits in all. `None` sizes it from the other bounds
    /// with [`worst_wait`], which is what production does; a test sets a short
    /// one to see the timeout.
    pub write_wait: Option<Duration>,
}

impl Default for WriterLimits {
    fn default() -> Self {
        Self {
            queue_events: QUEUE_EVENTS,
            queue_weight: QUEUE_WEIGHT,
            batch_events: BATCH_EVENTS,
            batch_weight: BATCH_WEIGHT,
            write_wait: None,
        }
    }
}

/// What the writer has done, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriterStats {
    pub batches: u64,
    pub events: u64,
    pub largest_batch: u64,
}

type Announce = Box<dyn Fn(Visibility, Event, Arc<str>) + Send + Sync>;

enum Reply {
    Async(oneshot::Sender<PutResult>),
    Sync(SyncSender<PutResult>),
}

impl Reply {
    fn send(self, result: PutResult) {
        // A caller that gave up has dropped its end; the event stands anyway.
        match self {
            Self::Async(sender) => {
                let _ = sender.send(result);
            }
            Self::Sync(sender) => {
                let _ = sender.send(result);
            }
        }
    }
}

/// What a queued event holds besides the event: how to answer, which place
/// it is, and the queue room it occupies until its batch is answered.
struct Pending {
    reply: Reply,
    seq: u64,
    _slot: OwnedSemaphorePermit,
    _weight: OwnedSemaphorePermit,
}

struct Item {
    put: PreparedPut,
    pending: Pending,
}

#[derive(Default)]
struct Queue {
    items: VecDeque<Item>,
    weight: usize,
    closed: bool,
    /// A batch has been taken and is not yet answered and announced.
    busy: bool,
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    idle: Condvar,
    slots: Arc<Semaphore>,
    weight: Arc<Semaphore>,
    limits: WriterLimits,
    write_wait: Duration,
    seq: AtomicU64,
    batches: AtomicU64,
    events: AtomicU64,
    largest: AtomicU64,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take the event queued as `seq` back out, if it is still waiting for a
    /// batch, and answer it as cancelled. One already in a batch is past
    /// recall and commits.
    fn cancel(&self, seq: u64) -> bool {
        let mut queue = self.lock();
        let Some(at) = queue.items.iter().position(|item| item.pending.seq == seq) else {
            return false;
        };
        let Some(item) = queue.items.remove(at) else {
            return false;
        };
        queue.weight = queue.weight.saturating_sub(item.put.weight());
        let idle = queue.items.is_empty() && !queue.busy;
        drop(queue);
        item.pending.reply.send(Err(EventStoreError::Cancelled));
        if idle {
            self.idle.notify_all();
        }
        true
    }
}

pub struct EventWriter {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

/// A place in the writer's queue that can be given back while the event is
/// still waiting for a batch.
#[derive(Clone)]
pub struct Cancel {
    shared: Arc<Shared>,
    seq: u64,
}

impl Cancel {
    /// Take the event out of the queue if no batch has it yet, answering it
    /// [`EventStoreError::Cancelled`]. Returns whether it did.
    pub fn cancel(&self) -> bool {
        self.shared.cancel(self.seq)
    }
}

/// A queued event whose answer has not arrived. Holds the receiver only: the
/// event itself is in the writer, which commits it whether or not anyone is
/// still waiting.
pub struct Reserved {
    receiver: oneshot::Receiver<PutResult>,
    cancel: Cancel,
}

impl Reserved {
    pub fn canceller(&self) -> Cancel {
        self.cancel.clone()
    }

    /// Wait for the commit or refusal until `deadline`. An `Err` from timing
    /// out does not mean the event was not stored: it may still commit, and a
    /// retry then finds it a duplicate.
    pub async fn wait_until(self, deadline: tokio::time::Instant) -> PutResult {
        match tokio::time::timeout_at(deadline, self.receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(closed()),
            Err(_) => Err(timed_out()),
        }
    }
}

/// [`Reserved`] for a caller that may block a thread.
pub struct ReservedBlocking {
    receiver: Receiver<PutResult>,
    cancel: Cancel,
}

impl ReservedBlocking {
    pub fn canceller(&self) -> Cancel {
        self.cancel.clone()
    }

    pub fn wait_until(self, deadline: Instant) -> PutResult {
        match self
            .receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(timed_out()),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(closed()),
        }
    }
}

fn timed_out() -> EventStoreError {
    EventStoreError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the event writer did not answer in time",
    ))
}

fn closed() -> EventStoreError {
    EventStoreError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "the event writer has stopped",
    ))
}

impl EventWriter {
    /// Start the writer thread. `announce` is called, in commit order and
    /// after every reply of the batch has been sent, for each event that was
    /// stored (or is ephemeral), with the event's JSON as stored.
    pub fn new(
        store: Arc<dyn EventStore>,
        announce: impl Fn(Visibility, Event, Arc<str>) + Send + Sync + 'static,
        limits: WriterLimits,
    ) -> Self {
        let limits = WriterLimits {
            queue_events: limits.queue_events.max(1),
            queue_weight: limits.queue_weight.max(1),
            batch_events: limits.batch_events.max(1),
            batch_weight: limits.batch_weight.max(1),
            write_wait: limits.write_wait,
        };
        let write_wait = limits.write_wait.unwrap_or_else(|| {
            worst_wait(
                limits.queue_events,
                limits.batch_events,
                limits.queue_weight,
                limits.batch_weight,
            )
        });
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::default()),
            ready: Condvar::new(),
            idle: Condvar::new(),
            slots: Arc::new(Semaphore::new(limits.queue_events)),
            weight: Arc::new(Semaphore::new(limits.queue_weight)),
            limits,
            write_wait,
            seq: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            events: AtomicU64::new(0),
            largest: AtomicU64::new(0),
        });
        let worker = Arc::clone(&shared);
        let announce: Announce = Box::new(announce);
        let thread = std::thread::Builder::new()
            .name("wok-event-writer".into())
            .spawn(move || run(worker, store, announce))
            .expect("spawn the event writer thread");
        Self {
            shared,
            thread: Some(thread),
        }
    }

    /// How long a caller should wait in all, to queue and to hear its fate.
    pub fn write_wait(&self) -> Duration {
        self.shared.write_wait
    }

    pub fn stats(&self) -> WriterStats {
        WriterStats {
            batches: self.shared.batches.load(Ordering::Relaxed),
            events: self.shared.events.load(Ordering::Relaxed),
            largest_batch: self.shared.largest.load(Ordering::Relaxed),
        }
    }

    /// Events and weight waiting for the writer, not yet taken into a batch.
    pub fn queued(&self) -> (usize, usize) {
        let queue = self.shared.lock();
        (queue.items.len(), queue.weight)
    }

    /// Block until everything queued so far has been committed, answered and
    /// announced. For an orderly stop and for tests that look at live
    /// delivery, which follows the reply by design.
    pub fn flush(&self) {
        let mut queue = self.shared.lock();
        while (!queue.items.is_empty() || queue.busy) && !queue.closed {
            queue = self
                .shared
                .idle
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn charge(&self, put: &PreparedPut) -> u32 {
        // Never more than the whole bound, or an oversized limit would wait forever.
        put.weight()
            .min(self.shared.limits.queue_weight)
            .min(u32::MAX as usize) as u32
    }

    async fn acquire(&self, charge: u32) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let slot = Arc::clone(&self.shared.slots).acquire_owned().await.ok()?;
        let weight = Arc::clone(&self.shared.weight)
            .acquire_many_owned(charge)
            .await
            .ok()?;
        Some((slot, weight))
    }

    fn push(
        &self,
        put: PreparedPut,
        reply: Reply,
        permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
    ) -> Result<Cancel, EventStoreError> {
        let mut queue = self.shared.lock();
        if queue.closed {
            return Err(closed());
        }
        let seq = self.shared.seq.fetch_add(1, Ordering::Relaxed);
        queue.weight += put.weight();
        queue.items.push_back(Item {
            put,
            pending: Pending {
                reply,
                seq,
                _slot: permits.0,
                _weight: permits.1,
            },
        });
        drop(queue);
        self.shared.ready.notify_one();
        Ok(Cancel {
            shared: Arc::clone(&self.shared),
            seq,
        })
    }

    /// Take a place in the queue for `put`, waiting in arrival order until
    /// `deadline` while it is full. There is no await between the place being
    /// granted and the event being queued, so a cancelled `reserve` queues
    /// nothing and one that returns has queued the event.
    pub async fn reserve_until(
        &self,
        put: PreparedPut,
        deadline: tokio::time::Instant,
    ) -> Result<Reserved, EventStoreError> {
        let charge = self.charge(&put);
        let permits = match tokio::time::timeout_at(deadline, self.acquire(charge)).await {
            Ok(Some(permits)) => permits,
            Ok(None) => return Err(closed()),
            Err(_) => return Err(timed_out()),
        };
        let (sender, receiver) = oneshot::channel();
        let cancel = self.push(put, Reply::Async(sender), permits)?;
        Ok(Reserved { receiver, cancel })
    }

    /// [`Self::reserve_until`] for a caller that is already on a thread it may
    /// block (the blocking pool, a test). It never panics inside a runtime.
    pub fn reserve_blocking(
        &self,
        put: PreparedPut,
        deadline: Instant,
    ) -> Result<ReservedBlocking, EventStoreError> {
        let charge = self.charge(&put);
        // Unconstrained: on a runtime thread the cooperative budget would
        // never refill while this thread blocks, and the wait would stall.
        let wait = tokio::task::coop::unconstrained(self.acquire(charge));
        let permits = match block_on_until(wait, deadline) {
            Some(Some(permits)) => permits,
            Some(None) => return Err(closed()),
            None => return Err(timed_out()),
        };
        let (sender, receiver) = sync_channel(1);
        let cancel = self.push(put, Reply::Sync(sender), permits)?;
        Ok(ReservedBlocking { receiver, cancel })
    }

    /// Queue `put` and wait for it to be committed (or refused), for at most
    /// `wait` in all. An `Err` from timing out does not mean the event was
    /// not stored: it may still commit, and a retry then finds it a duplicate.
    pub async fn submit(&self, put: PreparedPut, wait: Duration) -> PutResult {
        let deadline = tokio::time::Instant::now() + wait;
        self.reserve_until(put, deadline)
            .await?
            .wait_until(deadline)
            .await
    }

    /// [`Self::submit`] for a caller that is already on a thread it may block
    /// (the blocking pool, a test). It never panics inside a runtime.
    pub fn submit_blocking(&self, put: PreparedPut, wait: Duration) -> PutResult {
        let deadline = Instant::now() + wait;
        self.reserve_blocking(put, deadline)?.wait_until(deadline)
    }
}

impl Drop for EventWriter {
    fn drop(&mut self) {
        self.shared.lock().closed = true;
        self.shared.ready.notify_all();
        // The thread drains what is queued, then ends. Joining means the store
        // is released by the time the writer is gone. Known limit: if the last
        // handle is dropped on a runtime worker (a connection ending after
        // the relay), this blocks that worker while the queue drains, which
        // is bounded by the queue's size and not a deadlock, since the writer
        // depends on no runtime.
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

/// Close the queue however the thread ends, so no sender waits on a writer
/// that is gone: dropping the items drops their reply ends.
struct CloseOnExit(Arc<Shared>);

impl Drop for CloseOnExit {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Release builds abort on a panic, so this is for unwinding
            // builds: every later write is refused, and someone should know.
            tracing::error!("the event writer thread panicked; event writes are now refused");
        }
        let mut queue = self.0.lock();
        queue.closed = true;
        queue.items.clear();
        queue.weight = 0;
        queue.busy = false;
        drop(queue);
        self.0.idle.notify_all();
    }
}

fn run(shared: Arc<Shared>, store: Arc<dyn EventStore>, announce: Announce) {
    let _close = CloseOnExit(Arc::clone(&shared));
    loop {
        let mut items = Vec::new();
        {
            let mut queue = shared.lock();
            while queue.items.is_empty() {
                if queue.closed {
                    return;
                }
                queue = shared
                    .ready
                    .wait(queue)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            let mut weight = 0usize;
            while let Some(front) = queue.items.front() {
                let next = front.put.weight();
                if !items.is_empty()
                    && (items.len() >= shared.limits.batch_events
                        || weight.saturating_add(next) > shared.limits.batch_weight)
                {
                    break;
                }
                weight += next;
                queue.weight = queue.weight.saturating_sub(next);
                let Some(item) = queue.items.pop_front() else {
                    break;
                };
                let deletion = item.put.is_deletion();
                items.push(item);
                // A deletion rewrites pages with secure_delete and can add far
                // more WAL than its own size. End the batch there, so the next
                // event's free-space check sees what it wrote.
                if deletion {
                    break;
                }
            }
            queue.busy = true;
        }
        let count = items.len();
        let (puts, pendings): (Vec<PreparedPut>, Vec<Pending>) = items
            .into_iter()
            .map(|item| (item.put, item.pending))
            .unzip();
        let mut results = store.put_prepared_batch(&puts);
        // A store that answers short answers the rest as failed, never as stored.
        results.resize_with(count, || Err(closed()));
        let all_deferred = results
            .iter()
            .all(|result| matches!(result, Err(EventStoreError::Deferred)));
        let mut deferred = Vec::new();
        let mut replies = Vec::with_capacity(count);
        let mut held = Vec::with_capacity(count);
        let mut committed = Vec::with_capacity(count);
        for ((put, pending), result) in puts.into_iter().zip(pendings).zip(results) {
            // The store ran out of time before it started this event. It did
            // nothing with it, so it waits for the next batch, never refused.
            // A store that defers every event has made no progress, so those
            // are refused rather than offered again for ever.
            let result = match result {
                Err(EventStoreError::Deferred) if !all_deferred => {
                    deferred.push(Item { put, pending });
                    continue;
                }
                Err(EventStoreError::Deferred) => Err(closed()),
                other => other,
            };
            // A copied event is never ephemeral news: only direct ones go live so.
            let live = match &result {
                Ok(PutOutcome::Stored) => true,
                Ok(PutOutcome::Ephemeral) => !put.is_replicated(),
                _ => false,
            };
            replies.push((pending.reply, result));
            held.push((pending._slot, pending._weight));
            committed.push((put, live));
        }
        let answered = replies.len();
        // Counted before anyone is answered, so a caller holding its answer
        // always finds its batch in `stats()`.
        shared.batches.fetch_add(1, Ordering::Relaxed);
        shared.events.fetch_add(answered as u64, Ordering::Relaxed);
        shared.largest.fetch_max(answered as u64, Ordering::Relaxed);
        for (reply, result) in replies {
            reply.send(result);
        }
        drop(held);
        for (put, live) in committed {
            // The author was last asked before this event's statements, and
            // the commit came some time after. An author withdrawn since keeps
            // the stored event (a reader's own checks still apply) but is not
            // pushed to subscribers.
            if live && put.still_authorised() {
                let visibility = put.visibility();
                let (event, json) = put.into_parts();
                announce(visibility, event, json);
            }
        }
        {
            let mut queue = shared.lock();
            // Back at the front, in their old order, ahead of anything that
            // queued while this batch ran.
            for item in deferred.into_iter().rev() {
                queue.weight += item.put.weight();
                queue.items.push_front(item);
            }
            queue.busy = false;
        }
        shared.idle.notify_all();
    }
}

struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Poll `future` on this thread until it finishes or `deadline` passes. The
/// futures used here are tokio semaphore waits, which need no runtime.
fn block_on_until<F: Future>(future: F, deadline: Instant) -> Option<F::Output> {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return Some(output);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        std::thread::park_timeout(deadline - now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Slow, SqliteEventStore};
    use nostr::event::{EventBuilder, FinalizeEvent, Kind, Tag};
    use nostr::filter::Filter;
    use nostr::key::Keys;
    use nostr::types::Timestamp;
    use std::sync::atomic::AtomicUsize;
    use tempfile::TempDir;

    const NOW: u64 = 1_900_000_000;

    fn note(keys: &Keys, n: u64) -> Event {
        EventBuilder::new(Kind::from(1), format!("note {n:06}"))
            .custom_created_at(Timestamp::from_secs(NOW - 1_000 + n))
            .finalize(keys)
            .unwrap()
    }

    fn put(event: &Event) -> PreparedPut {
        PreparedPut::new(Visibility::Public, event.clone(), NOW, false).unwrap()
    }

    /// Holds batches at the store's door until released, so a test can pile
    /// events up behind one in flight.
    #[derive(Default)]
    struct Gate {
        held: Mutex<bool>,
        released: Condvar,
    }

    impl Gate {
        fn hold(&self) {
            *self.held.lock().unwrap() = true;
        }
        fn release(&self) {
            *self.held.lock().unwrap() = false;
            self.released.notify_all();
        }
        fn wait(&self) {
            let mut held = self.held.lock().unwrap();
            while *held {
                held = self.released.wait(held).unwrap();
            }
        }
    }

    struct Spy {
        inner: SqliteEventStore,
        gate: Gate,
        log: Arc<Mutex<Vec<String>>>,
        /// Every event id each time the store is offered it.
        seen: Mutex<Vec<String>>,
        entered: AtomicUsize,
        in_flight: AtomicUsize,
    }

    impl Spy {
        fn open(tmp: &TempDir) -> Arc<Self> {
            Self::open_with(tmp, None)
        }
        fn open_with(tmp: &TempDir, budget: Option<Duration>) -> Arc<Self> {
            let inner =
                SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap();
            Arc::new(Self {
                inner: match budget {
                    Some(budget) => inner.with_batch_budget(budget),
                    None => inner,
                },
                gate: Gate::default(),
                log: Arc::default(),
                seen: Mutex::default(),
                entered: AtomicUsize::new(0),
                in_flight: AtomicUsize::new(0),
            })
        }
        fn writer(self: &Arc<Self>, limits: WriterLimits) -> EventWriter {
            let log = Arc::clone(&self.log);
            EventWriter::new(
                Arc::clone(self) as Arc<dyn EventStore>,
                move |_, event, _| log.lock().unwrap().push(format!("announce:{}", event.id)),
                limits,
            )
        }
        fn stored(&self) -> usize {
            self.inner
                .query(Visibility::Public, &Filter::new().limit(128), NOW)
                .unwrap()
                .len()
        }
        fn wait_entered(&self, batches: usize) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.entered.load(Ordering::SeqCst) < batches {
                assert!(
                    Instant::now() < deadline,
                    "the writer never reached the store"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    impl EventStore for Spy {
        fn put(&self, v: Visibility, e: &Event, n: u64) -> PutResult {
            self.inner.put(v, e, n)
        }
        fn query(&self, v: Visibility, f: &Filter, n: u64) -> Result<Vec<Event>, EventStoreError> {
            self.inner.query(v, f, n)
        }
        fn logical_bytes(&self) -> Result<u64, EventStoreError> {
            self.inner.logical_bytes()
        }
        fn put_replicated(&self, v: Visibility, e: &Event, n: u64) -> PutResult {
            self.inner.put_replicated(v, e, n)
        }
        fn expire(&self, now: u64) -> Result<usize, EventStoreError> {
            self.inner.expire(now)
        }
        fn put_prepared_batch(&self, batch: &[PreparedPut]) -> Vec<PutResult> {
            self.in_flight.store(batch.len(), Ordering::SeqCst);
            self.seen
                .lock()
                .unwrap()
                .extend(batch.iter().map(|put| put.event().id.to_hex()));
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.gate.wait();
            let results = self.inner.put_prepared_batch(batch);
            let mut log = self.log.lock().unwrap();
            for put in batch {
                log.push(format!("committed:{}", put.event().id));
            }
            self.in_flight.store(0, Ordering::SeqCst);
            results
        }
    }

    fn position(log: &[String], entry: &str) -> usize {
        log.iter()
            .position(|e| e == entry)
            .unwrap_or_else(|| panic!("{entry} is not in the log"))
    }

    const LONG: Duration = Duration::from_secs(60);

    #[test]
    fn queued_events_commit_together_and_are_answered_and_announced_after_it() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        let events: Vec<Event> = (0..6).map(|n| note(&key, n)).collect();
        spy.gate.hold();
        std::thread::scope(|scope| {
            let spy = &spy;
            let writer = &writer;
            let mut handles = Vec::new();
            let mut submit = |event: &Event| {
                let (event, id) = (put(event), event.id);
                let log = Arc::clone(&spy.log);
                handles.push(scope.spawn(move || {
                    let result = writer.submit_blocking(event, LONG);
                    log.lock().unwrap().push(format!("reply:{id}"));
                    result
                }));
            };
            // One in flight at the gate, then five behind it.
            submit(&events[0]);
            spy.wait_entered(1);
            for event in &events[1..] {
                submit(event);
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while writer.queued().0 < 5 {
                assert!(Instant::now() < deadline, "the five never queued");
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(
                spy.log.lock().unwrap().is_empty(),
                "nothing answered before a commit"
            );
            spy.gate.release();
            for handle in handles {
                assert!(matches!(handle.join().unwrap(), Ok(PutOutcome::Stored)));
            }
        });
        let stats = writer.stats();
        assert_eq!(
            (stats.batches, stats.events, stats.largest_batch),
            (2, 6, 5)
        );
        assert_eq!(spy.inner.commits(), 2, "six events, two transactions");
        drop(writer);
        let log = spy.log.lock().unwrap().clone();
        for event in &events {
            let committed = position(&log, &format!("committed:{}", event.id));
            assert!(committed < position(&log, &format!("reply:{}", event.id)));
            assert!(committed < position(&log, &format!("announce:{}", event.id)));
        }
        assert_eq!(spy.stored(), 6);
    }

    #[test]
    fn a_failed_commit_answers_every_event_and_announces_none() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        spy.inner
            .commit_fault
            .store(rusqlite::ffi::SQLITE_FULL, Ordering::SeqCst);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        spy.gate.hold();
        let results: Vec<PutResult> = std::thread::scope(|scope| {
            let writer = &writer;
            let key = &key;
            let first = scope.spawn(move || writer.submit_blocking(put(&note(key, 0)), LONG));
            spy.wait_entered(1);
            let rest: Vec<_> = (1..4)
                .map(|n| scope.spawn(move || writer.submit_blocking(put(&note(key, n)), LONG)))
                .collect();
            while writer.queued().0 < 3 {
                std::thread::sleep(Duration::from_millis(2));
            }
            spy.gate.release();
            std::iter::once(first)
                .chain(rest)
                .map(|h| h.join().unwrap())
                .collect()
        });
        assert!(
            results
                .iter()
                .all(|r| matches!(r, Err(EventStoreError::Full)))
        );
        writer.flush();
        assert_eq!(writer.stats().largest_batch, 3);
        drop(writer);
        assert!(
            spy.log
                .lock()
                .unwrap()
                .iter()
                .all(|e| !e.starts_with("announce:")),
            "nothing is announced for a batch that did not commit"
        );
        assert_eq!(spy.stored(), 0);
    }

    #[test]
    fn a_flood_past_the_queue_bound_waits_and_loses_nothing() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let limits = WriterLimits {
            queue_events: 4,
            batch_events: 2,
            ..WriterLimits::default()
        };
        let writer = spy.writer(limits);
        let key = Keys::generate();
        spy.gate.hold();
        std::thread::scope(|scope| {
            let writer = &writer;
            let key = &key;
            let handles: Vec<_> = (0..40)
                .map(|n| scope.spawn(move || writer.submit_blocking(put(&note(key, n)), LONG)))
                .collect();
            spy.wait_entered(1);
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(10));
                let held = writer.queued().0 + spy.in_flight.load(Ordering::SeqCst);
                assert!(held <= 4, "{held} events are held against a bound of 4");
            }
            assert!(
                handles.iter().all(|h| !h.is_finished()),
                "nobody is answered while the writer is held"
            );
            spy.gate.release();
            for handle in handles {
                assert!(matches!(handle.join().unwrap(), Ok(PutOutcome::Stored)));
            }
        });
        writer.flush();
        let stats = writer.stats();
        assert_eq!(stats.events, 40);
        assert!(stats.largest_batch <= 2);
        assert_eq!(spy.stored(), 40);
    }

    #[test]
    fn the_queue_is_bounded_in_bytes_as_well() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let key = Keys::generate();
        let weight = put(&note(&key, 0)).weight();
        let limits = WriterLimits {
            queue_weight: weight * 3,
            ..WriterLimits::default()
        };
        let writer = spy.writer(limits);
        spy.gate.hold();
        std::thread::scope(|scope| {
            let writer = &writer;
            let key = &key;
            let handles: Vec<_> = (0..30)
                .map(|n| scope.spawn(move || writer.submit_blocking(put(&note(key, n)), LONG)))
                .collect();
            spy.wait_entered(1);
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(10));
                let (events, bytes) = writer.queued();
                let held = events + spy.in_flight.load(Ordering::SeqCst);
                assert!(held <= 3, "{held} events held against room for 3");
                assert!(bytes <= weight * 3);
            }
            spy.gate.release();
            for handle in handles {
                assert!(matches!(handle.join().unwrap(), Ok(PutOutcome::Stored)));
            }
        });
        assert_eq!(spy.stored(), 30);
    }

    #[test]
    fn a_full_queue_gives_up_at_the_deadline_without_queueing_the_event() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits {
            queue_events: 1,
            ..WriterLimits::default()
        });
        let key = Keys::generate();
        spy.gate.hold();
        std::thread::scope(|scope| {
            let writer = &writer;
            let key = &key;
            let held = scope.spawn(move || writer.submit_blocking(put(&note(key, 0)), LONG));
            spy.wait_entered(1);
            let began = Instant::now();
            let refused = writer.submit_blocking(put(&note(key, 1)), Duration::from_millis(150));
            assert!(
                matches!(refused, Err(EventStoreError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut)
            );
            assert!(began.elapsed() < Duration::from_secs(5));
            spy.gate.release();
            assert!(matches!(held.join().unwrap(), Ok(PutOutcome::Stored)));
        });
        assert_eq!(spy.stored(), 1, "the event that gave up was never queued");
    }

    #[test]
    fn a_wait_that_runs_out_may_still_commit_and_a_retry_is_a_duplicate() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let event = note(&Keys::generate(), 0);
        spy.gate.hold();
        let unknown = writer.submit_blocking(put(&event), Duration::from_millis(150));
        assert!(matches!(unknown, Err(EventStoreError::Io(_))));
        spy.gate.release();
        let retry = writer.submit_blocking(put(&event), LONG);
        assert!(matches!(retry, Ok(PutOutcome::Duplicate)));
        drop(writer);
        let log = spy.log.lock().unwrap().clone();
        assert_eq!(
            log.iter().filter(|e| e.starts_with("announce:")).count(),
            1,
            "a duplicate is not announced again"
        );
    }

    #[test]
    fn a_lone_event_commits_at_once_with_no_debounce() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        for n in 0..5 {
            let began = Instant::now();
            // Nothing else is ever sent: a writer that waited for company
            // would sit out the whole deadline.
            let result = writer.submit_blocking(put(&note(&key, n)), Duration::from_secs(5));
            assert!(matches!(result, Ok(PutOutcome::Stored)));
            assert!(
                began.elapsed() < Duration::from_millis(500),
                "a lone event waited {:?}",
                began.elapsed()
            );
        }
        writer.flush();
        let stats = writer.stats();
        assert_eq!((stats.batches, stats.largest_batch), (5, 1));
    }

    #[tokio::test]
    async fn async_submitters_are_answered_and_each_stored_event_is_announced_once() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = Arc::new(spy.writer(WriterLimits::default()));
        let key = Keys::generate();
        let mut tasks = Vec::new();
        for n in 0..20 {
            let writer = Arc::clone(&writer);
            let event = note(&key, n);
            tasks.push(tokio::spawn(async move {
                writer.submit(put(&event), Duration::from_secs(30)).await
            }));
        }
        for task in tasks {
            assert!(matches!(task.await.unwrap(), Ok(PutOutcome::Stored)));
        }
        drop(writer);
        let log = spy.log.lock().unwrap().clone();
        assert_eq!(
            log.iter().filter(|e| e.starts_with("announce:")).count(),
            20
        );
        assert_eq!(spy.stored(), 20);
    }

    /// Submit `events[0]` and hold it at the gate, then queue the rest behind
    /// it from other threads, in order (each waits for the one before it to be
    /// queued, or a loaded machine can let a later thread in first), so that
    /// they land in one batch. Returns every event's result, in order.
    fn first_alone_then_the_rest_together(
        spy: &Arc<Spy>,
        writer: &EventWriter,
        events: &[Event],
    ) -> Vec<PutResult> {
        spy.gate.hold();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| writer.submit_blocking(put(&events[0]), LONG));
            spy.wait_entered(1);
            let deadline = Instant::now() + Duration::from_secs(10);
            let rest: Vec<_> = events[1..]
                .iter()
                .enumerate()
                .map(|(i, event)| {
                    let put = put(event);
                    let handle = scope.spawn(move || writer.submit_blocking(put, LONG));
                    while writer.queued().0 < i + 1 {
                        assert!(Instant::now() < deadline, "event {} never queued", i + 1);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    handle
                })
                .collect();
            while writer.queued().0 < events.len() - 1 {
                assert!(Instant::now() < deadline, "the rest never queued");
                std::thread::sleep(Duration::from_millis(2));
            }
            spy.gate.release();
            std::iter::once(first)
                .chain(rest)
                .map(|handle| handle.join().unwrap())
                .collect()
        })
    }

    fn announced(spy: &Spy) -> Vec<String> {
        spy.log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.strip_prefix("announce:").map(str::to_owned))
            .collect()
    }

    /// One event that runs past its budget fails alone: the events it shares a
    /// batch with, from other connections, still commit, are answered and are
    /// announced. `how` decides whether SQLite leaves the transaction open (a
    /// read was interrupted: roll back to the savepoint) or takes it down (a
    /// write was: run the pass again without the event).
    fn one_slow_event_fails_alone(how: Slow, expected_reruns: u64) {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        let events: Vec<Event> = (0..6)
            .map(|n| {
                EventBuilder::new(Kind::from(1), format!("note {n}"))
                    .tags([Tag::parse(["t", "x"]).unwrap()])
                    .custom_created_at(Timestamp::from_secs(NOW - 1_000 + n))
                    .finalize(&key)
                    .unwrap()
            })
            .collect();
        // Not the first of its batch, with events either side of it.
        let slow = &events[3];
        spy.inner.slow.lock().unwrap().push((slow.id.to_hex(), how));
        let results = first_alone_then_the_rest_together(&spy, &writer, &events);
        for (n, result) in results.iter().enumerate() {
            if n == 3 {
                assert!(
                    matches!(
                        result,
                        Err(EventStoreError::Sqlite(rusqlite::Error::SqliteFailure(e, _)))
                            if e.code == rusqlite::ErrorCode::OperationInterrupted
                    ),
                    "the slow event is refused: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, Ok(PutOutcome::Stored)),
                    "event {n} is not its batch-mate's to fail: {result:?}"
                );
            }
        }
        writer.flush();
        assert_eq!(
            spy.inner.reruns.load(Ordering::SeqCst),
            expected_reruns,
            "{how:?}"
        );
        assert_eq!(spy.stored(), 5);
        let expected: Vec<String> = events
            .iter()
            .enumerate()
            .filter(|(n, _)| *n != 3)
            .map(|(_, e)| e.id.to_string())
            .collect();
        assert_eq!(
            announced(&spy),
            expected,
            "announced in commit order, none for the slow one"
        );
        // The store is still sound for what follows.
        let after = note(&key, 99);
        assert!(matches!(
            writer.submit_blocking(put(&after), LONG),
            Ok(PutOutcome::Stored)
        ));
        assert_eq!(spy.stored(), 6);
    }

    #[test]
    fn an_event_interrupted_on_a_read_fails_alone_and_its_batch_commits() {
        one_slow_event_fails_alone(Slow::AtFirstRead, 0);
    }

    #[test]
    fn an_event_interrupted_on_a_write_fails_alone_and_the_pass_runs_again_without_it() {
        one_slow_event_fails_alone(Slow::AtFirstWrite, 1);
    }

    #[test]
    fn events_not_started_when_the_batch_budget_runs_out_are_carried_over_not_refused() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open_with(&tmp, Some(Duration::from_millis(100)));
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        let events: Vec<Event> = (0..6).map(|n| note(&key, n)).collect();
        // Events[1] opens the second batch and takes three times its budget,
        // so the four behind it are never started in it.
        spy.inner
            .slow
            .lock()
            .unwrap()
            .push((events[1].id.to_hex(), Slow::Takes(300)));
        let results = first_alone_then_the_rest_together(&spy, &writer, &events);
        assert!(
            results.iter().all(|r| matches!(r, Ok(PutOutcome::Stored))),
            "none refused: {results:?}"
        );
        writer.flush();
        let stats = writer.stats();
        // [0], then [1] with four deferred, then the four together.
        assert_eq!(
            (stats.batches, stats.events, stats.largest_batch),
            (3, 6, 4)
        );
        let seen = spy.seen.lock().unwrap().clone();
        for event in &events {
            let times = seen.iter().filter(|id| **id == event.id.to_hex()).count();
            assert!(times <= 2, "{} was offered {times} times", event.id);
        }
        assert_eq!(
            announced(&spy),
            events.iter().map(|e| e.id.to_string()).collect::<Vec<_>>(),
            "arrival order survives the carry-over"
        );
        assert_eq!(spy.stored(), 6);
    }

    #[test]
    fn a_deletion_ends_its_batch() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        let doomed = note(&key, 1);
        let deletion = EventBuilder::new(Kind::from(5), "")
            .tags([Tag::parse(["e", &doomed.id.to_hex()]).unwrap()])
            .custom_created_at(Timestamp::from_secs(NOW - 500))
            .finalize(&key)
            .unwrap();
        let events = vec![
            note(&key, 0),
            doomed,
            deletion,
            note(&key, 2),
            note(&key, 3),
        ];
        let results = first_alone_then_the_rest_together(&spy, &writer, &events);
        assert!(results.iter().all(|r| matches!(r, Ok(PutOutcome::Stored))));
        writer.flush();
        // [0], then up to and including the deletion, then the rest.
        let stats = writer.stats();
        assert_eq!((stats.batches, stats.largest_batch), (3, 2));
        assert_eq!(spy.stored(), 4, "the deleted note is gone");
    }

    #[test]
    fn a_write_that_is_no_longer_authorised_is_refused_alone_and_never_announced() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        let allowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let events: Vec<Event> = (0..4).map(|n| note(&key, n)).collect();
        spy.gate.hold();
        let writer_ref = &writer;
        let events_ref = &events;
        let results: Vec<PutResult> = std::thread::scope(|scope| {
            let first = scope.spawn(move || writer_ref.submit_blocking(put(&events_ref[0]), LONG));
            spy.wait_entered(1);
            let flag = Arc::clone(&allowed);
            let revocable = put(&events[1])
                .with_recheck(Arc::new(move |_: &Event| flag.load(Ordering::SeqCst)));
            let mut handles =
                vec![scope.spawn(move || writer_ref.submit_blocking(revocable, LONG))];
            for event in &events[2..] {
                let put = put(event);
                handles.push(scope.spawn(move || writer_ref.submit_blocking(put, LONG)));
            }
            while writer.queued().0 < 3 {
                std::thread::sleep(Duration::from_millis(2));
            }
            // Revoked after it was queued, before its batch is applied.
            allowed.store(false, Ordering::SeqCst);
            spy.gate.release();
            std::iter::once(first)
                .chain(handles)
                .map(|h| h.join().unwrap())
                .collect()
        });
        assert!(matches!(results[1], Err(EventStoreError::Unauthorised)));
        for n in [0, 2, 3] {
            assert!(matches!(results[n], Ok(PutOutcome::Stored)), "{n}");
        }
        writer.flush();
        assert_eq!(spy.stored(), 3);
        assert!(!announced(&spy).contains(&events[1].id.to_string()));
    }

    #[test]
    fn an_author_withdrawn_after_the_store_asked_is_stored_but_not_announced() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        // Authorised when the store reaches the event, withdrawn by the time
        // the batch has committed and is about to be announced.
        let withdrawn_later = put(&note(&key, 1)).with_recheck(Arc::new(move |_: &Event| {
            counter.fetch_add(1, Ordering::SeqCst) == 0
        }));
        assert!(matches!(
            writer.submit_blocking(withdrawn_later, LONG),
            Ok(PutOutcome::Stored)
        ));
        let steady = note(&key, 2);
        assert!(matches!(
            writer.submit_blocking(put(&steady), LONG),
            Ok(PutOutcome::Stored)
        ));
        writer.flush();
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "before the write and before the announce"
        );
        assert_eq!(spy.stored(), 2);
        assert_eq!(
            announced(&spy),
            vec![steady.id.to_string()],
            "only the author still authorised is announced"
        );
    }

    #[test]
    fn a_queued_write_can_be_taken_back_until_a_batch_has_it() {
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        let writer = spy.writer(WriterLimits::default());
        let key = Keys::generate();
        let events: Vec<Event> = (0..3).map(|n| note(&key, n)).collect();
        spy.gate.hold();
        let deadline = Instant::now() + LONG;
        let writer_ref = &writer;
        let events_ref = &events;
        std::thread::scope(|scope| {
            let first = scope.spawn(move || writer_ref.submit_blocking(put(&events_ref[0]), LONG));
            spy.wait_entered(1);
            let queued = writer.reserve_blocking(put(&events[1]), deadline).unwrap();
            let kept = writer.reserve_blocking(put(&events[2]), deadline).unwrap();
            assert_eq!(writer.queued().0, 2);
            assert!(queued.canceller().cancel(), "still waiting for a batch");
            assert_eq!(writer.queued().0, 1, "its place is given back");
            assert!(
                matches!(queued.wait_until(deadline), Err(EventStoreError::Cancelled)),
                "answered as cancelled, never stored"
            );
            spy.gate.release();
            assert!(matches!(first.join().unwrap(), Ok(PutOutcome::Stored)));
            assert!(matches!(kept.wait_until(deadline), Ok(PutOutcome::Stored)));
        });
        writer.flush();
        assert_eq!(spy.stored(), 2);
        assert_eq!(writer.queued(), (0, 0));
    }

    #[test]
    fn the_wait_is_sized_from_the_bounds_it_has_to_cover() {
        // The queue can hold this many batches, each allowed its whole budget
        // and a commit, with the batch being written and the event's own.
        let batches = (QUEUE_EVENTS / BATCH_EVENTS) as u32;
        assert!(WRITE_WAIT >= (BATCH_BUDGET + COMMIT_ALLOWANCE) * (batches + 2));
        assert!(WRITE_WAIT >= BATCH_BUDGET * batches);
        let tmp = TempDir::new().unwrap();
        let spy = Spy::open(&tmp);
        assert_eq!(spy.writer(WriterLimits::default()).write_wait(), WRITE_WAIT);
        // Smaller bounds need less, larger need more, and a test can say.
        let small = WriterLimits {
            queue_events: 8,
            batch_events: 4,
            queue_weight: 1 << 30,
            batch_weight: 1 << 29,
            ..WriterLimits::default()
        };
        assert!(spy.writer(small).write_wait() < WRITE_WAIT);
        // The defaults hold four batches by weight and two by count: the wait
        // is set by weight, and stays at six batches' budget.
        assert_eq!(QUEUE_WEIGHT.div_ceil(BATCH_WEIGHT), 4);
        assert!(QUEUE_EVENTS.div_ceil(BATCH_EVENTS) <= 4);
        assert_eq!(WRITE_WAIT, (BATCH_BUDGET + COMMIT_ALLOWANCE) * 6);
        let set = WriterLimits {
            write_wait: Some(Duration::from_millis(7)),
            ..WriterLimits::default()
        };
        assert_eq!(spy.writer(set).write_wait(), Duration::from_millis(7));
    }
}
