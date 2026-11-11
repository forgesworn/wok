//! Writes: acknowledged events through the engine, and through the bare
//! `EventWriter` for comparison, in the same run.
//!
//! Each door takes its own subset of the corpus (see `doors`), and the same
//! subset goes through both paths. A cell is one connection count and one
//! in-flight window, on a fresh store. The sessions are tasks on a
//! multi-thread runtime; they are authenticated, and their frame texts are
//! serialised, before a shared start.
//!
//! Engine path, per frame: `PreparedFrame::parse` (the typed parse and the
//! signature check), `admit_frame`, `begin_prepared`. The `PendingWrite` that
//! comes back is then committed in one of two forms:
//!
//! - window 1: `PendingWrite::commit`, one write at a time per session.
//! - window above 1: `PendingWrite::reserve` in arrival order, then up to
//!   `window` `WriteTicket::wait` futures awaited together. They are polled by
//!   the session's own task, not spawned.
//!
//! Baseline path: the same events, already checked into `PreparedPut`s before
//! the clock, through `EventWriter::reserve_until` and `Reserved::wait_until`
//! in the same two forms, from the same tasks. It differs from
//! `ingest.rs::through_writer`, which submits from blocking threads with
//! `submit_blocking`: this one submits from async tasks, as a connection loop
//! does. The baseline's clock excludes signature verification, which the
//! engine's includes; the verification-only cost of each subset is reported
//! so that the two can be read against each other.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::key::Keys;
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use tokio::sync::{Barrier, Semaphore};
use tokio::task::{JoinHandle, spawn_blocking, unconstrained};
use tokio::time::timeout;
use wok_store::relay::{Handled, PUBLIC_KINDS, PreparedFrame, ok};
use wok_store::writer::{EventWriter, WriterLimits, WriterStats};
use wok_store::{
    EventStore, MAX_EXACT_COUNT, PreparedPut, PutOutcome, PutResult, SqliteEventStore, Visibility,
};

use super::{
    Clock, FRAME_LIMIT, Keepers, PRODUCTION_FRAME_LIMIT, STALL, authenticate_at, describe,
    event_text, relay_on, relay_url, runtime,
};
use crate::config::Config;
use crate::corpus::{Corpus, NOW};
use crate::support::{fresh_store, ms, partition_name, per_second, summarise, us};

/// Events checked by id after each cell, in chunks of `ID_CHUNK`.
const ID_SAMPLE: usize = 256;
const ID_CHUNK: usize = 64;

/// One door of the relay and the part of the corpus it admits.
struct Door<'a> {
    visibility: Visibility,
    rule: &'static str,
    /// The corpus events of this partition, and how many the door refuses by
    /// kind.
    in_partition: usize,
    refused_by_kind: BTreeMap<u16, usize>,
    admitted: usize,
    /// The events sent: the admitted ones, capped by `--engine-events`.
    events: Vec<&'a Event>,
}

impl Door<'_> {
    fn name(&self) -> &'static str {
        partition_name(self.visibility)
    }
}

/// Work out, from the engine's own rules, what each door takes.
///
/// - Public: the session must be a keeper, the event's author must be a keeper
///   and its kind one of `PUBLIC_KINDS`. Every corpus author is a keeper, so
///   the public door takes the public partition's kinds 0, 1 and 7 and refuses
///   its articles (kind 30023).
/// - Sheltered: a keeper session may store any kind from any author, so the
///   sheltered door takes the whole sheltered partition.
///
/// No check is weakened: the refused events are exactly the ones the door
/// would refuse, and `refusal_check` sends one to prove it.
fn doors<'a>(cfg: &Config, corpus: &'a Corpus, keepers: &Keepers) -> Result<Vec<Door<'a>>, String> {
    use wok_store::relay::KeeperAccess;
    let mut doors = Vec::new();
    for (visibility, rule) in [
        (
            Visibility::Public,
            "a keeper session; the event's author a keeper and its kind one of PUBLIC_KINDS (0, 1, 3, 5, 6, 7, 10002, 10050, 10063)",
        ),
        (
            Visibility::Sheltered,
            "a keeper session; any kind and any author",
        ),
    ] {
        let mut door = Door {
            visibility,
            rule,
            in_partition: 0,
            refused_by_kind: BTreeMap::new(),
            admitted: 0,
            events: Vec::new(),
        };
        for event in corpus.events_in(visibility) {
            door.in_partition += 1;
            let kind = event.kind.as_u16();
            let admitted = match visibility {
                Visibility::Public => keepers.owns(&event.pubkey) && PUBLIC_KINDS.contains(&kind),
                Visibility::Sheltered => true,
            };
            if admitted {
                door.admitted += 1;
                door.events.push(event);
            } else {
                *door.refused_by_kind.entry(kind).or_default() += 1;
            }
        }
        if cfg.engine_events > 0 {
            door.events.truncate(cfg.engine_events);
        }
        if door.events.is_empty() {
            return Err(format!(
                "the {} door admits no corpus event; raise --events",
                door.name()
            ));
        }
        doors.push(door);
    }
    Ok(doors)
}

/// What a session did, kept per lane and merged after the run.
#[derive(Default)]
pub(crate) struct Lane {
    /// Frame start to acknowledgement, in nanoseconds.
    pub(crate) latencies: Vec<u64>,
    pub(crate) parse_ns: u64,
    pub(crate) begin_ns: u64,
    /// End of `begin_prepared` (or the reservation, for the baseline) to the
    /// acknowledgement.
    pub(crate) queue_ns: u64,
    /// Time inside `reserve` (or `reserve_until`) alone.
    pub(crate) reserve_ns: u64,
    /// WebSocket Ping frames a socket lane saw while it wrote; 0 elsewhere.
    pub(crate) pings: u64,
    pub(crate) finished: Option<Instant>,
}

impl Lane {
    fn acknowledged(&mut self, started: Instant, mark: Instant, at: Instant) {
        self.latencies.push((at - started).as_nanos() as u64);
        self.queue_ns += (at - mark).as_nanos() as u64;
    }
}

type Pending<T> = Pin<Box<dyn Future<Output = T> + Send>>;

struct Slot<M, T> {
    started: Instant,
    mark: Instant,
    meta: M,
    future: Pending<T>,
}

struct Done<M, T> {
    started: Instant,
    mark: Instant,
    meta: M,
    output: T,
    at: Instant,
}

/// Up to `window` writes in flight, awaited together by one task.
struct Flight<M, T> {
    slots: Vec<Slot<M, T>>,
}

impl<M, T> Flight<M, T> {
    fn new(window: usize) -> Self {
        Self {
            slots: Vec::with_capacity(window),
        }
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn push(&mut self, started: Instant, mark: Instant, meta: M, future: Pending<T>) {
        self.slots.push(Slot {
            started,
            mark,
            meta,
            future,
        });
    }

    /// Poll every slot once; the ones that finished are removed, in order, and
    /// stamped with the time they were seen to finish.
    fn poll_done(&mut self, cx: &mut Context<'_>) -> Vec<Done<M, T>> {
        let mut done = Vec::new();
        let mut index = 0;
        while index < self.slots.len() {
            match self.slots[index].future.as_mut().poll(cx) {
                Poll::Ready(output) => {
                    let slot = self.slots.remove(index);
                    done.push(Done {
                        started: slot.started,
                        mark: slot.mark,
                        meta: slot.meta,
                        output,
                        at: Instant::now(),
                    });
                }
                Poll::Pending => index += 1,
            }
        }
        done
    }

    /// The writes that have finished by now, without waiting. The cooperative
    /// budget is lifted: polling a window of futures would otherwise spend it
    /// many times faster than a connection task does.
    async fn ready(&mut self) -> Vec<Done<M, T>> {
        unconstrained(poll_fn(|cx| Poll::Ready(self.poll_done(cx)))).await
    }

    /// Wait until at least one write has finished. Never call it empty.
    async fn some(&mut self) -> Vec<Done<M, T>> {
        unconstrained(poll_fn(|cx| {
            let done = self.poll_done(cx);
            if done.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(done)
            }
        }))
        .await
    }
}

fn expect_stored(label: &str, id: &str, replies: &[String]) -> Result<(), String> {
    if replies.len() == 1 && replies[0] == ok(id, true, "") {
        Ok(())
    } else {
        Err(format!(
            "{label}: write {id}: expected one OK true, got {}",
            describe(replies)
        ))
    }
}

fn expect_put(label: &str, index: usize, result: &PutResult) -> Result<(), String> {
    match result {
        Ok(PutOutcome::Stored) => Ok(()),
        other => Err(format!("{label}: put {index}: not stored: {other:?}")),
    }
}

/// One session's frames through the engine. `clock` gives the `now` of every
/// frame: fixed for the engine scenario, the wall clock where the figures are
/// read beside a door's, which stamps frames with wall time.
async fn engine_lane(
    label: String,
    mut session: wok_store::relay::RelaySession,
    frames: Vec<String>,
    window: usize,
    clock: Clock,
    start: Arc<Barrier>,
) -> Result<Lane, String> {
    let mut lane = Lane {
        latencies: Vec::with_capacity(frames.len()),
        ..Lane::default()
    };
    let mut flight: Flight<String, Vec<String>> = Flight::new(window);
    start.wait().await;
    for (index, text) in frames.into_iter().enumerate() {
        let started = Instant::now();
        let prepared = PreparedFrame::parse(text);
        let parsed = Instant::now();
        if !session.admit_frame(clock.now()) {
            return Err(format!(
                "{label}: frame {index}: the frame allowance refused it"
            ));
        }
        let handled = session.begin_prepared(prepared, clock.now());
        let begun = Instant::now();
        lane.parse_ns += (parsed - started).as_nanos() as u64;
        lane.begin_ns += (begun - parsed).as_nanos() as u64;
        let write = match handled {
            Handled::Write(write) => write,
            Handled::Replies(replies) => {
                return Err(format!(
                    "{label}: frame {index}: expected a write to queue, got {}",
                    describe(&replies)
                ));
            }
        };
        let id = write.id().to_owned();
        if window == 1 {
            let replies = write.commit().await;
            let acked = Instant::now();
            lane.acknowledged(started, begun, acked);
            expect_stored(&label, &id, &replies)?;
        } else {
            let reserving = Instant::now();
            let ticket = write.reserve().await.map_err(|replies| {
                format!(
                    "{label}: frame {index}: no place in the writer's queue: {}",
                    describe(&replies)
                )
            })?;
            lane.reserve_ns += reserving.elapsed().as_nanos() as u64;
            flight.push(started, begun, id, Box::pin(ticket.wait()));
            for done in flight.ready().await {
                finish_engine(&label, &mut lane, done)?;
            }
            while flight.len() >= window {
                for done in flight.some().await {
                    finish_engine(&label, &mut lane, done)?;
                }
            }
        }
    }
    while flight.len() > 0 {
        for done in flight.some().await {
            finish_engine(&label, &mut lane, done)?;
        }
    }
    lane.finished = Some(Instant::now());
    Ok(lane)
}

/// The door's blocking-pool hops, added to the engine lane by the
/// `door-path` scenario's stand-ins. The engine scenario and the socket
/// scenario's direct arm never take them: they run [`engine_lane`] unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hops {
    /// `PreparedFrame::parse` on `spawn_blocking`, awaited; `begin_prepared`
    /// inline on the lane's task.
    Parse,
    /// As [`Self::Parse`], then the door's `apply`: an owned permit from the
    /// shared work semaphore, awaited under the door's own I/O deadline, and
    /// `begin_prepared` on a second `spawn_blocking` whose closure holds the
    /// permit and takes and returns the session.
    ParseAndBegin,
}

impl Hops {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::ParseAndBegin => "parse_and_begin",
        }
    }
}

/// The door's deadline on taking a work permit (`IO_TIMEOUT` in `wok-ws`,
/// which is private).
pub(crate) const DOOR_PERMIT_WAIT: Duration = Duration::from_secs(10);

/// [`engine_lane`] with the door's blocking-pool hops. Everything else (the
/// order parse, `admit_frame`, `begin_prepared`, the two commit forms, the
/// timings and the checks) is as in [`engine_lane`]. `work` is the shared
/// work semaphore, used by [`Hops::ParseAndBegin`] only.
#[allow(clippy::too_many_arguments)]
async fn hop_lane(
    label: String,
    mut session: wok_store::relay::RelaySession,
    frames: Vec<String>,
    window: usize,
    clock: Clock,
    start: Arc<Barrier>,
    hops: Hops,
    work: Arc<Semaphore>,
) -> Result<Lane, String> {
    let mut lane = Lane {
        latencies: Vec::with_capacity(frames.len()),
        ..Lane::default()
    };
    let mut flight: Flight<String, Vec<String>> = Flight::new(window);
    start.wait().await;
    for (index, text) in frames.into_iter().enumerate() {
        let started = Instant::now();
        let prepared = spawn_blocking(move || PreparedFrame::parse(text))
            .await
            .map_err(|e| format!("{label}: frame {index}: the parse task failed: {e}"))?;
        let parsed = Instant::now();
        if !session.admit_frame(clock.now()) {
            return Err(format!(
                "{label}: frame {index}: the frame allowance refused it"
            ));
        }
        let handled = match hops {
            Hops::Parse => session.begin_prepared(prepared, clock.now()),
            Hops::ParseAndBegin => {
                let permit = timeout(DOOR_PERMIT_WAIT, Arc::clone(&work).acquire_owned())
                    .await
                    .map_err(|_| format!("{label}: frame {index}: no work permit in time"))?
                    .map_err(|e| format!("{label}: frame {index}: the work semaphore: {e}"))?;
                let (returned, handled) = spawn_blocking(move || {
                    let _permit = permit;
                    let handled = session.begin_prepared(prepared, clock.now());
                    (session, handled)
                })
                .await
                .map_err(|e| format!("{label}: frame {index}: the begin task failed: {e}"))?;
                session = returned;
                handled
            }
        };
        let begun = Instant::now();
        lane.parse_ns += (parsed - started).as_nanos() as u64;
        lane.begin_ns += (begun - parsed).as_nanos() as u64;
        let write = match handled {
            Handled::Write(write) => write,
            Handled::Replies(replies) => {
                return Err(format!(
                    "{label}: frame {index}: expected a write to queue, got {}",
                    describe(&replies)
                ));
            }
        };
        let id = write.id().to_owned();
        if window == 1 {
            let replies = write.commit().await;
            let acked = Instant::now();
            lane.acknowledged(started, begun, acked);
            expect_stored(&label, &id, &replies)?;
        } else {
            let reserving = Instant::now();
            let ticket = write.reserve().await.map_err(|replies| {
                format!(
                    "{label}: frame {index}: no place in the writer's queue: {}",
                    describe(&replies)
                )
            })?;
            lane.reserve_ns += reserving.elapsed().as_nanos() as u64;
            flight.push(started, begun, id, Box::pin(ticket.wait()));
            for done in flight.ready().await {
                finish_engine(&label, &mut lane, done)?;
            }
            while flight.len() >= window {
                for done in flight.some().await {
                    finish_engine(&label, &mut lane, done)?;
                }
            }
        }
    }
    while flight.len() > 0 {
        for done in flight.some().await {
            finish_engine(&label, &mut lane, done)?;
        }
    }
    lane.finished = Some(Instant::now());
    Ok(lane)
}

fn finish_engine(
    label: &str,
    lane: &mut Lane,
    done: Done<String, Vec<String>>,
) -> Result<(), String> {
    lane.acknowledged(done.started, done.mark, done.at);
    expect_stored(label, &done.meta, &done.output)
}

/// One submitter's puts straight through the writer.
async fn baseline_lane(
    label: String,
    writer: Arc<EventWriter>,
    puts: Vec<PreparedPut>,
    window: usize,
    start: Arc<Barrier>,
) -> Result<Lane, String> {
    let mut lane = Lane {
        latencies: Vec::with_capacity(puts.len()),
        ..Lane::default()
    };
    let wait = writer.write_wait();
    let mut flight: Flight<usize, PutResult> = Flight::new(window);
    start.wait().await;
    for (index, put) in puts.into_iter().enumerate() {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + wait;
        let reserved = writer
            .reserve_until(put, deadline)
            .await
            .map_err(|e| format!("{label}: put {index}: no place in the writer's queue: {e:?}"))?;
        let queued = Instant::now();
        lane.reserve_ns += (queued - started).as_nanos() as u64;
        if window == 1 {
            let result = reserved.wait_until(deadline).await;
            lane.acknowledged(started, queued, Instant::now());
            expect_put(&label, index, &result)?;
        } else {
            flight.push(
                started,
                queued,
                index,
                Box::pin(reserved.wait_until(deadline)),
            );
            for done in flight.ready().await {
                finish_baseline(&label, &mut lane, done)?;
            }
            while flight.len() >= window {
                for done in flight.some().await {
                    finish_baseline(&label, &mut lane, done)?;
                }
            }
        }
    }
    while flight.len() > 0 {
        for done in flight.some().await {
            finish_baseline(&label, &mut lane, done)?;
        }
    }
    lane.finished = Some(Instant::now());
    Ok(lane)
}

fn finish_baseline(
    label: &str,
    lane: &mut Lane,
    done: Done<usize, PutResult>,
) -> Result<(), String> {
    lane.acknowledged(done.started, done.mark, done.at);
    expect_put(label, done.meta, &done.output)
}

/// The lanes merged.
pub(crate) struct Merged {
    pub(crate) latencies: Vec<u64>,
    pub(crate) parse_ns: u64,
    pub(crate) begin_ns: u64,
    pub(crate) queue_ns: u64,
    pub(crate) reserve_ns: u64,
    pub(crate) pings: u64,
    pub(crate) lanes_with_events: usize,
    pub(crate) wall: Duration,
}

/// Release the lanes together, wait for them all and merge what they did.
pub(crate) fn drive(
    runtime: &Runtime,
    tasks: Vec<JoinHandle<Result<Lane, String>>>,
    start: &Arc<Barrier>,
) -> Result<Merged, String> {
    // Taken before the barrier opens, so the clock never starts after a lane.
    let started = Instant::now();
    runtime.block_on(start.wait());
    let mut merged = Merged {
        latencies: Vec::new(),
        parse_ns: 0,
        begin_ns: 0,
        queue_ns: 0,
        reserve_ns: 0,
        pings: 0,
        lanes_with_events: 0,
        wall: Duration::ZERO,
    };
    for handle in tasks {
        let joined = runtime.block_on(async { tokio::time::timeout(STALL, handle).await });
        let lane = match joined {
            Err(_) => return Err("a session did not finish in time".into()),
            Ok(Err(_)) => return Err("a session task panicked".into()),
            Ok(Ok(lane)) => lane?,
        };
        if !lane.latencies.is_empty() {
            merged.lanes_with_events += 1;
        }
        merged.latencies.extend(lane.latencies);
        merged.parse_ns += lane.parse_ns;
        merged.begin_ns += lane.begin_ns;
        merged.queue_ns += lane.queue_ns;
        merged.reserve_ns += lane.reserve_ns;
        merged.pings += lane.pings;
        if let Some(finished) = lane.finished {
            merged.wall = merged.wall.max(finished.saturating_duration_since(started));
        }
    }
    Ok(merged)
}

fn mean_us(total_ns: u64, events: usize) -> f64 {
    us((total_ns as u128 / events.max(1) as u128) as u64)
}

pub(crate) fn mean(events: u64, batches: u64) -> f64 {
    if batches == 0 {
        return 0.0;
    }
    (events as f64 / batches as f64 * 100.0).round() / 100.0
}

pub(crate) fn writer_json(stats: WriterStats, commits: u64) -> Value {
    json!({
        "batches": stats.batches,
        "events": stats.events,
        "mean_batch_events": mean(stats.events, stats.batches),
        "largest_batch_events": stats.largest_batch,
        "commits": commits,
    })
}

/// The store holds exactly the events sent to `visibility` and nothing in the
/// other partition, and the writer stored exactly that many. `now` is the time
/// the store's expiry checks are made at.
pub(crate) fn verify_cell(
    store: &SqliteEventStore,
    visibility: Visibility,
    events: &[&Event],
    stats: WriterStats,
    now: u64,
) -> Result<(), String> {
    let name = partition_name(visibility);
    let sent = events.len();
    if stats.events != sent as u64 {
        return Err(format!(
            "the writer stored {} events for a subset of {sent}",
            stats.events
        ));
    }
    // The count is capped at the exact-count bound plus one.
    let expected = sent.min(MAX_EXACT_COUNT as usize + 1) as u64;
    let counted = store
        .count(visibility, &[Filter::new()], now)
        .map_err(|e| format!("count the {name} partition: {e}"))?;
    if counted != expected {
        return Err(format!(
            "the {name} partition holds {counted} events, expected {expected}"
        ));
    }
    // The partition-wide count stops at the exact-count bound, so the subset
    // is also counted by author and kind, each group below the bound where
    // the corpus allows. With the writer's own event count above, this fixes
    // the stored total.
    let mut groups: BTreeMap<(nostr::key::PublicKey, u16), u64> = BTreeMap::new();
    for event in events {
        *groups
            .entry((event.pubkey, event.kind.as_u16()))
            .or_default() += 1;
    }
    for ((author, kind), sent_in_group) in groups {
        let filter = Filter::new().author(author).kind(Kind::from(kind));
        let counted = store
            .count(visibility, &[filter], now)
            .map_err(|e| format!("count kind {kind} of one author: {e}"))?;
        let expected = sent_in_group.min(MAX_EXACT_COUNT + 1);
        if counted != expected {
            return Err(format!(
                "the {name} partition holds {counted} kind {kind} events of one author, expected {expected}"
            ));
        }
    }
    let other = match visibility {
        Visibility::Public => Visibility::Sheltered,
        Visibility::Sheltered => Visibility::Public,
    };
    let strays = store
        .count(other, &[Filter::new()], now)
        .map_err(|e| format!("count the {} partition: {e}", partition_name(other)))?;
    if strays != 0 {
        return Err(format!(
            "the {} partition holds {strays} events, expected none",
            partition_name(other)
        ));
    }
    let step = (sent / ID_SAMPLE).max(1);
    let sample: Vec<&Event> = events
        .iter()
        .copied()
        .step_by(step)
        .take(ID_SAMPLE)
        .collect();
    for chunk in sample.chunks(ID_CHUNK) {
        let filter = Filter::new().ids(chunk.iter().map(|event| event.id));
        let mut found: Vec<String> = store
            .query_stored(visibility, &filter, now)
            .map_err(|e| format!("look up sampled ids: {e}"))?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let mut wanted: Vec<String> = chunk.iter().map(|event| event.id.to_hex()).collect();
        found.sort_unstable();
        wanted.sort_unstable();
        if found != wanted {
            return Err(format!(
                "the {name} partition does not hold the sampled events: {} found of {}",
                found.len(),
                wanted.len()
            ));
        }
    }
    Ok(())
}

/// The cell's shared figures.
pub(crate) fn cell_json(merged: &mut Merged, events: usize, window: usize) -> Value {
    json!({
        "events": events,
        "lanes_with_events": merged.lanes_with_events,
        "seconds": (merged.wall.as_secs_f64() * 1e3).round() / 1e3,
        "acknowledged_per_s": per_second(events, merged.wall),
        "ok_latency": summarise(&mut merged.latencies),
        "window": window,
    })
}

/// One cell: the events one partition takes, a connection count, a window and
/// the clock the frames are stamped with.
pub(crate) struct Cell<'a> {
    pub(crate) cfg: &'a Config,
    pub(crate) runtime: &'a Runtime,
    pub(crate) visibility: Visibility,
    /// The events sent, in the order they are dealt to the sessions.
    pub(crate) events: &'a [&'a Event],
    /// Sizes the store's ceiling.
    pub(crate) total_events: usize,
    pub(crate) connections: usize,
    pub(crate) window: usize,
    pub(crate) clock: Clock,
}

pub(crate) fn engine_cell(
    cell: &Cell,
    frames: &[String],
    keepers: &Arc<Keepers>,
    keys: &[Keys],
) -> Result<Value, String> {
    engine_cell_with(cell, frames, keepers, keys, None)
}

/// [`engine_cell`], its sessions on [`hop_lane`] when `hops` is given, with
/// the hops and the cell's own work semaphore (the caller makes a fresh one
/// per cell, as each door holds its own).
pub(crate) fn engine_cell_with(
    cell: &Cell,
    frames: &[String],
    keepers: &Arc<Keepers>,
    keys: &[Keys],
    hops: Option<(Hops, Arc<Semaphore>)>,
) -> Result<Value, String> {
    let (_dir, store) = fresh_store(cell.cfg, cell.total_events)?;
    let relay = relay_on(
        Arc::clone(&store) as Arc<dyn EventStore>,
        keepers,
        None,
        cell.clock,
    );
    let url = relay_url()?;
    let start = Arc::new(Barrier::new(cell.connections + 1));
    let mut tasks = Vec::with_capacity(cell.connections);
    for lane in 0..cell.connections {
        let label = format!("{} door, session {lane}", partition_name(cell.visibility));
        let mut session = relay.session(cell.visibility, url.clone(), cell.clock.now());
        authenticate_at(
            &mut session,
            &keys[lane % keys.len()],
            &label,
            cell.clock.now(),
        )?;
        let lane_frames: Vec<String> = frames
            .iter()
            .skip(lane)
            .step_by(cell.connections)
            .cloned()
            .collect();
        let lane_start = Arc::clone(&start);
        tasks.push(match &hops {
            None => cell.runtime.spawn(engine_lane(
                label,
                session,
                lane_frames,
                cell.window,
                cell.clock,
                lane_start,
            )),
            Some((hops, work)) => cell.runtime.spawn(hop_lane(
                label,
                session,
                lane_frames,
                cell.window,
                cell.clock,
                lane_start,
                *hops,
                Arc::clone(work),
            )),
        });
    }
    let mut merged = drive(cell.runtime, tasks, &start)?;
    relay.flush();
    let stats = relay.writer_stats();
    let commits = store.commits();
    verify_cell(
        &store,
        cell.visibility,
        cell.events,
        stats,
        cell.clock.now(),
    )?;
    let events = frames.len();
    let mut out = cell_json(&mut merged, events, cell.window);
    let reserve_await = if cell.window > 1 {
        json!(mean_us(merged.reserve_ns, events))
    } else {
        Value::Null
    };
    let hops = hops.map(|(hops, _)| hops);
    out["stage_mean_us"] = match hops {
        None => json!({
            "parse_and_signature_check": mean_us(merged.parse_ns, events),
            "begin_prepared": mean_us(merged.begin_ns, events),
            "queue_and_commit": mean_us(merged.queue_ns, events),
            "reserve_await": reserve_await,
        }),
        // The hops are inside the stages they wrap, and named so.
        Some(Hops::Parse) => json!({
            "parse_hop_and_signature_check": mean_us(merged.parse_ns, events),
            "admit_and_begin_prepared": mean_us(merged.begin_ns, events),
            "queue_and_commit": mean_us(merged.queue_ns, events),
            "reserve_await": reserve_await,
        }),
        Some(Hops::ParseAndBegin) => json!({
            "parse_hop_and_signature_check": mean_us(merged.parse_ns, events),
            "admit_permit_and_begin_prepared_hop": mean_us(merged.begin_ns, events),
            "queue_and_commit": mean_us(merged.queue_ns, events),
            "reserve_await": reserve_await,
        }),
    };
    if let Some(hops) = hops {
        out["hops"] = json!(hops.name());
    }
    out["writer"] = writer_json(stats, commits);
    out["form"] = json!(if cell.window == 1 {
        "PendingWrite::commit, one write at a time per session"
    } else {
        "PendingWrite::reserve in arrival order, up to `window` WriteTicket::wait futures awaited together in the session's task"
    });
    Ok(out)
}

fn baseline_cell(cell: &Cell, corpus_events: &[&Event]) -> Result<Value, String> {
    let (_dir, store) = fresh_store(cell.cfg, cell.total_events)?;
    // Checked into puts before the clock, as `ingest.rs` does.
    let mut lanes: Vec<Vec<PreparedPut>> = (0..cell.connections).map(|_| Vec::new()).collect();
    for (index, event) in corpus_events.iter().enumerate() {
        let put = PreparedPut::new(cell.visibility, (*event).clone(), cell.clock.now(), false)
            .map_err(|e| format!("prepare an event: {e}"))?;
        lanes[index % cell.connections].push(put);
    }
    let writer = Arc::new(EventWriter::new(
        Arc::clone(&store) as Arc<dyn EventStore>,
        |_, _, _| {},
        WriterLimits::default(),
    ));
    let start = Arc::new(Barrier::new(cell.connections + 1));
    let mut tasks = Vec::with_capacity(cell.connections);
    for (lane, puts) in lanes.into_iter().enumerate() {
        let label = format!(
            "{} baseline, submitter {lane}",
            partition_name(cell.visibility)
        );
        tasks.push(cell.runtime.spawn(baseline_lane(
            label,
            Arc::clone(&writer),
            puts,
            cell.window,
            Arc::clone(&start),
        )));
    }
    let mut merged = drive(cell.runtime, tasks, &start)?;
    writer.flush();
    let stats = writer.stats();
    let commits = store.commits();
    verify_cell(
        &store,
        cell.visibility,
        cell.events,
        stats,
        cell.clock.now(),
    )?;
    let events = corpus_events.len();
    let mut out = cell_json(&mut merged, events, cell.window);
    out["stage_mean_us"] = json!({
        "reserve_await": mean_us(merged.reserve_ns, events),
        "queue_and_commit": mean_us(merged.queue_ns, events),
    });
    out["writer"] = writer_json(stats, commits);
    out["form"] = json!(if cell.window == 1 {
        "EventWriter::reserve_until then Reserved::wait_until, one write at a time per submitter"
    } else {
        "EventWriter::reserve_until in arrival order, up to `window` Reserved::wait_until futures awaited together in the submitter's task"
    });
    drop(writer);
    Ok(out)
}

/// Send one event the public door refuses, and check that it is refused with
/// a restriction and not stored: the evidence that the subset is the door's
/// rule and not a choice.
fn refusal_check(
    cfg: &Config,
    corpus: &Corpus,
    door: &Door,
    keepers: &Arc<Keepers>,
    keys: &[Keys],
) -> Result<Value, String> {
    let Some(kind) = door.refused_by_kind.keys().next().copied() else {
        return Ok(Value::Null);
    };
    let event = corpus
        .events_in(door.visibility)
        .find(|event| event.kind.as_u16() == kind)
        .ok_or("a refused kind has no event")?;
    let (_dir, store) = fresh_store(cfg, corpus.items.len())?;
    let relay = relay_on(
        Arc::clone(&store) as Arc<dyn EventStore>,
        keepers,
        None,
        Clock::Fixed(NOW),
    );
    let mut session = relay.session(door.visibility, relay_url()?, NOW);
    authenticate_at(&mut session, &keys[0], "refusal check", NOW)?;
    let replies = session.handle(&event_text(event)?, NOW);
    let reply = replies.first().cloned().unwrap_or_default();
    let refused = replies.len() == 1
        && serde_json::from_str::<Value>(&reply).is_ok_and(|value| {
            value[0] == "OK"
                && value[2] == false
                && value[3]
                    .as_str()
                    .is_some_and(|why| why.starts_with("restricted:"))
        });
    if !refused {
        return Err(format!(
            "the {} door should refuse a kind {kind} event with a restriction, got {}",
            door.name(),
            describe(&replies)
        ));
    }
    relay.flush();
    let held = store
        .count(door.visibility, &[Filter::new()], NOW)
        .map_err(|e| e.to_string())?;
    if held != 0 {
        return Err(format!("a refused event was stored ({held} held)"));
    }
    Ok(json!({ "kind": kind, "reply": reply, "stored": held }))
}

/// Signature verification alone over the subset, on one thread: what
/// `PreparedFrame::parse` and `PreparedPut::new` each spend on it.
fn verification_only(door: &Door) -> Result<Value, String> {
    let events: Vec<Event> = door.events.iter().map(|event| (*event).clone()).collect();
    let started = Instant::now();
    for event in &events {
        event
            .verify()
            .map_err(|e| format!("a corpus event does not verify: {e}"))?;
    }
    let took = started.elapsed();
    Ok(json!({
        "events": events.len(),
        "threads": 1,
        "total_ms": ms(took),
        "per_event_us": us((took.as_nanos() / events.len().max(1) as u128) as u64),
        "events_per_s": per_second(events.len(), took),
    }))
}

pub fn run(
    cfg: &Config,
    corpus: &Corpus,
    keepers: &Arc<Keepers>,
    keys: &[Keys],
) -> Result<Value, String> {
    let runtime = runtime(cfg.engine_workers)?;
    let mut door_results = Vec::new();
    for door in doors(cfg, corpus, keepers)? {
        let frames: Vec<String> = door
            .events
            .iter()
            .map(|event| event_text(event))
            .collect::<Result<_, _>>()?;
        eprintln!(
            "engine: writes, {} door, {} of {} partition events admitted",
            door.name(),
            door.events.len(),
            door.in_partition
        );
        let refusal = refusal_check(cfg, corpus, &door, keepers, keys)?;
        let verification = verification_only(&door)?;
        let mut cells = Vec::new();
        for &connections in &cfg.engine_connections {
            for &window in &cfg.engine_windows {
                eprintln!(
                    "engine: writes, {} door, {connections} session(s), window {window}",
                    door.name()
                );
                let cell = Cell {
                    cfg,
                    runtime: &runtime,
                    visibility: door.visibility,
                    events: &door.events,
                    total_events: corpus.items.len(),
                    connections,
                    window,
                    clock: Clock::Fixed(NOW),
                };
                let engine = engine_cell(&cell, &frames, keepers, keys)?;
                let baseline = baseline_cell(&cell, &door.events)?;
                cells.push(json!({
                    "connections": connections,
                    "window": window,
                    "engine": engine,
                    "writer_only": baseline,
                }));
            }
        }
        door_results.push(json!({
            "door": door.name(),
            "partition": door.name(),
            "admits": door.rule,
            "partition_events": door.in_partition,
            "admitted_events": door.admitted,
            "events_sent": door.events.len(),
            "refused_by_kind": door
                .refused_by_kind
                .iter()
                .map(|(kind, count)| (kind.to_string(), json!(count)))
                .collect::<serde_json::Map<_, _>>(),
            "refusal_check": refusal,
            "signature_verification_only": verification,
            "cells": cells,
        }));
    }
    Ok(json!({
        "settings": {
            "connections": cfg.engine_connections,
            "windows": cfg.engine_windows,
            "workers": cfg.engine_workers,
            "events_cap": cfg.engine_events,
            "frame_limit_used": FRAME_LIMIT,
            "frame_limit_production_default": PRODUCTION_FRAME_LIMIT,
            "sessions": "tasks on a multi-thread runtime, each authenticated with a real NIP-42 AUTH before a shared start; the subset is dealt to them round-robin and the EVENT frame texts are serialised before the clock",
            "fresh_store_per_cell": true,
        },
        "baseline_note": "writer_only sends the same subset through EventWriter with no engine, from the same number of async tasks and the same window. It differs from ingest.rs::through_writer, which submits from blocking threads with submit_blocking. Its puts are checked into PreparedPut before the clock, so its time excludes signature verification, which the engine's time includes (see signature_verification_only).",
        "stage_note": "stage_mean_us are per-event means of the time each stage took. At a window above 1 the stages overlap across events, so their sum can exceed the wall time; queue_and_commit then includes the time the session spent on later frames while the write waited",
        "doors": door_results,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flight_of(ready: &[bool]) -> Flight<usize, usize> {
        let mut flight = Flight::new(ready.len());
        for (n, &now) in ready.iter().enumerate() {
            let future: Pending<usize> = if now {
                Box::pin(async move { n })
            } else {
                Box::pin(std::future::pending())
            };
            flight.push(Instant::now(), Instant::now(), n, future);
        }
        flight
    }

    #[test]
    fn a_flight_hands_back_only_the_writes_that_finished_and_in_order() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut flight = flight_of(&[true, false, true]);
            let done = flight.ready().await;
            let metas: Vec<usize> = done.iter().map(|d| d.meta).collect();
            assert_eq!(metas, vec![0, 2]);
            assert_eq!(flight.len(), 1);
            assert!(flight.ready().await.is_empty());
            assert_eq!(flight.len(), 1);
        });
    }

    #[test]
    fn waiting_for_some_returns_once_one_has_finished() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut flight: Flight<usize, usize> = Flight::new(2);
            flight.push(
                Instant::now(),
                Instant::now(),
                7,
                Box::pin(async {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    1
                }),
            );
            flight.push(
                Instant::now(),
                Instant::now(),
                8,
                Box::pin(std::future::pending()),
            );
            let done = flight.some().await;
            assert_eq!(done.len(), 1);
            assert_eq!((done[0].meta, done[0].output), (7, 1));
            assert_eq!(flight.len(), 1);
        });
    }
}
