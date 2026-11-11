//! The durable event store.
//!
//! The caller supplies the authorised visibility partition. Authentication
//! and any grant model belong to the relay, never inferred from an event's
//! tags here. No event crosses partitions during query or deletion.
//! This synchronous interface is called through `spawn_blocking` by transports.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{
    AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering as AtomicOrdering,
};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use rusqlite::{
    Connection, OptionalExtension, TransactionBehavior, params, params_from_iter, types::Value,
};
use thiserror::Error;

/// Intake and query bounds, independent of the on-disk logical byte ceiling.
pub const MAX_EVENT_BYTES: usize = 256 * 1024;
pub const MAX_EVENT_TAGS: usize = 512;
pub const MAX_QUERY_EVENTS: usize = 128;
/// One committed expiry pass. Callers release shared work capacity between passes.
pub const MAX_EXPIRE_EVENTS: usize = 128;
const EXPIRY_BUDGET: Duration = Duration::from_secs(5);
/// How long one history query, count or batched event may run.
const QUERY_BUDGET: Duration = Duration::from_secs(2);
/// SQLite calls a connection's [`Budget`] check every this many VM steps.
const BUDGET_STEPS: std::ffi::c_int = 10_000;
/// How long any connection waits for a lock before SQLite reports busy. The
/// writer returns to it after the ceiling checkpoint's longer wait.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
// A minimal signed one-id NIP-09 request, its tag index and replay barrier
// fit inside this allowance. Charge it before accepting the payload, so a
// keeper can still delete when ordinary intake has exhausted the budget.
const DELETION_RESERVE_BYTES: u64 = 1536;
const MAX_QUERY_VALUES: usize = 512;
/// The most events a NIP-45 count tallies one by one. A count that would pass
/// it stops there, so an anonymous COUNT costs at most this many index rows;
/// the relay reports such a count as approximate.
pub const MAX_EXACT_COUNT: u64 = 10_000;
/// Read-only connections for history queries, so a REQ never waits on the
/// writer's lock. Each holds its own WAL snapshot per statement.
const READ_CONNECTIONS: usize = 2;
const STATEMENT_CACHE: usize = 64;
/// Up to this many values of the driving tag are merged branch by branch,
/// each walking the tag index newest-first; more fall back to one sorted scan.
const MAX_MERGED_VALUES: usize = 32;
/// Filter shapes whose built SQL is kept; the cache starts again when full.
const SQL_CACHE_SHAPES: usize = 256;
/// Bytes of built SQL the cache may hold; it starts again when a new entry
/// would pass this. A real page's SQL is a few hundred bytes.
const SQL_CACHE_BYTES: usize = 256 * 1024;
/// SQL longer than this is not kept at all: only a filter with many values
/// builds it, and keeping it would let a few such filters fill the cache.
const SQL_CACHE_ENTRY_BYTES: usize = 4 * 1024;
const MAX_FUTURE_SECONDS: u64 = 600;
const TRANSACTION_GUARD_BYTES: u64 = 16 * 1024 * 1024;
/// The WAL file is truncated to this size whenever a checkpoint resets it.
const WAL_SIZE_LIMIT_BYTES: i64 = 32 * 1024 * 1024;
/// Replicated intake leaves `max_bytes / REPLICA_RESERVE_DIVISOR` of the
/// logical budget to direct keeper writes.
pub const REPLICA_RESERVE_DIVISOR: u64 = 8;
/// Replicated intake also leaves this much disk above the ordinary reserve.
pub const REPLICA_DISK_RESERVE_BYTES: u64 = 16 * 1024 * 1024;

trait FreeSpace: Send + Sync {
    fn available_bytes(&self, path: &Path) -> std::io::Result<u64>;
}

struct FilesystemFreeSpace;
impl FreeSpace for FilesystemFreeSpace {
    fn available_bytes(&self, path: &Path) -> std::io::Result<u64> {
        fs2::available_space(path)
    }
}

/// Maintenance happens only after a durable reclaiming commit. Keeping it
/// separate from admission lets tests prove that a failed best-effort request
/// cannot change the result of an acknowledged deletion.
trait Checkpoint: Send + Sync {
    fn passive(&self, conn: &Connection) -> Result<(), rusqlite::Error>;
}

struct SqliteCheckpoint;
impl Checkpoint for SqliteCheckpoint {
    fn passive(&self, conn: &Connection) -> Result<(), rusqlite::Error> {
        // PASSIVE does not wait for readers or writers. One request reclaims
        // what it can without adding a maintenance loop or an eviction policy.
        // SQLite reports a checkpoint refused by a concurrent one (the
        // checkpoint thread holds the lock) as a result row, not an error.
        let (busy, _, _) = run_checkpoint(conn, "PASSIVE")?;
        if busy != 0 {
            // Expected when the checkpoint thread is running: it was asked for
            // a fresh pass, which starts after this commit and clears the
            // deleted bytes itself.
            tracing::debug!(
                "event-store passive checkpoint after a deletion was refused by a concurrent checkpoint"
            );
        }
        Ok(())
    }
}

/// How much memory and background work one event store may use.
///
/// Two profiles are provided. [`StoreOptions::server`] is the default: a
/// keeper on a server or a desktop. [`StoreOptions::phone`] is for a phone
/// keeper, where memory and battery matter more than burst latency.
///
/// Memory policy: heap is the scarce, non-reclaimable resource, so the page
/// caches stay small and hot pages are kept in the operating system's page
/// cache through `mmap_size` instead. Mapped pages are file-backed and the
/// kernel can take them back under pressure, as with LMDB. Heap used by page
/// caches is at most `writer_cache_kib + READ_CONNECTIONS * reader_cache_kib
/// + checkpoint_cache_kib` (plus 1 MiB for the warm-up while it runs).
///
/// The server cache sizes come from the 2026-10-30 cache spike (three rounds,
/// system allocator), which compared writer/reader caches of 2 MiB/1 MiB (the
/// slice-4 defaults) with 512 KiB/256 KiB: household live footprint 10.7 to
/// 8.9 MB, room catch-up 16.4 to 11.5 MB. Turning lookaside off as well
/// saved only 0.3 MB more and cost about 3 percent of pages and some p99, so
/// it stays on. The writer then went back up to 1 MiB: with 512 KiB the
/// final rounds put the household-live publisher's OK p99 at 115 ms, and the
/// spike's 1 MiB writer arms ran at 97 to 98 ms for about 0.4 MB more
/// footprint.
#[derive(Clone, Debug)]
pub struct StoreOptions {
    /// Page cache of the writer connection, in KiB (heap). Server default
    /// 1 MiB (512 KiB cost the publisher's OK p99 about 17 ms; see above);
    /// phone 1 MiB. A larger cache did not speed up a burst on its own
    /// (first touches miss at any size) and costs heap.
    pub writer_cache_kib: u32,
    /// Page cache of each read-only connection, in KiB (heap). Server default
    /// 256 KiB (from the cache spike; SQLite's default is 2 MiB); phone
    /// 512 KiB. Every commit by another connection empties a reader's cache
    /// anyway, so it only serves reuse between commits.
    pub reader_cache_kib: u32,
    /// Page cache of the checkpoint thread's connection, in KiB (heap).
    /// Server default 256 KiB, the reader value; phone 1 MiB. A checkpoint
    /// copies WAL frames into the database without going through this cache,
    /// so it rarely fills.
    pub checkpoint_cache_kib: u32,
    /// `PRAGMA mmap_size` for the writer (and the warm-up), in bytes: how
    /// much of the main database file may be read through a memory map.
    /// File-backed and reclaimable, not heap. Only reads use it (in WAL mode
    /// SQLite never writes through the map, and pages still in the WAL are
    /// read from the log). Server default 512 MiB on 64-bit targets, phone
    /// default 128 MiB. It is 0 (off) on 32-bit targets, where the address
    /// space is too tight, and `0` turns every map off, the readers' too.
    /// Caveat: a map over a file that shrinks underneath the process, or a
    /// failing disk, ends in SIGBUS rather than an SQL error; the store never
    /// truncates its own database file, but a keeper on removable or network
    /// storage should set this to 0.
    pub mmap_bytes: u64,
    /// `PRAGMA mmap_size` for each read-only connection, in bytes, capped at
    /// `mmap_bytes`. Default 0 (off) in both profiles. A reader that starts a
    /// read after another connection has committed sees the WAL header change,
    /// and SQLite then drops its page cache and unmaps the whole region, so
    /// under concurrent writes a mapped reader pays an unmap, a remap and a
    /// fresh fault per touched page on its next query. The writer does not,
    /// since its own commits keep its copy of the header current, except
    /// after the checkpoint thread restarts or truncates the log. When reads
    /// share the
    /// writer connection (no WAL, or no reader could be opened) they use the
    /// writer's map.
    pub reader_mmap_bytes: u64,
    /// Run the WAL checkpoint on its own thread, never inside a commit. When
    /// false the writer keeps SQLite's automatic checkpoint (1,000 pages) and
    /// no thread is started.
    pub background_checkpoint: bool,
    /// The checkpoint thread starts a PASSIVE checkpoint once a commit leaves
    /// this many pages in the WAL. Server default 1,000 (about 4 MiB at the
    /// 4 KiB page size, SQLite's own default threshold), phone default 500.
    pub checkpoint_pages: u32,
    /// Ceiling, in WAL pages. If a commit leaves the WAL this long, which
    /// happens only when readers pin snapshots or the disk cannot keep up, the
    /// writer itself runs one blocking (FULL) checkpoint before it takes
    /// another batch. It waits up to [`CEILING_WAIT`] in all, first for any
    /// other checkpoint to let go of the checkpoint lock and then for the
    /// readers, so intake slows rather than the log growing. It is not a hard
    /// limit: if that wait runs out, commits go through for a second before
    /// the writer tries again, and the log grows in that time.
    /// Server default 8,192 pages (32 MiB, equal to the `journal_size_limit`),
    /// phone default 4,096.
    pub wal_ceiling_pages: u32,
    /// How long the store must see no commit before the checkpoint thread
    /// truncates the WAL file to nothing and goes back to sleep.
    pub idle_truncate_after: Duration,
    /// Touch the store's indexes in the background after open, through the
    /// memory map, so the first writes after a restart find their pages in the
    /// operating system's cache. It fills no heap cache. Needs `mmap_bytes`
    /// above zero to be of use; off by default.
    pub warm: bool,
    /// Upper bound on the index bytes the warm-up touches (an estimate of 96
    /// bytes per index entry). Server default 64 MiB, phone default 16 MiB.
    pub warm_max_bytes: u64,
}

impl StoreOptions {
    /// A server or desktop keeper.
    pub fn server() -> Self {
        Self {
            writer_cache_kib: 1024,
            reader_cache_kib: 256,
            checkpoint_cache_kib: 256,
            mmap_bytes: if cfg!(target_pointer_width = "64") {
                512 * 1024 * 1024
            } else {
                0
            },
            reader_mmap_bytes: 0,
            background_checkpoint: true,
            checkpoint_pages: 1000,
            wal_ceiling_pages: 8192,
            idle_truncate_after: Duration::from_secs(2),
            warm: false,
            warm_max_bytes: 64 * 1024 * 1024,
        }
    }

    /// A phone keeper: small caches and map, a smaller WAL, no warm-up.
    pub fn phone() -> Self {
        Self {
            writer_cache_kib: 1024,
            reader_cache_kib: 512,
            checkpoint_cache_kib: 1024,
            mmap_bytes: if cfg!(target_pointer_width = "64") {
                128 * 1024 * 1024
            } else {
                0
            },
            checkpoint_pages: 500,
            wal_ceiling_pages: 4096,
            warm_max_bytes: 16 * 1024 * 1024,
            ..Self::server()
        }
    }

    /// A tool that opens the store while nothing else serves it (an
    /// operator's removal, say): the server's caches, with no background
    /// checkpoint thread and no warm-up scan, so no other connection is
    /// holding the write-ahead log when the tool truncates it.
    pub fn offline() -> Self {
        Self {
            background_checkpoint: false,
            warm: false,
            ..Self::server()
        }
    }
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self::server()
    }
}

/// How long the writer waits in all, for the checkpoint lock and then for
/// readers, when the WAL is over its ceiling.
pub const CEILING_WAIT: Duration = Duration::from_secs(2);
/// After a blocking checkpoint that was held off until [`CEILING_WAIT`] ran
/// out, the writer starts no other for this long.
const CEILING_RETRY: Duration = Duration::from_secs(1);
/// While another checkpoint holds the checkpoint lock, the writer tries for it
/// again after this, doubling each time up to [`CEILING_LOCK_STEP_MAX`].
const CEILING_LOCK_STEP: Duration = Duration::from_millis(1);
const CEILING_LOCK_STEP_MAX: Duration = Duration::from_millis(10);
/// The checkpoint thread starts at most one PASSIVE checkpoint per interval.
const CHECKPOINT_MIN_GAP: Duration = Duration::from_millis(50);
/// The checkpoint thread does not hold the writer off for longer than this
/// while a reader keeps a TRUNCATE from finishing.
const CHECKPOINT_BUSY: Duration = Duration::from_millis(200);
/// Page cache of the warm-up connection (heap).
const WARM_CACHE_KIB: i64 = 1024;
const WARM_BYTES_PER_ENTRY: u64 = 96;
/// The warm-up yields for a millisecond every this many SQLite VM steps.
const WARM_THROTTLE_STEPS: i32 = 20_000;
/// One warm-up scan holds a read snapshot, which stops a checkpoint from
/// passing it; it is cut off after this long and the warm-up moves on.
const WARM_SCAN_DEADLINE: Duration = Duration::from_secs(1);

/// State shared by the writer (through the WAL hook) and the checkpoint
/// thread. The hook runs on the writer thread right after each commit and
/// does a few atomic operations; it takes the lock only to wake the thread.
struct WalShared {
    threshold: u32,
    ceiling: u32,
    idle_after: Duration,
    /// Pages in the WAL after the latest commit (1 until the first commit, so
    /// that a WAL left by an earlier run is truncated once the store is idle).
    pages: AtomicU32,
    /// Highest WAL size any commit has left, for tests and diagnostics.
    peak_pages: AtomicU32,
    /// When the latest commit happened, in nanoseconds after `born`.
    last_commit_ns: AtomicU64,
    born: Instant,
    /// A commit has happened since the thread last went to sleep.
    armed: AtomicBool,
    /// The WAL reached `threshold` since the thread last looked.
    pending: AtomicBool,
    /// The WAL reached `ceiling`; the writer clears this when it acts.
    over_ceiling: AtomicBool,
    stop: AtomicBool,
    gate: Mutex<()>,
    wake: Condvar,
    last_blocking: Mutex<Option<Instant>>,
    passive_runs: AtomicU64,
    truncate_runs: AtomicU64,
    blocking_runs: AtomicU64,
    /// Time the writer has spent in its blocking checkpoints, in nanoseconds,
    /// and the longest single one. Diagnostics only.
    blocking_ns: AtomicU64,
    blocking_longest_ns: AtomicU64,
    warm_rows: AtomicU64,
    warm_cancelled: AtomicBool,
    warm_finished: AtomicBool,
}

thread_local! {
    /// The store whose writer commit is running on this thread, for the WAL hook.
    static WAL_PROBE: RefCell<Option<Arc<WalShared>>> = const { RefCell::new(None) };
}

/// Routes the WAL hook of the writer connection to `shared` while alive.
/// Every lock of the writer connection carries one (see [`WriterGuard`]), so
/// no commit path can bypass the page count.
struct ProbeGuard(Option<Arc<WalShared>>);

impl ProbeGuard {
    fn enter(shared: Option<&Arc<WalShared>>) -> Self {
        let previous = WAL_PROBE.with(|p| p.replace(shared.cloned()));
        Self(previous)
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        WAL_PROBE.with(|p| *p.borrow_mut() = previous);
    }
}

/// The writer connection's lock, held together with the WAL probe: the only
/// way to reach the writer, so a commit through it is always counted and the
/// checkpoint thread and the ceiling always hear of it.
struct WriterGuard<'a> {
    // Field order: the probe is released before the lock is.
    _probe: ProbeGuard,
    conn: MutexGuard<'a, Connection>,
}

impl std::ops::Deref for WriterGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}

impl std::ops::DerefMut for WriterGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// Installed in place of SQLite's automatic checkpoint, which would run inside
/// the commit. It only records how large the log is.
fn wal_observe(_: &mut rusqlite::hooks::Wal, pages: std::ffi::c_int) -> rusqlite::Result<()> {
    WAL_PROBE.with(|p| {
        if let Ok(slot) = p.try_borrow()
            && let Some(shared) = slot.as_ref()
        {
            shared.observe(u32::try_from(pages).unwrap_or(u32::MAX));
        }
    });
    Ok(())
}

impl WalShared {
    fn new(options: &StoreOptions) -> Self {
        Self {
            threshold: options.checkpoint_pages.max(1),
            ceiling: options
                .wal_ceiling_pages
                .max(options.checkpoint_pages)
                .max(1),
            idle_after: options.idle_truncate_after,
            pages: AtomicU32::new(1),
            peak_pages: AtomicU32::new(0),
            last_commit_ns: AtomicU64::new(0),
            born: Instant::now(),
            armed: AtomicBool::new(true),
            pending: AtomicBool::new(false),
            over_ceiling: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            gate: Mutex::new(()),
            wake: Condvar::new(),
            last_blocking: Mutex::new(None),
            passive_runs: AtomicU64::new(0),
            truncate_runs: AtomicU64::new(0),
            blocking_runs: AtomicU64::new(0),
            blocking_ns: AtomicU64::new(0),
            blocking_longest_ns: AtomicU64::new(0),
            warm_rows: AtomicU64::new(0),
            warm_cancelled: AtomicBool::new(false),
            warm_finished: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn stopped(&self) -> bool {
        self.stop.load(AtomicOrdering::Acquire)
    }

    /// Time since the latest commit (since the store opened, before any).
    fn since_last_commit(&self) -> Duration {
        let last = Duration::from_nanos(self.last_commit_ns.load(AtomicOrdering::Relaxed));
        self.born.elapsed().saturating_sub(last)
    }

    fn signal(&self) {
        drop(self.lock());
        self.wake.notify_all();
    }

    /// Called on the writer thread after each commit.
    fn observe(&self, pages: u32) {
        // Commit time first, so the checkpoint thread never sees the new page
        // count with the previous commit's time.
        self.last_commit_ns.store(
            u64::try_from(self.born.elapsed().as_nanos()).unwrap_or(u64::MAX),
            AtomicOrdering::Relaxed,
        );
        self.pages.store(pages, AtomicOrdering::Relaxed);
        self.peak_pages.fetch_max(pages, AtomicOrdering::Relaxed);
        if pages >= self.ceiling {
            self.over_ceiling.store(true, AtomicOrdering::Relaxed);
        }
        let mut wake = false;
        if pages >= self.threshold && !self.pending.swap(true, AtomicOrdering::AcqRel) {
            wake = true;
        }
        if !self.armed.swap(true, AtomicOrdering::AcqRel) {
            wake = true;
        }
        if wake {
            self.signal();
        }
    }

    /// A commit deleted data: have the thread run a PASSIVE checkpoint now,
    /// below the threshold too, so the deleted bytes leave the log promptly.
    fn request_checkpoint(&self) {
        if !self.pending.swap(true, AtomicOrdering::AcqRel) {
            self.signal();
        }
    }

    /// Sleep until stopped, armed or pending, using no CPU.
    fn sleep_until_work(&self) {
        let mut guard = self.lock();
        while !self.stopped()
            && !self.armed.load(AtomicOrdering::Acquire)
            && !self.pending.load(AtomicOrdering::Acquire)
        {
            guard = self.wake.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Sleep for `span`, or less if stopped or a threshold checkpoint is due.
    fn sleep_active(&self, span: Duration) {
        let deadline = Instant::now() + span;
        let mut guard = self.lock();
        while !self.stopped() && !self.pending.load(AtomicOrdering::Acquire) {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            if left.is_zero() {
                return;
            }
            guard = self
                .wake
                .wait_timeout(guard, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Sleep for `span` unless stopped.
    fn sleep_unless_stopped(&self, span: Duration) {
        let deadline = Instant::now() + span;
        let mut guard = self.lock();
        while !self.stopped() {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            if left.is_zero() {
                return;
            }
            guard = self
                .wake
                .wait_timeout(guard, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

/// `PRAGMA wal_checkpoint(mode)`: `(busy, frames in the log, frames checkpointed)`.
/// One event out, in an operator's removal: barred by author and id, its
/// head (if it is one) and the row, whose tags go with it.
fn remove_one(
    tx: &Connection,
    scope: i64,
    author: &[u8],
    id: &[u8],
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT OR IGNORE INTO deleted_ids VALUES(?,?,?)",
        params![scope, author, id],
    )?;
    tx.execute(
        "DELETE FROM heads WHERE visibility=? AND author=? AND id=?",
        params![scope, author, id],
    )?;
    tx.execute(
        "DELETE FROM events WHERE visibility=? AND id=?",
        params![scope, id],
    )?;
    Ok(())
}

/// Truncate the write-ahead log after a removal; whether it was.
fn truncate_after_removal(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let (busy, _, _) = run_checkpoint(conn, "TRUNCATE")?;
    Ok(busy == 0)
}

fn run_checkpoint(conn: &Connection, mode: &str) -> Result<(i64, i64, i64), rusqlite::Error> {
    conn.query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })
}

/// How the writer's blocking checkpoint ended ([`checkpoint_within`]).
#[derive(Debug)]
enum CeilingCheckpoint {
    /// It copied the whole log.
    Finished,
    /// It ran, but readers kept it from finishing before the wait ran out.
    HeldByReaders,
    /// Another checkpoint held the checkpoint lock until the wait ran out.
    HeldByCheckpoint,
    Failed(rusqlite::Error),
}

/// One blocking checkpoint within `wait`. `attempt(timeout)` runs it with that
/// busy timeout and returns the `PRAGMA wal_checkpoint` row.
///
/// SQLite does not call the busy handler for the checkpoint lock: a
/// checkpoint that finds another one running is refused at once, and reports
/// busy with no log size (-1). Such a refusal is tried again here after a
/// short sleep, until the lock is free or `wait` has passed. The busy timeout
/// then covers the wait for readers, from whatever time is left. It is never
/// zero, which would remove the busy handler.
fn checkpoint_within(
    wait: Duration,
    mut attempt: impl FnMut(Duration) -> Result<(i64, i64, i64), rusqlite::Error>,
) -> CeilingCheckpoint {
    let deadline = Instant::now() + wait;
    let mut step = CEILING_LOCK_STEP;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match attempt(left.max(Duration::from_millis(1))) {
            Ok((0, _, _)) => return CeilingCheckpoint::Finished,
            Ok((_, -1, _)) => {}
            Ok(_) => return CeilingCheckpoint::HeldByReaders,
            Err(error) => return CeilingCheckpoint::Failed(error),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return CeilingCheckpoint::HeldByCheckpoint;
        }
        std::thread::sleep(step.min(left));
        step = (step * 2).min(CEILING_LOCK_STEP_MAX);
    }
}

/// The checkpoint thread. It sleeps with no timer while the store is idle.
/// After a commit it wakes when the quiet spell would end, to see whether
/// commits continue (so at most once per `idle_truncate_after`); a
/// WAL past the threshold starts a PASSIVE checkpoint (never more often than
/// every `CHECKPOINT_MIN_GAP`); a quiet store gets a TRUNCATE and the thread
/// sleeps again. On shutdown it does a final TRUNCATE.
fn checkpoint_loop(shared: Arc<WalShared>, conn: Connection) {
    'life: loop {
        shared.sleep_until_work();
        if shared.stopped() {
            break;
        }
        let mut wait = shared.idle_after;
        loop {
            shared.sleep_active(wait);
            if shared.stopped() {
                break 'life;
            }
            if shared.pending.swap(false, AtomicOrdering::AcqRel) {
                match run_checkpoint(&conn, "PASSIVE") {
                    Ok(_) => {
                        shared.passive_runs.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "event-store background checkpoint did not complete");
                    }
                }
                shared.sleep_unless_stopped(CHECKPOINT_MIN_GAP);
                wait = shared.idle_after;
                continue;
            }
            // Not yet quiet: sleep exactly until the quiet spell would end.
            let quiet = shared.since_last_commit();
            if quiet < shared.idle_after {
                wait = shared.idle_after - quiet;
                continue;
            }
            // Quiet. Clear the flag first: a commit that lands during the
            // truncate re-arms the thread instead of being lost.
            shared.armed.store(false, AtomicOrdering::Release);
            if shared.pages.load(AtomicOrdering::Relaxed) > 0 {
                truncate_wal(&shared, &conn);
            }
            break;
        }
    }
    truncate_wal(&shared, &conn);
}

fn truncate_wal(shared: &WalShared, conn: &Connection) {
    // What the commits had left before the truncate began: if one lands
    // during or after it, `pages` or the commit time has moved and `pages`
    // stays set, so the next quiet spell truncates again.
    let before = shared.pages.load(AtomicOrdering::Relaxed);
    let last = shared.last_commit_ns.load(AtomicOrdering::Relaxed);
    match run_checkpoint(conn, "TRUNCATE") {
        Ok((0, _, _)) => {
            shared.truncate_runs.fetch_add(1, AtomicOrdering::Relaxed);
            if shared.last_commit_ns.load(AtomicOrdering::Relaxed) == last {
                let _ = shared.pages.compare_exchange(
                    before,
                    0,
                    AtomicOrdering::Relaxed,
                    AtomicOrdering::Relaxed,
                );
            }
        }
        Ok(_) => {
            // A reader kept it from finishing; try again at the next quiet spell.
            shared.armed.store(true, AtomicOrdering::Release);
            shared.pages.fetch_max(1, AtomicOrdering::Relaxed);
        }
        Err(error) => {
            tracing::warn!(%error, "event-store WAL was not truncated");
        }
    }
}

/// How the warm-up ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WarmOutcome {
    Finished(u64),
    Cancelled(u64),
}

/// Touch the keys of five of the b-trees a write touches (the id index of
/// `events`, the `tags` table, and the time, author and tag-by-time
/// indexes; not the `events` table, which holds the bodies, nor
/// `events_coordinate`, `events_expiry` or the small tables), in index order,
/// through the connection's memory map, so the operating system holds their
/// pages without the heap cache filling. At most about `max_bytes` of entries
/// are read, split between the indexes, and the work stops at once when `stop`
/// is set. Each scan also stops after `scan_deadline` of wall-clock time (it
/// holds a read snapshot, which a checkpoint cannot pass) and the next index
/// starts. SQLite calls the progress handler every `WARM_THROTTLE_STEPS` VM
/// steps; it sleeps `pause` there, so the thread leaves most of a core to
/// everything else.
fn warm_indexes(
    conn: &mut Connection,
    stop: &Arc<AtomicBool>,
    max_bytes: u64,
    pause: Duration,
    scan_deadline: Duration,
) -> Result<WarmOutcome, rusqlite::Error> {
    const INDEXES: [(&str, &str); 5] = [
        // The `tags` table itself: a WITHOUT ROWID table is its primary key.
        ("tags", "sqlite_autoindex_tags_1"),
        ("events", "events_id"),
        ("events", "events_time"),
        ("events", "events_author_kind"),
        ("tags", "tags_by_time"),
    ];
    let per_index = (max_bytes / WARM_BYTES_PER_ENTRY / INDEXES.len() as u64).max(1);
    let per_index = i64::try_from(per_index).unwrap_or(i64::MAX);
    let flag = Arc::clone(stop);
    let base = Instant::now();
    let scan_ends = Arc::new(AtomicU64::new(u64::MAX));
    let ends = Arc::clone(&scan_ends);
    conn.progress_handler(
        WARM_THROTTLE_STEPS,
        Some(move || {
            if flag.load(AtomicOrdering::Acquire) {
                return true;
            }
            let now = u64::try_from(base.elapsed().as_nanos()).unwrap_or(u64::MAX);
            if now >= ends.load(AtomicOrdering::Relaxed) {
                return true;
            }
            if !pause.is_zero() {
                std::thread::sleep(pause);
            }
            false
        }),
    )?;
    let mut rows = 0u64;
    let outcome = (|| {
        for (table, index) in INDEXES {
            if stop.load(AtomicOrdering::Acquire) {
                return Ok(WarmOutcome::Cancelled(rows));
            }
            let sql =
                format!("SELECT count(*) FROM (SELECT 1 FROM {table} INDEXED BY {index} LIMIT ?1)");
            let ends_at = base.elapsed().saturating_add(scan_deadline);
            scan_ends.store(
                u64::try_from(ends_at.as_nanos()).unwrap_or(u64::MAX),
                AtomicOrdering::Relaxed,
            );
            match conn.query_row(&sql, [per_index], |r| r.get::<_, i64>(0)) {
                Ok(n) => rows += u64::try_from(n).unwrap_or(0),
                Err(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::OperationInterrupted =>
                {
                    // Told to stop, or only this scan ran out of time.
                    if stop.load(AtomicOrdering::Acquire) {
                        return Ok(WarmOutcome::Cancelled(rows));
                    }
                    tracing::debug!(index, "event-store warm-up scan stopped at its deadline");
                }
                Err(error) => return Err(error),
            }
        }
        Ok(WarmOutcome::Finished(rows))
    })();
    conn.progress_handler(0, None::<fn() -> bool>)?;
    outcome
}

/// Counts of a store's checkpoints since it was opened, for diagnostics and
/// benchmarks ([`SqliteEventStore::checkpoint_stats`]). A store opened
/// without the background checkpoint leaves SQLite's automatic checkpoint in
/// charge and counts nothing here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckpointStats {
    /// PASSIVE checkpoints the checkpoint thread has run without an error,
    /// whether or not each copied the whole log.
    pub passive: u64,
    /// TRUNCATE checkpoints the checkpoint thread has finished on a quiet
    /// store.
    pub truncating: u64,
    /// Blocking checkpoints the writer has run because a commit left the WAL
    /// at its ceiling, each counted once however long it waited for the
    /// checkpoint lock.
    pub blocking: u64,
    /// Time the writer has spent in those, its waits for the checkpoint lock
    /// and for readers included, during which it took no batch.
    pub blocking_time: Duration,
    /// The longest single one.
    pub longest_blocking: Duration,
    /// The most WAL pages any commit has left.
    pub peak_wal_pages: u32,
}

/// The store's background threads. Dropping it stops them and waits: the
/// checkpoint thread ends with a final TRUNCATE, the warm-up with its next
/// progress check.
struct Maintenance {
    shared: Arc<WalShared>,
    warm_stop: Arc<AtomicBool>,
    /// The WAL hook is installed and the checkpoint thread owns checkpointing.
    background: bool,
    threads: Vec<JoinHandle<()>>,
}

impl Drop for Maintenance {
    fn drop(&mut self) {
        self.warm_stop.store(true, AtomicOrdering::Release);
        self.shared.stop.store(true, AtomicOrdering::Release);
        self.shared.signal();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Explicit storage visibility; nothing promotes private events to public.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Sheltered,
}
impl Visibility {
    fn key(self) -> i64 {
        match self {
            Self::Public => 0,
            Self::Sheltered => 1,
        }
    }
}

/// An accepted duplicate does not generate another live delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Stored,
    Duplicate,
    Ephemeral,
}

/// What an operator's removal did ([`SqliteEventStore::remove`],
/// [`SqliteEventStore::remove_author`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// The events removed, each now barred from being stored again.
    pub removed: Vec<nostr::event::EventId>,
    /// Whether the write-ahead log was truncated afterwards, so the removed
    /// bytes are gone from it as well as from the database file. `false`
    /// means another connection was holding it: the bytes leave when it is
    /// next truncated, and the removal itself is already durable.
    pub erased: bool,
}

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("event database: {0}")]
    Sqlite(rusqlite::Error),
    #[error("event database file: {0}")]
    Io(std::io::Error),
    #[error("event database lock poisoned")]
    Poisoned,
    #[error("unsupported event database schema")]
    Schema,
    /// The store was written by a newer version, whose schema this build
    /// does not read. Nothing was changed.
    #[error(
        "the event database is schema {found}, from a newer version; this build reads up to \
         schema {supported}. Run that version or newer, or export with it and import into a \
         fresh store here (the store was left unchanged)"
    )]
    NewerSchema { found: i64, supported: i64 },
    #[error("invalid event")]
    Invalid,
    #[error("event too large")]
    Oversize,
    #[error("event expired")]
    Expired,
    #[error("event deleted or superseded")]
    Retired,
    #[error("event store full; existing events were retained")]
    Full,
    /// The disk, not the store's own byte budget, has too little free space
    /// to open or upgrade the store. Nothing was changed.
    #[error(
        "not enough free disk space for the event store: about {needed} bytes needed, \
         {available} available (the store was left unchanged)"
    )]
    DiskSpace { needed: u64, available: u64 },
    #[error("unsupported or oversized query")]
    Query,
    #[error("stored event cannot be decoded")]
    Corrupt,
    /// The author's authority was withdrawn between the relay's check and the
    /// write, and the write-time check refused it. Nothing was stored.
    #[error("the author is no longer authorised to write")]
    Unauthorised,
    /// The write was withdrawn before it reached a batch. Nothing was stored.
    #[error("the write was cancelled before it was stored")]
    Cancelled,
    /// A batch ran out of time before this event was started. Nothing was
    /// done with it: a caller that can queue again does so, and a caller that
    /// cannot treats it as a refusal that stored nothing.
    #[error("the event was not attempted in this batch")]
    Deferred,
}

impl From<rusqlite::Error> for EventStoreError {
    fn from(error: rusqlite::Error) -> Self {
        if matches!(
            &error,
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::DiskFull
        ) {
            Self::Full
        } else {
            Self::Sqlite(error)
        }
    }
}

impl From<std::io::Error> for EventStoreError {
    fn from(error: std::io::Error) -> Self {
        if matches!(
            error.kind(),
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
        ) {
            Self::Full
        } else {
            Self::Io(error)
        }
    }
}

/// The durable store a relay writes through and reads from.
/// The byte ceiling rejects intake; it never evicts acknowledged events.
pub trait EventStore: Send + Sync {
    fn put(
        &self,
        visibility: Visibility,
        event: &Event,
        now: u64,
    ) -> Result<PutOutcome, EventStoreError>;
    fn query(
        &self,
        visibility: Visibility,
        filter: &Filter,
        now: u64,
    ) -> Result<Vec<Event>, EventStoreError>;
    /// [`EventStore::query`], answered as each event's stored JSON with the
    /// few fields a reader needs, so that a reply can send the JSON verbatim
    /// instead of rebuilding it. The default serialises what `query` returns.
    fn query_stored(
        &self,
        visibility: Visibility,
        filter: &Filter,
        now: u64,
    ) -> Result<Vec<StoredEvent>, EventStoreError> {
        self.query(visibility, filter, now)?
            .iter()
            .map(StoredEvent::from_event)
            .collect()
    }
    /// NIP-45: how many events in the partition match any of `filters`, each
    /// counted once, up to [`MAX_EXACT_COUNT`] + 1: a larger answer means
    /// "more than [`MAX_EXACT_COUNT`]". Each filter's `limit` is ignored. A
    /// store that cannot count answers [`EventStoreError::Query`].
    fn count(
        &self,
        visibility: Visibility,
        filters: &[Filter],
        now: u64,
    ) -> Result<u64, EventStoreError> {
        let _ = (visibility, filters, now);
        Err(EventStoreError::Query)
    }
    fn logical_bytes(&self) -> Result<u64, EventStoreError>;
    /// [`EventStore::put`] for an event copied from another box, under a
    /// reserve: it is refused as `Full` unless, once stored, a share of the
    /// logical budget ([`REPLICA_RESERVE_DIVISOR`]) and extra disk headroom
    /// ([`REPLICA_DISK_RESERVE_BYTES`]) remain for the keeper's own direct
    /// writes. Replication can fill the store only up to that reserve.
    fn put_replicated(
        &self,
        visibility: Visibility,
        event: &Event,
        now: u64,
    ) -> Result<PutOutcome, EventStoreError>;
    /// Store prepared events in order, as if by [`EventStore::put`] (or
    /// [`EventStore::put_replicated`]) one at a time, and answer each. A store
    /// may commit them together; each answer is then given only once that
    /// commit has happened. An answer of [`EventStoreError::Deferred`] means
    /// the store did not get to that event (its batch ran out of time): it did
    /// nothing with it, and it may be offered again. A write that carries a
    /// [`Recheck`] is refused as [`EventStoreError::Unauthorised`] if the
    /// author is no longer authorised when the store reaches it. The default
    /// stores them one by one.
    fn put_prepared_batch(
        &self,
        batch: &[PreparedPut],
    ) -> Vec<Result<PutOutcome, EventStoreError>> {
        batch
            .iter()
            .map(|put| {
                if !put.still_authorised() {
                    return Err(EventStoreError::Unauthorised);
                }
                if put.replicated {
                    self.put_replicated(put.visibility, &put.event, put.now)
                } else {
                    self.put(put.visibility, &put.event, put.now)
                }
            })
            .collect()
    }
    /// Remove at most MAX_EXPIRE_EVENTS author-expired payloads in one commit.
    /// Replacement/deletion barriers remain. A full batch may have more behind it.
    fn expire(&self, now: u64) -> Result<usize, EventStoreError>;
}

/// One stored event as its stored JSON, with the fields a reader needs to
/// order it and to apply a guest's read rule, read from that JSON without
/// building the event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    pub created_at: u64,
    /// Lowercase hex, so it orders as the event id's bytes do.
    pub id: String,
    pub kind: u16,
    /// The value of the event's `d` tag under `single_d_value`'s rule, or
    /// `None` when it has no such tag.
    pub room: Option<String>,
    /// The event's JSON exactly as stored.
    pub json: String,
}

impl StoredEvent {
    /// From a built event, serialised as the store serialises it on write.
    pub fn from_event(event: &Event) -> Result<Self, EventStoreError> {
        Ok(Self {
            created_at: event.created_at.as_secs(),
            id: event.id.to_hex(),
            kind: event.kind.as_u16(),
            room: single_d_value(event.tags.iter().map(|tag| tag.as_slice())).map(str::to_owned),
            json: serde_json::to_string(event).map_err(|_| EventStoreError::Corrupt)?,
        })
    }

    /// From a stored row. A cheap structural check stands in for building the
    /// event: the row is a JSON object with exactly the seven event fields and
    /// their types, the id is lowercase hex and the author and signature hex,
    /// each of the right length, the kind fits a `u16`, and every tag is a
    /// non-empty array of strings (as `nostr` requires). The row is sent as it
    /// is, so nothing beyond an event object may pass. A row that fails is
    /// `Corrupt`, as a row that did not parse as an event was.
    /// Not checked here: that the author is a valid curve point and the
    /// signature well formed, which the write path verified.
    pub fn from_stored(json: String) -> Result<Self, EventStoreError> {
        // A derived struct also accepts the array form; only an object will do.
        if !json.starts_with('{') {
            return Err(EventStoreError::Corrupt);
        }
        let head: StoredHead<'_> =
            serde_json::from_str(&json).map_err(|_| EventStoreError::Corrupt)?;
        if head.tags.iter().any(Vec::is_empty) {
            return Err(EventStoreError::Corrupt);
        }
        let room = single_d_value(head.tags.iter().map(Vec::as_slice)).map(str::to_owned);
        let (created_at, kind) = (head.created_at, head.kind);
        // Owned before the head, which borrows the row, goes and the row moves.
        let id = head.id.0.0.into_owned();
        Ok(Self {
            created_at,
            id,
            kind,
            room,
            json,
        })
    }
}

/// The value of an event's single `d` tag: `Some` only when exactly one tag
/// is named `d` and that tag has exactly two elements. The one definition of
/// a room, for built events and for stored JSON alike.
pub(crate) fn single_d_value<'t, T: AsRef<str> + 't>(
    tags: impl IntoIterator<Item = &'t [T]>,
) -> Option<&'t str> {
    let mut found = None;
    for tag in tags {
        if tag.first().is_some_and(|name| name.as_ref() == "d") {
            if found.is_some() {
                return None;
            }
            found = Some(tag);
        }
    }
    found
        .filter(|tag| tag.len() == 2)
        .map(|tag| tag[1].as_ref())
}

/// The parts of a stored event's JSON [`StoredEvent::from_stored`] reads.
/// Strings are borrowed from the row where they have no escapes.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHead<'a> {
    #[serde(borrow)]
    id: HexText<'a, 64>,
    #[allow(dead_code)]
    pubkey: HexCheck<64>,
    created_at: u64,
    kind: u16,
    #[serde(borrow)]
    tags: Vec<Vec<Text<'a>>>,
    #[allow(dead_code)]
    content: StrCheck,
    #[allow(dead_code)]
    sig: HexCheck<128>,
}

/// A JSON string, borrowed when it has no escapes.
struct Text<'a>(std::borrow::Cow<'a, str>);

impl AsRef<str> for Text<'_> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'de: 'a, 'a> serde::Deserialize<'de> for Text<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Text<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                v: &'de str,
            ) -> Result<Self::Value, E> {
                Ok(Text(std::borrow::Cow::Borrowed(v)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Text(std::borrow::Cow::Owned(v.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(Text(std::borrow::Cow::Owned(v)))
            }
        }
        deserializer.deserialize_str(Visit)
    }
}

/// A JSON string of exactly `N` lowercase hex digits, kept.
struct HexText<'a, const N: usize>(Text<'a>);

impl<'de: 'a, 'a, const N: usize> serde::Deserialize<'de> for HexText<'a, N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Text::deserialize(deserializer)?;
        if is_hex(&text.0, N) && !text.0.bytes().any(|b| b.is_ascii_uppercase()) {
            Ok(Self(text))
        } else {
            Err(serde::de::Error::custom("not hex of the expected length"))
        }
    }
}

/// A JSON string of exactly `N` hex digits, checked and not kept.
struct HexCheck<const N: usize>;

impl<'de, const N: usize> serde::Deserialize<'de> for HexCheck<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit<const N: usize>;
        impl<const N: usize> serde::de::Visitor<'_> for Visit<N> {
            type Value = HexCheck<N>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a string of {N} hex digits")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if is_hex(v, N) {
                    Ok(HexCheck)
                } else {
                    Err(E::custom("not hex of the expected length"))
                }
            }
        }
        deserializer.deserialize_str(Visit::<N>)
    }
}

/// Any JSON string, checked and not kept.
struct StrCheck;

impl<'de> serde::Deserialize<'de> for StrCheck {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit;
        impl serde::de::Visitor<'_> for Visit {
            type Value = StrCheck;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(StrCheck)
            }
        }
        deserializer.deserialize_str(Visit)
    }
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}

pub struct SqliteEventStore {
    // First, so the background threads stop (and the checkpoint thread makes
    // its final checkpoint) while every connection is still open.
    maintenance: Maintenance,
    // Declared before the writer so the writer drops last: the final
    // connection to close checkpoints and removes the WAL, and a read-only
    // one cannot. Empty when the database cannot use WAL; reads then share
    // the writer connection.
    readers: Vec<Mutex<Reader>>,
    next_reader: AtomicUsize,
    conn: Mutex<Connection>,
    /// The writer's statement deadline.
    budget: Budget,
    max_bytes: u64,
    min_free_bytes: u64,
    parent: PathBuf,
    free_space: Arc<dyn FreeSpace>,
    checkpoint: Arc<dyn Checkpoint>,
    commits: AtomicU64,
    /// How long one batch may keep starting events; see [`BATCH_BUDGET`].
    batch_budget: Duration,
    /// Built history SQL by filter shape ([`query_shape`]), bounded by
    /// [`SQL_CACHE_SHAPES`] and [`SQL_CACHE_BYTES`].
    sql_cache: Mutex<SqlCache>,
    /// Test seam: a SQLite result code that makes every commit fail.
    #[cfg(test)]
    pub(crate) commit_fault: std::sync::atomic::AtomicI32,
    /// Test seam: events (by id) that are slow, and how.
    #[cfg(test)]
    pub(crate) slow: Mutex<Vec<(String, Slow)>>,
    /// Test seam: passes that had to be run again without an event whose
    /// interrupt had taken the whole transaction with it.
    #[cfg(test)]
    pub(crate) reruns: AtomicU64,
    /// Test seam: insert tags one statement at a time, as before the
    /// multi-row insert, for the differential test.
    #[cfg(test)]
    pub(crate) legacy_tags: AtomicBool,
}

/// How a test makes one event exceed its budget, so that the real
/// `SQLITE_INTERRUPT` path runs.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Slow {
    /// Interrupted at its first statement, a read: the transaction survives.
    AtFirstRead,
    /// Interrupted at its first write: SQLite rolls the whole transaction back.
    AtFirstWrite,
    /// Not interrupted; it just takes this many milliseconds.
    Takes(u64),
}

/// The version 1 layout, which the migrations below start from. New stores
/// are created at version 4 ([`create_v4`]); this is kept for the fixtures
/// that build a store as an earlier release left it.
#[cfg(test)]
const SCHEMA_V1: &str = r#"
CREATE TABLE events (
  visibility INTEGER NOT NULL CHECK(visibility IN (0,1)), id TEXT NOT NULL,
  author TEXT NOT NULL, kind INTEGER NOT NULL, created_at INTEGER NOT NULL,
  coordinate TEXT, expires_at INTEGER, json TEXT NOT NULL,
  PRIMARY KEY(visibility,id)
);
CREATE INDEX events_time ON events(visibility,created_at DESC,id);
CREATE INDEX events_author_kind ON events(visibility,author,kind,created_at DESC,id);
CREATE INDEX events_coordinate ON events(visibility,author,kind,coordinate);
CREATE TABLE tags (
  visibility INTEGER NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
  PRIMARY KEY(visibility,id,name,value),
  FOREIGN KEY(visibility,id) REFERENCES events(visibility,id) ON DELETE CASCADE
);
CREATE INDEX tags_lookup ON tags(visibility,name,value,id);
CREATE TABLE heads (
  visibility INTEGER NOT NULL, author TEXT NOT NULL, kind INTEGER NOT NULL,
  coordinate TEXT NOT NULL, created_at INTEGER NOT NULL, id TEXT NOT NULL,
  PRIMARY KEY(visibility,author,kind,coordinate)
);
CREATE TABLE deleted_ids (
  visibility INTEGER NOT NULL, author TEXT NOT NULL, id TEXT NOT NULL,
  PRIMARY KEY(visibility,author,id)
);
CREATE TABLE deleted_coordinates (
  visibility INTEGER NOT NULL, author TEXT NOT NULL, kind INTEGER NOT NULL,
  coordinate TEXT NOT NULL, through INTEGER NOT NULL,
  PRIMARY KEY(visibility,author,kind,coordinate)
);
CREATE TABLE usage (id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER NOT NULL CHECK(bytes>=0));
INSERT INTO usage VALUES(1,0);
PRAGMA user_version=1;
"#;

/// The version 4 tables that hold events, `{s}` standing for a suffix: none
/// for the live tables, `_v4` while the upgrade from version 3 copies into
/// them beside the old ones. Ids and public keys are 32-byte BLOBs, whose
/// order is the order of their lowercase hex. An event's row number `seq` is
/// its handle: tag rows refer to it rather than repeating the id, and the
/// `tags` table is keyed by it, so both grow at their right-hand edge.
const V4_EVENT_TABLES: &str = "CREATE TABLE events{s} (
  seq INTEGER PRIMARY KEY,
  visibility INTEGER NOT NULL CHECK(visibility IN (0,1)),
  id BLOB NOT NULL CHECK(length(id)=32),
  author BLOB NOT NULL CHECK(length(author)=32),
  kind INTEGER NOT NULL, created_at INTEGER NOT NULL,
  coordinate TEXT, expires_at INTEGER, json TEXT NOT NULL
);
CREATE TABLE tags{s} (
  seq INTEGER NOT NULL REFERENCES events{s}(seq) ON DELETE CASCADE,
  name TEXT NOT NULL, value TEXT NOT NULL,
  visibility INTEGER NOT NULL, created_at INTEGER NOT NULL,
  id BLOB NOT NULL CHECK(length(id)=32),
  PRIMARY KEY(seq,name,value)
) WITHOUT ROWID;";

/// The version 4 replacement and deletion barriers, keyed as in version 3
/// with BLOB authors and ids.
const V4_BARRIER_TABLES: &str = "CREATE TABLE heads{s} (
  visibility INTEGER NOT NULL, author BLOB NOT NULL CHECK(length(author)=32),
  kind INTEGER NOT NULL, coordinate TEXT NOT NULL, created_at INTEGER NOT NULL,
  id BLOB NOT NULL CHECK(length(id)=32),
  PRIMARY KEY(visibility,author,kind,coordinate)
);
CREATE TABLE deleted_ids{s} (
  visibility INTEGER NOT NULL, author BLOB NOT NULL CHECK(length(author)=32),
  id BLOB NOT NULL CHECK(length(id)=32),
  PRIMARY KEY(visibility,author,id)
);
CREATE TABLE deleted_coordinates{s} (
  visibility INTEGER NOT NULL, author BLOB NOT NULL CHECK(length(author)=32),
  kind INTEGER NOT NULL, coordinate TEXT NOT NULL, through INTEGER NOT NULL,
  PRIMARY KEY(visibility,author,kind,coordinate)
);";

/// The version 4 indexes, by name. The time-ordered ones are ascending on
/// `created_at` with `id DESC`, so a new event lands at the right-hand edge
/// and a backward scan is NIP-01 order (`created_at DESC, id ASC`) with no
/// sort. `events_coordinate` holds only replaceable and addressable events;
/// every statement that uses it names a `coordinate`, which implies not null.
/// Each is built in its own transaction once an upgrade has filled the
/// tables, and an open builds any that are missing.
const V4_INDEXES: [(&str, &str); 6] = [
    (
        "events_id",
        "CREATE UNIQUE INDEX IF NOT EXISTS events_id ON events(visibility,id)",
    ),
    (
        "events_time",
        "CREATE INDEX IF NOT EXISTS events_time ON events(visibility,created_at,id DESC)",
    ),
    (
        "events_author_kind",
        "CREATE INDEX IF NOT EXISTS events_author_kind ON events(visibility,author,kind,created_at,id DESC)",
    ),
    (
        "events_coordinate",
        "CREATE INDEX IF NOT EXISTS events_coordinate ON events(visibility,author,kind,coordinate) WHERE coordinate IS NOT NULL",
    ),
    (
        "events_expiry",
        "CREATE INDEX IF NOT EXISTS events_expiry ON events(expires_at) WHERE expires_at IS NOT NULL",
    ),
    (
        "tags_by_time",
        "CREATE INDEX IF NOT EXISTS tags_by_time ON tags(visibility,name,value,created_at,id DESC)",
    ),
];

/// The logical byte charge of one row of each table, as `ROW.` columns. The
/// same formulas as version 3, so an upgrade leaves `usage` and every quota
/// where they were.
fn charge_costs() -> [(&'static str, String); 5] {
    [
        (
            "events",
            format!(
                "length(CAST(ROW.json AS BLOB))+512+CASE WHEN ROW.kind=5 THEN 0 ELSE {DELETION_RESERVE_BYTES} END"
            ),
        ),
        ("tags", "length(CAST(ROW.value AS BLOB))+160".to_owned()),
        (
            "heads",
            "length(CAST(ROW.coordinate AS BLOB))+256".to_owned(),
        ),
        ("deleted_ids", "192".to_owned()),
        (
            "deleted_coordinates",
            "length(CAST(ROW.coordinate AS BLOB))+192".to_owned(),
        ),
    ]
}

/// The charge triggers that keep `usage` equal to the sum of the costs.
fn create_charge_triggers(conn: &Connection) -> Result<(), rusqlite::Error> {
    for (table, cost) in charge_costs() {
        let new = cost.replace("ROW.", "NEW.");
        let old = cost.replace("ROW.", "OLD.");
        conn.execute_batch(&format!("CREATE TRIGGER {table}_charge_insert AFTER INSERT ON {table} BEGIN UPDATE usage SET bytes=bytes+({new}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_delete AFTER DELETE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_update AFTER UPDATE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old})+({new}) WHERE id=1; END;"))?;
    }
    Ok(())
}

/// A new, empty store, straight at version 4.
fn create_v4(conn: &mut Connection) -> Result<(), rusqlite::Error> {
    let tx = conn.transaction()?;
    tx.execute_batch(&V4_EVENT_TABLES.replace("{s}", ""))?;
    tx.execute_batch(&V4_BARRIER_TABLES.replace("{s}", ""))?;
    tx.execute_batch("CREATE TABLE usage (id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER NOT NULL CHECK(bytes>=0));
INSERT INTO usage VALUES(1,0);")?;
    for (_, sql) in V4_INDEXES {
        tx.execute(sql, [])?;
    }
    create_charge_triggers(&tx)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()
}

/// A 32-byte id or public key as it is bound to SQL: the bytes, for a BLOB
/// column. The one conversion at the statement boundary in this direction.
fn key_blob(bytes: &[u8; 32]) -> Value {
    Value::Blob(bytes.to_vec())
}

/// Lowercase 64-character hex as the 32 bytes it spells, or `None`.
fn hex_key(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
}

impl SqliteEventStore {
    /// A separate database: opening a newer or unrelated schema never migrates it.
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self, EventStoreError> {
        Self::open_with_space(path, max_bytes, 0, Arc::new(FilesystemFreeSpace))
    }

    pub fn open_with_headroom(
        path: &Path,
        max_bytes: u64,
        min_free_bytes: u64,
    ) -> Result<Self, EventStoreError> {
        Self::open_with_space(
            path,
            max_bytes,
            min_free_bytes,
            Arc::new(FilesystemFreeSpace),
        )
    }

    fn open_with_space(
        path: &Path,
        max_bytes: u64,
        min_free_bytes: u64,
        free_space: Arc<dyn FreeSpace>,
    ) -> Result<Self, EventStoreError> {
        Self::open_with_all(
            path,
            max_bytes,
            min_free_bytes,
            free_space,
            Arc::new(SqliteCheckpoint),
            StoreOptions::default(),
        )
    }

    /// As [`SqliteEventStore::open_with_headroom`], with explicit memory and
    /// background-work options; see [`StoreOptions`].
    pub fn open_with_options(
        path: &Path,
        max_bytes: u64,
        min_free_bytes: u64,
        options: StoreOptions,
    ) -> Result<Self, EventStoreError> {
        Self::open_with_all(
            path,
            max_bytes,
            min_free_bytes,
            Arc::new(FilesystemFreeSpace),
            Arc::new(SqliteCheckpoint),
            options,
        )
    }

    #[cfg(test)]
    fn open_with_dependencies(
        path: &Path,
        max_bytes: u64,
        min_free_bytes: u64,
        free_space: Arc<dyn FreeSpace>,
        checkpoint: Arc<dyn Checkpoint>,
    ) -> Result<Self, EventStoreError> {
        Self::open_with_all(
            path,
            max_bytes,
            min_free_bytes,
            free_space,
            checkpoint,
            StoreOptions::default(),
        )
    }

    fn open_with_all(
        path: &Path,
        max_bytes: u64,
        min_free_bytes: u64,
        free_space: Arc<dyn FreeSpace>,
        checkpoint: Arc<dyn Checkpoint>,
        options: StoreOptions,
    ) -> Result<Self, EventStoreError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut create = std::fs::OpenOptions::new();
        create.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            create.mode(0o600);
        }
        match create.open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(EventStoreError::Schema);
        }
        // macOS's /var and Android's storage roots may themselves be symlinks.
        // Resolve the directory, while NOFOLLOW still protects the final file.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let canonical = parent
            .canonicalize()?
            .join(path.file_name().ok_or(EventStoreError::Schema)?);
        let canonical_parent = canonical
            .parent()
            .ok_or(EventStoreError::Schema)?
            .to_path_buf();
        let open_needed = min_free_bytes.saturating_add(TRANSACTION_GUARD_BYTES);
        let open_available = free_space.available_bytes(&canonical_parent)?;
        if open_available < open_needed {
            // Name what the whole start needs, not only the headroom: a store
            // that still has an upgrade to run is refused again, with the
            // upgrade's larger figure, once that much has been freed.
            let pending = pending_upgrade_bytes(&canonical).unwrap_or(0);
            return Err(EventStoreError::DiskSpace {
                needed: open_needed.saturating_add(pending),
                available: open_available,
            });
        }
        let mut conn = Connection::open_with_flags(
            &canonical,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
        let budget = Budget::new();
        budget.attach(&mut conn, BUDGET_STEPS)?;
        let mut version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == 0 {
            let tables: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get(0),
            )?;
            if tables != 0 {
                return Err(EventStoreError::Schema);
            }
            // A new store starts at the current layout: nothing to migrate.
            create_v4(&mut conn)?;
            version = SCHEMA_VERSION;
        } else if version > SCHEMA_VERSION {
            // A newer schema. Every core before version 4 refuses a version 4
            // store (as `Schema`), so going back after an upgrade is an
            // export with the newer build ([`export_stored`]) and an
            // import with the older one, never a downgrade in place.
            return Err(EventStoreError::NewerSchema {
                found: version,
                supported: SCHEMA_VERSION,
            });
        } else if version < 1 {
            return Err(EventStoreError::Schema);
        }
        for table in [
            "events",
            "tags",
            "heads",
            "deleted_ids",
            "deleted_coordinates",
            "usage",
        ] {
            conn.prepare(&format!("SELECT * FROM {table} LIMIT 0"))?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // The readers can hold snapshots across writes, and a WAL only
        // restarts when none does, so under sustained load it can keep
        // growing. Automatic PASSIVE checkpoints run every 1000 pages (the
        // default, stated here so it is not lost) until the store has opened
        // and, unless the options say otherwise, the checkpoint thread takes
        // over (see below); after any checkpoint that does reset the log the
        // file is cut back to this limit.
        conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
        conn.pragma_update(None, "journal_size_limit", WAL_SIZE_LIMIT_BYTES)?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "secure_delete", true)?;
        for table in [
            "events",
            "tags",
            "heads",
            "deleted_ids",
            "deleted_coordinates",
        ] {
            for action in ["insert", "delete", "update"] {
                let name = format!("{table}_charge_{action}");
                if conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?",
                        [&name],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_none()
                {
                    return Err(EventStoreError::Schema);
                }
            }
        }
        if version < 2 {
            let tx = conn.transaction()?;
            tx.execute(
                "UPDATE usage SET bytes=bytes+?*(SELECT count(*) FROM events WHERE kind<>5) WHERE id=1",
                [DELETION_RESERVE_BYTES as i64],
            )?;
            let cost = format!(
                "length(CAST(ROW.json AS BLOB))+512+CASE WHEN ROW.kind=5 THEN 0 ELSE {DELETION_RESERVE_BYTES} END"
            );
            let new = cost.replace("ROW.", "NEW.");
            let old = cost.replace("ROW.", "OLD.");
            tx.execute_batch(&format!("DROP TRIGGER events_charge_insert;
DROP TRIGGER events_charge_delete;
DROP TRIGGER events_charge_update;
CREATE TRIGGER events_charge_insert AFTER INSERT ON events BEGIN UPDATE usage SET bytes=bytes+({new}) WHERE id=1; END;
CREATE TRIGGER events_charge_delete AFTER DELETE ON events BEGIN UPDATE usage SET bytes=bytes-({old}) WHERE id=1; END;
CREATE TRIGGER events_charge_update AFTER UPDATE ON events BEGIN UPDATE usage SET bytes=bytes-({old})+({new}) WHERE id=1; END;
PRAGMA user_version=2;"))?;
            tx.commit()?;
        }
        if version < 3 {
            // Tag rows carry their event's time so a room query can walk the
            // index newest-first. One transaction: a failure (disk full, a
            // kill) rolls back to v2 untouched and the next open retries.
            // The backfill fires `tags_charge_update`, which nets to zero
            // because the charged `value` does not change, so usage is the
            // same before and after. `tags_by_time` supersedes `tags_lookup`.
            //
            // The migration writes the `tags` table again (the backfill), a
            // new index, and, because `secure_delete` is on, zeroes the pages
            // of the dropped `tags_lookup`, all through the WAL before a
            // checkpoint. That is a function of the tag data, not of the
            // events' JSON, so it is estimated from the tag rows
            // ([`migration_estimate`]) rather than from the file size: refuse
            // up front, with the open-time headroom on top, rather than fill
            // the disk part way and leave a large WAL behind. The caller
            // starts without the shelter and retries on the next start.
            // A store created by this open has nothing to rewrite.
            let mut estimate = None;
            // The free space the upgrade needs, the same figure for the
            // up-front refusal and for a disk that fills part way. A store
            // created by this open has no tag rows, so only the headroom.
            let mut required = min_free_bytes.saturating_add(TRANSACTION_GUARD_BYTES);
            if version != 0 {
                let needed_by_migration = migration_estimate(&conn)?;
                required = required.saturating_add(needed_by_migration.disk_bytes);
                let available = free_space.available_bytes(&canonical_parent)?;
                if available < required {
                    tracing::error!(
                        available,
                        required,
                        tag_rows = needed_by_migration.tag_rows,
                        "the event store upgrade needs more free disk space than there is; not started"
                    );
                    return Err(EventStoreError::DiskSpace {
                        needed: required,
                        available,
                    });
                }
                estimate = Some(needed_by_migration);
            }
            // `CREATE INDEX` sorts every tag row. Past the sorter's small
            // page cache SQLite spills the sort to temp files, found through
            // TMPDIR and a short list of system directories, and an Android
            // host often has none writable. The sort holds only the new
            // index's key bytes, about 1.3 times the tag text counted above
            // (measured: 83 MB of heap for 500k tag rows of 129 bytes). That
            // text is bounded by the operator's disk budget, not the host's
            // RAM, so memory is used only up to [`MIGRATION_MEMORY_SORT_CEILING`]
            // and a larger store keeps the default file-backed temp store
            // rather than risk the OOM killer on every start. Android builds
            // of the bundled SQLite already force in-memory temp
            // (`SQLITE_TEMP_STORE=3`), so the ceiling matters for server and
            // desktop builds. Restored afterwards so ordinary query temp
            // tables keep the default. Not unit-tested with a bad TMPDIR:
            // forcing it needs the process-global `sqlite3_temp_directory`,
            // which would race every other test.
            let tag_bytes = estimate.as_ref().map_or(0, |e| e.tag_bytes);
            conn.execute_batch(migration_temp_store_pragma(tag_bytes))?;
            if let Some(estimate) = &estimate {
                tracing::info!(
                    tag_rows = estimate.tag_rows,
                    sort_memory_bytes = estimate.tag_bytes,
                    "upgrading the event store (tag index with time)"
                );
            }
            let migrated = (|| -> Result<(), EventStoreError> {
                let tx = conn.transaction()?;
                tx.execute_batch(MIGRATE_V3_SQL)?;
                tx.commit()?;
                Ok(())
            })();
            if let Err(error) = conn.execute_batch("PRAGMA temp_store = DEFAULT") {
                tracing::warn!(%error, "event-store temp_store was not restored after the upgrade");
            }
            // Success or failure, hand the migration's WAL back: a rolled-back
            // attempt otherwise keeps its file at full size until some later
            // checkpoint, using the space the next try needs. Best effort.
            if let Err(error) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)") {
                tracing::warn!(%error, "event-store WAL was not truncated after the upgrade");
            }
            // A disk filling part way is a disk problem, not the store's
            // byte budget being full: say so.
            migrated.map_err(|error| match error {
                EventStoreError::Full => EventStoreError::DiskSpace {
                    needed: required,
                    available: free_space.available_bytes(&canonical_parent).unwrap_or(0),
                },
                other => other,
            })?;
        }
        let upgrade = UpgradeEnv {
            free_space: free_space.as_ref(),
            parent: &canonical_parent,
            min_free_bytes,
        };
        if version < 4 {
            // Version 4 rewrites every event and tag row (see
            // [`upgrade_v4`]): in bounded transactions, each checkpointed,
            // resumable after a kill, and refused up front without the disk
            // space it needs.
            let upgraded = upgrade_v4(&mut conn, &upgrade);
            if let Err(error) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)") {
                tracing::warn!(%error, "event-store WAL was not truncated after the upgrade");
            }
            upgraded?;
        }
        // Every open, after schema validation: build any version 4 index that
        // is missing (the last steps of an upgrade, or a repair), then finish
        // zeroing the pages an upgrade freed.
        let finished = finish_v4(&mut conn, &upgrade);
        if let Err(error) = conn.execute_batch("PRAGMA temp_store = DEFAULT") {
            tracing::warn!(%error, "event-store temp_store was not restored after an index build");
        }
        finished?;
        // Readers open last, once the schema is final and WAL is confirmed.
        let journal: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        let wal = journal.eq_ignore_ascii_case("wal");
        // The writer's heap cache stays small; hot pages live in the memory
        // map. Set after any migration, which runs on SQLite's defaults.
        conn.pragma_update(None, "cache_size", -i64::from(options.writer_cache_kib))?;
        set_mmap(&conn, options.mmap_bytes);
        let reader_mmap = options.reader_mmap_bytes.min(options.mmap_bytes);
        let readers = if wal {
            open_readers(READ_CONNECTIONS, || {
                open_reader(&canonical, options.reader_cache_kib, reader_mmap)
            })
        } else {
            tracing::warn!(%journal, "event store is not in WAL mode; reads share the writer connection");
            Vec::new()
        };
        let shared = Arc::new(WalShared::new(&options));
        // Built before any thread starts, so that an early return below drops
        // it and stops and joins whatever has been spawned.
        let mut maintenance = Maintenance {
            shared: Arc::clone(&shared),
            warm_stop: Arc::new(AtomicBool::new(false)),
            background: false,
            threads: Vec::new(),
        };
        if wal && options.background_checkpoint {
            match spawn_checkpointer(&canonical, &shared, options.checkpoint_cache_kib) {
                Ok(thread) => {
                    maintenance.threads.push(thread);
                    // The pragma clears SQLite's automatic checkpoint (itself
                    // a WAL hook); ours replaces it and only counts pages.
                    conn.pragma_update(None, "wal_autocheckpoint", 0)?;
                    conn.wal_hook(Some(wal_observe))?;
                    maintenance.background = true;
                }
                Err(error) => {
                    tracing::warn!(%error, "event-store checkpoint thread did not start; the writer keeps its automatic checkpoint");
                }
            }
        }
        if wal && options.warm {
            match spawn_warmer(&canonical, &options, &shared, &maintenance.warm_stop) {
                Ok(thread) => maintenance.threads.push(thread),
                Err(error) => {
                    tracing::warn!(%error, "event-store warm-up did not start");
                }
            }
        }
        Ok(Self {
            maintenance,
            readers,
            next_reader: AtomicUsize::new(0),
            conn: Mutex::new(conn),
            budget,
            max_bytes,
            min_free_bytes,
            parent: canonical_parent,
            free_space,
            checkpoint,
            commits: AtomicU64::new(0),
            batch_budget: BATCH_BUDGET,
            sql_cache: Mutex::new(SqlCache::default()),
            #[cfg(test)]
            commit_fault: std::sync::atomic::AtomicI32::new(0),
            #[cfg(test)]
            slow: Mutex::new(Vec::new()),
            #[cfg(test)]
            reruns: AtomicU64::new(0),
            #[cfg(test)]
            legacy_tags: AtomicBool::new(false),
        })
    }
    fn has_headroom(&self, guard: bool, extra: u64) -> Result<bool, EventStoreError> {
        let required = self
            .min_free_bytes
            .saturating_add(if guard { TRANSACTION_GUARD_BYTES } else { 0 })
            .saturating_add(extra);
        Ok(self.free_space.available_bytes(&self.parent)? >= required)
    }
    /// The writer connection, with the WAL probe bound for as long as it is
    /// held. `conn` is locked nowhere else.
    fn lock(&self) -> Result<WriterGuard<'_>, EventStoreError> {
        let conn = self.conn.lock().map_err(|_| EventStoreError::Poisoned)?;
        let _probe = ProbeGuard::enter(
            self.maintenance
                .background
                .then_some(&self.maintenance.shared),
        );
        Ok(WriterGuard { _probe, conn })
    }

    /// Run `f` on a read-only connection, taking a free one if any, so
    /// history queries neither wait for the writer nor serialise on each other
    /// beyond the pool size. Without WAL it uses the writer connection. Each
    /// statement of `f` is interrupted once [`QUERY_BUDGET`] has passed.
    fn with_reader<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, EventStoreError>,
    ) -> Result<T, EventStoreError> {
        let count = self.readers.len();
        if count == 0 {
            let conn = self.lock()?;
            return self.budget.within(QUERY_BUDGET, || f(&conn));
        }
        let first = self.next_reader.fetch_add(1, AtomicOrdering::Relaxed) % count;
        for offset in 0..count {
            match self.readers[(first + offset) % count].try_lock() {
                Ok(reader) => return reader.budget.within(QUERY_BUDGET, || f(&reader.conn)),
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Poisoned(_)) => return Err(EventStoreError::Poisoned),
            }
        }
        let reader = self.readers[first]
            .lock()
            .map_err(|_| EventStoreError::Poisoned)?;
        reader.budget.within(QUERY_BUDGET, || f(&reader.conn))
    }

    /// The one place the writer checkpoints. Normally the checkpoint thread
    /// keeps the WAL short and this does nothing. If a commit has left the WAL
    /// at its ceiling (readers have pinned old snapshots, or the disk is
    /// slower than intake), run a blocking FULL checkpoint here, waiting up to
    /// [`CEILING_WAIT`] in all for the checkpoint lock and then for the
    /// readers. Writes stall for that time, which is the point: intake is
    /// slowed rather than the log allowed to grow. After a wait that ran out,
    /// no other is started for [`CEILING_RETRY`].
    fn enforce_wal_ceiling(&self, conn: &Connection) {
        let shared = &self.maintenance.shared;
        if !self.maintenance.background || !shared.over_ceiling.swap(false, AtomicOrdering::AcqRel)
        {
            return;
        }
        if shared
            .last_blocking
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|at| at.elapsed() < CEILING_RETRY)
        {
            return;
        }
        let began = Instant::now();
        let outcome = checkpoint_within(CEILING_WAIT, |timeout| {
            let _ = conn.busy_timeout(timeout);
            run_checkpoint(conn, "FULL")
        });
        let _ = conn.busy_timeout(BUSY_TIMEOUT);
        let took = began.elapsed();
        let took_ns = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX);
        shared.blocking_runs.fetch_add(1, AtomicOrdering::Relaxed);
        shared
            .blocking_ns
            .fetch_add(took_ns, AtomicOrdering::Relaxed);
        shared
            .blocking_longest_ns
            .fetch_max(took_ns, AtomicOrdering::Relaxed);
        // A checkpoint that finished needs no pause before the next, and nor
        // does one that failed: the next commit over the ceiling tries again.
        // One held off until the wait ran out, by readers or by another
        // checkpoint, is not repeated for a second, so a reader or checkpoint
        // that never lets go costs the writer at most CEILING_WAIT in every
        // CEILING_WAIT + CEILING_RETRY.
        let held = matches!(
            outcome,
            CeilingCheckpoint::HeldByReaders | CeilingCheckpoint::HeldByCheckpoint
        );
        *shared
            .last_blocking
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = held.then(Instant::now);
        match outcome {
            CeilingCheckpoint::Finished => {}
            CeilingCheckpoint::HeldByReaders => tracing::warn!(
                "event-store WAL is over its ceiling and readers kept the blocking checkpoint from finishing"
            ),
            CeilingCheckpoint::HeldByCheckpoint => tracing::warn!(
                "event-store WAL is over its ceiling and another checkpoint held the checkpoint lock throughout the wait"
            ),
            CeilingCheckpoint::Failed(error) => {
                tracing::warn!(%error, "event-store blocking checkpoint did not complete");
            }
        }
    }

    fn checkpoint_after_reclaim(&self, conn: &Connection) {
        // The thread's PASSIVE may be running from an older safe frame, which
        // would leave the deleted bytes in the main file; ask for another
        // whatever the WAL's size, and it runs once the current one is done.
        if self.maintenance.background {
            self.maintenance.shared.request_checkpoint();
        }
        if let Err(error) = self.checkpoint.passive(conn) {
            // The transaction has already committed. Reporting this as a failed
            // write would invite a retry of a deletion that is already durable.
            tracing::warn!(%error, "event-store passive checkpoint did not complete");
        }
    }
}

/// A pool of `count` readers, or none if any will not open: reads are an
/// optimisation of the writer connection (which [`SqliteEventStore::with_reader`]
/// falls back to), not a requirement, so a reader that fails to open does not
/// stop the store.
fn open_readers(
    count: usize,
    open: impl Fn() -> Result<Connection, EventStoreError>,
) -> Vec<Mutex<Reader>> {
    let mut readers = Vec::with_capacity(count);
    for _ in 0..count {
        match open().and_then(|conn| Ok(Reader::new(conn)?)) {
            Ok(reader) => readers.push(Mutex::new(reader)),
            Err(error) => {
                tracing::warn!(%error, "event-store reader did not open; reads share the writer connection");
                return Vec::new();
            }
        }
    }
    readers
}

const MIGRATE_V3_SQL: &str = "ALTER TABLE tags ADD COLUMN created_at INTEGER;
UPDATE tags SET created_at=(SELECT e.created_at FROM events e WHERE e.visibility=tags.visibility AND e.id=tags.id);
CREATE INDEX tags_by_time ON tags(visibility,name,value,created_at DESC,id);
DROP INDEX tags_lookup;
PRAGMA user_version=3;";

/// The schema this build writes, after every migration above. A store at
/// this version is refused by every earlier core: going back is an export
/// and an import, not a downgrade.
pub const SCHEMA_VERSION: i64 = 4;

/// Events copied per transaction by the upgrade to version 4.
const UPGRADE_CHUNK_EVENTS: i64 = 20_000;
/// Free pages overwritten with zeros per transaction by the scrub that ends
/// an upgrade.
const SCRUB_CHUNK_BYTES: i64 = 16 * 1024 * 1024;
/// One scrub row: a zero BLOB filling a cell and its overflow pages.
const SCRUB_ROW_BYTES: i64 = 64 * 1024;

/// The bookkeeping of an upgrade in progress, created by its first
/// transaction and dropped by its last. While the copy runs, triggers on the
/// version 3 `events` table set `dirty` if anything (an older core, opened
/// on the store between two attempts) writes it, so a resumed copy never
/// keeps rows the old table no longer agrees with. `scrub` marks a switched
/// store whose free pages still hold the old tables.
const UPGRADE_START_SQL: &str = "CREATE TABLE event_store_upgrade (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO event_store_upgrade VALUES('dirty',0);
CREATE TRIGGER event_store_upgrade_insert AFTER INSERT ON events BEGIN UPDATE event_store_upgrade SET value=1 WHERE key='dirty'; END;
CREATE TRIGGER event_store_upgrade_delete AFTER DELETE ON events BEGIN UPDATE event_store_upgrade SET value=1 WHERE key='dirty'; END;
CREATE TRIGGER event_store_upgrade_update AFTER UPDATE ON events BEGIN UPDATE event_store_upgrade SET value=1 WHERE key='dirty'; END;";

/// The copy of one chunk of events, by the old row number, which becomes
/// `seq`: unique and increasing, so the new table and its tags are written
/// in key order.
const UPGRADE_COPY_EVENTS_SQL: &str = "INSERT INTO events_v4(seq,visibility,id,author,kind,created_at,coordinate,expires_at,json)
SELECT rowid,visibility,unhex(id),unhex(author),kind,created_at,coordinate,expires_at,json FROM events WHERE rowid>?1 ORDER BY rowid LIMIT ?2";

/// The tags of the events with row numbers in `(?1, ?2]`. The event's own
/// time is the tag row's time.
const UPGRADE_COPY_TAGS_SQL: &str = "INSERT INTO tags_v4(seq,name,value,visibility,created_at,id)
SELECT e.rowid,t.name,t.value,t.visibility,e.created_at,unhex(e.id) FROM events e JOIN tags t ON t.visibility=e.visibility AND t.id=e.id WHERE e.rowid>?1 AND e.rowid<=?2";

/// The switch: the small tables are copied, every version 3 table is
/// dropped (its triggers with it) and the new ones take their names. SQLite
/// rewrites the `tags` foreign key to `events` with the rename.
const UPGRADE_SWITCH_SQL: &str = "INSERT INTO heads_v4(visibility,author,kind,coordinate,created_at,id)
  SELECT visibility,unhex(author),kind,coordinate,created_at,unhex(id) FROM heads;
INSERT INTO deleted_ids_v4(visibility,author,id) SELECT visibility,unhex(author),unhex(id) FROM deleted_ids;
INSERT INTO deleted_coordinates_v4(visibility,author,kind,coordinate,through)
  SELECT visibility,unhex(author),kind,coordinate,through FROM deleted_coordinates;
DROP TABLE tags;
DROP TABLE events;
DROP TABLE heads;
DROP TABLE deleted_ids;
DROP TABLE deleted_coordinates;
ALTER TABLE events_v4 RENAME TO events;
ALTER TABLE tags_v4 RENAME TO tags;
ALTER TABLE heads_v4 RENAME TO heads;
ALTER TABLE deleted_ids_v4 RENAME TO deleted_ids;
ALTER TABLE deleted_coordinates_v4 RENAME TO deleted_coordinates;
INSERT INTO event_store_upgrade VALUES('scrub',1);";

/// Test seam for the upgrade: a smaller chunk, a stop (as a kill would stop
/// it) after a number of committed upgrade transactions, and the largest
/// WAL any one of them left.
#[cfg(test)]
#[derive(Default)]
struct UpgradeProbe {
    chunk_events: Option<i64>,
    scrub_bytes: Option<i64>,
    stop_after: Option<u32>,
    steps: u32,
    max_wal: u64,
}

#[cfg(test)]
thread_local! {
    static UPGRADE_PROBE: RefCell<UpgradeProbe> = RefCell::new(UpgradeProbe::default());
}

fn upgrade_chunk_events() -> i64 {
    #[cfg(test)]
    if let Some(n) = UPGRADE_PROBE.with(|p| p.borrow().chunk_events) {
        return n;
    }
    UPGRADE_CHUNK_EVENTS
}

fn scrub_chunk_bytes() -> i64 {
    #[cfg(test)]
    if let Some(n) = UPGRADE_PROBE.with(|p| p.borrow().scrub_bytes) {
        return n;
    }
    SCRUB_CHUNK_BYTES
}

/// What the upgrade needs from the open: the disk and the headroom.
struct UpgradeEnv<'a> {
    free_space: &'a dyn FreeSpace,
    parent: &'a Path,
    min_free_bytes: u64,
}

impl UpgradeEnv<'_> {
    /// After every upgrade transaction commits: hand the log back, so the WAL
    /// never holds more than one of them.
    fn step_done(&self, conn: &Connection) -> Result<(), EventStoreError> {
        #[cfg(test)]
        {
            let wal = conn
                .path()
                .and_then(|p| std::fs::metadata(format!("{p}-wal")).ok())
                .map_or(0, |m| m.len());
            let stop = UPGRADE_PROBE.with(|p| {
                let mut p = p.borrow_mut();
                p.max_wal = p.max_wal.max(wal);
                p.steps += 1;
                p.stop_after.is_some_and(|n| p.steps >= n)
            });
            if stop {
                return Err(EventStoreError::Io(std::io::Error::other(
                    "test: the upgrade stopped here",
                )));
            }
        }
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    /// A disk filling part way is a disk problem, not the store's byte
    /// budget being full: say so.
    fn disk_error(&self, error: EventStoreError, needed: u64) -> EventStoreError {
        match error {
            EventStoreError::Full => EventStoreError::DiskSpace {
                needed,
                available: self.free_space.available_bytes(self.parent).unwrap_or(0),
            },
            other => other,
        }
    }
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn index_exists(conn: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1",
            [name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn upgrade_dirty(conn: &Connection) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT value FROM event_store_upgrade WHERE key='dirty'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|value| value != 0)
}

/// Run `f` with `secure_delete` off, and always turn it back on. Used only
/// where the pages freed are copies of rows that are still live, and the
/// scrub that ends the upgrade ([`scrub_free_pages`]) zeroes them before
/// the store serves anything.
fn without_secure_delete<T>(
    conn: &mut Connection,
    f: impl FnOnce(&mut Connection) -> Result<T, EventStoreError>,
) -> Result<T, EventStoreError> {
    conn.pragma_update(None, "secure_delete", false)?;
    let result = f(conn);
    conn.pragma_update(None, "secure_delete", true)?;
    result
}

/// What the upgrade to version 4 needs from the disk, from the version 3
/// store.
struct UpgradeEstimate {
    events: u64,
    tag_rows: u64,
    /// Free disk space the upgrade needs on top of the open-time headroom.
    disk_bytes: u64,
}

/// The new tables are smaller than the old (binary keys and ids), so the
/// live bytes of the old file bound them. On top: the largest one
/// transaction writes through the WAL before its checkpoint, which is a
/// chunk of the copy, an index build (the tag index from the tag text and
/// about 64 bytes a row, the event's id among them; the event indexes from
/// about 128 bytes an event) or a scrub chunk, with half as much again
/// because pages are not full. The indexes are built after
/// the switch, into the pages the old tables freed. A resumed copy counts
/// the rows it has already copied again, which only overstates the need.
fn upgrade_estimate(conn: &Connection) -> Result<UpgradeEstimate, EventStoreError> {
    let pragma = |name: &str| -> Result<u64, rusqlite::Error> {
        conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get::<_, i64>(0))
            .map(|v| u64::try_from(v).unwrap_or(0))
    };
    let page_size = pragma("page_size")?;
    let live = pragma("page_count")?
        .saturating_sub(pragma("freelist_count")?)
        .saturating_mul(page_size);
    let events: i64 = conn.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
    let events = u64::try_from(events).unwrap_or(0);
    let (rows, text): (i64, i64) = conn.query_row(
        "SELECT count(*), COALESCE(SUM(length(CAST(name AS BLOB))+length(CAST(value AS BLOB))),0) FROM tags",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let tag_rows = u64::try_from(rows).unwrap_or(0);
    let tag_text = u64::try_from(text).unwrap_or(0);
    let chunk = u64::try_from(upgrade_chunk_events()).unwrap_or(1);
    let copy = (live / events.max(1)).saturating_mul(chunk).min(live);
    let index = tag_text
        .saturating_add(tag_rows.saturating_mul(64))
        .max(events.saturating_mul(128));
    let scrub = u64::try_from(scrub_chunk_bytes()).unwrap_or(0);
    let wal = copy
        .max(index)
        .max(scrub)
        .saturating_mul(MIGRATION_SAFETY_PERCENT)
        / 100;
    Ok(UpgradeEstimate {
        events,
        tag_rows,
        disk_bytes: live.saturating_add(wal),
    })
}

/// Version 3 to 4. The events and tags are copied in chunks of
/// [`UPGRADE_CHUNK_EVENTS`] into new tables beside the old ones, each chunk
/// its own transaction followed by a TRUNCATE checkpoint, so the WAL holds
/// one chunk rather than the whole store. Until the switch the version
/// stays 3 and the old tables are untouched (an older core can still open
/// the store), and an interrupted copy continues from the highest `seq`
/// copied, or starts again if the old table changed meanwhile. The new
/// tables have no secondary indexes and no charge triggers during the copy:
/// the old rows' charges are already in `usage` and the formulas are
/// unchanged, so `usage` stays exact. One transaction then switches the
/// store to version 4 (see [`UPGRADE_SWITCH_SQL`]). It drops the old tables
/// with `secure_delete` off, since zeroing them would write the whole store
/// through the WAL in that one transaction; their pages are copies of live
/// rows, and the open goes on to build the indexes and zero every free page
/// ([`finish_v4`]) before the store serves anything. Refused up front, and
/// with nothing written, without the disk space it needs.
fn upgrade_v4(conn: &mut Connection, env: &UpgradeEnv<'_>) -> Result<(), EventStoreError> {
    let estimate = upgrade_estimate(conn)?;
    let required = env
        .min_free_bytes
        .saturating_add(TRANSACTION_GUARD_BYTES)
        .saturating_add(estimate.disk_bytes);
    let available = env.free_space.available_bytes(env.parent)?;
    if available < required {
        tracing::error!(
            available,
            required,
            events = estimate.events,
            tag_rows = estimate.tag_rows,
            "the event store upgrade to schema 4 needs more free disk space than there is; not started"
        );
        return Err(EventStoreError::DiskSpace {
            needed: required,
            available,
        });
    }
    tracing::info!(
        events = estimate.events,
        tag_rows = estimate.tag_rows,
        "migrating the event store to schema 4: copying every event and tag"
    );
    copy_and_switch(conn, env).map_err(|error| env.disk_error(error, required))
}

fn copy_and_switch(conn: &mut Connection, env: &UpgradeEnv<'_>) -> Result<(), EventStoreError> {
    let fresh_copy = V4_EVENT_TABLES.replace("{s}", "_v4");
    loop {
        if !table_exists(conn, "event_store_upgrade")? {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(UPGRADE_START_SQL)?;
            tx.execute_batch(&fresh_copy)?;
            tx.commit()?;
            env.step_done(conn)?;
        } else if upgrade_dirty(conn)? {
            tracing::warn!(
                "the event store changed while its upgrade was interrupted; copying again from the start"
            );
            without_secure_delete(conn, |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute_batch(
                    "DROP TABLE tags_v4; DROP TABLE events_v4; UPDATE event_store_upgrade SET value=0 WHERE key='dirty';",
                )?;
                tx.execute_batch(&fresh_copy)?;
                tx.commit()?;
                Ok(())
            })?;
            env.step_done(conn)?;
        }
        let chunk = upgrade_chunk_events();
        let max_row = |conn: &Connection, sql: &str| -> Result<i64, rusqlite::Error> {
            conn.query_row(sql, [], |r| r.get(0))
        };
        let mut copied = max_row(conn, "SELECT COALESCE(max(seq),0) FROM events_v4")?;
        let last = max_row(conn, "SELECT COALESCE(max(rowid),0) FROM events")?;
        if copied > 0 {
            tracing::info!(
                copied_through = copied,
                last,
                "migrating the event store to schema 4: continuing an interrupted copy"
            );
        }
        while copied < last {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let rows = tx.execute(UPGRADE_COPY_EVENTS_SQL, params![copied, chunk])?;
            if rows == 0 {
                break;
            }
            let through = max_row(&tx, "SELECT max(seq) FROM events_v4")?;
            tx.execute(UPGRADE_COPY_TAGS_SQL, params![copied, through])?;
            tx.commit()?;
            copied = through;
            env.step_done(conn)?;
            tracing::info!(
                copied_through = copied,
                last,
                "migrating the event store to schema 4: events copied"
            );
        }
        let switched = without_secure_delete(conn, |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if upgrade_dirty(&tx)? {
                return Ok(false);
            }
            tx.execute_batch(&V4_BARRIER_TABLES.replace("{s}", "_v4"))?;
            tx.execute_batch(UPGRADE_SWITCH_SQL)?;
            create_charge_triggers(&tx)?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            tx.commit()?;
            Ok(true)
        })?;
        if switched {
            env.step_done(conn)?;
            tracing::info!("migrating the event store to schema 4: switched; building its indexes");
            return Ok(());
        }
    }
}

/// The end of every open: build any version 4 index that is missing, each
/// in its own transaction (the last steps of an upgrade, or the repair of a
/// dropped index), then, if an upgrade has switched but not finished, zero
/// the pages it freed. Each step is repeated by the next open if it is
/// interrupted.
fn finish_v4(conn: &mut Connection, env: &UpgradeEnv<'_>) -> Result<(), EventStoreError> {
    let mut missing = Vec::new();
    for (name, sql) in V4_INDEXES {
        if !index_exists(conn, name)? {
            missing.push((name, sql));
        }
    }
    if !missing.is_empty() {
        // The sort holds the index's keys: an event index about 96 bytes an
        // event, the tag index the tag text and about 64 bytes a row (the
        // event's id among them).
        let events: i64 = conn.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        let (rows, text): (i64, i64) = conn.query_row(
            "SELECT count(*), COALESCE(SUM(length(CAST(name AS BLOB))+length(CAST(value AS BLOB))),0) FROM tags",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let event_keys = u64::try_from(events).unwrap_or(0).saturating_mul(96);
        let tag_keys = u64::try_from(text)
            .unwrap_or(0)
            .saturating_add(u64::try_from(rows).unwrap_or(0).saturating_mul(64));
        let needed = env
            .min_free_bytes
            .saturating_add(TRANSACTION_GUARD_BYTES)
            .saturating_add(
                event_keys
                    .max(tag_keys)
                    .saturating_mul(MIGRATION_SAFETY_PERCENT)
                    / 100,
            );
        for (name, sql) in missing {
            let keys = if name == "tags_by_time" {
                tag_keys
            } else {
                event_keys
            };
            // As for the version 3 index: the sort stays in memory only while
            // it is small (see `migration_temp_store_pragma`).
            conn.execute_batch(migration_temp_store_pragma(keys))?;
            tracing::info!(index = name, "building an event store index");
            let built = (|| -> Result<(), EventStoreError> {
                let tx = conn.transaction()?;
                tx.execute(sql, [])?;
                tx.commit()?;
                Ok(())
            })();
            built.map_err(|error| env.disk_error(error, needed))?;
            env.step_done(conn)?;
        }
    }
    if table_exists(conn, "event_store_upgrade")? {
        scrub_free_pages(conn, env)?;
    }
    Ok(())
}

/// Overwrite every free page of the file with zeros, in bounded
/// transactions: the pages of the version 3 tables, which the switch freed
/// without zeroing them. Rows of zero BLOBs take the free pages (SQLite
/// allocates from the free list before it grows the file) until none is
/// left; their table is then dropped, again without zeroing, which frees
/// pages that hold only zeros. The file does not shrink: the free pages are
/// reused as the store grows.
fn scrub_free_pages(conn: &mut Connection, env: &UpgradeEnv<'_>) -> Result<(), EventStoreError> {
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS event_store_scrub (z BLOB NOT NULL)")?;
    let needed = env
        .min_free_bytes
        .saturating_add(TRANSACTION_GUARD_BYTES)
        .saturating_add(u64::try_from(scrub_chunk_bytes()).unwrap_or(0));
    let mut before = i64::MAX;
    loop {
        let free: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        if free == 0 {
            break;
        }
        if free >= before {
            // Not expected: SQLite takes free pages first. Keep the marker so
            // the next open tries again, rather than loop here.
            tracing::warn!(
                free_pages = free,
                "the event store upgrade could not zero its free pages; trying again on the next open"
            );
            return Ok(());
        }
        before = free;
        let pages = free.min(scrub_chunk_bytes() / page_size.max(1)).max(1);
        let rows = (pages.saturating_mul(page_size) / SCRUB_ROW_BYTES).max(1);
        tracing::debug!(
            free_pages = free,
            "zeroing the pages the event store upgrade freed"
        );
        conn.execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?1) INSERT INTO event_store_scrub SELECT zeroblob(?2) FROM n",
            params![rows, SCRUB_ROW_BYTES],
        )
        .map_err(|error| env.disk_error(error.into(), needed))?;
        env.step_done(conn)?;
    }
    without_secure_delete(conn, |conn| {
        let tx = conn.transaction()?;
        tx.execute_batch("DROP TABLE event_store_scrub; DROP TABLE event_store_upgrade;")?;
        tx.commit()?;
        Ok(())
    })?;
    env.step_done(conn)?;
    tracing::info!("migrating the event store to schema 4: complete");
    Ok(())
}

/// Events per page of [`export_stored`].
const EXPORT_PAGE: i64 = 1024;

/// Every unexpired event in one partition of the event database at `path`,
/// oldest first and then by id, each handed to `each` as its stored JSON:
/// the basis of a host's export command. It opens the file read-only, so it never creates,
/// migrates or changes a database (SQLite may still create its shared-memory
/// file beside a write-ahead-log database). It refuses a missing file, a
/// symlink and any schema but [`SCHEMA_VERSION`]. It reads in pages, each
/// its own short read transaction, so a running daemon can checkpoint
/// between them however slowly `each` writes; an event written or deleted
/// during the export may or may not be in it. Answers how many events it
/// handed over.
pub fn export_stored(
    path: &Path,
    visibility: Visibility,
    now: u64,
    mut each: impl FnMut(&str) -> std::io::Result<()>,
) -> Result<u64, EventStoreError> {
    // As when the store opens: the directory may be reached through a
    // symlink (macOS's /var), while NOFOLLOW still refuses a symlinked file.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let canonical = parent
        .canonicalize()?
        .join(path.file_name().ok_or(EventStoreError::Schema)?);
    let mut conn = Connection::open_with_flags(
        &canonical,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let now = now.min(i64::MAX as u64) as i64;
    // The paging key: time, then the id's bytes (whose order is its hex's).
    let mut after: Option<(i64, Vec<u8>)> = None;
    let mut exported = 0;
    loop {
        // The schema check and the page share one snapshot, so a daemon
        // that migrates on start cannot change the schema under a page.
        let page: Vec<(i64, Vec<u8>, String)> = {
            let tx = conn.transaction()?;
            let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if version > SCHEMA_VERSION {
                return Err(EventStoreError::NewerSchema {
                    found: version,
                    supported: SCHEMA_VERSION,
                });
            }
            if version != SCHEMA_VERSION {
                return Err(EventStoreError::Schema);
            }
            // An empty BLOB sorts before every 32-byte id.
            let (at, id) = after.clone().unwrap_or((i64::MIN, Vec::new()));
            let mut statement = tx.prepare_cached(
                "SELECT created_at,id,json FROM events WHERE visibility=?1 AND (expires_at IS NULL OR expires_at>?2) AND (created_at>?3 OR (created_at=?3 AND id>?4)) ORDER BY created_at ASC,id ASC LIMIT ?5",
            )?;
            let rows = statement
                .query_map(params![visibility.key(), now, at, id, EXPORT_PAGE], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
            rows.collect::<Result<_, _>>()?
        };
        let Some((at, id, _)) = page.last() else {
            return Ok(exported);
        };
        after = Some((*at, id.clone()));
        let full = page.len() as i64 == EXPORT_PAGE;
        for (_, _, json) in &page {
            each(json)?;
            exported += 1;
        }
        if !full {
            return Ok(exported);
        }
    }
}

/// Rough cost of one `tags` row beyond its text: the b-tree cell, record
/// header, rowid and the integer columns. Indexes carry a smaller header.
const TAG_TABLE_ROW_OVERHEAD: u64 = 32;
const TAG_INDEX_ROW_OVERHEAD: u64 = 16;
/// Pages are not full after a rewrite or a build: allow half as much again.
const MIGRATION_SAFETY_PERCENT: u64 = 150;

/// The free disk space an upgrade of the store at `path` would need on top
/// of the open-time headroom, read without writing to it, for the open-time
/// refusal. `None` for a current or new store, or one that cannot be read.
/// From schema 1 or 2 both upgrades run, so both estimates are added: an
/// upper figure, as the estimates themselves are.
fn pending_upgrade_bytes(path: &Path) -> Option<u64> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .ok()?;
    conn.busy_timeout(BUSY_TIMEOUT).ok()?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .ok()?;
    let v4 = || upgrade_estimate(&conn).ok().map(|e| e.disk_bytes);
    match version {
        1 | 2 => Some(
            migration_estimate(&conn)
                .ok()?
                .disk_bytes
                .saturating_add(v4()?),
        ),
        3 => v4(),
        _ => None,
    }
}

/// What the v3 migration needs, from the tag data alone.
struct MigrationEstimate {
    tag_rows: u64,
    /// Bytes of text in the tag rows (the new index's key bytes, which is
    /// also the heap its sort needs with an in-memory temp store).
    tag_bytes: u64,
    /// Upper estimate of the bytes the migration writes through the WAL.
    disk_bytes: u64,
}

/// Count the tag rows and their text, one read. Disk written is the `tags`
/// table again (the backfill), the new index, and the zeroed pages of the
/// dropped index (`secure_delete`): about three copies of the tag text plus
/// per-row overhead, times [`MIGRATION_SAFETY_PERCENT`]. The events' JSON,
/// which dominates the file, is not touched and is not counted. Measured
/// against the real WAL, the estimate is 1.4 to 1.5 times what is written
/// for stores of thousands of rows; page granularity on a tiny store can
/// exceed it by a few KB, which the 16 MiB guard added by the caller covers.
fn migration_estimate(conn: &Connection) -> Result<MigrationEstimate, EventStoreError> {
    let (rows, bytes): (i64, i64) = conn.query_row(
        "SELECT count(*), COALESCE(SUM(length(CAST(id AS BLOB))+length(CAST(name AS BLOB))+length(CAST(value AS BLOB))),0) FROM tags",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let tag_rows = u64::try_from(rows).unwrap_or(0);
    let tag_bytes = u64::try_from(bytes).unwrap_or(0);
    Ok(MigrationEstimate {
        tag_rows,
        tag_bytes,
        disk_bytes: migration_disk_bytes(tag_rows, tag_bytes),
    })
}

/// Most tag text, in bytes, for which the v3 index sort is kept in memory
/// (about 1.3 times this in heap). Above it the sort uses file-backed temp.
const MIGRATION_MEMORY_SORT_CEILING: u64 = 64 * 1024 * 1024;

/// The `temp_store` pragma for a migration over `tag_bytes` of tag text.
fn migration_temp_store_pragma(tag_bytes: u64) -> &'static str {
    if tag_bytes <= MIGRATION_MEMORY_SORT_CEILING {
        "PRAGMA temp_store = MEMORY"
    } else {
        "PRAGMA temp_store = DEFAULT"
    }
}

fn migration_disk_bytes(tag_rows: u64, tag_bytes: u64) -> u64 {
    let table = tag_bytes.saturating_add(tag_rows.saturating_mul(TAG_TABLE_ROW_OVERHEAD));
    let index = tag_bytes.saturating_add(tag_rows.saturating_mul(TAG_INDEX_ROW_OVERHEAD));
    // Table rewrite + new index + zeroed old index.
    table
        .saturating_add(index)
        .saturating_add(index)
        .saturating_mul(MIGRATION_SAFETY_PERCENT)
        / 100
}

/// The database file's size in bytes, from its page counts.
#[cfg(test)]
fn database_bytes(conn: &Connection) -> Result<u64, EventStoreError> {
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(u64::try_from(pages)
        .unwrap_or(0)
        .saturating_mul(u64::try_from(page_size).unwrap_or(0)))
}

/// A read-only WAL connection: it never writes the database, takes a snapshot
/// per statement and does not block, or wait for, the writer.
fn open_reader(
    path: &Path,
    cache_kib: u32,
    mmap_bytes: u64,
) -> Result<Connection, EventStoreError> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "query_only", true)?;
    conn.pragma_update(None, "cache_size", -i64::from(cache_kib))?;
    set_mmap(&conn, mmap_bytes);
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
    Ok(conn)
}

/// `PRAGMA mmap_size`. Best effort: a build or platform that refuses the map
/// simply reads through the heap cache.
fn set_mmap(conn: &Connection, bytes: u64) {
    let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
    if let Err(error) = conn.pragma_update(None, "mmap_size", bytes) {
        tracing::warn!(%error, "event-store mmap_size was not applied");
    }
}

/// The checkpoint thread and its own read-write connection. The thread has a
/// small stack; the connection a small cache and no map.
fn spawn_checkpointer(
    path: &Path,
    shared: &Arc<WalShared>,
    cache_kib: u32,
) -> Result<JoinHandle<()>, EventStoreError> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(CHECKPOINT_BUSY)?;
    conn.pragma_update(None, "cache_size", -i64::from(cache_kib))?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "journal_size_limit", WAL_SIZE_LIMIT_BYTES)?;
    let shared = Arc::clone(shared);
    Ok(std::thread::Builder::new()
        .name("wok-wal-checkpoint".into())
        .stack_size(256 * 1024)
        .spawn(move || checkpoint_loop(shared, conn))?)
}

/// The warm-up thread: a read-only connection with the writer's map (warming
/// the operating system's cache through it is its purpose) and a 1 MiB heap cache, closed when it finishes or is told to stop.
fn spawn_warmer(
    path: &Path,
    options: &StoreOptions,
    shared: &Arc<WalShared>,
    stop: &Arc<AtomicBool>,
) -> Result<JoinHandle<()>, EventStoreError> {
    let mut conn = open_reader(
        path,
        u32::try_from(WARM_CACHE_KIB).unwrap_or(1024),
        options.mmap_bytes,
    )?;
    let shared = Arc::clone(shared);
    let stop = Arc::clone(stop);
    let max_bytes = options.warm_max_bytes;
    Ok(std::thread::Builder::new()
        .name("wok-warm".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            match warm_indexes(
                &mut conn,
                &stop,
                max_bytes,
                Duration::from_millis(1),
                WARM_SCAN_DEADLINE,
            ) {
                Ok(WarmOutcome::Finished(rows)) => {
                    shared.warm_rows.store(rows, AtomicOrdering::Relaxed);
                    shared.warm_finished.store(true, AtomicOrdering::Release);
                }
                Ok(WarmOutcome::Cancelled(rows)) => {
                    shared.warm_rows.store(rows, AtomicOrdering::Relaxed);
                    shared.warm_cancelled.store(true, AtomicOrdering::Release);
                }
                Err(error) => {
                    tracing::warn!(%error, "event-store warm-up stopped");
                }
            }
        })?)
}

fn exec(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<usize, rusqlite::Error> {
    conn.prepare_cached(sql)?.execute(params)
}

fn probe<T>(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    map: impl FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Option<T>, rusqlite::Error> {
    conn.prepare_cached(sql)?.query_row(params, map).optional()
}

/// NIP-01 replaceable kinds. `Kind::is_replaceable` in the `nostr` crate also
/// counts kind 41, NIP-28 channel metadata, which names its channel with an `e`
/// tag and is not replaceable: one channel's update must not remove another's.
fn is_replaceable(kind: u16) -> bool {
    matches!(kind, 0 | 3) || (10_000..20_000).contains(&kind)
}

fn coordinate(event: &Event) -> Option<String> {
    if is_replaceable(event.kind.as_u16()) {
        Some(String::new())
    } else if event.kind.is_addressable() {
        Some(
            event
                .tags
                .iter()
                .find(|t| t.as_slice().first().is_some_and(|v| v == "d"))
                .and_then(|t| t.as_slice().get(1))
                .cloned()
                .unwrap_or_default(),
        )
    } else {
        None
    }
}

fn expiry(event: &Event) -> Result<Option<u64>, EventStoreError> {
    let mut values = event
        .tags
        .iter()
        .filter(|t| t.as_slice().first().is_some_and(|v| v == "expiration"));
    let Some(tag) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || tag.as_slice().len() != 2 {
        return Err(EventStoreError::Invalid);
    }
    let raw = &tag.as_slice()[1];
    if raw.is_empty() || !raw.bytes().all(|c| c.is_ascii_digit()) {
        return Err(EventStoreError::Invalid);
    }
    let value = raw.parse::<u64>().map_err(|_| EventStoreError::Invalid)?;
    if value > i64::MAX as u64 {
        return Err(EventStoreError::Invalid);
    }
    Ok(Some(value))
}

// Charge event JSON and index/tombstone material, including a conservative
// per-row allowance. This is a logical admission budget, not filesystem usage;
// SQLite pages/WAL need separate disk headroom. Non-deletion payloads also
// reserve space for a later signed deletion; tombstones cannot grow for free.
fn usage(conn: &Connection) -> Result<u64, rusqlite::Error> {
    let used: i64 = conn
        .prepare_cached("SELECT bytes FROM usage WHERE id=1")?
        .query_row([], |r| r.get(0))?;
    Ok(used as u64)
}

fn logical_bytes(conn: &Connection) -> Result<u64, EventStoreError> {
    Ok(usage(conn)?)
}

/// A connection's statement deadline. SQLite calls the connection's one
/// progress handler every [`BUDGET_STEPS`] VM steps, and the handler
/// interrupts the running statement once an armed deadline has passed.
/// rusqlite replaces a handler only through `&mut Connection`, which an open
/// transaction or savepoint does not give, so the handler is attached when
/// the connection opens and the deadline is armed and disarmed through this.
///
/// The connection's own thread arms the deadline and runs the statements the
/// handler checks, so relaxed ordering is enough.
#[derive(Clone)]
struct Budget(Arc<BudgetClock>);

struct BudgetClock {
    epoch: Instant,
    /// Nanoseconds after `epoch`, or `u64::MAX` when disarmed.
    deadline: AtomicU64,
}

impl BudgetClock {
    fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX - 1)
    }

    fn expired(&self) -> bool {
        let deadline = self.deadline.load(AtomicOrdering::Relaxed);
        deadline != u64::MAX && self.now() >= deadline
    }
}

impl Budget {
    fn new() -> Self {
        Self(Arc::new(BudgetClock {
            epoch: Instant::now(),
            deadline: AtomicU64::new(u64::MAX),
        }))
    }

    /// Install the deadline check as `conn`'s progress handler, called every
    /// `steps` VM steps.
    fn attach(&self, conn: &mut Connection, steps: std::ffi::c_int) -> rusqlite::Result<()> {
        let clock = Arc::clone(&self.0);
        conn.progress_handler(steps, Some(move || clock.expired()))
    }

    /// Interrupt any statement still running once `after` has passed.
    fn arm(&self, after: Duration) {
        let after = u64::try_from(after.as_nanos()).unwrap_or(u64::MAX);
        let at = self.0.now().saturating_add(after).min(u64::MAX - 1);
        self.0.deadline.store(at, AtomicOrdering::Relaxed);
    }

    fn disarm(&self) {
        self.0.deadline.store(u64::MAX, AtomicOrdering::Relaxed);
    }

    /// Run `f` armed for `after`, and disarm when it returns.
    fn within<T>(&self, after: Duration, f: impl FnOnce() -> T) -> T {
        self.arm(after);
        let out = f();
        self.disarm();
        out
    }

    /// Interrupt the running statement at the handler's next call.
    #[cfg(test)]
    fn interrupt(&self) {
        self.0.deadline.store(0, AtomicOrdering::Relaxed);
    }
}

/// A read-only connection of the pool, with its statement deadline.
struct Reader {
    conn: Connection,
    budget: Budget,
}

impl Reader {
    fn new(mut conn: Connection) -> rusqlite::Result<Self> {
        let budget = Budget::new();
        budget.attach(&mut conn, BUDGET_STEPS)?;
        Ok(Self { conn, budget })
    }
}

/// One event ready for [`EventStore::put_prepared_batch`]: every check that
/// needs neither the database nor the disk has already passed (size, shape,
/// signature, future timestamp, expiry, AUTH), so a caller can run them in
/// parallel and the single writer keeps only the transaction.
pub struct PreparedPut {
    visibility: Visibility,
    event: Event,
    now: u64,
    replicated: bool,
    /// The event's JSON as it is stored, shared with the live fan-out.
    json: Arc<str>,
    expires: Option<u64>,
    ephemeral: bool,
    recheck: Option<Recheck>,
}

/// Asked, for the event it is given, whether its author is still authorised.
/// The relay attaches one to every write it authorised before queueing it, so
/// the store can ask again at the moment it applies the event. `false` (or any
/// failure to find out) refuses the event: authority fails closed.
pub type Recheck = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

impl PreparedPut {
    /// Check `event` as [`EventStore::put`] (or, with `replicated`,
    /// [`EventStore::put_replicated`]) would, verifying its signature.
    pub fn new(
        visibility: Visibility,
        event: Event,
        now: u64,
        replicated: bool,
    ) -> Result<Self, EventStoreError> {
        Self::checked(visibility, event, now, replicated, false)
    }

    /// As [`Self::new`] for an event whose signature the caller has already
    /// verified. It skips the signature check, so only the relay engine's own
    /// prepared frames, verified moments earlier, may use it.
    pub(crate) fn verified(
        visibility: Visibility,
        event: Event,
        now: u64,
        replicated: bool,
    ) -> Result<Self, EventStoreError> {
        Self::checked(visibility, event, now, replicated, true)
    }

    fn checked(
        visibility: Visibility,
        event: Event,
        now: u64,
        replicated: bool,
        signature_checked: bool,
    ) -> Result<Self, EventStoreError> {
        let json: Arc<str> = serde_json::to_string(&event)
            .map_err(|_| EventStoreError::Invalid)?
            .into();
        if json.len() > MAX_EVENT_BYTES || event.tags.len() > MAX_EVENT_TAGS {
            return Err(EventStoreError::Oversize);
        }
        if (!signature_checked && event.verify().is_err())
            || event.created_at.as_secs() > now.saturating_add(MAX_FUTURE_SECONDS)
            || event.created_at.as_secs() > i64::MAX as u64
        {
            return Err(EventStoreError::Invalid);
        }
        let expires = expiry(&event)?;
        if expires.is_some_and(|t| t <= now) {
            return Err(EventStoreError::Expired);
        }
        // AUTH must never be persisted or fanned out, even when sent as EVENT.
        if event.kind.as_u16() == 22242 {
            return Err(EventStoreError::Invalid);
        }
        let ephemeral = event.kind.is_ephemeral();
        Ok(Self {
            visibility,
            event,
            now,
            replicated,
            json,
            expires,
            ephemeral,
            recheck: None,
        })
    }

    /// Have the store ask `recheck` as it applies this event, inside its
    /// transaction and immediately before the event's own statements.
    pub fn with_recheck(mut self, recheck: Recheck) -> Self {
        self.recheck = Some(recheck);
        self
    }

    /// Whether the author's authority still holds. Always true for a write
    /// that carries no recheck (an internal or test write).
    pub fn still_authorised(&self) -> bool {
        self.recheck
            .as_ref()
            .is_none_or(|recheck| recheck(&self.event))
    }

    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn is_replicated(&self) -> bool {
        self.replicated
    }

    pub fn into_event(self) -> Event {
        self.event
    }

    /// The event and its JSON exactly as stored, for the live fan-out to
    /// send without serialising it again.
    pub fn into_parts(self) -> (Event, Arc<str>) {
        (self.event, self.json)
    }

    /// What a queue should charge for holding this event: the event and its
    /// stored JSON.
    pub fn weight(&self) -> usize {
        self.json.len().saturating_mul(2).max(1)
    }

    /// Whether this is a NIP-09 deletion, which can remove a lot and is not
    /// charged for headroom.
    pub fn is_deletion(&self) -> bool {
        self.event.kind.as_u16() == 5
    }

    /// Ephemeral events are never stored: the store answers them without a
    /// write, and a writer queue has nothing to commit for them.
    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }
}

/// One batch may keep starting events for at most this long. Events behind
/// that point are not refused: they come back as [`EventStoreError::Deferred`]
/// and are offered again in the next batch, which always starts its first
/// event. Each statement is also cut off after two seconds. A pass run again
/// after an interrupted event counts from the same start, not afresh.
pub const BATCH_BUDGET: Duration = Duration::from_secs(5);

/// The same failure again, for each event of a batch that failed as a whole.
fn again(error: &EventStoreError) -> EventStoreError {
    match error {
        EventStoreError::Sqlite(error) => EventStoreError::Sqlite(match error {
            rusqlite::Error::SqliteFailure(code, message) => {
                rusqlite::Error::SqliteFailure(*code, message.clone())
            }
            other => rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(other.to_string()),
            ),
        }),
        EventStoreError::Io(error) => {
            EventStoreError::Io(std::io::Error::new(error.kind(), error.to_string()))
        }
        EventStoreError::Poisoned => EventStoreError::Poisoned,
        EventStoreError::Full => EventStoreError::Full,
        EventStoreError::DiskSpace { needed, available } => EventStoreError::DiskSpace {
            needed: *needed,
            available: *available,
        },
        EventStoreError::Schema => EventStoreError::Schema,
        EventStoreError::NewerSchema { found, supported } => EventStoreError::NewerSchema {
            found: *found,
            supported: *supported,
        },
        EventStoreError::Invalid => EventStoreError::Invalid,
        EventStoreError::Oversize => EventStoreError::Oversize,
        EventStoreError::Expired => EventStoreError::Expired,
        EventStoreError::Retired => EventStoreError::Retired,
        EventStoreError::Query => EventStoreError::Query,
        EventStoreError::Corrupt => EventStoreError::Corrupt,
        EventStoreError::Unauthorised => EventStoreError::Unauthorised,
        EventStoreError::Cancelled => EventStoreError::Cancelled,
        EventStoreError::Deferred => EventStoreError::Deferred,
    }
}

pub type PutResult = Result<PutOutcome, EventStoreError>;

/// How one pass over a batch ended.
enum BatchEnd {
    Committed {
        reclaimed: bool,
    },
    /// The disk has fallen below the reserve of these events. Nothing was
    /// committed; the rest may be tried again without them.
    Short {
        lost: Vec<usize>,
    },
    /// One event was interrupted (or otherwise failed on its own) and SQLite
    /// took the whole transaction down with it. Nothing was committed; the
    /// rest may be tried again without that event, which is refused alone.
    Lost {
        index: usize,
        error: EventStoreError,
    },
}

/// Errors that belong to one event's own statements, not to the database: the
/// event ran past its time budget, or its data broke a constraint. A batch
/// refuses that event alone. Anything else (disk, I/O, corruption) cannot be
/// pinned on one event and fails the batch.
fn is_event_fault(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::OperationInterrupted
                    | rusqlite::ErrorCode::ConstraintViolation
                    | rusqlite::ErrorCode::TooBig
            )
    )
}

/// A tag is indexed when its name is one ASCII letter and it has a value.
fn indexable_tag(tag: &[String]) -> bool {
    tag.len() >= 2 && tag[0].len() == 1 && tag[0].as_bytes()[0].is_ascii_alphabetic()
}

/// Most tag rows in one INSERT. An event has at most [`MAX_EVENT_TAGS`].
const TAG_ROWS_PER_STATEMENT: usize = 128;

/// `INSERT OR IGNORE` of `rows` tag rows for one event: `?1` its `seq`, `?2`
/// visibility, `?3` created_at and `?4` id are shared, `?5..` are each row's
/// name and value.
/// One statement per power of two, so the statement cache holds eight of them.
fn tag_insert_sql(rows: usize) -> &'static str {
    static SQL: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let all = SQL.get_or_init(|| {
        let mut sizes = Vec::new();
        let mut n = 1;
        while n <= TAG_ROWS_PER_STATEMENT {
            let values: Vec<String> = (0..n)
                .map(|i| format!("(?1,?{},?{},?2,?3,?4)", 5 + 2 * i, 6 + 2 * i))
                .collect();
            sizes.push(format!(
                "INSERT OR IGNORE INTO tags(seq,name,value,visibility,created_at,id) VALUES {}",
                values.join(",")
            ));
            n *= 2;
        }
        sizes
    });
    &all[rows.next_power_of_two().trailing_zeros() as usize]
}

/// The event's indexed tags in as few statements as possible: one
/// multi-row INSERT per up to 128 tags. A group is padded to a power of two by
/// repeating its last row, which `OR IGNORE` drops (as it drops a tag the
/// event repeats), without firing the usage trigger, so the rows and the byte
/// charge are exactly those of one INSERT per tag.
///
/// The foreign-key parent lookup per row stays. `defer_foreign_keys` only
/// moves the check to commit and still does the lookup per row to count the
/// violation, and switching foreign keys off on the writer would lose the
/// `ON DELETE CASCADE` that every replacement, deletion and expiry relies on.
fn insert_tags(
    tx: &Connection,
    seq: i64,
    scope: i64,
    at: i64,
    event: &Event,
) -> Result<(), rusqlite::Error> {
    let tags: Vec<&[String]> = event
        .tags
        .iter()
        .map(|t| t.as_slice())
        .filter(|t| indexable_tag(t))
        .collect();
    let id = event.id.as_bytes().as_slice();
    for group in tags.chunks(TAG_ROWS_PER_STATEMENT) {
        let mut binds: Vec<&dyn rusqlite::ToSql> =
            Vec::with_capacity(4 + 2 * group.len().next_power_of_two());
        binds.push(&seq);
        binds.push(&scope);
        binds.push(&at);
        binds.push(&id);
        for tag in group {
            binds.push(&tag[0]);
            binds.push(&tag[1]);
        }
        let last = group[group.len() - 1];
        for _ in group.len()..group.len().next_power_of_two() {
            binds.push(&last[0]);
            binds.push(&last[1]);
        }
        exec(tx, tag_insert_sql(group.len()), binds.as_slice())?;
    }
    Ok(())
}

/// The insert as it was before [`insert_tags`], kept to test it against.
#[cfg(test)]
fn insert_tags_one_by_one(
    tx: &Connection,
    seq: i64,
    scope: i64,
    at: i64,
    event: &Event,
) -> Result<(), rusqlite::Error> {
    for tag in event.tags.iter().map(|t| t.as_slice()) {
        if indexable_tag(tag) {
            exec(
                tx,
                "INSERT OR IGNORE INTO tags(seq,name,value,visibility,created_at,id) VALUES(?,?,?,?,?,?)",
                params![
                    seq,
                    tag[0],
                    tag[1],
                    scope,
                    at,
                    event.id.as_bytes().as_slice()
                ],
            )?;
        }
    }
    Ok(())
}

impl SqliteEventStore {
    fn reserves(&self, put: &PreparedPut) -> (u64, u64) {
        if put.replicated {
            (
                self.max_bytes / REPLICA_RESERVE_DIVISOR,
                REPLICA_DISK_RESERVE_BYTES,
            )
        } else {
            (0, 0)
        }
    }

    /// Replace the time one batch may keep starting events (tests).
    #[cfg(test)]
    pub(crate) fn with_batch_budget(mut self, budget: Duration) -> Self {
        self.batch_budget = budget;
        self
    }

    /// Commits so far, one per batch that stored or removed anything.
    pub fn commits(&self) -> u64 {
        self.commits.load(AtomicOrdering::Relaxed)
    }

    /// What the store's checkpointing has done since it was opened. Reading
    /// it changes nothing.
    pub fn checkpoint_stats(&self) -> CheckpointStats {
        let shared = &self.maintenance.shared;
        CheckpointStats {
            passive: shared.passive_runs.load(AtomicOrdering::Relaxed),
            truncating: shared.truncate_runs.load(AtomicOrdering::Relaxed),
            blocking: shared.blocking_runs.load(AtomicOrdering::Relaxed),
            blocking_time: Duration::from_nanos(shared.blocking_ns.load(AtomicOrdering::Relaxed)),
            longest_blocking: Duration::from_nanos(
                shared.blocking_longest_ns.load(AtomicOrdering::Relaxed),
            ),
            peak_wal_pages: shared.peak_pages.load(AtomicOrdering::Relaxed),
        }
    }

    /// A room-profile owner serialises all of its stores and assigns each
    /// one's remaining share of a node-wide logical byte ceiling before
    /// intake. Lowering the ceiling never evicts acknowledged events.
    pub fn set_byte_ceiling(&mut self, bytes: u64) {
        self.max_bytes = bytes;
    }

    /// Purge a dedicated room database, including replacement/deletion
    /// barriers. The room-profile owner must first stop intake and readers.
    /// Ordinary household stores never call this operation.
    pub fn purge_room_database(&self) -> Result<u64, EventStoreError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let count = tx.query_row("SELECT count(*) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })?;
        for table in ["events", "heads", "deleted_ids", "deleted_coordinates"] {
            tx.execute(&format!("DELETE FROM {table}"), [])?;
        }
        tx.commit()?;
        let (busy, _, _) = run_checkpoint(&conn, "TRUNCATE")?;
        if busy != 0 {
            return Err(EventStoreError::Sqlite(
                rusqlite::Error::ExecuteReturnedResults,
            ));
        }
        Ok(count as u64)
    }

    /// An operator's removal: take the events with these ids out of
    /// `visibility`, whoever signed them, and bar each from being stored
    /// again. It is for acting on a report, with nothing else serving this
    /// store: another process's readers, live delivery and byte accounting
    /// would not see it. Deletion events are removed like any other, and a
    /// replaceable head that points at a removed event goes too, so its
    /// coordinate text is not left behind. An id that is not stored is not
    /// in [`Removal::removed`] and is not barred, because the bar is kept by
    /// author. One transaction; the write-ahead log is truncated afterwards.
    pub fn remove(
        &self,
        visibility: Visibility,
        ids: &[nostr::event::EventId],
    ) -> Result<Removal, EventStoreError> {
        let scope = visibility.key();
        let mut removed = Vec::new();
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for id in ids {
            let author: Option<Vec<u8>> = probe(
                &tx,
                "SELECT author FROM events WHERE visibility=? AND id=?",
                params![scope, id.as_bytes()],
                |row| row.get(0),
            )?;
            if let Some(author) = author {
                remove_one(&tx, scope, &author, id.as_bytes())?;
                removed.push(*id);
            }
        }
        tx.commit()?;
        let erased = !removed.is_empty() && truncate_after_removal(&conn)?;
        Ok(Removal { removed, erased })
    }

    /// An operator's removal of every event `author` signed in
    /// `visibility`, as [`Self::remove`], in transactions of at most
    /// [`MAX_EXPIRE_EVENTS`] events so a large backlog makes durable
    /// progress. Events stored later under that key are not barred: the bar
    /// is per id.
    pub fn remove_author(
        &self,
        visibility: Visibility,
        author: &nostr::key::PublicKey,
    ) -> Result<Removal, EventStoreError> {
        let scope = visibility.key();
        let author = author.as_bytes();
        let mut removed = Vec::new();
        let mut conn = self.lock()?;
        loop {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let batch: Vec<Vec<u8>> = {
                let mut statement =
                    tx.prepare("SELECT id FROM events WHERE visibility=? AND author=? LIMIT ?")?;
                statement
                    .query_map(params![scope, author, MAX_EXPIRE_EVENTS as i64], |row| {
                        row.get(0)
                    })?
                    .collect::<Result<_, _>>()?
            };
            if batch.is_empty() {
                break;
            }
            for id in &batch {
                remove_one(&tx, scope, author, id)?;
                removed.push(
                    nostr::event::EventId::from_slice(id).map_err(|_| EventStoreError::Corrupt)?,
                );
            }
            tx.commit()?;
        }
        let erased = !removed.is_empty() && truncate_after_removal(&conn)?;
        Ok(Removal { removed, erased })
    }

    /// The per-event body of a write, inside a transaction the caller owns:
    /// duplicate, deleted-id and coordinate barriers, replacement, NIP-09
    /// handling, the inserts and the byte budget. `Err` in the inner result
    /// refuses this event alone; an SQL error is the outer `Err` and means the
    /// transaction can no longer be trusted. The caller rolls back a refusal.
    fn apply_one(
        &self,
        tx: &Connection,
        put: &PreparedPut,
    ) -> Result<Result<(PutOutcome, bool), EventStoreError>, rusqlite::Error> {
        let (logical_reserve, _) = self.reserves(put);
        let event = &put.event;
        let scope = put.visibility.key();
        let id = event.id.as_bytes();
        let author = event.pubkey.as_bytes();
        let kind = event.kind.as_u16();
        let at = event.created_at.as_secs() as i64;
        let coord = coordinate(event);
        #[cfg(test)]
        self.slow_hook(&event.id.to_hex(), Slow::AtFirstRead);
        let used_before = usage(tx)?;
        if probe(
            tx,
            "SELECT 1 FROM events WHERE visibility=? AND id=?",
            params![scope, id],
            |_| Ok(()),
        )?
        .is_some()
        {
            return Ok(Ok((PutOutcome::Duplicate, false)));
        }
        if kind != 5
            && probe(
                tx,
                "SELECT 1 FROM deleted_ids WHERE visibility=? AND author=? AND id=?",
                params![scope, author, id],
                |_| Ok(()),
            )?
            .is_some()
        {
            return Ok(Err(EventStoreError::Retired));
        }
        if let Some(d) = &coord {
            let cutoff: Option<i64> = probe(
                tx,
                "SELECT through FROM deleted_coordinates WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                params![scope, author, kind, d],
                |r| r.get(0),
            )?;
            if cutoff.is_some_and(|t| at <= t) {
                return Ok(Err(EventStoreError::Retired));
            }
            // The head's id as bytes, compared as bytes: the order of its hex.
            let head: Option<(i64, Vec<u8>)> = probe(
                tx,
                "SELECT created_at,id FROM heads WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                params![scope, author, kind, d],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if head.is_some_and(|(t, old)| at < t || (at == t && id.as_slice() >= old.as_slice())) {
                return Ok(Err(EventStoreError::Retired));
            }
            exec(
                tx,
                "DELETE FROM events WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                params![scope, author, kind, d],
            )?;
            exec(
                tx,
                "INSERT INTO heads VALUES(?,?,?,?,?,?) ON CONFLICT(visibility,author,kind,coordinate) DO UPDATE SET created_at=excluded.created_at,id=excluded.id",
                params![scope, author, kind, d, at, id],
            )?;
        }
        if kind == 5 {
            // A deletion's `a` tags name their author in hex.
            let author_hex = event.pubkey.to_hex();
            for tag in event.tags.iter().map(|t| t.as_slice()) {
                if tag.len() < 2 {
                    continue;
                }
                // Lowercase hex only, as before: the bytes are what is stored.
                let target = if tag[0] == "e" {
                    hex_key(&tag[1])
                } else {
                    None
                };
                if let Some(target) = target {
                    exec(
                        tx,
                        "INSERT OR IGNORE INTO deleted_ids VALUES(?,?,?)",
                        params![scope, author, target],
                    )?;
                    exec(
                        tx,
                        "DELETE FROM events WHERE visibility=? AND author=? AND id=? AND kind<>5",
                        params![scope, author, target],
                    )?;
                } else if tag[0] == "a" {
                    let parts: Vec<_> = tag[1].splitn(3, ':').collect();
                    if parts.len() != 3 || parts[1] != author_hex {
                        continue;
                    }
                    let Ok(k) = parts[0].parse::<u16>() else {
                        continue;
                    };
                    let k_type = Kind::from(k);
                    if !(k_type.is_addressable() || (is_replaceable(k) && parts[2].is_empty())) {
                        continue;
                    }
                    exec(
                        tx,
                        "INSERT INTO deleted_coordinates VALUES(?,?,?,?,?) ON CONFLICT(visibility,author,kind,coordinate) DO UPDATE SET through=max(through,excluded.through)",
                        params![scope, author, k, parts[2], at],
                    )?;
                    // INDEXED BY: left to itself SQLite walks the author's
                    // events of this kind up to `at`, every version of every
                    // coordinate, not the one live event at this coordinate.
                    exec(
                        tx,
                        "DELETE FROM events INDEXED BY events_coordinate WHERE visibility=? AND author=? AND kind=? AND coordinate=? AND created_at<=?",
                        params![scope, author, k, parts[2], at],
                    )?;
                }
            }
        }
        #[cfg(test)]
        self.slow_hook(&event.id.to_hex(), Slow::AtFirstWrite);
        exec(
            tx,
            "INSERT INTO events(visibility,id,author,kind,created_at,coordinate,expires_at,json) VALUES(?,?,?,?,?,?,?,?)",
            params![
                scope,
                id,
                author,
                kind,
                at,
                coord,
                put.expires.map(|v| v as i64),
                &*put.json
            ],
        )?;
        // The tags refer to the row just inserted.
        let seq = tx.last_insert_rowid();
        #[cfg(test)]
        if self.legacy_tags.load(AtomicOrdering::Relaxed) {
            insert_tags_one_by_one(tx, seq, scope, at, event)?;
        } else {
            insert_tags(tx, seq, scope, at, event)?;
        }
        #[cfg(not(test))]
        insert_tags(tx, seq, scope, at, event)?;
        let used_after = usage(tx)?;
        // A v1 migration or reduced configured ceiling may start over budget.
        // Allow deletion only when it reduces the total charge, spending the
        // payload's precharged reserve. Unknown-id requests, padded deletions
        // and tombstone floods get no unlimited exemption.
        if used_after.saturating_add(logical_reserve) > self.max_bytes
            && !(kind == 5 && used_after < used_before)
        {
            return Ok(Err(EventStoreError::Full));
        }
        Ok(Ok((
            PutOutcome::Stored,
            kind == 5 && used_after < used_before,
        )))
    }

    #[cfg(test)]
    fn slow_of(&self, id: &str) -> Option<Slow> {
        self.slow
            .lock()
            .unwrap()
            .iter()
            .find(|(slow, _)| slow == id)
            .map(|(_, how)| *how)
    }

    /// Make the event interrupt at this point if a test said it should.
    #[cfg(test)]
    fn slow_hook(&self, id: &str, at: Slow) {
        if self.slow_of(id) == Some(at) {
            self.budget.interrupt();
        }
    }

    /// One pass over `idxs` of `batch` in a single transaction, with a
    /// savepoint per event so a refusal costs only that event. Fills
    /// `results` for every index it was given: an event not started before
    /// the batch budget ran out is left as [`EventStoreError::Deferred`]. An
    /// event that is interrupted or breaks a constraint is refused alone,
    /// whether SQLite left the transaction open (roll back to the savepoint
    /// and go on) or took it down (the pass ends as [`BatchEnd::Lost`] and is
    /// run again without that event). Any other SQL error, a failed commit or
    /// an unreadable free-space figure rolls the whole pass back and is
    /// returned for the caller to give every event.
    fn run_batch(
        &self,
        conn: &mut Connection,
        batch: &[PreparedPut],
        idxs: &[usize],
        results: &mut [Option<PutResult>],
        began: std::time::Instant,
    ) -> Result<BatchEnd, EventStoreError> {
        // The first event a pass reaches is always started, whatever the
        // clock says, so every pass makes progress.
        let mut started = false;
        for &i in idxs {
            results[i] = None;
        }
        // A test interrupt lands on the next VM step, not up to
        // `BUDGET_STEPS` later.
        #[cfg(test)]
        if !self.slow.lock().unwrap().is_empty() {
            self.budget.attach(conn, 1)?;
        }
        // Immediate: the write lock is taken at BEGIN, under the busy handler.
        // A deferred transaction reads first, and an idle TRUNCATE on the
        // checkpoint connection (which resets the log) between that read and
        // the first write fails it with SQLITE_BUSY_SNAPSHOT, which no busy
        // handler retries and which would refuse the whole batch.
        let mut tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut reclaimed = false;
        let mut stored_ordinary = Vec::new();
        for &i in idxs {
            // Before anything that can wait on the state database, so a
            // deferred event costs no read.
            if started && began.elapsed() > self.batch_budget {
                results[i] = Some(Err(EventStoreError::Deferred));
                continue;
            }
            // The writer re-asks, inside the transaction and just before the
            // event's own statements, whether its author is still authorised.
            if !batch[i].still_authorised() {
                results[i] = Some(Err(EventStoreError::Unauthorised));
                continue;
            }
            started = true;
            // Each event gets its own deadline; the commit gets none.
            self.budget.arm(QUERY_BUDGET);
            #[cfg(test)]
            if let Some(Slow::Takes(ms)) = self.slow_of(&batch[i].event.id.to_hex()) {
                std::thread::sleep(Duration::from_millis(ms));
            }
            let mut savepoint = tx.savepoint()?;
            match self.apply_one(&savepoint, &batch[i]) {
                Ok(Ok((outcome, reclaimed_here))) => {
                    savepoint.commit()?;
                    if outcome == PutOutcome::Stored && !batch[i].is_deletion() {
                        stored_ordinary.push(i);
                    }
                    reclaimed |= reclaimed_here;
                    results[i] = Some(Ok(outcome));
                }
                Ok(Err(refusal)) => {
                    savepoint.rollback()?;
                    savepoint.commit()?;
                    results[i] = Some(Err(refusal));
                }
                Err(error) if is_event_fault(&error) => {
                    // The expired timer would interrupt the very statements
                    // that undo this event, so drop it first.
                    self.budget.disarm();
                    if savepoint.is_autocommit() {
                        // An interrupted write rolled the transaction back,
                        // this event's savepoint and every earlier event's
                        // work with it. Run the pass again without it.
                        drop(savepoint);
                        return Ok(BatchEnd::Lost {
                            index: i,
                            error: error.into(),
                        });
                    }
                    savepoint.rollback()?;
                    savepoint.commit()?;
                    results[i] = Some(Err(error.into()));
                }
                Err(error) => return Err(error.into()),
            }
        }
        // Once, just before the commit and for the whole batch: the disk
        // must still leave each ordinary event's reserve. Deletions are
        // exempt, as one at a time.
        if !stored_ordinary.is_empty() {
            let available = self.free_space.available_bytes(&self.parent)?;
            let lost: Vec<usize> = stored_ordinary
                .into_iter()
                .filter(|&i| {
                    let (_, disk) = self.reserves(&batch[i]);
                    available < self.min_free_bytes.saturating_add(disk)
                })
                .collect();
            if !lost.is_empty() {
                tx.rollback()?;
                return Ok(BatchEnd::Short { lost });
            }
        }
        // Do not interrupt the commit with a timer that began at the first
        // statement.
        self.budget.disarm();
        #[cfg(test)]
        {
            let code = self.commit_fault.load(AtomicOrdering::SeqCst);
            if code != 0 {
                return Err(
                    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None).into(),
                );
            }
        }
        tx.commit()?;
        self.commits.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(BatchEnd::Committed { reclaimed })
    }

    /// Take the write lock and settle `idxs`, retrying without the events a
    /// shrinking disk cannot hold. Every index ends with a result.
    fn commit_batch(
        &self,
        batch: &[PreparedPut],
        results: &mut [Option<PutResult>],
        mut idxs: Vec<usize>,
    ) {
        let mut conn = match self.lock() {
            Ok(conn) => conn,
            Err(error) => {
                for &i in &idxs {
                    results[i] = Some(Err(again(&error)));
                }
                return;
            }
        };
        // One budget for the whole call: a pass run again after an event was
        // lost does not get a fresh one, or interrupted events could stack
        // their time without end.
        let began = std::time::Instant::now();
        while !idxs.is_empty() {
            let end = self.run_batch(&mut conn, batch, &idxs, results, began);
            // Never leave an expired timer on the connection for whatever
            // runs next, not even its BEGIN.
            self.budget.disarm();
            match end {
                Ok(BatchEnd::Committed { reclaimed }) => {
                    if reclaimed {
                        self.checkpoint_after_reclaim(&conn);
                    }
                    self.enforce_wal_ceiling(&conn);
                    return;
                }
                Ok(BatchEnd::Short { lost }) => {
                    for &i in &lost {
                        results[i] = Some(Err(EventStoreError::Full));
                    }
                    idxs.retain(|i| !lost.contains(i));
                }
                Ok(BatchEnd::Lost { index, error }) => {
                    #[cfg(test)]
                    self.reruns.fetch_add(1, AtomicOrdering::Relaxed);
                    results[index] = Some(Err(error));
                    idxs.retain(|&i| i != index);
                }
                Err(error) => {
                    for &i in &idxs {
                        // Not started, or refused outright before the
                        // statements that failed: neither is part of it.
                        if !matches!(
                            results[i],
                            Some(Err(
                                EventStoreError::Deferred | EventStoreError::Unauthorised
                            ))
                        ) {
                            results[i] = Some(Err(again(&error)));
                        }
                    }
                    return;
                }
            }
        }
    }

    fn put_one(
        &self,
        visibility: Visibility,
        event: &Event,
        now: u64,
        replicated: bool,
    ) -> PutResult {
        let prepared = PreparedPut::new(visibility, event.clone(), now, replicated)?;
        self.put_prepared_batch(std::slice::from_ref(&prepared))
            .pop()
            .unwrap_or(Err(EventStoreError::Poisoned))
    }
}

impl EventStore for SqliteEventStore {
    fn expire(&self, now: u64) -> Result<usize, EventStoreError> {
        let mut conn = self.lock()?;
        // Expiry has its own deadline, rather than inheriting the history
        // query's timer. Each bounded transaction makes durable progress.
        self.budget.arm(EXPIRY_BUDGET);
        // Immediate, as in `run_batch`: see there.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute(
            "DELETE FROM events WHERE rowid IN (SELECT rowid FROM events INDEXED BY events_expiry WHERE expires_at IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT ?)",
            params![now.min(i64::MAX as u64) as i64, MAX_EXPIRE_EVENTS as i64],
        );
        // Do not interrupt commit with a timer that began before the DELETE.
        // On an interrupted statement the transaction drops and rolls back.
        self.budget.disarm();
        let removed = removed?;
        tx.commit()?;
        if removed > 0 {
            self.checkpoint_after_reclaim(&conn);
        }
        self.enforce_wal_ceiling(&conn);
        Ok(removed)
    }

    fn logical_bytes(&self) -> Result<u64, EventStoreError> {
        let conn = self.lock()?;
        self.budget.within(QUERY_BUDGET, || logical_bytes(&conn))
    }

    fn put_prepared_batch(
        &self,
        batch: &[PreparedPut],
    ) -> Vec<Result<PutOutcome, EventStoreError>> {
        let mut results: Vec<Option<PutResult>> = batch.iter().map(|_| None).collect();
        let mut idxs = Vec::with_capacity(batch.len());
        for (i, put) in batch.iter().enumerate() {
            if put.ephemeral {
                results[i] = Some(if put.still_authorised() {
                    Ok(PutOutcome::Ephemeral)
                } else {
                    Err(EventStoreError::Unauthorised)
                });
                continue;
            }
            if !put.is_deletion() {
                let (_, disk_reserve) = self.reserves(put);
                match self.has_headroom(true, disk_reserve) {
                    Ok(true) => {}
                    Ok(false) => {
                        results[i] = Some(Err(EventStoreError::Full));
                        continue;
                    }
                    Err(error) => {
                        results[i] = Some(Err(error));
                        continue;
                    }
                }
            }
            idxs.push(i);
        }
        if !idxs.is_empty() {
            self.commit_batch(batch, &mut results, idxs);
        }
        results
            .into_iter()
            .map(|r| r.unwrap_or(Err(EventStoreError::Poisoned)))
            .collect()
    }

    fn put(
        &self,
        visibility: Visibility,
        event: &Event,
        now: u64,
    ) -> Result<PutOutcome, EventStoreError> {
        self.put_one(visibility, event, now, false)
    }

    fn put_replicated(
        &self,
        visibility: Visibility,
        event: &Event,
        now: u64,
    ) -> Result<PutOutcome, EventStoreError> {
        self.put_one(visibility, event, now, true)
    }

    fn query(
        &self,
        visibility: Visibility,
        filter: &Filter,
        now: u64,
    ) -> Result<Vec<Event>, EventStoreError> {
        let Some((sql, values)) = self.query_sql(visibility, filter, now)? else {
            return Ok(vec![]);
        };
        self.run_query(&sql, values, |json| {
            serde_json::from_str(&json).map_err(|_| EventStoreError::Corrupt)
        })
    }

    /// The same query and rows as [`EventStore::query`], each row checked by
    /// [`StoredEvent::from_stored`] instead of being built into an event.
    fn query_stored(
        &self,
        visibility: Visibility,
        filter: &Filter,
        now: u64,
    ) -> Result<Vec<StoredEvent>, EventStoreError> {
        let Some((sql, values)) = self.query_sql(visibility, filter, now)? else {
            return Ok(vec![]);
        };
        self.run_query(&sql, values, StoredEvent::from_stored)
    }

    /// One statement for every filter, under the same reader and two-second
    /// progress deadline as a history query.
    fn count(
        &self,
        visibility: Visibility,
        filters: &[Filter],
        now: u64,
    ) -> Result<u64, EventStoreError> {
        let Some((sql, values)) = build_count(visibility, filters, now)? else {
            return Ok(0);
        };
        self.with_reader(|conn| {
            let mut statement = conn.prepare(&sql)?;
            let count: i64 = statement.query_row(params_from_iter(values), |r| r.get(0))?;
            u64::try_from(count).map_err(|_| EventStoreError::Corrupt)
        })
    }
}

/// Built SQL by filter shape, and the bytes it holds (the SQL and its key).
#[derive(Default)]
struct SqlCache {
    entries: std::collections::HashMap<Vec<u32>, Arc<str>>,
    bytes: usize,
}

impl SqlCache {
    fn get(&self, shape: &[u32]) -> Option<Arc<str>> {
        self.entries.get(shape).cloned()
    }

    /// Keep `sql` for `shape`, unless it is too long to keep; start again
    /// when the entry or byte bound would be passed.
    fn insert(&mut self, shape: Vec<u32>, sql: &Arc<str>) {
        if sql.len() > SQL_CACHE_ENTRY_BYTES || self.entries.contains_key(&shape) {
            return;
        }
        let cost = sql.len() + shape.len() * std::mem::size_of::<u32>();
        if self.entries.len() >= SQL_CACHE_SHAPES || self.bytes + cost > SQL_CACHE_BYTES {
            self.entries.clear();
            self.bytes = 0;
        }
        self.bytes += cost;
        self.entries.insert(shape, Arc::clone(sql));
    }
}

/// One history query's SQL, shared by every query of its shape, and the
/// values it binds.
type BuiltQuery = (Arc<str>, Vec<Value>);

/// The shape of a filter: everything the SQL text [`build_query`] makes for
/// it depends on, and none of what it binds. Which fields are present, how
/// many values each holds, and the value count of each tag in order (which
/// also picks the driving tag and the merge form). `None` for a filter
/// `build_query` returns nothing for or refuses, which is never cached.
fn query_shape(filter: &Filter, tag_driven: bool) -> Option<Vec<u32>> {
    if filter
        .since
        .is_some_and(|since| since.as_secs() > i64::MAX as u64)
        || filter.generic_tags.values().any(|values| values.is_empty())
    {
        return None;
    }
    let ids = filter.ids.as_ref().map(|ids| ids.len());
    let authors = filter.authors.as_ref().map(|authors| authors.len());
    let kinds = filter.kinds.as_ref().map(|kinds| kinds.len());
    // Everything bound before the limit, as `build_query` counts it.
    let mut bound = 2
        + ids.unwrap_or(0)
        + authors.unwrap_or(0)
        + kinds.unwrap_or(0)
        + usize::from(filter.since.is_some())
        + usize::from(filter.until.is_some());
    let count = |n: Option<usize>| n.map_or(u32::MAX, |n| u32::try_from(n).unwrap_or(u32::MAX - 1));
    let mut shape = vec![
        u32::from(tag_driven),
        count(ids),
        count(authors),
        count(kinds),
        u32::from(filter.since.is_some()),
        u32::from(filter.until.is_some()),
    ];
    for values in filter.generic_tags.values() {
        bound += 1 + values.len();
        shape.push(count(Some(values.len())));
    }
    (bound <= MAX_QUERY_VALUES).then_some(shape)
}

/// The values [`build_query`] binds, in its order, for a filter that has a
/// [`query_shape`].
fn query_values(visibility: Visibility, filter: &Filter, now: u64, limit: usize) -> Vec<Value> {
    let mut values = vec![
        Value::Integer(visibility.key()),
        Value::Integer(now.min(i64::MAX as u64) as i64),
    ];
    if let Some(ids) = &filter.ids {
        values.extend(ids.iter().map(|i| key_blob(i.as_bytes())));
    }
    if let Some(authors) = &filter.authors {
        values.extend(authors.iter().map(|i| key_blob(i.as_bytes())));
    }
    if let Some(kinds) = &filter.kinds {
        values.extend(kinds.iter().map(|i| Value::Integer(i.as_u16() as i64)));
    }
    if let Some(since) = filter.since {
        values.push(Value::Integer(since.as_secs() as i64));
    }
    if let Some(until) = filter.until {
        values.push(Value::Integer(until.as_secs().min(i64::MAX as u64) as i64));
    }
    for (name, tag_values) in &filter.generic_tags {
        values.push(Value::Text(name.to_string()));
        values.extend(tag_values.iter().map(|v| Value::Text(v.to_string())));
    }
    values.push(Value::Integer(limit as i64));
    values
}

impl SqliteEventStore {
    /// The SQL and bound values for one history query, or `None` when it
    /// returns nothing. SQL already built for the filter's shape is reused,
    /// so a repeated page formats no SQL; only its values are collected.
    fn query_sql(
        &self,
        visibility: Visibility,
        filter: &Filter,
        now: u64,
    ) -> Result<Option<BuiltQuery>, EventStoreError> {
        if filter.search.is_some() {
            return Err(EventStoreError::Query);
        }
        let limit = filter
            .limit
            .unwrap_or(MAX_QUERY_EVENTS)
            .min(MAX_QUERY_EVENTS);
        if limit == 0 {
            return Ok(None);
        }
        let Some(shape) = query_shape(filter, true) else {
            return Ok(build_query(visibility, filter, now, limit, true)?
                .map(|(sql, values)| (sql.into(), values)));
        };
        let cached = self
            .sql_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&shape);
        if let Some(sql) = cached {
            return Ok(Some((sql, query_values(visibility, filter, now, limit))));
        }
        let Some((sql, values)) = build_query(visibility, filter, now, limit, true)? else {
            return Ok(None);
        };
        let sql: Arc<str> = sql.into();
        self.sql_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(shape, &sql);
        Ok(Some((sql, values)))
    }

    fn run_query<T>(
        &self,
        sql: &str,
        values: Vec<Value>,
        row: impl Fn(String) -> Result<T, EventStoreError>,
    ) -> Result<Vec<T>, EventStoreError> {
        self.with_reader(|conn| {
            let mut statement = conn.prepare_cached(sql)?;
            let rows = statement.query_map(params_from_iter(values), |r| r.get::<_, String>(0))?;
            rows.map(|r| row(r?)).collect()
        })
    }
}

/// Numbered placeholders, so one bound value can serve several branches.
struct Binds(Vec<Value>);

impl Binds {
    fn add(&mut self, value: Value) -> String {
        self.0.push(value);
        format!("?{}", self.0.len())
    }
}

fn membership(sql: &mut String, binds: &mut Binds, field: &str, items: Vec<Value>) {
    if items.is_empty() {
        sql.push_str(" AND 0");
        return;
    }
    let marks: Vec<String> = items.into_iter().map(|item| binds.add(item)).collect();
    sql.push_str(&format!(" AND {field} IN ({})", marks.join(",")));
}

/// The SQL and bound values for one filter; `None` when it cannot match.
///
/// A filter with generic tags, no `ids` and no `authors` is driven from the
/// tag index: `tags_by_time` yields the driving tag's rows newest-first, so
/// the walk stops at the limit instead of probing every event in the
/// partition. The driving tag is the one with the fewest values.
///
/// A filter with 2 to [`MAX_MERGED_VALUES`] (author, kind) pairs and no
/// `ids` seeks each pair in `events_author_kind` and merges them.
///
/// Driver rule: `authors` wins. Its index (`events_author_kind`) is the only
/// one that bounds the walk by something the filter names, and a tag value
/// that is common (`#t`, `#p`) would otherwise be walked row by row until
/// `limit` hits turn up among an author's older events. So a filter with
/// `authors` stays event-driven and probes its tags with `EXISTS`. Room
/// queries (`kinds` + `#d`) have no authors, and a `d` value is selective,
/// so they stay tag-driven. `tag_driven = false` forces the event-driven
/// shape, which the tests use as an oracle.
///
/// The tag-driven merges carry `(created_at, id)` only; the JSON of the
/// at most `limit` survivors is read once, after the merge, so no temporary
/// table holds event bodies.
fn build_query(
    visibility: Visibility,
    filter: &Filter,
    now: u64,
    limit: usize,
    tag_driven: bool,
) -> Result<Option<(String, Vec<Value>)>, EventStoreError> {
    let mut binds = Binds(Vec::new());
    let vis = binds.add(Value::Integer(visibility.key()));
    let at = binds.add(Value::Integer(now.min(i64::MAX as u64) as i64));
    let mut conds = format!(" AND (e.expires_at IS NULL OR e.expires_at>{at})");
    if let Some(ids) = &filter.ids {
        let items = ids.iter().map(|i| key_blob(i.as_bytes())).collect();
        membership(&mut conds, &mut binds, "e.id", items);
    }
    // Every condition but the author and kind lists, for the pair merge.
    let mut others = conds.clone();
    let mut author_marks = Vec::new();
    if let Some(authors) = &filter.authors {
        let items: Vec<Value> = authors.iter().map(|i| key_blob(i.as_bytes())).collect();
        let before = binds.0.len();
        membership(&mut conds, &mut binds, "e.author", items);
        author_marks = (before + 1..=binds.0.len())
            .map(|n| format!("?{n}"))
            .collect();
    }
    let mut kind_marks = Vec::new();
    if let Some(kinds) = &filter.kinds {
        let items = kinds
            .iter()
            .map(|i| Value::Integer(i.as_u16() as i64))
            .collect();
        let before = binds.0.len();
        membership(&mut conds, &mut binds, "e.kind", items);
        kind_marks = (before + 1..=binds.0.len())
            .map(|n| format!("?{n}"))
            .collect();
    }
    let mut range = String::new();
    if let Some(since) = filter.since {
        if since.as_secs() > i64::MAX as u64 {
            return Ok(None);
        }
        let mark = binds.add(Value::Integer(since.as_secs() as i64));
        conds.push_str(&format!(" AND e.created_at>={mark}"));
        others.push_str(&format!(" AND e.created_at>={mark}"));
        range.push_str(&format!(" AND t.created_at>={mark}"));
    }
    if let Some(until) = filter.until {
        let mark = binds.add(Value::Integer(until.as_secs().min(i64::MAX as u64) as i64));
        conds.push_str(&format!(" AND e.created_at<={mark}"));
        others.push_str(&format!(" AND e.created_at<={mark}"));
        range.push_str(&format!(" AND t.created_at<={mark}"));
    }
    // (name placeholder, value placeholders) per generic tag.
    let mut tags: Vec<(String, Vec<String>)> = Vec::new();
    for (name, values) in &filter.generic_tags {
        let name = binds.add(Value::Text(name.to_string()));
        let values = values
            .iter()
            .map(|v| binds.add(Value::Text(v.to_string())))
            .collect();
        tags.push((name, values));
    }
    if binds.0.len() > MAX_QUERY_VALUES {
        return Err(EventStoreError::Query);
    }
    let limit = binds.add(Value::Integer(limit as i64));
    if !(tag_driven && filter.ids.is_none() && filter.authors.is_none() && !tags.is_empty()) {
        // Event-driven: walk events in time order and probe each tag.
        for (name, values) in &tags {
            let probe = if values.is_empty() {
                " AND 0".to_owned()
            } else {
                format!(
                    " AND EXISTS(SELECT 1 FROM tags t WHERE t.seq=e.seq AND t.name={name} AND t.value IN ({}))",
                    values.join(",")
                )
            };
            conds.push_str(&probe);
            others.push_str(&probe);
        }
        // Several authors or kinds: `events_author_kind` cannot yield their
        // union in time order, so SQLite walks `events_time` instead and,
        // for an author with few events, reads the whole partition to fill
        // the page. Each (author, kind) pair is one seek, already newest
        // first, and the pairs are merged by key as the tag values are. An
        // event has one author and one kind, so no event is in two pairs.
        let pairs = author_marks.len() * kind_marks.len();
        if tag_driven && filter.ids.is_none() && (2..=MAX_MERGED_VALUES).contains(&pairs) {
            let branches: Vec<String> = author_marks
                .iter()
                .flat_map(|author| kind_marks.iter().map(move |kind| (author, kind)))
                .map(|(author, kind)| {
                    format!(
                        "SELECT c,i,s FROM (SELECT e.created_at AS c,e.id AS i,e.seq AS s FROM events e INDEXED BY events_author_kind WHERE e.visibility={vis} AND e.author={author} AND e.kind={kind}{others} ORDER BY e.created_at DESC,e.id ASC LIMIT {limit})"
                    )
                })
                .collect();
            return Ok(Some((
                format!(
                    "SELECT e.json FROM ({} ORDER BY c DESC,i ASC LIMIT {limit}) m CROSS JOIN events e ON e.seq=m.s ORDER BY m.c DESC,m.i ASC",
                    branches.join(" UNION ALL ")
                ),
                binds.0,
            )));
        }
        // A filter that names ids is answered from the id index: one seek
        // for each id, then a sort of at most that many rows. Left to
        // choose, SQLite takes `events_time` for its order and, with fewer
        // ids than the limit, reads the whole partition to learn that no
        // more match. One id it seeks anyway; several it does not.
        let by_id = if filter.ids.is_some() {
            " INDEXED BY events_id"
        } else {
            ""
        };
        return Ok(Some((
            format!(
                "SELECT e.json FROM events e{by_id} WHERE e.visibility={vis}{conds} ORDER BY e.created_at DESC,e.id ASC LIMIT {limit}"
            ),
            binds.0,
        )));
    }
    if tags.iter().any(|(_, values)| values.is_empty()) {
        return Ok(None);
    }
    let driver = tags
        .iter()
        .enumerate()
        .min_by_key(|(_, (_, values))| values.len())
        .map(|(index, _)| index)
        .unwrap_or(0);
    for (index, (name, values)) in tags.iter().enumerate() {
        if index != driver {
            conds.push_str(&format!(
                " AND EXISTS(SELECT 1 FROM tags t2 WHERE t2.seq=e.seq AND t2.name={name} AND t2.value IN ({}))",
                values.join(",")
            ));
        }
    }
    let (name, values) = &tags[driver];
    // CROSS JOIN fixes the order: tag rows outside, one event lookup per hit,
    // by `seq`. The store never runs ANALYZE, so the planner is not left to
    // choose. A branch selects the sort key (`c`, `i`) and the event's `seq`
    // (`s`) only, all from the tag row; the event is joined for its
    // conditions, not its body.
    let branch = |select: &str, columns: &str, value_clause: &str| {
        format!(
            "{select} {columns} FROM tags t CROSS JOIN events e ON e.seq=t.seq WHERE t.visibility={vis} AND t.name={name} AND {value_clause}{range}{conds}"
        )
    };
    const KEYS: &str = "t.created_at AS c,t.id AS i,t.seq AS s";
    // NIP-01 order: newest first, then lowest id. The tag index holds the
    // event's id after its time, so a backward walk is already in that order
    // and stops at the limit however many events share a second.
    let newest = format!("ORDER BY t.created_at DESC,t.id ASC LIMIT {limit}");
    // The body is read once, for the rows the merge kept, in merge order.
    let bodies = |merged: String| {
        format!(
            "SELECT e.json FROM ({merged}) m CROSS JOIN events e ON e.seq=m.s ORDER BY m.c DESC,m.i ASC"
        )
    };
    let sql = if values.len() == 1 {
        // The walk is already in order and stops at the limit, so the body
        // is read for each hit directly; nothing is sorted or merged.
        let one = format!("t.value={}", values[0]);
        format!("{} {newest}", branch("SELECT", "e.json", &one))
    } else if values.len() <= MAX_MERGED_VALUES {
        // Each value's newest rows, merged; UNION drops an event that carries
        // several of the values, as the event-driven shape returns it once:
        // its `(created_at, id, seq)` is the same in every branch.
        let branches: Vec<String> = values
            .iter()
            .map(|value| {
                let one = format!("t.value={value}");
                format!(
                    "SELECT c,i,s FROM ({} {newest})",
                    branch("SELECT", KEYS, &one)
                )
            })
            .collect();
        bodies(format!(
            "{} ORDER BY c DESC,i ASC LIMIT {limit}",
            branches.join(" UNION ")
        ))
    } else {
        // Too many branches: one scan of every matching row, sorted. The
        // sorted rows are keys only.
        let any = format!("t.value IN ({})", values.join(","));
        bodies(format!(
            "SELECT c,i,s FROM ({}) ORDER BY c DESC,i ASC LIMIT {limit}",
            branch("SELECT DISTINCT", KEYS, &any)
        ))
    };
    Ok(Some((sql, binds.0)))
}

/// The SQL and bound values that count the events matching any of
/// `filters`; `None` when none of them can match.
///
/// Each filter is one branch yielding the ids it matches, in the two shapes
/// [`build_query`] uses: from the tag index when it names tags and neither
/// `ids` nor `authors`, otherwise from the events table with each tag probed
/// by `EXISTS`. Every branch yields the event's `seq`, so `DISTINCT` over
/// the branches counts an event matched by several filters, or by several
/// values of one tag, once. The count stops one past [`MAX_EXACT_COUNT`]. No
/// branch reads an event body.
fn build_count(
    visibility: Visibility,
    filters: &[Filter],
    now: u64,
) -> Result<Option<(String, Vec<Value>)>, EventStoreError> {
    let mut binds = Binds(Vec::new());
    let vis = binds.add(Value::Integer(visibility.key()));
    let at = binds.add(Value::Integer(now.min(i64::MAX as u64) as i64));
    let mut branches = Vec::new();
    for filter in filters {
        if filter.search.is_some() {
            return Err(EventStoreError::Query);
        }
        let before = binds.0.len();
        let branch = count_branch(&mut binds, &vis, &at, filter);
        if binds.0.len() - before > MAX_QUERY_VALUES {
            return Err(EventStoreError::Query);
        }
        match branch {
            Some(branch) => branches.push(branch),
            // Values bound before the filter proved unmatchable would
            // otherwise outnumber the statement's placeholders.
            None => binds.0.truncate(before),
        }
    }
    if branches.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        format!(
            "SELECT COUNT(*) FROM (SELECT DISTINCT i FROM ({}) LIMIT {})",
            branches.join(" UNION ALL "),
            MAX_EXACT_COUNT + 1
        ),
        binds.0,
    )))
}

/// One filter's branch for [`build_count`], or `None` when it cannot match.
fn count_branch(binds: &mut Binds, vis: &str, at: &str, filter: &Filter) -> Option<String> {
    let mut conds = format!(" AND (e.expires_at IS NULL OR e.expires_at>{at})");
    if let Some(ids) = &filter.ids {
        let items = ids.iter().map(|i| key_blob(i.as_bytes())).collect();
        membership(&mut conds, binds, "e.id", items);
    }
    if let Some(authors) = &filter.authors {
        let items = authors.iter().map(|i| key_blob(i.as_bytes())).collect();
        membership(&mut conds, binds, "e.author", items);
    }
    if let Some(kinds) = &filter.kinds {
        let items = kinds
            .iter()
            .map(|i| Value::Integer(i.as_u16() as i64))
            .collect();
        membership(&mut conds, binds, "e.kind", items);
    }
    if let Some(since) = filter.since {
        if since.as_secs() > i64::MAX as u64 {
            return None;
        }
        let mark = binds.add(Value::Integer(since.as_secs() as i64));
        conds.push_str(&format!(" AND e.created_at>={mark}"));
    }
    if let Some(until) = filter.until {
        let mark = binds.add(Value::Integer(until.as_secs().min(i64::MAX as u64) as i64));
        conds.push_str(&format!(" AND e.created_at<={mark}"));
    }
    let mut tags: Vec<(String, Vec<String>)> = Vec::new();
    for (name, values) in &filter.generic_tags {
        if values.is_empty() {
            return None;
        }
        let name = binds.add(Value::Text(name.to_string()));
        let values = values
            .iter()
            .map(|v| binds.add(Value::Text(v.to_string())))
            .collect();
        tags.push((name, values));
    }
    let probe = |alias: &str, (name, values): &(String, Vec<String>)| {
        format!(
            " AND EXISTS(SELECT 1 FROM tags {alias} WHERE {alias}.seq=e.seq AND {alias}.name={name} AND {alias}.value IN ({}))",
            values.join(",")
        )
    };
    if filter.ids.is_some() || filter.authors.is_some() || tags.is_empty() {
        for tag in &tags {
            conds.push_str(&probe("t", tag));
        }
        return Some(format!(
            "SELECT e.seq AS i FROM events e WHERE e.visibility={vis}{conds}"
        ));
    }
    let driver = tags
        .iter()
        .enumerate()
        .min_by_key(|(_, (_, values))| values.len())
        .map(|(index, _)| index)
        .unwrap_or(0);
    for (index, tag) in tags.iter().enumerate() {
        if index != driver {
            conds.push_str(&probe("t2", tag));
        }
    }
    let (name, values) = &tags[driver];
    Some(format!(
        "SELECT t.seq AS i FROM tags t CROSS JOIN events e ON e.seq=t.seq WHERE t.visibility={vis} AND t.name={name} AND t.value IN ({}){conds}",
        values.join(",")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::{EventBuilder, FinalizeEvent, Tag};
    use nostr::key::Keys;
    use nostr::types::Timestamp;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    const NOW: u64 = 1_900_000_000;
    fn event(keys: &Keys, kind: u16, at: u64, content: &str, tags: &[Vec<String>]) -> Event {
        EventBuilder::new(Kind::from(kind), content)
            .custom_created_at(Timestamp::from_secs(at))
            .tags(tags.iter().cloned().map(|v| Tag::parse(v).unwrap()))
            .finalize(keys)
            .unwrap()
    }
    fn tag(name: &str, value: impl ToString) -> Vec<String> {
        vec![name.into(), value.to_string()]
    }
    fn store(tmp: &TempDir) -> SqliteEventStore {
        SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap()
    }

    #[test]
    fn a_budget_armed_inside_a_transaction_interrupts_its_statement() {
        let mut conn = Connection::open_in_memory().unwrap();
        let budget = Budget::new();
        budget.attach(&mut conn, 100).unwrap();
        let count = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1000000) SELECT count(*) FROM n";
        let tx = conn.transaction().unwrap();
        // Disarmed, the statement runs to the end.
        assert_eq!(
            tx.query_row(count, [], |r| r.get::<_, i64>(0)).unwrap(),
            1_000_000
        );
        // Armed with no time left, through no `&mut Connection`.
        budget.arm(Duration::ZERO);
        match tx.query_row(count, [], |r| r.get::<_, i64>(0)) {
            Err(rusqlite::Error::SqliteFailure(e, _)) => {
                assert_eq!(e.code, rusqlite::ErrorCode::OperationInterrupted)
            }
            other => panic!("expected an interrupt, got {other:?}"),
        }
        budget.disarm();
        assert_eq!(
            tx.query_row(count, [], |r| r.get::<_, i64>(0)).unwrap(),
            1_000_000
        );
        // `within` leaves the deadline disarmed for whatever runs next.
        budget.within(Duration::ZERO, || ());
        assert!(!budget.0.expired());
    }
    struct SequenceFreeSpace(Mutex<Vec<u64>>);
    impl FreeSpace for SequenceFreeSpace {
        fn available_bytes(&self, _: &Path) -> std::io::Result<u64> {
            let mut values = self.0.lock().unwrap();
            Ok(if values.len() > 1 {
                values.remove(0)
            } else {
                *values.first().unwrap()
            })
        }
    }
    fn guarded_store(tmp: &TempDir, values: Vec<u64>) -> SqliteEventStore {
        SqliteEventStore::open_with_space(
            &tmp.path().join("events.sqlite"),
            10_000_000,
            16 * 1024 * 1024,
            std::sync::Arc::new(SequenceFreeSpace(Mutex::new(values))),
        )
        .unwrap()
    }
    struct CheckpointSpy {
        calls: AtomicUsize,
        fail: bool,
    }
    impl CheckpointSpy {
        fn working() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: true,
            }
        }
    }
    impl Checkpoint for CheckpointSpy {
        fn passive(&self, _: &Connection) -> Result<(), rusqlite::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                    None,
                ))
            } else {
                Ok(())
            }
        }
    }
    fn store_with_checkpoint(tmp: &TempDir, checkpoint: Arc<CheckpointSpy>) -> SqliteEventStore {
        SqliteEventStore::open_with_dependencies(
            &tmp.path().join("events.sqlite"),
            10_000_000,
            0,
            Arc::new(FilesystemFreeSpace),
            checkpoint,
        )
        .unwrap()
    }
    fn ids(store: &dyn EventStore, scope: Visibility, filter: Filter, now: u64) -> Vec<String> {
        store
            .query(scope, &filter, now)
            .unwrap()
            .iter()
            .map(|e| e.id.to_hex())
            .collect()
    }

    #[test]
    fn count_matches_any_filter_once_past_the_history_bound() {
        use nostr::filter::MatchEventOptions;
        use serde_json::json;
        let tmp = TempDir::new().unwrap();
        let db = SqliteEventStore::open(&tmp.path().join("count.sqlite"), 100_000_000).unwrap();
        let (a, b) = (Keys::generate(), Keys::generate());
        let room = "ab".repeat(32);
        let mut all = Vec::new();
        for i in 0..200u64 {
            let key = if i % 2 == 0 { &a } else { &b };
            let kind = if i % 3 == 0 { 7 } else { 1 };
            let mut tags = vec![tag("t", if i % 4 == 0 { "x" } else { "y" })];
            if i % 5 == 0 {
                tags.push(tag("t", "x"));
                tags.push(tag("t", "y"));
            }
            if i % 7 == 0 {
                tags.push(tag("d", &room));
            }
            let e = event(key, kind, NOW - 1_000 + i, &format!("n{i}"), &tags);
            db.put(Visibility::Public, &e, NOW).unwrap();
            all.push(e);
        }
        let expiring = event(&a, 1, NOW, "soon", &[tag("expiration", NOW + 10)]);
        db.put(Visibility::Public, &expiring, NOW).unwrap();
        let hidden = event(&a, 1, NOW, "sheltered", &[tag("t", "x")]);
        db.put(Visibility::Sheltered, &hidden, NOW).unwrap();
        let later = NOW + 20;

        let filter = |value: serde_json::Value| serde_json::from_value::<Filter>(value).unwrap();
        // The oracle: the events each filter matches, by NIP-01 rules.
        let expected = |filters: &[Filter]| {
            all.iter()
                .filter(|e| {
                    filters
                        .iter()
                        .any(|f| f.match_event(e, MatchEventOptions::default()))
                })
                .count() as u64
        };
        let cases: Vec<Vec<Filter>> = vec![
            vec![filter(json!({}))],
            vec![filter(json!({"kinds":[1]}))],
            vec![
                filter(json!({"kinds":[1]})),
                filter(json!({"authors":[a.public_key().to_hex()]})),
            ],
            vec![filter(json!({"#t":["x","y"]}))],
            vec![filter(json!({"#t":["x"], "#d":[room.clone()]}))],
            vec![filter(
                json!({"authors":[b.public_key().to_hex()], "#t":["x"]}),
            )],
            vec![filter(
                json!({"kinds":[7], "since": NOW - 900, "until": NOW - 850}),
            )],
            vec![filter(
                json!({"ids":[all[3].id.to_hex(), all[4].id.to_hex()], "limit": 1}),
            )],
            vec![
                filter(json!({"kinds":[1], "limit": 5})),
                filter(json!({"kinds":[7], "limit": 5})),
            ],
        ];
        for filters in &cases {
            assert_eq!(
                db.count(Visibility::Public, filters, later).unwrap(),
                expected(filters),
                "{filters:?}"
            );
        }
        // Past the bound a history query stops at.
        assert_eq!(
            db.count(Visibility::Public, &[filter(json!({}))], later)
                .unwrap(),
            200
        );
        assert_eq!(
            ids(&db, Visibility::Public, filter(json!({})), later).len(),
            MAX_QUERY_EVENTS
        );
        // Before it expires the expiring event counts; the sheltered one never does here.
        assert_eq!(
            db.count(Visibility::Public, &[filter(json!({}))], NOW)
                .unwrap(),
            201
        );
        assert_eq!(
            db.count(Visibility::Sheltered, &[filter(json!({"#t":["x"]}))], NOW)
                .unwrap(),
            1
        );
        assert_eq!(db.count(Visibility::Public, &[], NOW).unwrap(), 0);
        // A last filter that can never match leaves the count to the others.
        let mut unmatchable = filter(json!({"kinds":[1]}));
        unmatchable.since = Some(nostr::types::Timestamp::from_secs(u64::MAX));
        assert_eq!(
            db.count(
                Visibility::Public,
                &[filter(json!({"kinds":[7]})), unmatchable],
                later
            )
            .unwrap(),
            expected(&[filter(json!({"kinds":[7]}))])
        );
        assert!(matches!(
            db.count(Visibility::Public, &[filter(json!({"search":"n1"}))], NOW),
            Err(EventStoreError::Query)
        ));
    }

    #[test]
    fn export_reads_one_partition_oldest_first_without_writing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("export.sqlite");
        let key = Keys::generate();
        let older = event(&key, 1, NOW - 20, "older", &[]);
        let newer = event(&key, 1, NOW - 10, "newer", &[]);
        let expiring = event(&key, 1, NOW - 5, "soon", &[tag("expiration", NOW + 10)]);
        let sheltered = event(&key, 1, NOW - 15, "sheltered", &[]);
        {
            let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
            let version: i64 = db
                .lock()
                .unwrap()
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
            for e in [&newer, &expiring, &older] {
                db.put(Visibility::Public, e, NOW).unwrap();
            }
            db.put(Visibility::Sheltered, &sheltered, NOW).unwrap();
        }
        let export = |visibility, now| {
            let mut lines = Vec::new();
            let n = export_stored(&path, visibility, now, |json| {
                lines.push(serde_json::from_str::<Event>(json).unwrap().id);
                Ok(())
            })
            .unwrap();
            assert_eq!(n as usize, lines.len());
            lines
        };
        assert_eq!(
            export(Visibility::Public, NOW),
            vec![older.id, newer.id, expiring.id]
        );
        assert_eq!(
            export(Visibility::Public, NOW + 20),
            vec![older.id, newer.id]
        );
        assert_eq!(export(Visibility::Sheltered, NOW), vec![sheltered.id]);
        // Across pages, with ties on created_at broken by id.
        {
            let db = SqliteEventStore::open(&path, 100_000_000).unwrap();
            for i in 0..(EXPORT_PAGE as u64 * 2 + 3) {
                let e = event(&key, 1, NOW - 1_000 + i / 3, &format!("p{i}"), &[]);
                db.put(Visibility::Sheltered, &e, NOW).unwrap();
            }
        }
        let paged = export(Visibility::Sheltered, NOW);
        assert_eq!(paged.len() as i64, EXPORT_PAGE * 2 + 4);
        let mut sorted = paged.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), paged.len());
        // A failed write stops the walk and is reported.
        let broken = export_stored(&path, Visibility::Public, NOW, |_| {
            Err(std::io::Error::other("disk"))
        });
        assert!(matches!(broken, Err(EventStoreError::Io(_))));
        // Missing files are not created, and other schemas are refused.
        let missing = tmp.path().join("missing.sqlite");
        assert!(export_stored(&missing, Visibility::Public, NOW, |_| Ok(())).is_err());
        assert!(!missing.exists());
        let other = tmp.path().join("other.sqlite");
        Connection::open(&other)
            .unwrap()
            .execute_batch("PRAGMA user_version=2;")
            .unwrap();
        assert!(matches!(
            export_stored(&other, Visibility::Public, NOW, |_| Ok(())),
            Err(EventStoreError::Schema)
        ));
    }

    #[test]
    fn storage_exhaustion_maps_to_capacity_without_hiding_other_failures() {
        let sqlite_full = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        assert!(matches!(
            EventStoreError::from(sqlite_full),
            EventStoreError::Full
        ));
        let sqlite_corrupt = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            None,
        );
        assert!(matches!(
            EventStoreError::from(sqlite_corrupt),
            EventStoreError::Sqlite(_)
        ));
        for kind in [
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::QuotaExceeded,
        ] {
            assert!(matches!(
                EventStoreError::from(std::io::Error::from(kind)),
                EventStoreError::Full
            ));
        }
        assert!(matches!(
            EventStoreError::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            EventStoreError::Io(_)
        ));
    }

    #[test]
    fn reclaiming_deletion_requests_one_checkpoint_and_a_failed_request_keeps_the_commit() {
        let tmp = TempDir::new().unwrap();
        let checkpoint = Arc::new(CheckpointSpy::working());
        let db = store_with_checkpoint(&tmp, Arc::clone(&checkpoint));
        let key = Keys::generate();
        let note = event(&key, 1, NOW - 1, "reclaim", &[]);
        db.put(Visibility::Sheltered, &note, NOW).unwrap();
        assert_eq!(checkpoint.calls.load(Ordering::SeqCst), 0);
        let deletion = event(&key, 5, NOW, "", &[tag("e", note.id.to_hex())]);
        assert_eq!(
            db.put(Visibility::Sheltered, &deletion, NOW).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(checkpoint.calls.load(Ordering::SeqCst), 1);
        assert!(ids(&db, Visibility::Sheltered, Filter::new().id(note.id), NOW).is_empty());
        let unknown = event(&key, 5, NOW + 1, "", &[tag("e", "ab".repeat(32))]);
        db.put(Visibility::Sheltered, &unknown, NOW + 1).unwrap();
        assert_eq!(
            checkpoint.calls.load(Ordering::SeqCst),
            1,
            "a non-reclaiming deletion does not start maintenance"
        );

        let failed_tmp = TempDir::new().unwrap();
        let failed = Arc::new(CheckpointSpy::failing());
        let failed_db = store_with_checkpoint(&failed_tmp, Arc::clone(&failed));
        let retained = event(&key, 1, NOW - 1, "still commits", &[]);
        failed_db
            .put(Visibility::Sheltered, &retained, NOW)
            .unwrap();
        let deletion = event(&key, 5, NOW, "", &[tag("e", retained.id.to_hex())]);
        assert_eq!(
            failed_db
                .put(Visibility::Sheltered, &deletion, NOW)
                .unwrap(),
            PutOutcome::Stored,
            "post-commit maintenance cannot turn a durable deletion into a refusal"
        );
        assert_eq!(failed.calls.load(Ordering::SeqCst), 1);
        assert!(
            ids(
                &failed_db,
                Visibility::Sheltered,
                Filter::new().id(retained.id),
                NOW
            )
            .is_empty()
        );
    }

    #[test]
    fn reclaiming_expiry_requests_one_checkpoint_per_nonempty_batch() {
        let tmp = TempDir::new().unwrap();
        let checkpoint = Arc::new(CheckpointSpy::working());
        let db = store_with_checkpoint(&tmp, Arc::clone(&checkpoint));
        let key = Keys::generate();
        let expired = event(&key, 1, NOW, "expire", &[tag("expiration", NOW + 1)]);
        db.put(Visibility::Sheltered, &expired, NOW).unwrap();
        assert_eq!(db.expire(NOW + 1).unwrap(), 1);
        assert_eq!(checkpoint.calls.load(Ordering::SeqCst), 1);
        assert_eq!(db.expire(NOW + 1).unwrap(), 0);
        assert_eq!(checkpoint.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn headroom_refuses_startup_below_reserve_and_transaction_guard() {
        let tmp = TempDir::new().unwrap();
        let reserve = 16 * 1024 * 1024;
        assert!(matches!(
            SqliteEventStore::open_with_space(
                &tmp.path().join("events.sqlite"),
                10_000_000,
                reserve,
                std::sync::Arc::new(SequenceFreeSpace(Mutex::new(vec![
                    reserve + TRANSACTION_GUARD_BYTES - 1,
                ]))),
            ),
            Err(EventStoreError::DiskSpace { needed, available })
                if needed == reserve + TRANSACTION_GUARD_BYTES
                    && available == needed - 1
        ));
    }

    #[test]
    fn production_free_space_provider_opens_a_temporary_filesystem() {
        let tmp = TempDir::new().unwrap();
        let db = SqliteEventStore::open_with_headroom(
            &tmp.path().join("events.sqlite"),
            10_000_000,
            16 * 1024 * 1024,
        )
        .unwrap();
        assert_eq!(db.logical_bytes().unwrap(), 0);
    }

    #[test]
    fn ordinary_intake_rolls_back_when_the_reserve_falls_before_commit() {
        let tmp = TempDir::new().unwrap();
        let reserve = 16 * 1024 * 1024;
        let db = guarded_store(
            &tmp,
            vec![
                reserve + TRANSACTION_GUARD_BYTES,
                reserve + TRANSACTION_GUARD_BYTES,
                reserve - 1,
            ],
        );
        let key = Keys::generate();
        let note = event(&key, 1, NOW, "must not acknowledge", &[]);
        assert!(matches!(
            db.put(Visibility::Sheltered, &note, NOW),
            Err(EventStoreError::Full)
        ));
        assert!(
            ids(
                &db,
                Visibility::Sheltered,
                Filter::new().kind(Kind::from(1)),
                NOW
            )
            .is_empty()
        );
    }

    #[test]
    fn deletion_recovery_remains_available_below_the_admission_reserve() {
        let tmp = TempDir::new().unwrap();
        let reserve = 16 * 1024 * 1024;
        let db = guarded_store(
            &tmp,
            vec![
                reserve + TRANSACTION_GUARD_BYTES,
                reserve + TRANSACTION_GUARD_BYTES,
                reserve,
                0,
            ],
        );
        let key = Keys::generate();
        let note = event(&key, 1, NOW - 1, "reclaim", &[]);
        db.put(Visibility::Sheltered, &note, NOW).unwrap();
        let deletion = event(&key, 5, NOW, "", &[tag("e", note.id.to_hex())]);
        assert_eq!(
            db.put(Visibility::Sheltered, &deletion, NOW).unwrap(),
            PutOutcome::Stored
        );
        assert!(
            ids(
                &db,
                Visibility::Sheltered,
                Filter::new().kind(Kind::from(1)),
                NOW
            )
            .is_empty()
        );
    }

    #[test]
    fn restart_keeps_exact_events_and_visibility_cannot_leak_through_queries_or_deletion() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let e = event(
            &key,
            30078,
            NOW - 20,
            "ciphertext",
            &[tag("d", "signet:personas")],
        );
        {
            let db = store(&tmp);
            db.put(Visibility::Sheltered, &e, NOW).unwrap();
            assert!(ids(&db, Visibility::Public, Filter::new().id(e.id), NOW).is_empty());
            db.put(Visibility::Public, &e, NOW).unwrap();
            let deletion = event(&key, 5, NOW - 10, "", &[tag("e", e.id.to_hex())]);
            db.put(Visibility::Public, &deletion, NOW).unwrap();
        }
        let db = store(&tmp);
        assert_eq!(
            db.query(Visibility::Sheltered, &Filter::new(), NOW)
                .unwrap(),
            vec![e.clone()]
        );
        assert!(ids(&db, Visibility::Public, Filter::new().kind(e.kind), NOW).is_empty());
        assert!(matches!(
            db.put(Visibility::Public, &e, NOW),
            Err(EventStoreError::Retired)
        ));
    }

    #[test]
    fn addressable_replacement_and_ties_converge_in_either_order() {
        let key = Keys::generate();
        let a = event(&key, 30078, NOW - 20, "a", &[tag("d", "one")]);
        let b = event(&key, 30078, NOW - 20, "b", &[tag("d", "one")]);
        let mut pair = [a, b];
        pair.sort_by_key(|e| e.id);
        for order in [[0, 1], [1, 0]] {
            let tmp = TempDir::new().unwrap();
            let db = store(&tmp);
            db.put(Visibility::Sheltered, &pair[order[0]], NOW).unwrap();
            let _ = db.put(Visibility::Sheltered, &pair[order[1]], NOW);
            assert_eq!(
                ids(&db, Visibility::Sheltered, Filter::new(), NOW),
                vec![pair[0].id.to_hex()]
            );
            let newer = event(&key, 30078, NOW - 10, "new", &[tag("d", "one")]);
            let other = event(&key, 30078, NOW - 5, "other", &[tag("d", "two")]);
            db.put(Visibility::Sheltered, &newer, NOW).unwrap();
            db.put(Visibility::Sheltered, &other, NOW).unwrap();
            assert_eq!(
                ids(&db, Visibility::Sheltered, Filter::new(), NOW),
                vec![other.id.to_hex(), newer.id.to_hex()]
            );
        }
    }

    #[test]
    fn regular_replaceable_and_ephemeral_semantics_are_distinct() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        for kind in [0, 3, 10002] {
            let old = event(&key, kind, NOW - 20, "old", &[]);
            let new = event(&key, kind, NOW - 10, "new", &[]);
            db.put(Visibility::Public, &old, NOW).unwrap();
            db.put(Visibility::Public, &new, NOW).unwrap();
            assert_eq!(
                ids(
                    &db,
                    Visibility::Public,
                    Filter::new().kind(Kind::from(kind)),
                    NOW
                ),
                vec![new.id.to_hex()]
            );
        }
        let transient = event(&key, 20000, NOW, "live", &[]);
        assert_eq!(
            db.put(Visibility::Sheltered, &transient, NOW).unwrap(),
            PutOutcome::Ephemeral
        );
        assert!(ids(&db, Visibility::Sheltered, Filter::new(), NOW).is_empty());
        let auth = event(&key, 22242, NOW, "", &[tag("challenge", "not for storage")]);
        assert!(matches!(
            db.put(Visibility::Public, &auth, NOW),
            Err(EventStoreError::Invalid)
        ));
        let regular = event(&key, 1, NOW, "note", &[]);
        assert_eq!(
            db.put(Visibility::Public, &regular, NOW).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(
            db.put(Visibility::Public, &regular, NOW).unwrap(),
            PutOutcome::Duplicate
        );
    }

    #[test]
    fn channel_metadata_is_kept_per_channel() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let newer = event(&key, 41, NOW - 10, "channel a", &[tag("e", &a)]);
        let older = event(&key, 41, NOW - 20, "channel b", &[tag("e", &b)]);
        assert_eq!(
            db.put(Visibility::Sheltered, &newer, NOW).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(
            db.put(Visibility::Sheltered, &older, NOW).unwrap(),
            PutOutcome::Stored
        );
        let mut got = ids(
            &db,
            Visibility::Sheltered,
            Filter::new().kind(Kind::from(41)),
            NOW,
        );
        got.sort();
        let mut want = vec![newer.id.to_hex(), older.id.to_hex()];
        want.sort();
        assert_eq!(got, want);
        // A bare `41:<author>:` coordinate names nothing, so it deletes nothing.
        let delete = event(
            &key,
            5,
            NOW,
            "",
            &[tag("a", format!("41:{}:", key.public_key().to_hex()))],
        );
        db.put(Visibility::Sheltered, &delete, NOW).unwrap();
        let mut got = ids(
            &db,
            Visibility::Sheltered,
            Filter::new().kind(Kind::from(41)),
            NOW,
        );
        got.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn deletion_before_arrival_is_author_bound_and_survives_restart() {
        let tmp = TempDir::new().unwrap();
        let alice = Keys::generate();
        let mallory = Keys::generate();
        let note = event(&alice, 1, NOW - 100, "keep until Alice deletes", &[]);
        let forged = event(&mallory, 5, NOW - 90, "", &[tag("e", note.id.to_hex())]);
        {
            let db = store(&tmp);
            db.put(Visibility::Public, &forged, NOW).unwrap();
            db.put(Visibility::Public, &note, NOW).unwrap();
            assert_eq!(
                ids(&db, Visibility::Public, Filter::new().id(note.id), NOW),
                vec![note.id.to_hex()]
            );
            let deletion = event(&alice, 5, NOW - 80, "", &[tag("e", note.id.to_hex())]);
            db.put(Visibility::Public, &deletion, NOW).unwrap();
            // A deletion request cannot undo an earlier deletion request.
            let undo = event(&alice, 5, NOW - 70, "", &[tag("e", deletion.id.to_hex())]);
            db.put(Visibility::Public, &undo, NOW).unwrap();
            assert_eq!(
                ids(&db, Visibility::Public, Filter::new().id(deletion.id), NOW),
                vec![deletion.id.to_hex()]
            );
        }
        let db = store(&tmp);
        assert!(matches!(
            db.put(Visibility::Public, &note, NOW),
            Err(EventStoreError::Retired)
        ));
        let missing = event(&alice, 1, NOW - 150, "not received yet", &[]);
        let deletion = event(&alice, 5, NOW - 60, "", &[tag("e", missing.id.to_hex())]);
        db.put(Visibility::Public, &deletion, NOW).unwrap();
        assert!(matches!(
            db.put(Visibility::Public, &missing, NOW),
            Err(EventStoreError::Retired)
        ));
    }

    #[test]
    fn coordinate_deletion_blocks_older_versions_but_allows_a_later_recreation() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let address = format!("30078:{}:rail:with:colons", key.public_key());
        let deletion = event(&key, 5, NOW - 20, "", &[tag("a", address)]);
        let old = event(
            &key,
            30078,
            NOW - 30,
            "old",
            &[tag("d", "rail:with:colons")],
        );
        let new = event(
            &key,
            30078,
            NOW - 10,
            "new",
            &[tag("d", "rail:with:colons")],
        );
        {
            let db = store(&tmp);
            db.put(Visibility::Sheltered, &deletion, NOW).unwrap();
        }
        let db = store(&tmp);
        assert!(matches!(
            db.put(Visibility::Sheltered, &old, NOW),
            Err(EventStoreError::Retired)
        ));
        db.put(Visibility::Sheltered, &new, NOW).unwrap();
        assert_eq!(
            ids(
                &db,
                Visibility::Sheltered,
                Filter::new().kind(Kind::from(30078)),
                NOW
            ),
            vec![new.id.to_hex()]
        );
    }

    #[test]
    fn expiry_hides_records_without_resurrecting_an_older_replaceable_record() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let old = event(&key, 0, NOW - 30, "old", &[]);
        let new = event(&key, 0, NOW - 10, "new", &[tag("expiration", NOW + 10)]);
        {
            let db = store(&tmp);
            db.put(Visibility::Public, &old, NOW).unwrap();
            db.put(Visibility::Public, &new, NOW).unwrap();
        }
        let db = store(&tmp);
        assert_eq!(db.expire(NOW + 11).unwrap(), 1);
        assert!(ids(&db, Visibility::Public, Filter::new(), NOW + 11).is_empty());
        assert!(matches!(
            db.put(Visibility::Public, &old, NOW + 11),
            Err(EventStoreError::Retired)
        ));
        assert!(matches!(
            db.put(Visibility::Public, &new, NOW + 11),
            Err(EventStoreError::Expired)
        ));
    }

    #[test]
    fn expiry_backlog_makes_bounded_durable_progress_and_repairs_a_missing_index() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let key = Keys::generate();
        let count = MAX_EXPIRE_EVENTS * 2 + 3;
        let retained = event(&key, 1, NOW, "keep", &[]);
        let future = event(&key, 1, NOW, "later", &[tag("expiration", NOW + 100)]);
        {
            let db = store(&tmp);
            for n in 0..count {
                let expired = event(
                    &key,
                    1,
                    NOW,
                    &format!("backlog {n}"),
                    &[tag("expiration", NOW + 1), tag("t", "backlog")],
                );
                let partition = if n % 2 == 0 {
                    Visibility::Public
                } else {
                    Visibility::Sheltered
                };
                db.put(partition, &expired, NOW).unwrap();
            }
            db.put(Visibility::Public, &retained, NOW).unwrap();
            db.put(Visibility::Sheltered, &future, NOW).unwrap();
        }
        // Open repairs a missing expiry index independently of schema version.
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP INDEX events_expiry")
            .unwrap();
        let before;
        {
            let db = store(&tmp);
            let plan: String = db.lock().unwrap().query_row(
                "EXPLAIN QUERY PLAN SELECT rowid FROM events WHERE expires_at IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT 128",
                [(NOW + 2) as i64], |row| row.get(3),
            ).unwrap();
            assert!(
                plan.contains("events_expiry"),
                "expiry must use its index: {plan}"
            );
            before = db.logical_bytes().unwrap();
            assert_eq!(db.expire(NOW + 2).unwrap(), MAX_EXPIRE_EVENTS);
            assert!(db.logical_bytes().unwrap() < before);
        }
        // Completed batches survive interruption/restart. Expired records
        // remain hidden even while later batches are waiting for their turn.
        let db = store(&tmp);
        assert!(db.logical_bytes().unwrap() < before);
        assert_eq!(
            ids(&db, Visibility::Public, Filter::new(), NOW + 2),
            vec![retained.id.to_hex()]
        );
        assert_eq!(
            ids(&db, Visibility::Sheltered, Filter::new(), NOW + 2),
            vec![future.id.to_hex()]
        );
        assert_eq!(db.expire(NOW + 2).unwrap(), MAX_EXPIRE_EVENTS);
        assert_eq!(db.expire(NOW + 2).unwrap(), 3);
        assert_eq!(db.expire(NOW + 2).unwrap(), 0);
        let tags: i64 = db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM tags", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            tags, 0,
            "expired indexed tags are reclaimed with the payloads"
        );
    }

    #[test]
    fn indexed_filters_apply_all_conditions_and_keep_order_and_limit() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        let other = Keys::generate();
        let a = event(
            &key,
            1,
            NOW - 30,
            "a",
            &[tag("t", "rust"), tag("t", "nostr")],
        );
        let b = event(&key, 1, NOW - 20, "b", &[tag("t", "rust")]);
        let c = event(&other, 1, NOW - 10, "c", &[tag("t", "rust")]);
        for e in [&a, &b, &c] {
            db.put(Visibility::Public, e, NOW).unwrap();
        }
        let filter:Filter=serde_json::from_value(serde_json::json!({"authors":[key.public_key().to_hex()],"#t":["rust"],"since":NOW-25,"until":NOW-15,"kinds":[1],"limit":1})).unwrap();
        assert_eq!(
            ids(&db, Visibility::Public, filter, NOW),
            vec![b.id.to_hex()]
        );
        assert!(ids(&db, Visibility::Public, Filter::new().limit(0), NOW).is_empty());
        let empty: Filter = serde_json::from_value(serde_json::json!({"ids":[]})).unwrap();
        assert!(ids(&db, Visibility::Public, empty, NOW).is_empty());
        let unsupported: Filter =
            serde_json::from_value(serde_json::json!({"search":"note"})).unwrap();
        assert!(matches!(
            db.query(Visibility::Public, &unsupported, NOW),
            Err(EventStoreError::Query)
        ));
    }

    #[test]
    fn a_full_store_rejects_intake_and_rolls_back_replacement_and_tombstones() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let db = SqliteEventStore::open(&tmp.path().join("events.sqlite"), 3500).unwrap();
        let first = event(&key, 0, NOW - 30, "keep", &[]);
        db.put(Visibility::Public, &first, NOW).unwrap();
        let size = db.logical_bytes().unwrap();
        let too_big = event(&key, 0, NOW - 20, &"z".repeat(5000), &[]);
        assert!(matches!(
            db.put(Visibility::Public, &too_big, NOW),
            Err(EventStoreError::Full)
        ));
        assert_eq!(db.logical_bytes().unwrap(), size);
        assert_eq!(
            ids(&db, Visibility::Public, Filter::new(), NOW),
            vec![first.id.to_hex()]
        );
        let deletion = event(
            &key,
            5,
            NOW - 10,
            &"z".repeat(5000),
            &[tag("e", first.id.to_hex())],
        );
        assert!(matches!(
            db.put(Visibility::Public, &deletion, NOW),
            Err(EventStoreError::Full)
        ));
        assert_eq!(db.logical_bytes().unwrap(), size);
        assert_eq!(
            db.put(Visibility::Public, &first, NOW).unwrap(),
            PutOutcome::Duplicate
        );
        let replacement = event(&key, 0, NOW - 25, "small", &[]);
        db.put(Visibility::Public, &replacement, NOW).unwrap();
    }

    #[test]
    fn deletion_reserve_covers_a_maximal_minimal_one_id_request() {
        let key = Keys::generate();
        let deletion = event(&key, 5, i64::MAX as u64, "", &[tag("e", "ab".repeat(32))]);
        let event_charge = serde_json::to_string(&deletion).unwrap().len() as u64 + 512;
        let tag_charge = 64 + 160;
        let barrier_charge = 192;
        let charge = event_charge + tag_charge + barrier_charge;
        assert!(
            charge <= DELETION_RESERVE_BYTES,
            "a minimal one-id deletion costs {charge}, exceeding its {DELETION_RESERVE_BYTES}-byte reserve"
        );
    }

    #[test]
    fn deletion_reserve_keeps_a_full_store_deletable_without_free_tombstone_intake() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let key = Keys::generate();
        let notes: Vec<_> = (0..3)
            .map(|i| event(&key, 1, NOW - 2, &format!("note {i}"), &[]))
            .collect();
        let public = event(&key, 1, NOW - 2, "public", &[]);
        let budget;
        {
            let db = store(&tmp);
            for note in &notes {
                db.put(Visibility::Sheltered, note, NOW).unwrap();
            }
            db.put(Visibility::Public, &public, NOW).unwrap();
            budget = db.logical_bytes().unwrap();
        }
        let db = SqliteEventStore::open(&path, budget).unwrap();
        let next = event(&key, 1, NOW, "room for another note", &[]);
        assert!(matches!(
            db.put(Visibility::Sheltered, &next, NOW),
            Err(EventStoreError::Full)
        ));
        let unknown = event(&key, 5, NOW, "", &[tag("e", "ab".repeat(32))]);
        assert!(matches!(
            db.put(Visibility::Sheltered, &unknown, NOW),
            Err(EventStoreError::Full)
        ));
        let before = db.logical_bytes().unwrap();
        let wrong_partition = event(&key, 5, NOW, "", &[tag("e", public.id.to_hex())]);
        assert!(matches!(
            db.put(Visibility::Sheltered, &wrong_partition, NOW),
            Err(EventStoreError::Full)
        ));
        assert_eq!(db.logical_bytes().unwrap(), before);
        assert_eq!(
            ids(&db, Visibility::Public, Filter::new().id(public.id), NOW),
            vec![public.id.to_hex()]
        );
        for note in &notes {
            let deletion = event(&key, 5, NOW, "", &[tag("e", note.id.to_hex())]);
            let before = db.logical_bytes().unwrap();
            db.put(Visibility::Sheltered, &deletion, NOW).unwrap();
            assert!(db.logical_bytes().unwrap() < before);
            assert_eq!(
                ids(
                    &db,
                    Visibility::Sheltered,
                    Filter::new().id(deletion.id),
                    NOW
                ),
                vec![deletion.id.to_hex()]
            );
        }
        db.put(Visibility::Sheltered, &next, NOW).unwrap();
        drop(db);
        let db = SqliteEventStore::open(&path, budget).unwrap();
        for note in notes {
            assert!(matches!(
                db.put(Visibility::Sheltered, &note, NOW),
                Err(EventStoreError::Retired)
            ));
        }
        assert_eq!(
            ids(
                &db,
                Visibility::Sheltered,
                Filter::new().kind(Kind::from(1)),
                NOW
            ),
            vec![next.id.to_hex()]
        );
        assert_eq!(
            ids(&db, Visibility::Public, Filter::new().id(public.id), NOW),
            vec![public.id.to_hex()]
        );
    }

    #[test]
    fn v1_migration_preserves_events_and_allows_space_reducing_deletion_above_the_ceiling() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let key = Keys::generate();
        let other = Keys::generate();
        let public = event(&key, 1, NOW - 2, "public", &[]);
        let private = event(&key, 1, NOW - 2, "private", &[]);
        let old_usage;
        {
            // Frozen v1 layout and charges, independent of the current opener.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            for (table, cost) in [
                ("events", "length(CAST(ROW.json AS BLOB))+512"),
                ("tags", "length(CAST(ROW.value AS BLOB))+160"),
                ("heads", "length(CAST(ROW.coordinate AS BLOB))+256"),
                ("deleted_ids", "192"),
                (
                    "deleted_coordinates",
                    "length(CAST(ROW.coordinate AS BLOB))+192",
                ),
            ] {
                let new = cost.replace("ROW.", "NEW.");
                let old = cost.replace("ROW.", "OLD.");
                conn.execute_batch(&format!("CREATE TRIGGER {table}_charge_insert AFTER INSERT ON {table} BEGIN UPDATE usage SET bytes=bytes+({new}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_delete AFTER DELETE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_update AFTER UPDATE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old})+({new}) WHERE id=1; END;")).unwrap();
            }
            for (scope, note) in [
                (Visibility::Public, &public),
                (Visibility::Sheltered, &private),
            ] {
                conn.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?,NULL,NULL,?)",
                    params![
                        scope.key(),
                        note.id.to_hex(),
                        note.pubkey.to_hex(),
                        1,
                        note.created_at.as_secs() as i64,
                        serde_json::to_string(note).unwrap()
                    ],
                )
                .unwrap();
            }
            old_usage = logical_bytes(&conn).unwrap();
        }
        let db = SqliteEventStore::open(&path, old_usage).unwrap();
        let migrated = old_usage + 2 * DELETION_RESERVE_BYTES;
        assert_eq!(db.logical_bytes().unwrap(), migrated);
        assert_eq!(
            ids(&db, Visibility::Public, Filter::new(), NOW),
            vec![public.id.to_hex()]
        );
        assert_eq!(
            ids(&db, Visibility::Sheltered, Filter::new(), NOW),
            vec![private.id.to_hex()]
        );
        for deletion in [
            event(&other, 5, NOW, "", &[tag("e", public.id.to_hex())]),
            event(
                &key,
                5,
                NOW,
                &"x".repeat(5000),
                &[tag("e", public.id.to_hex())],
            ),
        ] {
            assert!(matches!(
                db.put(Visibility::Public, &deletion, NOW),
                Err(EventStoreError::Full)
            ));
            assert_eq!(db.logical_bytes().unwrap(), migrated);
        }
        let deletion = event(&key, 5, NOW, "", &[tag("e", public.id.to_hex())]);
        db.put(Visibility::Public, &deletion, NOW).unwrap();
        let reduced = db.logical_bytes().unwrap();
        assert!(reduced < migrated && reduced > old_usage);
        drop(db);
        let db = SqliteEventStore::open(&path, old_usage).unwrap();
        assert_eq!(
            db.logical_bytes().unwrap(),
            reduced,
            "the migration charges only once"
        );
        assert!(matches!(
            db.put(Visibility::Public, &public, NOW),
            Err(EventStoreError::Retired)
        ));
        assert_eq!(
            ids(&db, Visibility::Public, Filter::new(), NOW),
            vec![deletion.id.to_hex()]
        );
        assert_eq!(
            ids(&db, Visibility::Sheltered, Filter::new(), NOW),
            vec![private.id.to_hex()]
        );
    }

    #[test]
    fn failed_v1_reserve_migration_keeps_v1_accounting_and_version() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let key = Keys::generate();
        let note = event(&key, 1, NOW - 2, "v1 record", &[]);
        let (usage, event_trigger);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            for (table, cost) in [
                ("events", "length(CAST(ROW.json AS BLOB))+512"),
                ("tags", "length(CAST(ROW.value AS BLOB))+160"),
                ("heads", "length(CAST(ROW.coordinate AS BLOB))+256"),
                ("deleted_ids", "192"),
                (
                    "deleted_coordinates",
                    "length(CAST(ROW.coordinate AS BLOB))+192",
                ),
            ] {
                let new = cost.replace("ROW.", "NEW.");
                let old = cost.replace("ROW.", "OLD.");
                conn.execute_batch(&format!("CREATE TRIGGER {table}_charge_insert AFTER INSERT ON {table} BEGIN UPDATE usage SET bytes=bytes+({new}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_delete AFTER DELETE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_update AFTER UPDATE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old})+({new}) WHERE id=1; END;"))
                    .unwrap();
            }
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,NULL,NULL,?)",
                params![
                    Visibility::Sheltered.key(),
                    note.id.to_hex(),
                    note.pubkey.to_hex(),
                    1,
                    note.created_at.as_secs() as i64,
                    serde_json::to_string(&note).unwrap()
                ],
            )
            .unwrap();
            usage = logical_bytes(&conn).unwrap();
            event_trigger = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='events_charge_insert'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap();
            // A failure on the first migration write must leave every prior
            // trigger and the schema version in place for a later retry.
            conn.execute_batch("CREATE TRIGGER test_refuse_reserve BEFORE UPDATE OF bytes ON usage BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;")
                .unwrap();
        }
        assert!(matches!(
            SqliteEventStore::open(&path, 10_000_000),
            Err(EventStoreError::Sqlite(_))
        ));
        let conn = Connection::open(&path).unwrap();
        assert_eq!(logical_bytes(&conn).unwrap(), usage);
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='events_charge_insert'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            event_trigger
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM events", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn invalid_signatures_oversize_and_malformed_expiries_never_enter_storage() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        let mut invalid = event(&key, 1, NOW, "original", &[]);
        invalid.content = "tampered".into();
        assert!(matches!(
            db.put(Visibility::Public, &invalid, NOW),
            Err(EventStoreError::Invalid)
        ));
        for tags in [
            vec![tag("expiration", "bad")],
            vec![tag("expiration", NOW + 10), tag("expiration", NOW + 20)],
        ] {
            assert!(matches!(
                db.put(Visibility::Public, &event(&key, 1, NOW, "", &tags), NOW),
                Err(EventStoreError::Invalid)
            ));
        }
        let big = event(&key, 1, NOW, &"x".repeat(MAX_EVENT_BYTES), &[]);
        assert!(matches!(
            db.put(Visibility::Public, &big, NOW),
            Err(EventStoreError::Oversize)
        ));
        assert!(
            db.query(Visibility::Public, &Filter::new(), NOW)
                .unwrap()
                .is_empty()
        );
        assert_eq!(db.logical_bytes().unwrap(), 0);
    }

    #[test]
    fn newer_or_unrelated_databases_are_refused_without_modification() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("future.sqlite");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch("CREATE TABLE saved(value); INSERT INTO saved VALUES('untouched'); PRAGMA user_version=5;").unwrap();
        }
        let refused = SqliteEventStore::open(&path, 1000);
        assert!(matches!(
            refused,
            Err(EventStoreError::NewerSchema {
                found: 5,
                supported: SCHEMA_VERSION
            })
        ));
        let message = refused.err().unwrap().to_string();
        assert!(message.contains("newer version"), "{message}");
        assert!(!message.contains("disk"), "{message}");
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT value FROM saved", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "untouched"
        );
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            5
        );
    }

    // ---- tag index, migration and read connections ----

    fn explain(
        conn: &Connection,
        sql: &str,
        values: Vec<Value>,
    ) -> Result<Vec<String>, rusqlite::Error> {
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        statement
            .query_map(params_from_iter(values), |r| r.get::<_, String>(3))?
            .collect()
    }

    /// Several authors or kinds: one `events_author_kind` seek per pair,
    /// merged, so an author with few events does not cost a walk of the
    /// partition. Same events, in the same order, as the event-driven oracle.
    #[test]
    fn several_authors_or_kinds_seek_each_pair_and_merge() {
        use serde_json::json;
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let (a, b, busy) = (Keys::generate(), Keys::generate(), Keys::generate());
        for (i, key) in [&a, &b].into_iter().enumerate() {
            for kind in [1, 7] {
                let at = NOW - 9000 + 10 * i as u64 + kind as u64;
                db.put(
                    Visibility::Public,
                    &event(key, kind, at, "old", &[tag("t", "x")]),
                    NOW,
                )
                .unwrap();
            }
            // One second shared by both quiet authors: the order is by id.
            db.put(
                Visibility::Public,
                &event(key, 1, NOW - 8000, "tie", &[]),
                NOW,
            )
            .unwrap();
        }
        for n in 0..300u64 {
            let note = event(&busy, 1, NOW - 4000 + n, &format!("n{n}"), &[]);
            db.put(Visibility::Public, &note, NOW).unwrap();
        }
        let (a, b, busy) = (
            a.public_key().to_hex(),
            b.public_key().to_hex(),
            busy.public_key().to_hex(),
        );
        for (raw, found) in [
            (json!({"authors": [a, b], "kinds": [1], "limit": 3}), 3),
            (json!({"authors": [a], "kinds": [1, 7], "limit": 10}), 3),
            (json!({"authors": [a, b], "kinds": [1, 7], "limit": 4}), 4),
            (json!({"authors": [a, b], "kinds": [1, 7]}), 6),
            (
                json!({"authors": [a, b, busy], "kinds": [1, 7], "limit": 5, "until": NOW - 3900}),
                5,
            ),
            (
                json!({"authors": [a, b], "kinds": [1, 7], "since": NOW - 8990, "until": NOW - 8000}),
                4,
            ),
            (json!({"authors": [a, b], "kinds": [1, 7], "#t": ["x"]}), 4),
        ] {
            let filter: Filter = serde_json::from_value(raw.clone()).unwrap();
            let limit = filter.limit.unwrap_or(MAX_QUERY_EVENTS);
            let (sql, values) = build_query(Visibility::Public, &filter, NOW, limit, true)
                .unwrap()
                .unwrap();
            let plan = db
                .with_reader(|conn| Ok(explain(conn, &sql, values)?))
                .unwrap()
                .join("\n");
            assert!(
                plan.contains("events_author_kind (visibility=? AND author=? AND kind=?"),
                "{raw}: {plan}"
            );
            assert!(!plan.contains("events_time"), "{raw}: {plan}");
            let got = ids(&db, Visibility::Public, filter.clone(), NOW);
            assert_eq!(got.len(), found, "{raw}");
            assert_eq!(got, oracle(&db, Visibility::Public, &filter, NOW), "{raw}");
        }
    }

    /// SQL reused by shape is the SQL `build_query` makes, with the same
    /// values in the same order, on the first query of a shape and on every
    /// later one; the cache stays within its bound.
    #[test]
    fn sql_cached_by_shape_matches_build_query_for_every_shape() {
        let tmp = TempDir::new().unwrap();
        let db = SqliteEventStore::open(&tmp.path().join("events.sqlite"), 1_000_000).unwrap();
        let (ka, kb) = (Keys::generate(), Keys::generate());
        let a = ka.public_key().to_hex();
        let b = kb.public_key().to_hex();
        // Rows for the queries to find, in both partitions.
        let mut seeded = Vec::new();
        for (i, (key, kind, tags)) in [
            (&ka, 1, vec![tag("t", "a")]),
            (&kb, 7, vec![tag("t", "b"), tag("d", "r")]),
            (&ka, 1460, vec![tag("d", "room")]),
            (&kb, 1460, vec![tag("d", "r1"), tag("t", "v3")]),
            (&ka, 1460, vec![tag("d", "r"), tag("t", "a")]),
            (&kb, 1, vec![tag("t", "v7")]),
        ]
        .into_iter()
        .enumerate()
        {
            let e = event(key, kind, NOW - 50 + i as u64, "seed", &tags);
            for scope in [Visibility::Public, Visibility::Sheltered] {
                db.put(scope, &e, NOW).unwrap();
            }
            seeded.push(e);
        }
        let id = seeded[2].id.to_hex();
        let many: Vec<String> = (0..MAX_MERGED_VALUES + 3)
            .map(|i| format!("v{i}"))
            .collect();
        let too_many: Vec<String> = (0..MAX_QUERY_VALUES).map(|i| format!("w{i}")).collect();
        let filters = [
            serde_json::json!({}),
            serde_json::json!({"limit": 5}),
            serde_json::json!({"ids": [id]}),
            serde_json::json!({"ids": []}),
            serde_json::json!({"authors": [a, b], "kinds": [1, 7]}),
            serde_json::json!({"kinds": [1460], "#d": ["room"]}),
            serde_json::json!({"kinds": [1460], "#d": ["other-room"], "limit": 50}),
            serde_json::json!({"kinds": [1460], "#d": ["r1", "r2"], "until": NOW - 5}),
            serde_json::json!({"#t": many}),
            serde_json::json!({"#t": ["a", "b"], "#d": ["r"], "since": NOW - 100}),
            serde_json::json!({"#d": ["r"], "#t": ["a", "b"]}),
            serde_json::json!({"authors": [a], "#d": ["r"]}),
            serde_json::json!({"since": NOW - 10, "until": NOW}),
            serde_json::json!({"#d": []}),
            serde_json::json!({"#t": too_many}),
            serde_json::json!({"since": u64::MAX}),
            serde_json::json!({"until": u64::MAX}),
        ];
        for scope in [Visibility::Public, Visibility::Sheltered] {
            for raw in &filters {
                let filter: Filter = serde_json::from_value(raw.clone()).unwrap();
                let limit = filter
                    .limit
                    .unwrap_or(MAX_QUERY_EVENTS)
                    .min(MAX_QUERY_EVENTS);
                let want = build_query(scope, &filter, NOW, limit, true);
                for pass in 0..2 {
                    let got = db
                        .query_sql(scope, &filter, NOW)
                        .map(|q| q.map(|(sql, values)| (sql.to_string(), values)));
                    match (&got, &want) {
                        (Ok(got), Ok(want)) => assert_eq!(got, want, "{raw} pass {pass}"),
                        (Err(_), Err(_)) => {}
                        _ => panic!("{raw} pass {pass}: {got:?} against {want:?}"),
                    }
                }
                // The cached SQL finds the rows the freshly built SQL finds.
                let fresh = want.as_ref().map(|q| {
                    q.as_ref().map_or_else(Vec::new, |(sql, values)| {
                        db.run_query(sql, values.clone(), StoredEvent::from_stored)
                            .unwrap()
                            .into_iter()
                            .map(|e| e.id)
                            .collect::<Vec<_>>()
                    })
                });
                let cached = db
                    .query_stored(scope, &filter, NOW)
                    .map(|rows| rows.into_iter().map(|e| e.id).collect::<Vec<_>>());
                match (&cached, &fresh) {
                    (Ok(cached), Ok(fresh)) => assert_eq!(cached, fresh, "{raw}"),
                    (Err(_), Err(_)) => {}
                    _ => panic!("{raw}: {cached:?} against {fresh:?}"),
                }
            }
        }
        // Bounded: many distinct shapes never hold more than the cap.
        for n in 1..=(SQL_CACHE_SHAPES + 40) {
            let values: Vec<String> = (0..n % 40 + 1).map(|i| format!("x{i}")).collect();
            let kinds: Vec<u16> = (0..(n / 40 + 1) as u16).collect();
            let filter: Filter =
                serde_json::from_value(serde_json::json!({"kinds": kinds, "#t": values})).unwrap();
            db.query_sql(Visibility::Public, &filter, NOW).unwrap();
            let cache = db.sql_cache.lock().unwrap();
            assert!(cache.entries.len() <= SQL_CACHE_SHAPES);
            assert!(cache.bytes <= SQL_CACHE_BYTES);
        }
        // Long SQL is never kept, and many long shapes cannot pass the byte
        // bound: the merged form repeats every other condition per branch.
        let kinds: Vec<u16> = (0..200).collect();
        let driver: Vec<String> = (0..MAX_MERGED_VALUES).map(|i| format!("d{i}")).collect();
        // `#x` keeps more values than `#t`, so `#t` drives in the merged form.
        for m in MAX_MERGED_VALUES + 1..=MAX_MERGED_VALUES + 60 {
            let other: Vec<String> = (0..m).map(|i| format!("o{i}")).collect();
            let filter: Filter = serde_json::from_value(
                serde_json::json!({"kinds": kinds, "#t": driver, "#x": other}),
            )
            .unwrap();
            let (sql, _) = db
                .query_sql(Visibility::Public, &filter, NOW)
                .unwrap()
                .unwrap();
            assert!(sql.len() > SQL_CACHE_ENTRY_BYTES);
            let cache = db.sql_cache.lock().unwrap();
            assert!(
                cache
                    .entries
                    .values()
                    .all(|sql| sql.len() <= SQL_CACHE_ENTRY_BYTES)
            );
            assert!(cache.bytes <= SQL_CACHE_BYTES);
        }
    }

    /// The event-driven shape, as it ran before the tag index existed.
    fn oracle(db: &SqliteEventStore, scope: Visibility, filter: &Filter, now: u64) -> Vec<String> {
        let limit = filter
            .limit
            .unwrap_or(MAX_QUERY_EVENTS)
            .min(MAX_QUERY_EVENTS);
        if limit == 0 {
            return vec![];
        }
        match build_query(scope, filter, now, limit, false).unwrap() {
            None => vec![],
            Some((sql, values)) => db
                .run_query(&sql, values, StoredEvent::from_stored)
                .unwrap()
                .into_iter()
                .map(|e| e.id)
                .collect(),
        }
    }

    /// Both partitions: ties in `created_at`, events with several tag
    /// values, an addressable room, expiring events and some deletions.
    fn seed_tag_matrix(db: &SqliteEventStore, keys: &[Keys]) -> Vec<String> {
        let mut seeded = Vec::new();
        let mut known = Vec::new();
        for partition in [Visibility::Public, Visibility::Sheltered] {
            for i in 0..48u64 {
                let author = (i % 3) as usize;
                let kind = if i % 4 == 0 { 30023 } else { 1 };
                let at = NOW - 200 + (i / 3) * 5;
                let mut tags = vec![tag("d", format!("room-{}", i % 5))];
                if i % 10 == 0 {
                    tags.push(tag("d", "room-9"));
                }
                if i % 2 == 0 {
                    tags.push(tag("t", "a"));
                }
                if i % 3 == 0 {
                    tags.push(tag("t", "b"));
                }
                if i % 7 == 0 {
                    tags.push(tag("p", keys[2].public_key().to_hex()));
                }
                if i % 11 == 0 {
                    tags.push(tag("expiration", NOW + 1));
                }
                let note = event(&keys[author], kind, at, &format!("note {i}"), &tags);
                db.put(partition, &note, NOW).unwrap();
                known.push(note.id.to_hex());
                seeded.push((partition, author, note));
            }
        }
        for (partition, author, note) in seeded.iter().filter(|(_, _, n)| n.content.ends_with('1'))
        {
            let deletion = event(
                &keys[*author],
                5,
                NOW - 1,
                "",
                &[tag("e", note.id.to_hex())],
            );
            db.put(*partition, &deletion, NOW).unwrap();
        }
        known
    }

    fn tag_matrix_filters(keys: &[Keys], known: &[String]) -> Vec<Filter> {
        let many: Vec<String> = (0..40).map(|n| format!("room-{n}")).collect();
        let peer = keys[2].public_key().to_hex();
        let tag_sets = [
            serde_json::json!({"#d":["room-1"]}),
            serde_json::json!({"#d":["room-1","room-2"]}),
            serde_json::json!({"#d":["room-9","room-1","room-3"]}),
            serde_json::json!({"#t":["a"]}),
            serde_json::json!({"#t":["a","b"]}),
            serde_json::json!({"#d":["room-1"],"#t":["a"]}),
            serde_json::json!({"#d":["room-0","room-1"],"#t":["a","b"]}),
            serde_json::json!({"#d":["room-1"],"#t":["a","b"],"#p":[peer]}),
            serde_json::json!({"#d":["nope"]}),
            serde_json::json!({"#d":[]}),
            serde_json::json!({"#p":[peer]}),
            serde_json::json!({"#d": many}),
            serde_json::json!({"#d": many, "#t":["b"]}),
            serde_json::json!({"ids":[known[3], known[4], known[60]],"#t":["a"]}),
            serde_json::json!({"ids":[known[3]],"#d":["room-3"]}),
        ];
        let mut out = Vec::new();
        for tags in &tag_sets {
            for authors in 0..3 {
                for kinds in 0..3 {
                    for window in 0..4 {
                        for limit in [None, Some(1), Some(4), Some(200)] {
                            let mut f = tags.as_object().unwrap().clone();
                            match authors {
                                1 => {
                                    f.insert(
                                        "authors".into(),
                                        serde_json::json!([keys[0].public_key().to_hex()]),
                                    );
                                }
                                2 => {
                                    f.insert(
                                        "authors".into(),
                                        serde_json::json!([
                                            keys[0].public_key().to_hex(),
                                            keys[1].public_key().to_hex()
                                        ]),
                                    );
                                }
                                _ => {}
                            }
                            match kinds {
                                1 => {
                                    f.insert("kinds".into(), serde_json::json!([1]));
                                }
                                2 => {
                                    f.insert("kinds".into(), serde_json::json!([1, 30023]));
                                }
                                _ => {}
                            }
                            if window & 1 == 1 {
                                f.insert("since".into(), serde_json::json!(NOW - 170));
                            }
                            if window & 2 == 2 {
                                f.insert("until".into(), serde_json::json!(NOW - 150));
                            }
                            if let Some(limit) = limit {
                                f.insert("limit".into(), serde_json::json!(limit));
                            }
                            out.push(serde_json::from_value(serde_json::Value::Object(f)).unwrap());
                        }
                    }
                }
            }
        }
        out
    }

    #[test]
    fn tag_driven_queries_match_the_event_driven_oracle() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let known = seed_tag_matrix(&db, &keys);
        let filters = tag_matrix_filters(&keys, &known);
        let (mut compared, mut non_empty, mut multi_hit) = (0, 0, 0);
        for filter in &filters {
            for scope in [Visibility::Public, Visibility::Sheltered] {
                // NOW + 1 expires the events carrying an expiration tag.
                for now in [NOW, NOW + 1] {
                    let got = ids(&db, scope, filter.clone(), now);
                    let want = oracle(&db, scope, filter, now);
                    assert_eq!(got, want, "filter {filter:?} scope {scope:?} now {now}");
                    let unique: std::collections::BTreeSet<_> = got.iter().collect();
                    assert_eq!(unique.len(), got.len(), "no event is returned twice");
                    compared += 1;
                    non_empty += usize::from(!got.is_empty());
                    multi_hit += usize::from(got.len() > 3);
                }
            }
        }
        assert!(compared > 1000 && non_empty > 500 && multi_hit > 50);
        // Past the merge limit the sorted fallback is used, with the same result.
        // The driving tag is the one with the fewest values, so both tags need
        // more than MAX_MERGED_VALUES for the fallback to be the driver.
        let rooms: Vec<String> = (0..40).map(|n| format!("room-{n}")).collect();
        let topics: Vec<String> = ["a", "b"]
            .into_iter()
            .map(String::from)
            .chain((0..38).map(|n| format!("unused-{n}")))
            .collect();
        let many: Filter = serde_json::from_value(serde_json::json!({
            "#d": rooms,
            "#t": topics,
            "limit": 10
        }))
        .unwrap();
        let (sql, _) = build_query(Visibility::Public, &many, NOW, 10, true)
            .unwrap()
            .unwrap();
        assert!(sql.contains("SELECT DISTINCT"));
        let got = ids(&db, Visibility::Public, many.clone(), NOW);
        assert_eq!(got.len(), 10);
        assert_eq!(got, oracle(&db, Visibility::Public, &many, NOW));
        // Same bound on the number of values as before.
        let too_many: Filter = serde_json::from_value(serde_json::json!({
            "#d": (0..600).map(|n| format!("room-{n}")).collect::<Vec<_>>()
        }))
        .unwrap();
        assert!(matches!(
            db.query(Visibility::Public, &too_many, NOW),
            Err(EventStoreError::Query)
        ));
    }

    /// What NIP-01 says the filter selects, computed in Rust from every live
    /// event of the partition: independent of both SQL shapes.
    fn model(all: &[Event], filter: &Filter, now: u64) -> Vec<String> {
        let mut hits: Vec<&Event> = all
            .iter()
            .filter(|e| filter.match_event(e, nostr::filter::MatchEventOptions::default()))
            .filter(|e| {
                !e.tags.iter().any(|t| {
                    let t = t.as_slice();
                    t.first().is_some_and(|n| n == "expiration")
                        && t.get(1)
                            .and_then(|v| v.parse::<u64>().ok())
                            .is_some_and(|at| at <= now)
                })
            })
            .collect();
        hits.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
        });
        hits.truncate(
            filter
                .limit
                .unwrap_or(MAX_QUERY_EVENTS)
                .min(MAX_QUERY_EVENTS),
        );
        hits.iter().map(|e| e.id.to_hex()).collect()
    }

    #[test]
    fn every_query_shape_matches_the_filter_semantics_computed_in_rust() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let known = seed_tag_matrix(&db, &keys);
        let filters = tag_matrix_filters(&keys, &known);
        let mut compared = 0;
        for scope in [Visibility::Public, Visibility::Sheltered] {
            let all = db
                .query(
                    scope,
                    &serde_json::from_value::<Filter>(serde_json::json!({"limit": 5000})).unwrap(),
                    0,
                )
                .unwrap();
            assert!(all.len() > 30, "the dump is not empty");
            // The dump is itself a query, so it is capped; a universe at the
            // cap may be truncated and would quietly weaken the comparison.
            assert!(
                all.len() < MAX_QUERY_EVENTS,
                "the universe ({}) must stay under the query cap ({MAX_QUERY_EVENTS}); \
                 shrink the seed or build the universe from the seeded events",
                all.len()
            );
            for now in [NOW, NOW + 1] {
                for filter in &filters {
                    let got = ids(&db, scope, filter.clone(), now);
                    assert_eq!(
                        got,
                        model(&all, filter, now),
                        "filter {filter:?} scope {scope:?} now {now}"
                    );
                    compared += 1;
                }
            }
        }
        assert!(compared > 2000);
    }

    /// A tag value that nearly every event carries, an author whose matching
    /// events are old: the author index answers it, not a walk of the tag.
    #[test]
    fn an_author_with_a_common_tag_is_driven_from_the_author_index() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let quiet = Keys::generate();
        let busy = Keys::generate();
        let old = event(&quiet, 1, NOW - 5000, "old", &[tag("t", "common")]);
        db.put(Visibility::Public, &old, NOW).unwrap();
        for n in 0..300u64 {
            let note = event(
                &busy,
                1,
                NOW - 4000 + n,
                &format!("n{n}"),
                &[tag("t", "common")],
            );
            db.put(Visibility::Public, &note, NOW).unwrap();
        }
        let filter: Filter = serde_json::from_value(serde_json::json!({
            "authors": [quiet.public_key().to_hex()],
            "kinds": [1],
            "#t": ["common"],
            "limit": 10
        }))
        .unwrap();
        let (sql, values) = build_query(Visibility::Public, &filter, NOW, 10, true)
            .unwrap()
            .unwrap();
        let plan = db
            .with_reader(|conn| Ok(explain(conn, &sql, values)?))
            .unwrap()
            .join("\n");
        assert!(plan.contains("events_author_kind"), "{plan}");
        assert!(!plan.contains("tags_by_time"), "{plan}");
        assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        assert_eq!(
            ids(&db, Visibility::Public, filter.clone(), NOW),
            vec![old.id.to_hex()]
        );
        assert_eq!(
            oracle(&db, Visibility::Public, &filter, NOW),
            vec![old.id.to_hex()]
        );
        // Authors without kinds are event-driven too, whatever the tag.
        let no_kind: Filter = serde_json::from_value(serde_json::json!({
            "authors": [quiet.public_key().to_hex()],
            "#t": ["common"]
        }))
        .unwrap();
        let (sql, _) = build_query(Visibility::Public, &no_kind, NOW, 10, true)
            .unwrap()
            .unwrap();
        assert!(!sql.contains("tags_by_time") && !sql.contains("FROM tags t CROSS JOIN"));
        // And without authors the same tag is still walked from the tag index.
        let room: Filter =
            serde_json::from_value(serde_json::json!({"kinds":[1],"#t":["common"],"limit":10}))
                .unwrap();
        let (sql, _) = build_query(Visibility::Public, &room, NOW, 10, true)
            .unwrap()
            .unwrap();
        assert!(sql.contains("FROM tags t CROSS JOIN events e"));
    }

    #[test]
    fn a_merged_room_query_sorts_keys_only_and_reads_each_body_once() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        seed_tag_matrix(&db, &keys);
        let rooms: Vec<String> = (0..40).map(|n| format!("room-{n}")).collect();
        for filter in [
            serde_json::json!({"#d":["room-1","room-2","room-9"],"limit":20}),
            serde_json::json!({"#d": rooms, "#t": ["a"], "limit": 20}),
            serde_json::json!({"#d": rooms, "#t": (0..40).map(|n| format!("t-{n}")).chain(["a".to_owned()]).collect::<Vec<_>>(), "limit": 20}),
        ] {
            let filter: Filter = serde_json::from_value(filter).unwrap();
            let (sql, values) = build_query(Visibility::Public, &filter, NOW, 20, true)
                .unwrap()
                .unwrap();
            assert_eq!(
                sql.matches("json").count(),
                1,
                "the body is selected once, in the outermost query: {sql}"
            );
            let plan = db
                .with_reader(|conn| Ok(explain(conn, &sql, values)?))
                .unwrap()
                .join("\n");
            // The merge sorts keys inside its co-routine; the outer query then
            // only looks each survivor's body up by primary key, in order,
            // with no sort of its own that would carry the body.
            // A single-value walk has no merge and no sort: the index holds
            // the id after the time, so even events tied on time come in
            // NIP-01 order.
            assert!(!plan.contains("SCAN e"), "{plan}");
            let outer = plan.rsplit("SCAN m").next().unwrap();
            assert!(!outer.contains("TEMP B-TREE"), "{plan}");
            assert!(
                outer.contains("SEARCH e USING INTEGER PRIMARY KEY"),
                "{plan}"
            );
            let got = ids(&db, Visibility::Public, filter.clone(), NOW);
            assert_eq!(got, oracle(&db, Visibility::Public, &filter, NOW));
            assert!(!got.is_empty());
        }
    }

    #[test]
    fn a_room_query_walks_the_tag_index_newest_first_without_sorting() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        seed_tag_matrix(&db, &keys);
        let filter: Filter =
            serde_json::from_value(serde_json::json!({"kinds":[1],"#d":["room-1"],"limit":50}))
                .unwrap();
        let (sql, values) = build_query(Visibility::Public, &filter, NOW, 50, true)
            .unwrap()
            .unwrap();
        let plan = db
            .with_reader(|conn| Ok(explain(conn, &sql, values)?))
            .unwrap();
        let plan = plan.join("\n");
        assert!(
            plan.contains("COVERING INDEX tags_by_time (visibility=? AND name=? AND value=?)"),
            "{plan}"
        );
        assert!(plan.contains("USING INTEGER PRIMARY KEY"), "{plan}");
        // Nothing is sorted, not even events tied on time: the walk is in
        // index order (time, then id) and stops at the limit however many
        // events share a second.
        assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        assert!(!plan.contains("SCAN"), "{plan}");
        // Several rooms: each is its own newest-first walk of the index.
        let rooms: Filter =
            serde_json::from_value(serde_json::json!({"#d":["room-1","room-2"],"limit":50}))
                .unwrap();
        let (sql, values) = build_query(Visibility::Public, &rooms, NOW, 50, true)
            .unwrap()
            .unwrap();
        let plan = db
            .with_reader(|conn| Ok(explain(conn, &sql, values)?))
            .unwrap()
            .join("\n");
        assert_eq!(
            plan.matches("COVERING INDEX tags_by_time").count(),
            2,
            "{plan}"
        );
        // `SCAN e`/`SCAN t` would be a table scan; `SCAN (subquery-N)` is the merge.
        assert!(
            plan.lines()
                .all(|l| !(l.starts_with("SCAN e") || l.starts_with("SCAN t"))),
            "{plan}"
        );
    }

    /// A store as the previous release left it: schema v1 plus the v2 reserve
    /// triggers, tags with four columns and the `tags_lookup` index.
    fn v2_fixture(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        for (table, cost) in [
            ("events", "length(CAST(ROW.json AS BLOB))+512"),
            ("tags", "length(CAST(ROW.value AS BLOB))+160"),
            ("heads", "length(CAST(ROW.coordinate AS BLOB))+256"),
            ("deleted_ids", "192"),
            (
                "deleted_coordinates",
                "length(CAST(ROW.coordinate AS BLOB))+192",
            ),
        ] {
            let new = cost.replace("ROW.", "NEW.");
            let old = cost.replace("ROW.", "OLD.");
            conn.execute_batch(&format!("CREATE TRIGGER {table}_charge_insert AFTER INSERT ON {table} BEGIN UPDATE usage SET bytes=bytes+({new}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_delete AFTER DELETE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old}) WHERE id=1; END;
CREATE TRIGGER {table}_charge_update AFTER UPDATE ON {table} BEGIN UPDATE usage SET bytes=bytes-({old})+({new}) WHERE id=1; END;")).unwrap();
        }
        let cost = format!(
            "length(CAST(ROW.json AS BLOB))+512+CASE WHEN ROW.kind=5 THEN 0 ELSE {DELETION_RESERVE_BYTES} END"
        );
        let new = cost.replace("ROW.", "NEW.");
        let old = cost.replace("ROW.", "OLD.");
        conn.execute_batch(&format!("DROP TRIGGER events_charge_insert;
DROP TRIGGER events_charge_delete;
DROP TRIGGER events_charge_update;
CREATE TRIGGER events_charge_insert AFTER INSERT ON events BEGIN UPDATE usage SET bytes=bytes+({new}) WHERE id=1; END;
CREATE TRIGGER events_charge_delete AFTER DELETE ON events BEGIN UPDATE usage SET bytes=bytes-({old}) WHERE id=1; END;
CREATE TRIGGER events_charge_update AFTER UPDATE ON events BEGIN UPDATE usage SET bytes=bytes-({old})+({new}) WHERE id=1; END;
PRAGMA user_version=2;")).unwrap();
        conn
    }

    fn insert_v2(conn: &Connection, scope: Visibility, note: &Event) {
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,NULL,NULL,?)",
            params![
                scope.key(),
                note.id.to_hex(),
                note.pubkey.to_hex(),
                note.kind.as_u16(),
                note.created_at.as_secs() as i64,
                serde_json::to_string(note).unwrap()
            ],
        )
        .unwrap();
        for tag in note.tags.iter().map(|t| t.as_slice()) {
            if tag.len() >= 2 && tag[0].len() == 1 && tag[0].as_bytes()[0].is_ascii_alphabetic() {
                conn.execute(
                    "INSERT OR IGNORE INTO tags VALUES(?,?,?,?)",
                    params![scope.key(), note.id.to_hex(), tag[0], tag[1]],
                )
                .unwrap();
            }
        }
    }

    fn v2_fixture_with_events(path: &Path) -> (i64, Vec<(i64, String, String, String)>) {
        let conn = v2_fixture(path);
        let key = Keys::generate();
        for i in 0..40u64 {
            let scope = if i % 2 == 0 {
                Visibility::Public
            } else {
                Visibility::Sheltered
            };
            let mut tags = vec![tag("d", format!("room-{}", i % 4))];
            if i % 3 == 0 {
                tags.push(tag("t", "a"));
                tags.push(tag("t", "b"));
            }
            insert_v2(
                &conn,
                scope,
                &event(&key, 1, NOW - 100 + i / 2, &format!("old {i}"), &tags),
            );
        }
        (logical_bytes(&conn).unwrap() as i64, tag_rows(&conn))
    }

    /// Every tag row as (visibility, event id in hex, name, value), from
    /// either layout: version 4 keeps the id on the event.
    fn tag_rows(conn: &Connection) -> Vec<(i64, String, String, String)> {
        let v4: bool = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('tags') WHERE name='seq'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
            == 1;
        let sql = if v4 {
            "SELECT t.visibility,lower(hex(e.id)),t.name,t.value FROM tags t JOIN events e ON e.seq=t.seq ORDER BY 1,2,3,4"
        } else {
            "SELECT visibility,id,name,value FROM tags ORDER BY 1,2,3,4"
        };
        conn.prepare(sql)
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn schema_snapshot(conn: &Connection) -> Vec<(String, String, Option<String>)> {
        conn.prepare("SELECT type,name,sql FROM sqlite_master ORDER BY 1,2")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// A version 2 store goes through version 3 to version 4 in one open.
    #[test]
    fn v2_migration_backfills_tag_times_keeps_usage_and_reruns_as_a_no_op() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let (usage, tags_before) = v2_fixture_with_events(&path);
        assert!(tags_before.len() > 40);
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        assert_eq!(db.logical_bytes().unwrap() as i64, usage);
        let (schema, version) = {
            let conn = db.lock().unwrap();
            assert_eq!(tag_rows(&conn), tags_before);
            let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
            assert_eq!(count("SELECT count(*) FROM events"), 40);
            assert_eq!(
                count("SELECT count(*) FROM tags WHERE created_at IS NULL"),
                0
            );
            assert_eq!(
                count(
                    "SELECT count(*) FROM tags t JOIN events e ON e.seq=t.seq WHERE t.created_at IS NOT e.created_at OR t.visibility IS NOT e.visibility OR t.id IS NOT e.id"
                ),
                0,
                "every tag row carries its event's time and id"
            );
            assert_eq!(
                count("SELECT count(*) FROM sqlite_master WHERE name='tags_by_time'"),
                1
            );
            assert_eq!(
                count("SELECT count(*) FROM sqlite_master WHERE name='tags_lookup'"),
                0
            );
            (schema_snapshot(&conn), count("PRAGMA user_version"))
        };
        assert_eq!(version, SCHEMA_VERSION);
        // The migrated index answers room queries exactly as the old walk did.
        let room: Filter = serde_json::from_value(
            serde_json::json!({"#d":["room-1","room-2"],"#t":["b"],"limit":50}),
        )
        .unwrap();
        for scope in [Visibility::Public, Visibility::Sheltered] {
            let got = ids(&db, scope, room.clone(), NOW);
            assert!(!got.is_empty());
            assert_eq!(got, oracle(&db, scope, &room, NOW));
        }
        // New writes and the migrated rows live in one index.
        let key = Keys::generate();
        let fresh = event(&key, 1, NOW, "fresh", &[tag("d", "room-1"), tag("t", "b")]);
        db.put(Visibility::Public, &fresh, NOW).unwrap();
        assert_eq!(
            ids(&db, Visibility::Public, room.clone(), NOW)[0],
            fresh.id.to_hex()
        );
        drop(db);
        // Re-running is a no-op: same schema, rows and charge.
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        let conn = db.lock().unwrap();
        let mut again = schema_snapshot(&conn);
        again.sort();
        let mut before = schema;
        before.sort();
        assert_eq!(again, before);
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn a_failed_v3_migration_leaves_the_v2_store_untouched_and_retries() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let (usage, tags_before) = v2_fixture_with_events(&path);
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TRIGGER test_refuse_backfill BEFORE UPDATE ON tags BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;")
            .unwrap();
        assert!(matches!(
            SqliteEventStore::open(&path, 10_000_000),
            Err(EventStoreError::Sqlite(_))
        ));
        let conn = Connection::open(&path).unwrap();
        let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
        assert_eq!(count("PRAGMA user_version"), 2);
        assert_eq!(
            count("SELECT count(*) FROM pragma_table_info('tags') WHERE name='created_at'"),
            0
        );
        assert_eq!(
            count("SELECT count(*) FROM sqlite_master WHERE name='tags_lookup'"),
            1
        );
        assert_eq!(
            count("SELECT count(*) FROM sqlite_master WHERE name='tags_by_time'"),
            0
        );
        assert_eq!(logical_bytes(&conn).unwrap() as i64, usage);
        assert_eq!(tag_rows(&conn), tags_before);
        conn.execute_batch("DROP TRIGGER test_refuse_backfill")
            .unwrap();
        drop(conn);
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        assert_eq!(db.logical_bytes().unwrap() as i64, usage);
        assert_eq!(ids(&db, Visibility::Public, Filter::new(), NOW).len(), 20);
    }

    #[test]
    fn a_v3_migration_without_the_free_space_it_needs_is_refused_before_it_starts() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let (usage, tags_before) = v2_fixture_with_events(&path);
        let before = std::fs::metadata(&path).unwrap().len();
        // Enough for the open-time guard, then too little for the rewrite.
        let tight = SqliteEventStore::open_with_space(
            &path,
            10_000_000,
            0,
            Arc::new(SequenceFreeSpace(Mutex::new(vec![
                TRANSACTION_GUARD_BYTES,
                TRANSACTION_GUARD_BYTES,
            ]))),
        );
        // A disk refusal, named as one: not the store's own byte budget.
        match tight {
            Err(EventStoreError::DiskSpace { needed, available }) => {
                assert_eq!(available, TRANSACTION_GUARD_BYTES);
                assert!(needed > available, "{needed} vs {available}");
                let estimate = migration_estimate(&Connection::open(&path).unwrap()).unwrap();
                assert_eq!(
                    needed,
                    TRANSACTION_GUARD_BYTES + estimate.disk_bytes,
                    "min_free (0 here) + guard + the estimate"
                );
            }
            other => panic!("expected a disk-space refusal, got {:?}", other.err()),
        }
        let conn = Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2,
            "still the v2 store"
        );
        assert_eq!(tag_rows(&conn), tags_before);
        assert_eq!(logical_bytes(&conn).unwrap() as i64, usage);
        drop(conn);
        assert!(
            std::fs::metadata(&path).unwrap().len() <= before + 64 * 1024,
            "nothing was written"
        );
        // Once space is freed the next open upgrades it.
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        assert_eq!(db.logical_bytes().unwrap() as i64, usage);
    }

    /// A store of `events` events with `tags_each` distinct tags and
    /// `content` bytes of text each, as the previous release left it.
    fn v2_store_of(path: &Path, events: u64, tags_each: u64, content: usize) {
        let conn = v2_fixture(path);
        let key = Keys::generate();
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..events {
            let tags: Vec<Vec<String>> = (0..tags_each)
                .map(|t| tag("e", format!("{:064x}", i * 1_000_003 + t)))
                .collect();
            insert_v2(
                &conn,
                Visibility::Public,
                &event(&key, 1, NOW - i, &"x".repeat(content), &tags),
            );
        }
        conn.execute_batch("COMMIT").unwrap();
    }

    #[test]
    fn the_v3_index_sort_stays_in_memory_only_below_the_ceiling() {
        assert_eq!(migration_temp_store_pragma(0), "PRAGMA temp_store = MEMORY");
        assert_eq!(
            migration_temp_store_pragma(MIGRATION_MEMORY_SORT_CEILING),
            "PRAGMA temp_store = MEMORY"
        );
        assert_eq!(
            migration_temp_store_pragma(MIGRATION_MEMORY_SORT_CEILING + 1),
            "PRAGMA temp_store = DEFAULT"
        );
    }

    #[test]
    fn the_v3_estimate_follows_the_tag_data_not_the_size_of_the_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        // Event text dominates the file; each event carries one tag.
        v2_store_of(&path, 200, 1, 8000);
        let conn = Connection::open(&path).unwrap();
        let estimate = migration_estimate(&conn).unwrap();
        assert_eq!(estimate.tag_rows, 200);
        assert_eq!(estimate.tag_bytes, 200 * 129);
        let whole = database_bytes(&conn).unwrap();
        assert!(
            estimate.disk_bytes < whole / 4,
            "a JSON-heavy store is not charged for its JSON: {} vs {whole}",
            estimate.disk_bytes
        );
        assert_eq!(migration_disk_bytes(0, 0), 0, "no tags, nothing to rewrite");
    }

    #[test]
    fn the_v3_estimate_covers_what_the_migration_writes_through_the_wal() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        // Tag-heavy: every tag is a 64-hex id, so the tag rows outweigh the JSON.
        v2_store_of(&path, 100, 100, 10);
        let conn = Connection::open(&path).unwrap();
        let estimate = migration_estimate(&conn).unwrap();
        assert_eq!(estimate.tag_rows, 10_000);
        // The migration's own statements, in a WAL that is never checkpointed,
        // so the file after commit is what it wrote through the log.
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        conn.pragma_update(None, "secure_delete", true).unwrap();
        conn.execute_batch("BEGIN").unwrap();
        conn.execute_batch(MIGRATE_V3_SQL).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        let wal = std::fs::metadata(path.with_extension("sqlite-wal"))
            .unwrap()
            .len();
        assert!(wal > estimate.tag_bytes, "the log really took the rewrite");
        assert!(
            estimate.disk_bytes >= wal,
            "estimate {} must cover the WAL the migration wrote, {wal}",
            estimate.disk_bytes
        );
    }

    #[test]
    fn a_reader_that_will_not_open_does_not_stop_the_store() {
        // The pool is all or nothing: one failure leaves reads on the writer.
        let opened = AtomicUsize::new(0);
        let pool = open_readers(2, || {
            if opened.fetch_add(1, Ordering::SeqCst) == 1 {
                Err(EventStoreError::Schema)
            } else {
                Ok(Connection::open_in_memory().unwrap())
            }
        });
        assert!(pool.is_empty());
        assert_eq!(opened.load(Ordering::SeqCst), 2);

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        assert!(!db.readers.is_empty());
        drop(db);
        let writer_only = SqliteEventStore {
            readers: Vec::new(),
            ..SqliteEventStore::open(&path, 10_000_000).unwrap()
        };
        let key = Keys::generate();
        let note = event(&key, 1, NOW, "via the writer", &[tag("d", "room")]);
        writer_only.put(Visibility::Public, &note, NOW).unwrap();
        assert_eq!(
            ids(
                &writer_only,
                Visibility::Public,
                serde_json::from_value(serde_json::json!({"#d":["room"]})).unwrap(),
                NOW
            ),
            vec![note.id.to_hex()]
        );
    }

    #[test]
    fn the_wal_is_bounded_and_checkpointed_by_the_store() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let conn = db.lock().unwrap();
        // The checkpoint thread owns checkpointing: SQLite's automatic one,
        // which would run inside the commit, is off.
        assert_eq!(
            conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("PRAGMA journal_size_limit", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            WAL_SIZE_LIMIT_BYTES
        );
        assert!(db.maintenance.background);
    }

    #[test]
    fn without_the_background_checkpoint_the_writer_keeps_the_automatic_one() {
        let tmp = TempDir::new().unwrap();
        let db = SqliteEventStore::open_with_options(
            &tmp.path().join("events.sqlite"),
            10_000_000,
            0,
            StoreOptions {
                background_checkpoint: false,
                ..StoreOptions::default()
            },
        )
        .unwrap();
        assert!(db.maintenance.threads.is_empty());
        let conn = db.lock().unwrap();
        assert_eq!(
            conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1000
        );
    }

    #[test]
    fn a_read_does_not_wait_for_the_writer_lock() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(store(&tmp));
        let key = Keys::generate();
        let note = event(&key, 1, NOW - 5, "visible", &[tag("d", "room")]);
        db.put(Visibility::Public, &note, NOW).unwrap();
        let writer = db.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = Arc::clone(&db);
        let handle = std::thread::spawn(move || {
            let filter: Filter =
                serde_json::from_value(serde_json::json!({"#d":["room"]})).unwrap();
            let rows = reader
                .query(Visibility::Public, &filter, NOW)
                .map(|v| v.len());
            let plain = reader
                .query(Visibility::Public, &Filter::new(), NOW)
                .map(|v| v.len());
            sender.send((rows.unwrap(), plain.unwrap())).unwrap();
        });
        let got = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("a query must not queue behind the writer");
        drop(writer);
        handle.join().unwrap();
        assert_eq!(got, (1, 1));
    }

    #[test]
    fn a_read_in_progress_does_not_block_a_write_and_keeps_its_snapshot() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        assert!(!db.readers.is_empty(), "the store opened read connections");
        let key = Keys::generate();
        for n in 0..3 {
            let note = event(&key, 1, NOW - 10 + n, &format!("n{n}"), &[tag("d", "room")]);
            db.put(Visibility::Public, &note, NOW).unwrap();
        }
        let late = event(&key, 1, NOW - 1, "late", &[tag("d", "room")]);
        db.with_reader(|conn| {
            let journal: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            assert_eq!(journal, "wal");
            let mut statement = conn.prepare("SELECT id FROM events ORDER BY id")?;
            let mut rows = statement.query([])?;
            assert!(rows.next()?.is_some(), "the read transaction is now open");
            let began = std::time::Instant::now();
            assert_eq!(
                db.put(Visibility::Public, &late, NOW).unwrap(),
                PutOutcome::Stored
            );
            assert!(
                began.elapsed() < Duration::from_secs(2),
                "the write did not wait for the reader"
            );
            let mut seen = 1;
            while rows.next()?.is_some() {
                seen += 1;
            }
            assert_eq!(seen, 3, "the open read keeps its snapshot");
            Ok(())
        })
        .unwrap();
        // A later read sees the committed write.
        assert_eq!(ids(&db, Visibility::Public, Filter::new(), NOW).len(), 4);
    }

    fn prepared(vis: Visibility, event: &Event) -> PreparedPut {
        PreparedPut::new(vis, event.clone(), NOW, false).unwrap()
    }

    fn notes(keys: &Keys, count: u64, text: &str) -> Vec<Event> {
        (0..count)
            .map(|n| event(keys, 1, NOW - 1000 + n, &format!("{text}{n}"), &[]))
            .collect()
    }

    fn all_ids(db: &SqliteEventStore) -> Vec<String> {
        let mut found = ids(db, Visibility::Public, Filter::new().limit(128), NOW);
        found.extend(ids(
            db,
            Visibility::Sheltered,
            Filter::new().limit(128),
            NOW,
        ));
        found.sort();
        found
    }

    #[test]
    fn a_batch_of_events_is_one_commit_where_single_puts_are_one_each() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        let batch: Vec<_> = notes(&key, 20, "batched")
            .iter()
            .map(|e| prepared(Visibility::Public, e))
            .collect();
        let before = db.commits();
        let results = db.put_prepared_batch(&batch);
        assert_eq!(results.len(), 20);
        assert!(results.iter().all(|r| matches!(r, Ok(PutOutcome::Stored))));
        assert_eq!(db.commits() - before, 1, "twenty events, one transaction");
        assert_eq!(all_ids(&db).len(), 20);
        let singles = notes(&key, 5, "single");
        let before = db.commits();
        for e in &singles {
            db.put(Visibility::Public, e, NOW).unwrap();
        }
        assert_eq!(db.commits() - before, 5, "a lone put is its own commit");
    }

    /// The pre-state and batch for the differential test: every refusal the
    /// store makes, in an order where later events depend on earlier ones.
    fn mixed_scenario() -> (Vec<Event>, Vec<Event>) {
        let key = Keys::generate();
        let other = Keys::generate();
        let held = event(&key, 1, NOW - 50, "already held", &[]);
        // A tombstone for an id that has not arrived, and a coordinate barrier.
        let doomed = event(&key, 1, NOW - 40, "deleted before arrival", &[]);
        let barred = event(&key, 30023, NOW - 30, "barred", &[tag("d", "page")]);
        let barrier = event(
            &key,
            5,
            NOW - 20,
            "",
            &[
                tag("e", doomed.id.to_hex()),
                tag("a", format!("30023:{}:page", key.public_key())),
            ],
        );
        let fresh = event(&key, 1, NOW - 10, "fresh", &[tag("t", "x")]);
        let head_new = event(&key, 10002, NOW - 9, "head new", &[]);
        let head_old = event(&key, 10002, NOW - 108, "head old", &[]);
        let page_ok = event(
            &key,
            30023,
            NOW - 1,
            "page after barrier",
            &[tag("d", "page")],
        );
        let big = event(&key, 1, NOW - 7, &"b".repeat(60_000), &[]);
        let removal = event(&key, 5, NOW - 5, "", &[tag("e", fresh.id.to_hex())]);
        let mut batch = vec![
            fresh.clone(),
            held.clone(),
            fresh,
            doomed,
            barred,
            head_new,
            head_old,
            page_ok,
            big,
            event(&other, 1, NOW - 4, "other author", &[]),
            event(&other, 20001, NOW - 3, "ephemeral", &[]),
        ];
        // Enough small events to run the budget out part way through.
        batch.extend(notes(&other, 40, "fill"));
        batch.push(removal);
        batch.push(event(&other, 1, NOW - 2, "after the budget", &[]));
        (vec![held, barrier], batch)
    }

    #[test]
    fn a_mixed_batch_gets_what_each_event_gets_one_at_a_time() {
        let tmp = TempDir::new().unwrap();
        let open = |name: &str| SqliteEventStore::open(&tmp.path().join(name), 40_000).unwrap();
        let batched = open("batched.sqlite");
        let single = open("single.sqlite");
        let (pre, events) = mixed_scenario();
        for db in [&batched, &single] {
            for e in &pre {
                db.put(Visibility::Public, e, NOW).unwrap();
            }
        }
        let puts: Vec<_> = events
            .iter()
            .map(|e| prepared(Visibility::Public, e))
            .collect();
        let together: Vec<String> = batched
            .put_prepared_batch(&puts)
            .iter()
            .map(|r| format!("{r:?}"))
            .collect();
        let apart: Vec<String> = events
            .iter()
            .map(|e| format!("{:?}", single.put(Visibility::Public, e, NOW)))
            .collect();
        assert_eq!(together, apart);
        for expected in [
            "Ok(Stored)",
            "Ok(Duplicate)",
            "Err(Retired)",
            "Err(Full)",
            "Ok(Ephemeral)",
        ] {
            assert!(together.iter().any(|r| r == expected), "no {expected}");
        }
        assert_eq!(all_ids(&batched), all_ids(&single));
        assert_eq!(
            batched.logical_bytes().unwrap(),
            single.logical_bytes().unwrap()
        );
    }

    #[test]
    fn a_failed_commit_answers_every_event_and_stores_none_of_them() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        let held = event(&key, 1, NOW - 50, "already held", &[]);
        db.put(Visibility::Public, &held, NOW).unwrap();
        let used = db.logical_bytes().unwrap();
        let mut events = notes(&key, 6, "doomed");
        events.push(held.clone());
        let batch: Vec<_> = events
            .iter()
            .map(|e| prepared(Visibility::Public, e))
            .collect();
        for (code, full) in [
            (rusqlite::ffi::SQLITE_FULL, true),
            (rusqlite::ffi::SQLITE_IOERR, false),
        ] {
            db.commit_fault.store(code, AtomicOrdering::SeqCst);
            let commits = db.commits();
            let results = db.put_prepared_batch(&batch);
            assert_eq!(results.len(), batch.len());
            for result in &results {
                match result {
                    Err(EventStoreError::Full) if full => {}
                    Err(EventStoreError::Sqlite(_)) if !full => {}
                    other => panic!("every event takes the failure, got {other:?}"),
                }
            }
            assert_eq!(db.commits(), commits, "nothing committed");
            assert_eq!(all_ids(&db), vec![held.id.to_hex()]);
            assert_eq!(db.logical_bytes().unwrap(), used);
        }
        db.commit_fault.store(0, AtomicOrdering::SeqCst);
        let results = db.put_prepared_batch(&batch);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(PutOutcome::Stored)))
                .count(),
            6
        );
        assert!(matches!(results[6], Ok(PutOutcome::Duplicate)));
    }

    /// A store whose batches get a budget of `budget`, with a clean open.
    fn budgeted(tmp: &TempDir, budget: Duration) -> SqliteEventStore {
        SqliteEventStore::open(&tmp.path().join("budgeted.sqlite"), 10_000_000)
            .unwrap()
            .with_batch_budget(budget)
    }

    fn stored_count(results: &[PutResult]) -> usize {
        results
            .iter()
            .filter(|r| matches!(r, Ok(PutOutcome::Stored)))
            .count()
    }

    fn is_deferred(result: &PutResult) -> bool {
        matches!(result, Err(EventStoreError::Deferred))
    }

    #[test]
    fn a_rerun_pass_counts_from_the_batch_start_so_interrupted_events_cannot_stack_their_time() {
        let tmp = TempDir::new().unwrap();
        let db = budgeted(&tmp, Duration::from_millis(600));
        let key = Keys::generate();
        let events = notes(&key, 6, "rerun");
        // [1] spends two thirds of the budget, then [2] is interrupted at its
        // first write, which takes the transaction (and [0], [1]) down. The
        // rerun starts [0], then [1] again, which spends the rest.
        {
            let mut slow = db.slow.lock().unwrap();
            slow.push((events[1].id.to_hex(), Slow::Takes(400)));
            slow.push((events[2].id.to_hex(), Slow::AtFirstWrite));
        }
        let batch: Vec<_> = events
            .iter()
            .map(|e| prepared(Visibility::Public, e))
            .collect();
        let began = std::time::Instant::now();
        let results = db.put_prepared_batch(&batch);
        let took = began.elapsed();
        assert_eq!(db.reruns.load(AtomicOrdering::SeqCst), 1, "{results:?}");
        assert!(matches!(results[0], Ok(PutOutcome::Stored)), "{results:?}");
        assert!(matches!(results[1], Ok(PutOutcome::Stored)), "{results:?}");
        assert!(
            matches!(
                results[2],
                Err(EventStoreError::Sqlite(rusqlite::Error::SqliteFailure(e, _)))
                    if e.code == rusqlite::ErrorCode::OperationInterrupted
            ),
            "{results:?}"
        );
        // With a fresh budget the rerun would have gone on to store these.
        for result in &results[3..] {
            assert!(
                is_deferred(result),
                "carried over, not started: {results:?}"
            );
        }
        assert!(
            took < Duration::from_millis(1_400),
            "two slow passes of 400 ms each, no third: {took:?}"
        );
        assert_eq!(all_ids(&db).len(), 2);
    }

    #[test]
    fn every_pass_starts_its_first_event_so_a_spent_budget_still_terminates() {
        let tmp = TempDir::new().unwrap();
        // Spent before the first event is reached.
        let db = budgeted(&tmp, Duration::ZERO);
        let key = Keys::generate();
        let events = notes(&key, 4, "spent");
        let batch: Vec<_> = events
            .iter()
            .map(|e| prepared(Visibility::Public, e))
            .collect();
        let results = db.put_prepared_batch(&batch);
        assert!(matches!(results[0], Ok(PutOutcome::Stored)), "{results:?}");
        for result in &results[1..] {
            assert!(is_deferred(result), "{results:?}");
        }
        assert_eq!(all_ids(&db).len(), 1);

        // Every event interrupted at its write, so every pass is lost: each
        // rerun starts the next event, and the loop ends having refused all.
        let more = notes(&key, 4, "lost");
        {
            let mut slow = db.slow.lock().unwrap();
            for e in &more {
                slow.push((e.id.to_hex(), Slow::AtFirstWrite));
            }
        }
        let batch: Vec<_> = more
            .iter()
            .map(|e| prepared(Visibility::Public, e))
            .collect();
        let before = db.reruns.load(AtomicOrdering::SeqCst);
        let results = db.put_prepared_batch(&batch);
        assert_eq!(db.reruns.load(AtomicOrdering::SeqCst) - before, 4);
        assert!(
            results
                .iter()
                .all(|r| matches!(r, Err(EventStoreError::Sqlite(_)))),
            "each was started once and refused: {results:?}"
        );
        assert_eq!(all_ids(&db).len(), 1, "nothing of a lost pass is stored");
    }

    #[test]
    fn the_budget_is_checked_before_the_recheck_and_a_slow_recheck_cannot_defer_a_whole_batch() {
        let tmp = TempDir::new().unwrap();
        let db = budgeted(&tmp, Duration::from_millis(50));
        let key = Keys::generate();
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let batch: Vec<_> = notes(&key, 4, "slow recheck")
            .iter()
            .map(|e| {
                let asked = Arc::clone(&asked);
                prepared(Visibility::Public, e).with_recheck(Arc::new(move |_: &Event| {
                    asked.fetch_add(1, AtomicOrdering::SeqCst);
                    // A state database that is busy: longer than the budget.
                    std::thread::sleep(Duration::from_millis(120));
                    true
                }))
            })
            .collect();
        let results = db.put_prepared_batch(&batch);
        assert!(
            matches!(results[0], Ok(PutOutcome::Stored)),
            "the first event is started whatever its recheck cost: {results:?}"
        );
        assert_eq!(stored_count(&results), 1);
        for result in &results[1..] {
            assert!(is_deferred(result), "{results:?}");
        }
        assert_eq!(
            asked.load(AtomicOrdering::SeqCst),
            1,
            "a deferred event costs no recheck"
        );
    }

    #[test]
    fn a_batch_that_fails_as_a_whole_keeps_the_events_it_refused_before_the_failure() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        let events = notes(&key, 3, "doomed");
        let batch = vec![
            prepared(Visibility::Public, &events[0]),
            prepared(Visibility::Public, &events[1]).with_recheck(Arc::new(|_: &Event| false)),
            prepared(Visibility::Public, &events[2]),
        ];
        db.commit_fault
            .store(rusqlite::ffi::SQLITE_IOERR, AtomicOrdering::SeqCst);
        let results = db.put_prepared_batch(&batch);
        db.commit_fault.store(0, AtomicOrdering::SeqCst);
        assert!(
            matches!(results[0], Err(EventStoreError::Sqlite(_))),
            "{results:?}"
        );
        assert!(
            matches!(results[1], Err(EventStoreError::Unauthorised)),
            "a definite refusal is not replaced by the batch's error: {results:?}"
        );
        assert!(matches!(results[2], Err(EventStoreError::Sqlite(_))));
        assert!(all_ids(&db).is_empty());
    }

    #[test]
    fn a_batch_recheck_failure_rolls_back_ordinary_events_and_keeps_deletions() {
        let tmp = TempDir::new().unwrap();
        let reserve = 16 * 1024 * 1024;
        let ok = reserve + TRANSACTION_GUARD_BYTES;
        // open, two pre-checks, then the recheck falls short, then room again.
        let db = guarded_store(&tmp, vec![ok, ok, ok, reserve - 1, ok]);
        let key = Keys::generate();
        let removal = event(&key, 5, NOW - 7, "", &[tag("e", "ab".repeat(32))]);
        let a = event(&key, 1, NOW - 9, "a", &[]);
        let b = event(&key, 1, NOW - 8, "b", &[]);
        let batch = vec![
            prepared(Visibility::Public, &a),
            prepared(Visibility::Public, &removal),
            prepared(Visibility::Public, &b),
        ];
        let results = db.put_prepared_batch(&batch);
        assert!(
            matches!(results[0], Err(EventStoreError::Full)),
            "{results:?}"
        );
        assert!(matches!(results[2], Err(EventStoreError::Full)));
        // A deletion is exempt from headroom, so it is tried again alone.
        assert!(matches!(results[1], Ok(PutOutcome::Stored)), "{results:?}");
        assert_eq!(all_ids(&db), vec![removal.id.to_hex()]);
        assert_eq!(db.commits(), 1, "the retry is one commit of the deletion");
    }

    // ---- store I/O: background checkpoint, caches, map, warm-up, tag insert ----

    fn io_store(tmp: &TempDir, options: StoreOptions) -> SqliteEventStore {
        SqliteEventStore::open_with_options(
            &tmp.path().join("events.sqlite"),
            1_000_000_000,
            0,
            options,
        )
        .unwrap()
    }

    fn wal_len(tmp: &TempDir) -> u64 {
        std::fs::metadata(tmp.path().join("events.sqlite-wal"))
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// `count` big notes in batches of `per_batch`; every batch is one commit.
    fn write_notes(db: &SqliteEventStore, key: &Keys, from: u64, count: u64, per_batch: u64) {
        let text = "w".repeat(3000);
        let all: Vec<PreparedPut> = (from..from + count)
            .map(|n| {
                prepared(
                    Visibility::Public,
                    &event(
                        key,
                        1,
                        NOW - 1000 + n,
                        &format!("{text}{n}"),
                        &[tag("d", "room")],
                    ),
                )
            })
            .collect();
        for chunk in all.chunks(per_batch as usize) {
            let results = db.put_prepared_batch(chunk);
            assert!(results.iter().all(|r| matches!(r, Ok(PutOutcome::Stored))));
        }
    }

    fn count_events(path: &Path) -> i64 {
        let conn = Connection::open(path).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        conn.query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap()
    }

    fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let by = Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(Instant::now() < by, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_commit_never_runs_a_checkpoint() {
        let tmp = TempDir::new().unwrap();
        // The thread is told to wait for a WAL no test will reach and for an
        // hour of quiet: any checkpoint would have to come from the writer.
        let db = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: u32::MAX / 2,
                wal_ceiling_pages: u32::MAX,
                idle_truncate_after: Duration::from_secs(3600),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        write_notes(&db, &key, 0, 800, 4);
        let shared = &db.maintenance.shared;
        // Past SQLite's own 1,000-page automatic threshold, and still growing:
        // the log was never checkpointed and restarted by a commit.
        assert!(
            shared.peak_pages.load(AtomicOrdering::Relaxed) > 1000,
            "the WAL reached {} pages",
            shared.peak_pages.load(AtomicOrdering::Relaxed)
        );
        assert_eq!(
            shared.pages.load(AtomicOrdering::Relaxed),
            shared.peak_pages.load(AtomicOrdering::Relaxed)
        );
        assert_eq!(shared.passive_runs.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(shared.truncate_runs.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(shared.blocking_runs.load(AtomicOrdering::Relaxed), 0);
        let writer_autocheckpoint = db
            .lock()
            .unwrap()
            .query_row("PRAGMA wal_autocheckpoint", [], |r| r.get::<_, i64>(0))
            .unwrap();
        assert_eq!(writer_autocheckpoint, 0);
    }

    #[test]
    fn checkpoint_stats_report_the_blocking_checkpoints_and_their_time() {
        // No checkpoint is reachable: only the peak moves.
        let tmp = TempDir::new().unwrap();
        let quiet = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: u32::MAX / 2,
                wal_ceiling_pages: u32::MAX,
                idle_truncate_after: Duration::from_secs(3600),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        write_notes(&quiet, &key, 0, 8, 4);
        let stats = quiet.checkpoint_stats();
        assert!(stats.peak_wal_pages > 0);
        assert_eq!(
            stats,
            CheckpointStats {
                peak_wal_pages: stats.peak_wal_pages,
                ..CheckpointStats::default()
            }
        );

        // A ceiling the first commit passes (it is never below the threshold,
        // so both are low): the writer goes to its blocking checkpoint, which
        // is counted and timed whether or not the thread's passive one got
        // there first.
        let tmp = TempDir::new().unwrap();
        let db = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: 12,
                wal_ceiling_pages: 12,
                idle_truncate_after: Duration::from_secs(3600),
                ..StoreOptions::default()
            },
        );
        write_notes(&db, &key, 0, 40, 4);
        let stats = db.checkpoint_stats();
        assert!(stats.blocking >= 1, "the writer ran a blocking checkpoint");
        assert!(stats.longest_blocking > Duration::ZERO);
        assert!(stats.blocking_time >= stats.longest_blocking);
        assert!(stats.peak_wal_pages >= 12);
        assert_eq!(stats.truncating, 0);
        // Reading changed nothing: the writer is idle, so its counts stand.
        let again = db.checkpoint_stats();
        assert_eq!(
            (again.blocking, again.blocking_time, again.longest_blocking),
            (stats.blocking, stats.blocking_time, stats.longest_blocking)
        );
    }

    /// Review M2: the probe is carried by the writer lock itself, so a commit
    /// that does not go through `commit_batch` or `expire` is still counted
    /// (and so still reaches the checkpoint thread and the ceiling).
    #[test]
    fn a_commit_through_any_writer_lock_is_counted() {
        let tmp = TempDir::new().unwrap();
        let db = io_store(&tmp, StoreOptions::default());
        let shared = Arc::clone(&db.maintenance.shared);
        assert_eq!(shared.peak_pages.load(AtomicOrdering::Relaxed), 0);
        db.lock()
            .unwrap()
            .execute("UPDATE usage SET bytes = bytes + 1 WHERE id = 1", [])
            .unwrap();
        assert!(
            shared.peak_pages.load(AtomicOrdering::Relaxed) > 0,
            "a bare writer commit was not observed"
        );
        // And the probe is released with the lock: another store's writer, on
        // this thread, is not routed to this one.
        let other_tmp = TempDir::new().unwrap();
        let other = io_store(&other_tmp, StoreOptions::default());
        let before = shared.peak_pages.load(AtomicOrdering::Relaxed);
        shared.peak_pages.store(0, AtomicOrdering::Relaxed);
        other
            .lock()
            .unwrap()
            .execute("UPDATE usage SET bytes = bytes + 1 WHERE id = 1", [])
            .unwrap();
        assert_eq!(shared.peak_pages.load(AtomicOrdering::Relaxed), 0);
        assert!(
            other
                .maintenance
                .shared
                .peak_pages
                .load(AtomicOrdering::Relaxed)
                > 0
        );
        assert!(before > 0);
    }

    /// Review M1: a TRUNCATE on another connection, at any moment between a
    /// commit and the next, must never fail a batch with SQLITE_BUSY_SNAPSHOT.
    #[test]
    fn a_truncate_on_another_connection_never_fails_a_batch() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().canonicalize().unwrap().join("events.sqlite");
        let db = io_store(
            &tmp,
            StoreOptions {
                idle_truncate_after: Duration::from_millis(1),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        let done = Arc::new(AtomicBool::new(false));
        let hammer = {
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let conn = Connection::open(&path).unwrap();
                conn.busy_timeout(Duration::from_millis(20)).unwrap();
                let mut truncates = 0u64;
                while !done.load(AtomicOrdering::Acquire) {
                    if run_checkpoint(&conn, "TRUNCATE").is_ok_and(|(busy, _, _)| busy == 0) {
                        truncates += 1;
                    }
                    // A pause between attempts. Back to back, the truncates
                    // hold the write lock almost continuously, and on a slow
                    // runner the writer's polling busy handler can miss every
                    // gap for its whole timeout: a plain SQLITE_BUSY, which is
                    // what any SQLite writer reports against a lock held that
                    // long, not the SQLITE_BUSY_SNAPSHOT this test guards.
                    std::thread::sleep(Duration::from_micros(500));
                }
                truncates
            })
        };
        for n in 0..400u64 {
            let note = event(&key, 1, NOW - 1000 + n, &format!("snap {n}"), &[]);
            assert_eq!(
                db.put(Visibility::Public, &note, NOW).unwrap(),
                PutOutcome::Stored,
                "write {n}"
            );
            if n % 50 == 0 {
                assert_eq!(db.expire(NOW).unwrap(), 0);
            }
        }
        done.store(true, AtomicOrdering::Release);
        let truncates = hammer.join().unwrap();
        assert!(truncates > 0, "the competing truncate never ran");
        assert_eq!(count_events(&tmp.path().join("events.sqlite")), 400);
    }

    /// Review L2: a deletion has the thread checkpoint at once, even far
    /// below the threshold, so the writer's own request refused by a
    /// concurrent checkpoint cannot leave the deleted bytes in the log.
    #[test]
    fn a_deletion_has_the_checkpoint_thread_run_a_passive_at_once() {
        let tmp = TempDir::new().unwrap();
        let db = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: u32::MAX / 2,
                wal_ceiling_pages: u32::MAX,
                idle_truncate_after: Duration::from_secs(3600),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        let note = event(&key, 1, NOW - 1, "to delete", &[]);
        db.put(Visibility::Public, &note, NOW).unwrap();
        let shared = Arc::clone(&db.maintenance.shared);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(shared.passive_runs.load(AtomicOrdering::Relaxed), 0);
        let deletion = event(&key, 5, NOW, "", &[tag("e", note.id.to_hex())]);
        assert_eq!(
            db.put(Visibility::Public, &deletion, NOW).unwrap(),
            PutOutcome::Stored
        );
        eventually("the thread's PASSIVE after a deletion", || {
            shared.passive_runs.load(AtomicOrdering::Relaxed) >= 1
        });
    }

    #[test]
    fn the_checkpoint_thread_advances_the_log_and_truncates_it_when_idle() {
        let tmp = TempDir::new().unwrap();
        let db = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: 8,
                idle_truncate_after: Duration::from_millis(100),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        write_notes(&db, &key, 0, 60, 3);
        let shared = Arc::clone(&db.maintenance.shared);
        // Reaching the threshold started checkpoints off the writer.
        eventually("a threshold checkpoint", || {
            shared.passive_runs.load(AtomicOrdering::Relaxed) >= 1
        });
        // Then a quiet store has its log cut to nothing.
        eventually("the idle truncate", || {
            shared.truncate_runs.load(AtomicOrdering::Relaxed) >= 1 && wal_len(&tmp) == 0
        });
        assert_eq!(all_ids(&db).len(), 60.min(MAX_QUERY_EVENTS));
        assert_eq!(count_events(&tmp.path().join("events.sqlite")), 60);
        // And a later write wakes it again.
        let before = shared.truncate_runs.load(AtomicOrdering::Relaxed);
        write_notes(&db, &key, 100, 3, 3);
        eventually("a second idle truncate", || {
            shared.truncate_runs.load(AtomicOrdering::Relaxed) > before && wal_len(&tmp) == 0
        });
    }

    #[test]
    fn an_idle_store_keeps_its_checkpoint_thread_asleep() {
        let tmp = TempDir::new().unwrap();
        let db = io_store(
            &tmp,
            StoreOptions {
                idle_truncate_after: Duration::from_millis(50),
                ..StoreOptions::default()
            },
        );
        let shared = Arc::clone(&db.maintenance.shared);
        // The initial pass (a WAL left by an earlier run) happens, then the
        // thread parks: no flag is set, so nothing wakes it.
        eventually("the thread to park", || {
            !shared.armed.load(AtomicOrdering::Acquire)
                && shared.truncate_runs.load(AtomicOrdering::Relaxed) >= 1
        });
        let runs = shared.truncate_runs.load(AtomicOrdering::Relaxed);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(shared.truncate_runs.load(AtomicOrdering::Relaxed), runs);
        assert!(!shared.armed.load(AtomicOrdering::Acquire));
        assert_eq!(shared.passive_runs.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn a_blocking_checkpoint_refused_at_the_lock_is_tried_again() {
        // SQLite's answer while another checkpoint holds the lock: busy, with
        // no log size.
        let mut rows = [Ok((1, -1, -1)), Ok((1, -1, -1)), Ok((0, 40, 40))].into_iter();
        let mut timeouts = Vec::new();
        let outcome = checkpoint_within(Duration::from_secs(2), |timeout| {
            timeouts.push(timeout);
            rows.next().unwrap()
        });
        assert!(
            matches!(outcome, CeilingCheckpoint::Finished),
            "{outcome:?}"
        );
        assert_eq!(timeouts.len(), 3);
        // Each try waits for readers only for the time that is left.
        assert!(timeouts[0] <= Duration::from_secs(2), "{timeouts:?}");
        assert!(timeouts.windows(2).all(|w| w[1] <= w[0]), "{timeouts:?}");
    }

    #[test]
    fn a_checkpoint_lock_held_throughout_ends_the_wait_when_it_runs_out() {
        let wait = Duration::from_millis(100);
        let mut least = Duration::MAX;
        let began = Instant::now();
        let outcome = checkpoint_within(wait, |timeout| {
            least = least.min(timeout);
            Ok((1, -1, -1))
        });
        let took = began.elapsed();
        assert!(
            matches!(outcome, CeilingCheckpoint::HeldByCheckpoint),
            "{outcome:?}"
        );
        assert!(took >= wait, "gave up after {took:?}");
        // A zero busy timeout would remove the busy handler.
        assert!(least >= Duration::from_millis(1), "{least:?}");
    }

    #[test]
    fn readers_or_an_error_end_a_blocking_checkpoint_without_another_try() {
        let mut attempts = 0;
        let outcome = checkpoint_within(Duration::from_secs(2), |_| {
            attempts += 1;
            Ok((1, 120, 40))
        });
        assert!(
            matches!(outcome, CeilingCheckpoint::HeldByReaders),
            "{outcome:?}"
        );
        assert_eq!(attempts, 1);
        let outcome = checkpoint_within(Duration::from_secs(2), |_| {
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                None,
            ))
        });
        assert!(
            matches!(outcome, CeilingCheckpoint::Failed(_)),
            "{outcome:?}"
        );
    }

    /// What the ceiling wait rests on: SQLite refuses a checkpoint at once
    /// while another holds the checkpoint lock, reporting busy with no log
    /// size, and does not call the busy handler for it.
    #[test]
    fn sqlite_refuses_a_checkpoint_at_once_while_another_holds_the_lock() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lock.sqlite");
        let writer = Connection::open(&path).unwrap();
        writer
            .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES(1);")
            .unwrap();
        // A reader on a snapshot older than the log's end, which a FULL
        // checkpoint waits for.
        let reader = Connection::open(&path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        reader
            .query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0))
            .unwrap();
        writer.execute("INSERT INTO t VALUES(2)", []).unwrap();
        let holder = {
            let path = path.clone();
            std::thread::spawn(move || {
                let conn = Connection::open(&path).unwrap();
                conn.busy_timeout(Duration::from_secs(60)).unwrap();
                // Tried again only if the probe below held the lock just then.
                loop {
                    let row = run_checkpoint(&conn, "FULL").unwrap();
                    if row != (1, -1, -1) {
                        return row;
                    }
                }
            })
        };
        let probe = Connection::open(&path).unwrap();
        eventually("the other checkpoint to take the lock", || {
            run_checkpoint(&probe, "PASSIVE").unwrap() == (1, -1, -1)
        });
        probe.busy_timeout(Duration::from_secs(30)).unwrap();
        let began = Instant::now();
        let refused = run_checkpoint(&probe, "FULL").unwrap();
        let took = began.elapsed();
        reader.execute_batch("COMMIT").unwrap();
        let held = holder.join().unwrap();
        assert_eq!(refused, (1, -1, -1));
        assert!(
            took < Duration::from_secs(10),
            "the refused checkpoint took {took:?}, as if it had waited for its busy handler"
        );
        assert_eq!(held.0, 0, "the other checkpoint finished: {held:?}");
    }

    #[test]
    fn the_writer_clears_a_wal_that_a_pinned_reader_would_let_grow() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        // One of these commits adds about eight pages, so the first two leave
        // the WAL well short of the ceiling, which is first reached under the
        // pin.
        let ceiling = 40;
        let db = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: 4,
                wal_ceiling_pages: ceiling,
                idle_truncate_after: Duration::from_secs(3600),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        write_notes(&db, &key, 0, 2, 1);
        // A reader holds the snapshot from here on, so no checkpoint can
        // restart the log until it lets go.
        let pin = Connection::open(&path).unwrap();
        pin.execute_batch("BEGIN").unwrap();
        pin.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))
            .unwrap();
        // Let go once the WAL has reached its ceiling under the pin, not after
        // a fixed time: on a loaded machine the writes may not get there first.
        let watched = Arc::clone(&db.maintenance.shared);
        let release = std::thread::spawn(move || {
            eventually("the WAL to reach its ceiling", || {
                watched.peak_pages.load(AtomicOrdering::Relaxed) >= ceiling
            });
            let seen = Instant::now();
            std::thread::sleep(Duration::from_millis(50));
            drop(pin);
            seen.elapsed()
        });
        write_notes(&db, &key, 10, 60, 1);
        let held_for = release.join().unwrap();
        let stats = db.checkpoint_stats();
        assert!(
            stats.blocking >= 1,
            "the writer never ran a blocking checkpoint: {stats:?}"
        );
        // The commit that reaches the ceiling waits in its blocking checkpoint
        // until the pin lets go, and a later one that meets the checkpoint
        // thread's checkpoint waits for the lock instead of letting the next
        // commit through.
        assert_the_ceiling_held(
            &stats,
            ceiling,
            &format!("the pin let go {held_for:?} after the release thread saw the ceiling"),
        );
        assert_eq!(count_events(&path), 62);
    }

    /// What the ceiling promises: the log ends at most one commit (about
    /// eight pages in these tests) past it, unless a blocking checkpoint
    /// waited out CEILING_WAIT, after which the writer lets commits through
    /// for a second.
    fn assert_the_ceiling_held(stats: &CheckpointStats, ceiling: u32, context: &str) {
        let waited_out = stats.longest_blocking >= CEILING_WAIT;
        if waited_out {
            println!("a blocking checkpoint waited out CEILING_WAIT ({context}): {stats:?}");
        }
        assert!(
            stats.peak_wal_pages < ceiling + 12 || waited_out,
            "the WAL reached {} pages against a ceiling of {ceiling}, and no blocking checkpoint \
             waited out {CEILING_WAIT:?}; {context}; {stats:?}",
            stats.peak_wal_pages
        );
    }

    #[test]
    fn the_writer_waits_for_another_checkpoint_rather_than_let_the_wal_grow() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let ceiling = 40;
        let db = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: 4,
                wal_ceiling_pages: ceiling,
                idle_truncate_after: Duration::from_secs(3600),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        // Another connection checkpoints without pause, so the writer's
        // blocking checkpoint often finds the checkpoint lock taken and is
        // refused at once. When the writer let the next commit through after
        // such a refusal, the log could pass the ceiling many times over. On a
        // loaded machine that connection can keep the lock for the whole of
        // CEILING_WAIT, and the log may then grow while the writer pauses.
        let stop = Arc::new(AtomicBool::new(false));
        let other = {
            let stop = Arc::clone(&stop);
            let path = path.clone();
            std::thread::spawn(move || {
                let conn = Connection::open(&path).unwrap();
                while !stop.load(AtomicOrdering::Relaxed) {
                    run_checkpoint(&conn, "PASSIVE").unwrap();
                }
            })
        };
        write_notes(&db, &key, 0, 60, 1);
        stop.store(true, AtomicOrdering::Relaxed);
        other.join().unwrap();
        let stats = db.checkpoint_stats();
        assert!(
            stats.blocking >= 1,
            "the WAL never reached its ceiling: {stats:?}"
        );
        assert_the_ceiling_held(
            &stats,
            ceiling,
            "another connection checkpointing without pause",
        );
        assert_eq!(count_events(&path), 60);
    }

    #[test]
    fn shutdown_with_a_pending_wal_leaves_every_committed_event() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let db = io_store(
            &tmp,
            StoreOptions {
                checkpoint_pages: u32::MAX / 2,
                wal_ceiling_pages: u32::MAX,
                idle_truncate_after: Duration::from_secs(3600),
                ..StoreOptions::default()
            },
        );
        let key = Keys::generate();
        write_notes(&db, &key, 0, 100, 5);
        assert!(wal_len(&tmp) > 0, "a WAL is pending");
        // A crash image taken now: database file and log as they stand.
        let image = TempDir::new().unwrap();
        std::fs::copy(&path, image.path().join("events.sqlite")).unwrap();
        std::fs::copy(
            tmp.path().join("events.sqlite-wal"),
            image.path().join("events.sqlite-wal"),
        )
        .unwrap();
        assert_eq!(count_events(&image.path().join("events.sqlite")), 100);
        // A clean shutdown stops the thread and checkpoints what is left. It
        // is the thread's own final checkpoint, not SQLite's close-time one:
        // the count of truncates rises while the writer connection is open.
        let shared = Arc::clone(&db.maintenance.shared);
        let before = shared.truncate_runs.load(AtomicOrdering::Relaxed);
        drop(db);
        assert!(shared.truncate_runs.load(AtomicOrdering::Relaxed) > before);
        assert_eq!(wal_len(&tmp), 0, "the final checkpoint truncated the log");
        assert_eq!(count_events(&path), 100);
        let reopened = SqliteEventStore::open(&path, 1_000_000_000).unwrap();
        assert_eq!(
            reopened
                .query(Visibility::Public, &Filter::new().limit(128), NOW)
                .unwrap()
                .len(),
            100.min(MAX_QUERY_EVENTS)
        );
    }

    #[test]
    fn cache_and_map_options_reach_every_connection() {
        let tmp = TempDir::new().unwrap();
        let db = io_store(
            &tmp,
            StoreOptions {
                writer_cache_kib: 1234,
                reader_cache_kib: 321,
                mmap_bytes: 64 * 1024 * 1024,
                reader_mmap_bytes: 16 * 1024 * 1024,
                ..StoreOptions::default()
            },
        );
        let pragma = |conn: &Connection, name: &str| -> i64 {
            conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
                .unwrap()
        };
        {
            let writer = db.lock().unwrap();
            assert_eq!(pragma(&writer, "cache_size"), -1234);
            assert_eq!(pragma(&writer, "mmap_size"), 64 * 1024 * 1024);
        }
        assert_eq!(db.readers.len(), READ_CONNECTIONS);
        for reader in &db.readers {
            let reader = reader.lock().unwrap();
            assert_eq!(pragma(&reader.conn, "cache_size"), -321);
            assert_eq!(pragma(&reader.conn, "mmap_size"), 16 * 1024 * 1024);
        }
        let default = SqliteEventStore::open(&tmp.path().join("other.sqlite"), 1_000_000).unwrap();
        let options = StoreOptions::default();
        assert_eq!(
            pragma(&default.lock().unwrap(), "cache_size"),
            -i64::from(options.writer_cache_kib)
        );
        // The profiles' heap caches: the server's from the cache spike
        // (writer 1 MiB, readers and checkpoint 256 KiB), the phone's as
        // they were (1 MiB, 512 KiB, 1 MiB).
        let phone = StoreOptions::phone();
        assert_eq!(
            (
                options.writer_cache_kib,
                options.reader_cache_kib,
                options.checkpoint_cache_kib
            ),
            (1024, 256, 256)
        );
        assert_eq!(
            (
                phone.writer_cache_kib,
                phone.reader_cache_kib,
                phone.checkpoint_cache_kib
            ),
            (1024, 512, 1024)
        );
        assert!(phone.mmap_bytes <= options.mmap_bytes);
        assert!(!options.warm && !phone.warm);
        assert_eq!(options.mmap_bytes == 0, cfg!(target_pointer_width = "32"));
        // Readers are unmapped by default in both profiles.
        assert_eq!(options.reader_mmap_bytes, 0);
        assert_eq!(phone.reader_mmap_bytes, 0);
    }

    #[test]
    fn readers_are_unmapped_by_default_and_capped_by_the_writer_map() {
        let pragma = |conn: &Connection, name: &str| -> i64 {
            conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
                .unwrap()
        };
        let map_of = |db: &SqliteEventStore| -> (i64, Vec<i64>) {
            let writer = pragma(&db.lock().unwrap(), "mmap_size");
            let readers = db
                .readers
                .iter()
                .map(|r| pragma(&r.lock().unwrap().conn, "mmap_size"))
                .collect();
            (writer, readers)
        };
        let tmp = TempDir::new().unwrap();
        // Default: the writer keeps its map, the readers have none.
        let db = io_store(
            &tmp,
            StoreOptions {
                mmap_bytes: 8 * 1024 * 1024,
                ..StoreOptions::default()
            },
        );
        let (writer, readers) = map_of(&db);
        assert_eq!(writer, 8 * 1024 * 1024);
        assert_eq!(readers.len(), READ_CONNECTIONS);
        assert!(readers.iter().all(|&m| m == 0), "{readers:?}");
        drop(db);
        // A reader map larger than the writer's is capped at the writer's.
        let tmp = TempDir::new().unwrap();
        let db = io_store(
            &tmp,
            StoreOptions {
                mmap_bytes: 4 * 1024 * 1024,
                reader_mmap_bytes: 64 * 1024 * 1024,
                ..StoreOptions::default()
            },
        );
        let (writer, readers) = map_of(&db);
        assert_eq!(writer, 4 * 1024 * 1024);
        assert!(readers.iter().all(|&m| m == 4 * 1024 * 1024), "{readers:?}");
        drop(db);
        // `mmap_bytes = 0` still turns every map off.
        let tmp = TempDir::new().unwrap();
        let db = io_store(
            &tmp,
            StoreOptions {
                mmap_bytes: 0,
                reader_mmap_bytes: 64 * 1024 * 1024,
                ..StoreOptions::default()
            },
        );
        let (writer, readers) = map_of(&db);
        assert_eq!(writer, 0);
        assert!(readers.iter().all(|&m| m == 0), "{readers:?}");
    }

    fn many_events(path: &Path, rows: u32) {
        // Fast bulk rows for scan tests: the store's own triggers still charge them.
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?1) \
             INSERT INTO events(visibility,id,author,kind,created_at,json) SELECT 0, unhex(printf('%064x',i)), unhex(printf('%064x',7)), 1, i, '{}' FROM n",
            [rows],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tags(seq,name,value,visibility,created_at,id) \
             SELECT seq, 'd', 'v', 0, created_at, id FROM events",
            [],
        )
        .unwrap();
    }

    #[test]
    fn a_count_stops_one_past_the_exact_bound() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().canonicalize().unwrap().join("events.sqlite");
        let db = store(&tmp);
        many_events(&path, MAX_EXACT_COUNT as u32 + 50);
        let all = Filter::new().kind(Kind::from(1));
        assert_eq!(
            db.count(Visibility::Public, &[all.clone(), all], NOW)
                .unwrap(),
            MAX_EXACT_COUNT + 1
        );
        let few = Filter::new()
            .kind(Kind::from(1))
            .until(Timestamp::from_secs(20));
        assert_eq!(db.count(Visibility::Public, &[few], NOW).unwrap(), 20);
    }

    #[test]
    fn the_warm_up_is_bounded_and_cancellable() {
        let tmp = TempDir::new().unwrap();
        // NOFOLLOW wants the resolved path; /var is a symlink on macOS.
        let path = tmp.path().canonicalize().unwrap().join("events.sqlite");
        // Open: a read-only connection needs the live store's WAL index.
        let _store = store(&tmp);
        many_events(&path, 60_000);
        let mut reader = open_reader(&path, 256, 64 * 1024 * 1024).unwrap();
        // Bounded: ten entries an index, five indexes (the tag indexes hold
        // as many rows as events here).
        let stop = Arc::new(AtomicBool::new(false));
        assert_eq!(
            warm_indexes(
                &mut reader,
                &stop,
                WARM_BYTES_PER_ENTRY * 50,
                Duration::ZERO,
                WARM_SCAN_DEADLINE
            )
            .unwrap(),
            WarmOutcome::Finished(50)
        );
        // Told to stop before it starts: it reads nothing.
        let stopped = Arc::new(AtomicBool::new(true));
        assert_eq!(
            warm_indexes(
                &mut reader,
                &stopped,
                u64::MAX / 2,
                Duration::ZERO,
                WARM_SCAN_DEADLINE
            )
            .unwrap(),
            WarmOutcome::Cancelled(0)
        );
        // A scan that outlives its deadline is cut short and the warm-up goes
        // on to the next index and finishes: this is not a cancellation.
        let unstopped = Arc::new(AtomicBool::new(false));
        let began = Instant::now();
        let slow = warm_indexes(
            &mut reader,
            &unstopped,
            WARM_BYTES_PER_ENTRY * 5 * 1_000_000,
            Duration::from_millis(5),
            Duration::from_millis(30),
        )
        .unwrap();
        assert!(
            matches!(slow, WarmOutcome::Finished(rows) if rows < 300_000),
            "{slow:?}"
        );
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "five scans of 30 ms each, not five full scans"
        );
        // Told to stop part-way: SQLite is interrupted inside a scan of three
        // hundred thousand entries, well before the end.
        let later = Arc::new(AtomicBool::new(false));
        let setter = {
            let later = Arc::clone(&later);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(5));
                later.store(true, AtomicOrdering::Release);
            })
        };
        let outcome = warm_indexes(
            &mut reader,
            &later,
            WARM_BYTES_PER_ENTRY * 5 * 1_000_000,
            Duration::from_millis(20),
            WARM_SCAN_DEADLINE,
        )
        .unwrap();
        setter.join().unwrap();
        assert!(
            matches!(outcome, WarmOutcome::Cancelled(rows) if rows < 300_000),
            "{outcome:?}"
        );
        // The connection is usable afterwards and the handler is gone.
        let n: i64 = reader
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 60_000);
    }

    #[test]
    fn the_store_warms_in_the_background_and_shutdown_cancels_it() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        drop(store(&tmp));
        many_events(&path, 2_000);
        let db = io_store(
            &tmp,
            StoreOptions {
                warm: true,
                ..StoreOptions::default()
            },
        );
        let shared = Arc::clone(&db.maintenance.shared);
        eventually("the warm-up", || {
            shared.warm_finished.load(AtomicOrdering::Acquire)
        });
        assert!(shared.warm_rows.load(AtomicOrdering::Relaxed) >= 2_000);
        // A store dropped at once does not wait for a long warm-up.
        let slow = TempDir::new().unwrap();
        let slow_path = slow.path().join("events.sqlite");
        drop(store(&slow));
        many_events(&slow_path, 60_000);
        let began = Instant::now();
        drop(io_store(
            &slow,
            StoreOptions {
                warm: true,
                warm_max_bytes: u64::MAX / 2,
                ..StoreOptions::default()
            },
        ));
        assert!(
            began.elapsed() < Duration::from_secs(20),
            "shutdown waited {:?}",
            began.elapsed()
        );
    }

    /// Events covering the tag shapes: repeats, groups of every padding size,
    /// more tags than one statement holds, and tags that are never indexed.
    fn tag_corpus(keys: &[Keys]) -> Vec<(Visibility, Event)> {
        let mut corpus = Vec::new();
        for partition in [Visibility::Public, Visibility::Sheltered] {
            for i in 0..48u64 {
                let author = (i % 3) as usize;
                let kind = if i % 4 == 0 { 30023 } else { 1 };
                let at = NOW - 200 + (i / 3) * 5;
                let mut tags = vec![tag("d", format!("room-{}", i % 5))];
                if i % 10 == 0 {
                    tags.push(tag("d", "room-9"));
                }
                if i % 2 == 0 {
                    tags.push(tag("t", "a"));
                }
                if i % 3 == 0 {
                    tags.push(tag("t", "b"));
                }
                if i % 7 == 0 {
                    tags.push(tag("p", keys[2].public_key().to_hex()));
                }
                if i % 11 == 0 {
                    tags.push(tag("expiration", NOW + 1));
                }
                corpus.push((
                    partition,
                    event(&keys[author], kind, at, &format!("note {i}"), &tags),
                ));
            }
        }
        // A group of n distinct tags, n of every size around the powers of two.
        for n in [
            0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33, 64, 65, 127, 128, 129, 300,
        ] {
            let tags: Vec<_> = (0..n).map(|k| tag("t", format!("tag-{k}"))).collect();
            corpus.push((
                Visibility::Public,
                event(
                    &keys[0],
                    1,
                    NOW - 50 + n as u64,
                    &format!("group {n}"),
                    &tags,
                ),
            ));
        }
        // The same tag, and the same name with the same value, repeated.
        let repeats = vec![
            tag("t", "x"),
            tag("t", "x"),
            tag("t", "y"),
            tag("t", "x"),
            tag("p", "z"),
            tag("p", "z"),
            tag("t", "y"),
        ];
        corpus.push((
            Visibility::Public,
            event(&keys[1], 1, NOW - 40, "repeats", &repeats),
        ));
        // Tags that are not indexed: long names, digits, one element, empty value.
        let skipped = vec![
            tag("expiration", NOW + 5),
            tag("1", "digit"),
            vec!["e".to_string()],
            tag("t", ""),
            tag("emoji", "x"),
            tag("t", "kept"),
        ];
        corpus.push((
            Visibility::Public,
            event(&keys[1], 1, NOW - 39, "skipped", &skipped),
        ));
        // The same event in both partitions, and a replacement and a deletion.
        let both = event(&keys[2], 1, NOW - 30, "both", &[tag("t", "both")]);
        corpus.push((Visibility::Public, both.clone()));
        corpus.push((Visibility::Sheltered, both));
        let addressable = |at, tags: &[Vec<String>]| event(&keys[0], 30023, at, "page", tags);
        corpus.push((
            Visibility::Public,
            addressable(NOW - 20, &[tag("d", "p"), tag("t", "old")]),
        ));
        corpus.push((
            Visibility::Public,
            addressable(NOW - 19, &[tag("d", "p"), tag("t", "new")]),
        ));
        let victim = event(
            &keys[0],
            1,
            NOW - 18,
            "doomed",
            &[tag("t", "gone"), tag("t", "also")],
        );
        corpus.push((Visibility::Public, victim.clone()));
        corpus.push((
            Visibility::Public,
            event(&keys[0], 5, NOW - 17, "", &[tag("e", victim.id.to_hex())]),
        ));
        // And one whose own insert breaks the byte budget part-way is covered by
        // the existing full-store tests, which run through the same path.
        corpus
    }

    type TagRow = (i64, i64, String, String, String, Option<i64>);

    /// Tag rows by key (`seq`, then name and value: a WITHOUT ROWID table
    /// keeps no order of insertion), with their event's id, and the events
    /// by `seq`.
    fn dump(db: &SqliteEventStore) -> (Vec<TagRow>, u64, Vec<String>) {
        let conn = db.lock().unwrap();
        let mut statement = conn
            .prepare("SELECT t.seq,t.visibility,lower(hex(e.id)),t.name,t.value,t.created_at FROM tags t JOIN events e ON e.seq=t.seq ORDER BY t.seq,t.name,t.value")
            .unwrap();
        let tags = statement
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut statement = conn
            .prepare("SELECT seq||':'||visibility||lower(hex(id)) FROM events ORDER BY seq")
            .unwrap();
        let events = statement
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<String>, _>>()
            .unwrap();
        (tags, logical_bytes(&conn).unwrap(), events)
    }

    #[test]
    fn the_multi_row_tag_insert_stores_what_the_one_row_insert_stored() {
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let corpus = tag_corpus(&keys);
        let run = |legacy: bool, batch: usize| {
            let tmp = TempDir::new().unwrap();
            let db = store(&tmp);
            db.legacy_tags.store(legacy, AtomicOrdering::Relaxed);
            let puts: Vec<PreparedPut> = corpus.iter().map(|(v, e)| prepared(*v, e)).collect();
            let mut results = Vec::new();
            for chunk in puts.chunks(batch) {
                results.extend(
                    db.put_prepared_batch(chunk)
                        .into_iter()
                        .map(|r| format!("{r:?}")),
                );
            }
            (results, dump(&db))
        };
        for batch in [1usize, 7, 1000] {
            let old = run(true, batch);
            let new = run(false, batch);
            assert_eq!(old.0, new.0, "same outcomes, batch {batch}");
            assert_eq!(old.1.0.len(), new.1.0.len());
            assert_eq!(
                old.1.0, new.1.0,
                "same tag rows in the same order, batch {batch}"
            );
            assert_eq!(old.1.1, new.1.1, "same usage total, batch {batch}");
            assert_eq!(old.1.2, new.1.2, "same events, batch {batch}");
            assert!(old.1.0.len() > 1000, "the corpus stored real tag rows");
        }
    }

    // ---- the upgrade to version 4 ----

    /// A store exactly as release 0.1.10's open leaves a new file: the v1
    /// layout, the v2 reserve triggers, the v3 tag migration and the expiry
    /// index.
    fn v3_fixture(path: &Path) -> Connection {
        let conn = v2_fixture(path);
        conn.execute_batch(MIGRATE_V3_SQL).unwrap();
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS events_expiry ON events(expires_at) WHERE expires_at IS NOT NULL;",
        )
        .unwrap();
        conn
    }

    /// The version 3 write path as 0.1.10's `apply_one` runs it, without the
    /// byte budget: what that release stores for `event`.
    fn put_v3(conn: &Connection, scope: Visibility, event: &Event) {
        let vis = scope.key();
        let id = event.id.to_hex();
        let author = event.pubkey.to_hex();
        let kind = event.kind.as_u16();
        let at = event.created_at.as_secs() as i64;
        let coord = coordinate(event);
        let found = |sql: &str, values: &[&dyn rusqlite::ToSql]| {
            conn.query_row(sql, values, |_| Ok(()))
                .optional()
                .unwrap()
                .is_some()
        };
        if found(
            "SELECT 1 FROM events WHERE visibility=? AND id=?",
            &[&vis, &id],
        ) {
            return;
        }
        if kind != 5
            && found(
                "SELECT 1 FROM deleted_ids WHERE visibility=? AND author=? AND id=?",
                &[&vis, &author, &id],
            )
        {
            return;
        }
        if let Some(d) = &coord {
            let through: Option<i64> = conn
                .query_row(
                    "SELECT through FROM deleted_coordinates WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                    params![vis, author, kind, d],
                    |r| r.get(0),
                )
                .optional()
                .unwrap();
            if through.is_some_and(|t| at <= t) {
                return;
            }
            let head: Option<(i64, String)> = conn
                .query_row(
                    "SELECT created_at,id FROM heads WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                    params![vis, author, kind, d],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .unwrap();
            if head.is_some_and(|(t, old)| at < t || (at == t && id >= old)) {
                return;
            }
            conn.execute(
                "DELETE FROM events WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                params![vis, author, kind, d],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO heads VALUES(?,?,?,?,?,?) ON CONFLICT(visibility,author,kind,coordinate) DO UPDATE SET created_at=excluded.created_at,id=excluded.id",
                params![vis, author, kind, d, at, id],
            )
            .unwrap();
        }
        if kind == 5 {
            for tag in event.tags.iter().map(|t| t.as_slice()) {
                if tag.len() < 2 {
                    continue;
                }
                if tag[0] == "e" && hex_key(&tag[1]).is_some() {
                    conn.execute(
                        "INSERT OR IGNORE INTO deleted_ids VALUES(?,?,?)",
                        params![vis, author, tag[1]],
                    )
                    .unwrap();
                    conn.execute(
                        "DELETE FROM events WHERE visibility=? AND author=? AND id=? AND kind<>5",
                        params![vis, author, tag[1]],
                    )
                    .unwrap();
                } else if tag[0] == "a" {
                    let parts: Vec<_> = tag[1].splitn(3, ':').collect();
                    if parts.len() != 3 || parts[1] != author {
                        continue;
                    }
                    let Ok(k) = parts[0].parse::<u16>() else {
                        continue;
                    };
                    let k_type = Kind::from(k);
                    if !(k_type.is_addressable() || (is_replaceable(k) && parts[2].is_empty())) {
                        continue;
                    }
                    conn.execute(
                        "INSERT INTO deleted_coordinates VALUES(?,?,?,?,?) ON CONFLICT(visibility,author,kind,coordinate) DO UPDATE SET through=max(through,excluded.through)",
                        params![vis, author, k, parts[2], at],
                    )
                    .unwrap();
                    conn.execute(
                        "DELETE FROM events WHERE visibility=? AND author=? AND kind=? AND coordinate=? AND created_at<=?",
                        params![vis, author, k, parts[2], at],
                    )
                    .unwrap();
                }
            }
        }
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?)",
            params![
                vis,
                id,
                author,
                kind,
                at,
                coord,
                expiry(event).unwrap().map(|v| v as i64),
                serde_json::to_string(event).unwrap()
            ],
        )
        .unwrap();
        for tag in event.tags.iter().map(|t| t.as_slice()) {
            if indexable_tag(tag) {
                conn.execute(
                    "INSERT OR IGNORE INTO tags(visibility,id,name,value,created_at) VALUES(?,?,?,?,?)",
                    params![vis, id, tag[0], tag[1], at],
                )
                .unwrap();
            }
        }
    }

    /// Public and sheltered events with tags, the same event in both
    /// partitions, ties on time, a replaceable and two addressable events
    /// with heads (one replaced by a version with the same time and a lower
    /// id), a deletion of an id and of a coordinate, and an event that
    /// expires between `NOW` and `NOW + 100`.
    fn upgrade_corpus(keys: &[Keys; 3]) -> Vec<(Visibility, Event)> {
        let [a, b, c] = keys;
        let p = |k: &Keys| tag("p", k.public_key().to_hex());
        let mut corpus = Vec::new();
        for n in 0..30u64 {
            let scope = if n % 3 == 2 {
                Visibility::Sheltered
            } else {
                Visibility::Public
            };
            let author = &keys[(n % 3) as usize];
            let mut tags = vec![
                tag("t", format!("t-{}", n % 5)),
                tag("d", format!("room-{}", n % 4)),
            ];
            if n % 2 == 0 {
                tags.push(p(c));
            }
            corpus.push((
                scope,
                event(author, 1, NOW - 500 + n * 7, &format!("note {n}"), &tags),
            ));
        }
        // Eight events at one time, in both partitions and from every author.
        for n in 0..8u64 {
            let scope = if n % 4 == 3 {
                Visibility::Sheltered
            } else {
                Visibility::Public
            };
            corpus.push((
                scope,
                event(
                    &keys[(n % 3) as usize],
                    1,
                    NOW - 200,
                    &format!("tie {n}"),
                    &[tag("t", "tie"), tag("d", "room-1")],
                ),
            ));
        }
        let both = event(a, 1, NOW - 150, "both", &[tag("t", "both"), p(b)]);
        corpus.push((Visibility::Public, both.clone()));
        corpus.push((Visibility::Sheltered, both));
        // A replaceable event, replaced.
        corpus.push((Visibility::Public, event(b, 0, NOW - 400, "profile 1", &[])));
        corpus.push((Visibility::Public, event(b, 0, NOW - 100, "profile 2", &[])));
        // An addressable event, replaced.
        corpus.push((
            Visibility::Public,
            event(
                b,
                30023,
                NOW - 300,
                "post 1",
                &[tag("d", "post"), tag("t", "long")],
            ),
        ));
        corpus.push((
            Visibility::Public,
            event(
                b,
                30023,
                NOW - 90,
                "post 2",
                &[tag("d", "post"), tag("t", "long")],
            ),
        ));
        // Two versions at one time: the lower id stands, in either order.
        let mut tied: Vec<Event> = (0..2)
            .map(|n| {
                event(
                    c,
                    30023,
                    NOW - 80,
                    &format!("tied {n}"),
                    &[tag("d", "tied")],
                )
            })
            .collect();
        tied.sort_by_key(|e| std::cmp::Reverse(e.id.to_hex()));
        for e in tied {
            corpus.push((Visibility::Sheltered, e));
        }
        // A deletion of an id and of a coordinate, and the events it names.
        let doomed = event(a, 1, NOW - 350, "doomed", &[tag("t", "t-1")]);
        let gone = event(a, 30023, NOW - 340, "gone", &[tag("d", "gone")]);
        corpus.push((Visibility::Public, doomed.clone()));
        corpus.push((Visibility::Public, gone));
        corpus.push((
            Visibility::Public,
            event(
                a,
                5,
                NOW - 60,
                "",
                &[
                    tag("e", doomed.id.to_hex()),
                    tag("a", format!("30023:{}:gone", a.public_key().to_hex())),
                ],
            ),
        ));
        corpus.push((
            Visibility::Public,
            event(
                c,
                1,
                NOW - 50,
                "expiring",
                &[tag("expiration", NOW + 50), tag("t", "t-1")],
            ),
        ));
        corpus
    }

    /// Every query path's filters for the corpus: plain, by kind, author,
    /// id and time, each tag shape (one value, merged, the sorted scan past
    /// the merge bound), several tags, authors with a tag, and limits that
    /// cut a run of events tied on time.
    fn upgrade_filters(keys: &[Keys; 3], corpus: &[(Visibility, Event)]) -> Vec<Filter> {
        let hex = |k: &Keys| k.public_key().to_hex();
        let some_ids: Vec<String> = corpus
            .iter()
            .step_by(4)
            .map(|(_, e)| e.id.to_hex())
            .collect();
        let many: Vec<String> = (0..40)
            .map(|n| format!("t-{n}"))
            .chain(["tie".to_owned()])
            .collect();
        [
            serde_json::json!({}),
            serde_json::json!({"limit": 3}),
            serde_json::json!({"limit": 34}),
            serde_json::json!({"kinds": [1]}),
            serde_json::json!({"kinds": [0, 30023]}),
            serde_json::json!({"kinds": [5]}),
            serde_json::json!({"authors": [hex(&keys[0])]}),
            serde_json::json!({"authors": [hex(&keys[1])], "kinds": [0, 30023]}),
            serde_json::json!({"authors": [hex(&keys[0]), hex(&keys[2])], "kinds": [1], "limit": 5}),
            serde_json::json!({"ids": some_ids}),
            serde_json::json!({"since": NOW - 400, "until": NOW - 150}),
            serde_json::json!({"since": NOW - 200, "until": NOW - 200, "limit": 4}),
            serde_json::json!({"#t": ["tie"]}),
            serde_json::json!({"#t": ["tie"], "limit": 3}),
            serde_json::json!({"#t": ["tie", "t-1"], "limit": 5}),
            serde_json::json!({"#t": many, "limit": 6}),
            serde_json::json!({"#d": ["room-1"], "kinds": [1], "limit": 50}),
            serde_json::json!({"#d": ["post", "tied", "gone"]}),
            serde_json::json!({"#p": [hex(&keys[2])], "#t": ["t-0", "t-2"]}),
            serde_json::json!({"#p": [hex(&keys[1])]}),
            serde_json::json!({"authors": [hex(&keys[0])], "#t": ["t-1", "both"]}),
            serde_json::json!({"#t": ["long"], "kinds": [30023]}),
            serde_json::json!({"#x": ["nothing"]}),
        ]
        .into_iter()
        .map(|f| serde_json::from_value(f).unwrap())
        .collect()
    }

    /// 0.1.10's answer to one filter: its event-driven history query on the
    /// version 3 tables, as stored JSON (the tag-driven shapes answer the
    /// same, which `tag_driven_queries_match_the_event_driven_oracle`
    /// checks). `limit: None` is the count's unlimited set.
    fn v3_answers(
        conn: &Connection,
        scope: Visibility,
        filter: &Filter,
        now: u64,
        limit: Option<usize>,
    ) -> Vec<String> {
        let mut sql = "SELECT e.json FROM events e WHERE e.visibility=? AND (e.expires_at IS NULL OR e.expires_at>?)".to_owned();
        let mut values = vec![Value::Integer(scope.key()), Value::Integer(now as i64)];
        fn within(sql: &mut String, values: &mut Vec<Value>, field: &str, items: Vec<Value>) {
            sql.push_str(&format!(
                " AND {field} IN ({})",
                vec!["?"; items.len()].join(",")
            ));
            values.extend(items);
        }
        if let Some(ids) = &filter.ids {
            within(
                &mut sql,
                &mut values,
                "e.id",
                ids.iter().map(|i| Value::Text(i.to_hex())).collect(),
            );
        }
        if let Some(authors) = &filter.authors {
            within(
                &mut sql,
                &mut values,
                "e.author",
                authors.iter().map(|i| Value::Text(i.to_hex())).collect(),
            );
        }
        if let Some(kinds) = &filter.kinds {
            within(
                &mut sql,
                &mut values,
                "e.kind",
                kinds
                    .iter()
                    .map(|k| Value::Integer(k.as_u16().into()))
                    .collect(),
            );
        }
        if let Some(since) = filter.since {
            sql.push_str(" AND e.created_at>=?");
            values.push(Value::Integer(since.as_secs() as i64));
        }
        if let Some(until) = filter.until {
            sql.push_str(" AND e.created_at<=?");
            values.push(Value::Integer(until.as_secs() as i64));
        }
        for (name, tag_values) in &filter.generic_tags {
            sql.push_str(&format!(
                " AND EXISTS(SELECT 1 FROM tags t WHERE t.visibility=e.visibility AND t.id=e.id AND t.name=? AND t.value IN ({}))",
                vec!["?"; tag_values.len()].join(",")
            ));
            values.push(Value::Text(name.to_string()));
            values.extend(tag_values.iter().map(|v| Value::Text(v.to_string())));
        }
        sql.push_str(" ORDER BY e.created_at DESC,e.id ASC");
        if let Some(limit) = limit {
            sql.push_str(" LIMIT ?");
            values.push(Value::Integer(limit as i64));
        }
        conn.prepare(&sql)
            .unwrap()
            .query_map(params_from_iter(values), |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    type Answers = Vec<(String, Vec<String>)>;

    /// What 0.1.10 answers on the version 3 store at `path`, for every
    /// filter, partition and time: each REQ, the COUNT of each filter and of
    /// all of them at once, the export, and `usage`.
    fn v3_snapshot(path: &Path, filters: &[Filter]) -> Answers {
        let conn = Connection::open(path).unwrap();
        let mut out = Vec::new();
        for scope in [Visibility::Public, Visibility::Sheltered] {
            for now in [NOW, NOW + 100] {
                let mut all = std::collections::BTreeSet::new();
                for (n, filter) in filters.iter().enumerate() {
                    let limit = filter
                        .limit
                        .unwrap_or(MAX_QUERY_EVENTS)
                        .min(MAX_QUERY_EVENTS);
                    out.push((
                        format!("{scope:?} {now} req {n}"),
                        v3_answers(&conn, scope, filter, now, Some(limit)),
                    ));
                    let matched = v3_answers(&conn, scope, filter, now, None);
                    out.push((
                        format!("{scope:?} {now} count {n}"),
                        vec![matched.len().to_string()],
                    ));
                    all.extend(matched);
                }
                out.push((
                    format!("{scope:?} {now} count all"),
                    vec![all.len().to_string()],
                ));
                let export = conn
                    .prepare("SELECT json FROM events WHERE visibility=? AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at ASC,id ASC")
                    .unwrap()
                    .query_map(params![scope.key(), now as i64], |r| r.get(0))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                out.push((format!("{scope:?} {now} export"), export));
            }
        }
        out.push((
            "usage".into(),
            vec![logical_bytes(&conn).unwrap().to_string()],
        ));
        out
    }

    /// The same, from the store as this build reads it: REQ through the
    /// built SQL (and the event-driven oracle, which must agree), COUNT,
    /// the export and `usage`.
    fn v4_snapshot(db: &SqliteEventStore, path: &Path, filters: &[Filter]) -> Answers {
        let mut out = Vec::new();
        for scope in [Visibility::Public, Visibility::Sheltered] {
            for now in [NOW, NOW + 100] {
                for (n, filter) in filters.iter().enumerate() {
                    let req: Vec<String> = db
                        .query_stored(scope, filter, now)
                        .unwrap()
                        .into_iter()
                        .map(|e| e.json)
                        .collect();
                    let ids: Vec<String> = req
                        .iter()
                        .map(|json| StoredEvent::from_stored(json.clone()).unwrap().id)
                        .collect();
                    assert_eq!(ids, oracle(db, scope, filter, now), "{scope:?} {now} {n}");
                    out.push((format!("{scope:?} {now} req {n}"), req));
                    out.push((
                        format!("{scope:?} {now} count {n}"),
                        vec![
                            db.count(scope, std::slice::from_ref(filter), now)
                                .unwrap()
                                .to_string(),
                        ],
                    ));
                }
                out.push((
                    format!("{scope:?} {now} count all"),
                    vec![db.count(scope, filters, now).unwrap().to_string()],
                ));
                let mut export = Vec::new();
                export_stored(path, scope, now, |json| {
                    export.push(json.to_owned());
                    Ok(())
                })
                .unwrap();
                out.push((format!("{scope:?} {now} export"), export));
            }
        }
        out.push((
            "usage".into(),
            vec![db.logical_bytes().unwrap().to_string()],
        ));
        out
    }

    /// Every row of a version 4 store, in key order, ids as hex, and
    /// `usage`: what two upgrades that agree must both hold.
    fn v4_rows(conn: &Connection) -> Vec<String> {
        let mut out = Vec::new();
        for sql in [
            "SELECT seq||' '||visibility||' '||lower(hex(id))||' '||lower(hex(author))||' '||kind||' '||created_at||' '||ifnull(coordinate,'-')||' '||ifnull(expires_at,'-')||' '||json FROM events ORDER BY seq",
            "SELECT seq||' '||name||' '||value||' '||visibility||' '||created_at FROM tags ORDER BY seq,name,value",
            "SELECT visibility||' '||lower(hex(author))||' '||kind||' '||coordinate||' '||created_at||' '||lower(hex(id)) FROM heads ORDER BY 1",
            "SELECT visibility||' '||lower(hex(author))||' '||lower(hex(id)) FROM deleted_ids ORDER BY 1",
            "SELECT visibility||' '||lower(hex(author))||' '||kind||' '||coordinate||' '||through FROM deleted_coordinates ORDER BY 1",
            "SELECT 'usage '||bytes FROM usage",
            "SELECT 'version '||user_version FROM pragma_user_version",
        ] {
            let rows: Vec<String> = conn
                .prepare(sql)
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            out.extend(rows);
        }
        out
    }

    /// The schema with SQLite's quoting of renamed names removed, so an
    /// upgraded store compares with a new one.
    fn normalised_schema(conn: &Connection) -> Vec<(String, String, Option<String>)> {
        schema_snapshot(conn)
            .into_iter()
            .map(|(kind, name, sql)| (kind, name, sql.map(|sql| sql.replace('"', ""))))
            .collect()
    }

    fn reset_upgrade_probe(chunk: Option<i64>, scrub: Option<i64>, stop: Option<u32>) {
        UPGRADE_PROBE.with(|p| {
            *p.borrow_mut() = UpgradeProbe {
                chunk_events: chunk,
                scrub_bytes: scrub,
                stop_after: stop,
                ..UpgradeProbe::default()
            }
        });
    }

    fn upgrade_steps() -> u32 {
        UPGRADE_PROBE.with(|p| p.borrow().steps)
    }

    /// A version 3 store of the corpus at `path`, closed.
    fn v3_store_of(path: &Path, corpus: &[(Visibility, Event)]) {
        let conn = v3_fixture(path);
        for (scope, e) in corpus {
            put_v3(&conn, *scope, e);
        }
    }

    #[test]
    fn the_v4_upgrade_answers_every_query_as_version_3_did_and_keeps_usage() {
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let corpus = upgrade_corpus(&keys);
        let filters = upgrade_filters(&keys, &corpus);
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        v3_store_of(&path, &corpus);
        let before = v3_snapshot(&path, &filters);
        // The fixture is a real version 3 store with every barrier in it.
        {
            let conn = Connection::open(&path).unwrap();
            let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
            assert_eq!(count("PRAGMA user_version"), 3);
            assert_eq!(count("SELECT count(*) FROM heads"), 4);
            assert_eq!(count("SELECT count(*) FROM deleted_ids"), 1);
            assert_eq!(count("SELECT count(*) FROM deleted_coordinates"), 1);
            assert_eq!(
                count("SELECT count(*) FROM events WHERE expires_at IS NOT NULL"),
                1
            );
        }
        reset_upgrade_probe(Some(7), None, None);
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        let after = v4_snapshot(&db, &path, &filters);
        assert_eq!(after.len(), before.len());
        for ((label, old), (label_after, new)) in before.iter().zip(&after) {
            assert_eq!(label, label_after);
            assert_eq!(old, new, "{label}");
        }
        assert!(
            before
                .iter()
                .filter(|(l, a)| l.contains("req") && a.len() > 1)
                .count()
                > 40,
            "the filters return real answers"
        );
        // The same answers as a store that took the same events at version 4.
        let fresh_tmp = TempDir::new().unwrap();
        let fresh_path = fresh_tmp.path().join("events.sqlite");
        let fresh = SqliteEventStore::open(&fresh_path, 10_000_000).unwrap();
        for (scope, e) in &corpus {
            let _ = fresh.put(*scope, e, NOW);
        }
        assert_eq!(v4_snapshot(&fresh, &fresh_path, &filters), after);
        {
            let conn = db.lock().unwrap();
            let fresh_conn = fresh.lock().unwrap();
            // The layout is the new store's, the foreign key rewritten by
            // the rename, and nothing of the upgrade is left.
            assert_eq!(normalised_schema(&conn), normalised_schema(&fresh_conn));
            let tags_sql: String = conn
                .query_row("SELECT sql FROM sqlite_master WHERE name='tags'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(
                tags_sql.contains(r#"REFERENCES "events"(seq)"#),
                "{tags_sql}"
            );
            let parent: String = conn
                .query_row(
                    "SELECT \"table\" FROM pragma_foreign_key_list('tags')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(parent, "events");
            assert_eq!(
                conn.query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
                    .optional()
                    .unwrap(),
                None
            );
            for leftover in [
                "event_store_upgrade",
                "event_store_scrub",
                "events_v4",
                "tags_v4",
                "heads_v4",
            ] {
                assert!(!table_exists(&conn, leftover).unwrap(), "{leftover}");
            }
        }
        drop(fresh);
        // The barriers came across: a deleted id and coordinate stay
        // deleted, an older or tied-higher version is refused, a tied-lower
        // one replaces, a newer one replaces, and expiry still sweeps.
        let [a, b, c] = &keys;
        let doomed = &corpus
            .iter()
            .find(|(_, e)| e.content == "doomed")
            .unwrap()
            .1;
        for e in [
            doomed.clone(),
            event(a, 30023, NOW - 345, "gone again", &[tag("d", "gone")]),
            event(b, 0, NOW - 101, "profile 0", &[]),
            event(b, 30023, NOW - 95, "post 0", &[tag("d", "post")]),
        ] {
            assert!(
                matches!(
                    db.put(Visibility::Public, &e, NOW),
                    Err(EventStoreError::Retired)
                ),
                "{}",
                e.content
            );
        }
        let standing = ids(
            &db,
            Visibility::Sheltered,
            serde_json::from_value(serde_json::json!({"#d": ["tied"]})).unwrap(),
            NOW,
        );
        assert_eq!(standing.len(), 1);
        // The standing id is the lower of two random ids, so a fixed number of
        // draws can miss a lower one (64 missed about one run in 33): draw
        // until both sides are found.
        let mut lower = None;
        let mut higher = None;
        for n in 0.. {
            if lower.is_some() && higher.is_some() {
                break;
            }
            let e = event(
                c,
                30023,
                NOW - 80,
                &format!("tied again {n}"),
                &[tag("d", "tied")],
            );
            if e.id.to_hex() < standing[0] {
                lower.get_or_insert(e);
            } else {
                higher.get_or_insert(e);
            }
        }
        assert!(matches!(
            db.put(Visibility::Sheltered, &higher.unwrap(), NOW),
            Err(EventStoreError::Retired)
        ));
        let lower = lower.unwrap();
        assert_eq!(
            db.put(Visibility::Sheltered, &lower, NOW).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(
            ids(
                &db,
                Visibility::Sheltered,
                serde_json::from_value(serde_json::json!({"#d": ["tied"]})).unwrap(),
                NOW
            ),
            vec![lower.id.to_hex()]
        );
        assert_eq!(
            db.put(
                Visibility::Public,
                &event(b, 0, NOW - 10, "profile 3", &[]),
                NOW
            )
            .unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(db.expire(NOW + 100).unwrap(), 1);
    }

    #[test]
    fn an_upgrade_stopped_after_any_step_ends_as_one_that_ran_through() {
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let corpus = upgrade_corpus(&keys);
        let filters = upgrade_filters(&keys, &corpus);
        let tmp = TempDir::new().unwrap();
        let pristine = tmp.path().join("v3.sqlite");
        v3_store_of(&pristine, &corpus);
        let v3_rows = tag_rows(&Connection::open(&pristine).unwrap());
        let v3_usage = logical_bytes(&Connection::open(&pristine).unwrap()).unwrap();
        // Small chunks and scrub steps, so every phase has several steps.
        let (chunk, scrub) = (Some(5), Some(8 * 4096));
        let reference = tmp.path().join("reference.sqlite");
        std::fs::copy(&pristine, &reference).unwrap();
        reset_upgrade_probe(chunk, scrub, None);
        let db = SqliteEventStore::open(&reference, 10_000_000).unwrap();
        let steps = upgrade_steps();
        let (expected_rows, expected_schema) = {
            let conn = db.lock().unwrap();
            (v4_rows(&conn), normalised_schema(&conn))
        };
        let expected = v4_snapshot(&db, &reference, &filters);
        drop(db);
        assert!(
            steps > 12,
            "copy chunks, the switch, indexes and scrub steps: {steps}"
        );
        for stop in 1..steps {
            let path = tmp.path().join(format!("stopped-{stop}.sqlite"));
            std::fs::copy(&pristine, &path).unwrap();
            reset_upgrade_probe(chunk, scrub, Some(stop));
            assert!(
                SqliteEventStore::open(&path, 10_000_000).is_err(),
                "stop {stop}"
            );
            {
                let conn = Connection::open(&path).unwrap();
                let version: i64 = conn
                    .query_row("PRAGMA user_version", [], |r| r.get(0))
                    .unwrap();
                if version == 3 {
                    // Before the switch the old tables are as they were.
                    assert_eq!(tag_rows(&conn), v3_rows, "stop {stop}");
                    assert_eq!(logical_bytes(&conn).unwrap(), v3_usage, "stop {stop}");
                } else {
                    assert_eq!(version, SCHEMA_VERSION);
                }
            }
            reset_upgrade_probe(chunk, scrub, None);
            let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
            {
                let conn = db.lock().unwrap();
                assert_eq!(v4_rows(&conn), expected_rows, "stop {stop}");
                assert_eq!(normalised_schema(&conn), expected_schema, "stop {stop}");
                assert!(
                    !table_exists(&conn, "event_store_upgrade").unwrap()
                        && !table_exists(&conn, "event_store_scrub").unwrap(),
                    "stop {stop}: finished"
                );
            }
            assert_eq!(v4_snapshot(&db, &path, &filters), expected, "stop {stop}");
        }
    }

    #[test]
    fn an_upgrade_resumed_after_an_older_core_wrote_the_store_copies_it_again() {
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let corpus = upgrade_corpus(&keys);
        let filters = upgrade_filters(&keys, &corpus);
        let tmp = TempDir::new().unwrap();
        let pristine = tmp.path().join("v3.sqlite");
        v3_store_of(&pristine, &corpus);
        // What an older core does meanwhile: deletes an event that has been
        // copied, deletes the newest row and adds one (which takes its row
        // number).
        let late = event(
            &keys[0],
            1,
            NOW - 5,
            "written by an older core",
            &[tag("t", "t-1")],
        );
        let older_core = |path: &Path| {
            let conn = Connection::open(path).unwrap();
            conn.pragma_update(None, "foreign_keys", true).unwrap();
            conn.execute("DELETE FROM events WHERE rowid=2", [])
                .unwrap();
            conn.execute(
                "DELETE FROM events WHERE rowid=(SELECT max(rowid) FROM events)",
                [],
            )
            .unwrap();
            put_v3(&conn, Visibility::Public, &late);
        };
        let reference = tmp.path().join("reference.sqlite");
        std::fs::copy(&pristine, &reference).unwrap();
        older_core(&reference);
        reset_upgrade_probe(Some(5), None, None);
        let (expected_rows, expected) = {
            let db = SqliteEventStore::open(&reference, 10_000_000).unwrap();
            let rows = v4_rows(&db.lock().unwrap());
            (rows, v4_snapshot(&db, &reference, &filters))
        };
        let path = tmp.path().join("events.sqlite");
        std::fs::copy(&pristine, &path).unwrap();
        // Start, and copy one chunk.
        reset_upgrade_probe(Some(5), None, Some(2));
        assert!(SqliteEventStore::open(&path, 10_000_000).is_err());
        older_core(&path);
        reset_upgrade_probe(Some(5), None, None);
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        assert_eq!(v4_rows(&db.lock().unwrap()), expected_rows);
        assert_eq!(v4_snapshot(&db, &path, &filters), expected);
    }

    #[test]
    fn a_v4_upgrade_without_the_free_space_it_needs_is_refused_before_it_starts() {
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let corpus = upgrade_corpus(&keys);
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        v3_store_of(&path, &corpus);
        let (schema, rows, usage) = {
            let conn = Connection::open(&path).unwrap();
            (
                schema_snapshot(&conn),
                tag_rows(&conn),
                logical_bytes(&conn).unwrap(),
            )
        };
        let before = std::fs::metadata(&path).unwrap().len();
        reset_upgrade_probe(None, None, None);
        // Enough for the open-time guard, then too little for the upgrade.
        let tight = SqliteEventStore::open_with_space(
            &path,
            10_000_000,
            0,
            Arc::new(SequenceFreeSpace(Mutex::new(vec![
                TRANSACTION_GUARD_BYTES,
                TRANSACTION_GUARD_BYTES,
            ]))),
        );
        match tight {
            Err(EventStoreError::DiskSpace { needed, available }) => {
                assert_eq!(available, TRANSACTION_GUARD_BYTES);
                let estimate = upgrade_estimate(&Connection::open(&path).unwrap()).unwrap();
                assert_eq!(needed, TRANSACTION_GUARD_BYTES + estimate.disk_bytes);
                assert!(
                    estimate.disk_bytes >= before / 2,
                    "{} vs {before}",
                    estimate.disk_bytes
                );
            }
            other => panic!("expected a disk-space refusal, got {:?}", other.err()),
        }
        assert_eq!(upgrade_steps(), 0, "no upgrade transaction ran");
        let conn = Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3,
            "still the v3 store"
        );
        assert_eq!(schema_snapshot(&conn), schema, "nothing was added");
        assert_eq!(tag_rows(&conn), rows);
        assert_eq!(logical_bytes(&conn).unwrap(), usage);
        drop(conn);
        assert!(std::fs::metadata(&path).unwrap().len() <= before + 64 * 1024);
        // With the space, the next open upgrades it.
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        assert_eq!(db.logical_bytes().unwrap(), usage);
    }

    #[test]
    fn an_open_time_refusal_of_a_v3_store_names_the_space_its_upgrade_needs() {
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let corpus = upgrade_corpus(&keys);
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        v3_store_of(&path, &corpus);
        let estimate = upgrade_estimate(&Connection::open(&path).unwrap()).unwrap();
        reset_upgrade_probe(None, None, None);
        // Below even the open-time headroom: refused before the upgrade's own
        // check, but with the figure that check would ask for.
        let refused = SqliteEventStore::open_with_space(
            &path,
            10_000_000,
            0,
            Arc::new(SequenceFreeSpace(Mutex::new(vec![1]))),
        );
        match refused {
            Err(EventStoreError::DiskSpace { needed, available }) => {
                assert_eq!(available, 1);
                assert_eq!(needed, TRANSACTION_GUARD_BYTES + estimate.disk_bytes);
            }
            other => panic!("expected a disk-space refusal, got {:?}", other.err()),
        }
        assert_eq!(upgrade_steps(), 0, "no upgrade transaction ran");
        let conn = Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        drop(conn);
        // A current store is refused with the headroom alone.
        let current = tmp.path().join("current.sqlite");
        drop(SqliteEventStore::open(&current, 10_000_000).unwrap());
        match SqliteEventStore::open_with_space(
            &current,
            10_000_000,
            0,
            Arc::new(SequenceFreeSpace(Mutex::new(vec![1]))),
        ) {
            Err(EventStoreError::DiskSpace { needed, .. }) => {
                assert_eq!(needed, TRANSACTION_GUARD_BYTES)
            }
            other => panic!("expected a disk-space refusal, got {:?}", other.err()),
        }
    }

    #[test]
    fn the_v4_upgrade_writes_through_the_wal_a_step_at_a_time_within_its_estimate() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        {
            let conn = v3_fixture(&path);
            conn.execute_batch("BEGIN").unwrap();
            for n in 0..3000u64 {
                let e = event(
                    &keys[(n % 3) as usize],
                    1,
                    NOW - 5000 + n,
                    &"x".repeat(400 + (n % 7) as usize * 50),
                    &[
                        tag("t", format!("t-{}", n % 11)),
                        tag("p", keys[0].public_key().to_hex()),
                    ],
                );
                put_v3(&conn, Visibility::Public, &e);
            }
            conn.execute_batch("COMMIT").unwrap();
        }
        let conn = Connection::open(&path).unwrap();
        let estimate = upgrade_estimate(&conn).unwrap();
        let live = database_bytes(&conn).unwrap();
        drop(conn);
        reset_upgrade_probe(Some(250), Some(64 * 4096), None);
        let estimate_small = {
            let conn = Connection::open(&path).unwrap();
            upgrade_estimate(&conn).unwrap()
        };
        drop(SqliteEventStore::open(&path, 10_000_000).unwrap());
        let max_wal = UPGRADE_PROBE.with(|p| p.borrow().max_wal);
        assert!(max_wal > 0);
        assert!(
            max_wal < live / 4,
            "no step writes the store through the WAL at once: {max_wal} of {live}"
        );
        assert!(
            estimate_small.disk_bytes.saturating_sub(live) >= max_wal,
            "estimate {} must cover the largest step {max_wal} over {live}",
            estimate_small.disk_bytes
        );
        assert!(estimate.disk_bytes >= estimate_small.disk_bytes);
    }

    #[test]
    fn the_upgrade_leaves_no_copy_of_an_event_that_is_deleted_after_it() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.sqlite");
        let key = Keys::generate();
        let marker = "upgrade-secret-5d2a9c";
        let secret = event(
            &key,
            1,
            NOW - 100,
            &format!("{marker} {}", "s".repeat(3000)),
            &[tag("t", marker)],
        );
        {
            let conn = v3_fixture(&path);
            put_v3(&conn, Visibility::Public, &secret);
            for n in 0..200u64 {
                put_v3(
                    &conn,
                    Visibility::Public,
                    &event(&key, 1, NOW - 90 + n, &"f".repeat(500), &[]),
                );
            }
        }
        let on_disk = |path: &Path| {
            let mut bytes = std::fs::read(path).unwrap();
            if let Ok(wal) = std::fs::read(path.with_extension("sqlite-wal")) {
                bytes.extend(wal);
            }
            bytes
                .windows(marker.len())
                .filter(|w| *w == marker.as_bytes())
                .count()
        };
        assert!(
            on_disk(&path) >= 2,
            "the fixture holds the event and its tag"
        );
        reset_upgrade_probe(None, None, None);
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        drop(db);
        assert!(on_disk(&path) >= 2, "the live copy is still there");
        let db = SqliteEventStore::open(&path, 10_000_000).unwrap();
        db.put(
            Visibility::Public,
            &event(&key, 5, NOW, "", &[tag("e", secret.id.to_hex())]),
            NOW,
        )
        .unwrap();
        drop(db);
        assert_eq!(
            on_disk(&path),
            0,
            "neither the old tables' pages nor the new rows keep the deleted event"
        );
    }

    #[test]
    fn events_tied_on_time_come_back_lowest_id_first_in_every_shape() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let keys = [Keys::generate(), Keys::generate(), Keys::generate()];
        let mut tied = Vec::new();
        for n in 0..12u64 {
            let e = event(
                &keys[(n % 3) as usize],
                1,
                NOW - 10,
                &format!("tie {n}"),
                &[tag("t", "tie"), tag("d", "room")],
            );
            db.put(Visibility::Public, &e, NOW).unwrap();
            tied.push(e);
        }
        let newer = event(
            &keys[0],
            1,
            NOW - 5,
            "newer",
            &[tag("t", "tie"), tag("d", "room")],
        );
        let older = event(
            &keys[0],
            1,
            NOW - 20,
            "older",
            &[tag("t", "tie"), tag("d", "room")],
        );
        db.put(Visibility::Public, &newer, NOW).unwrap();
        db.put(Visibility::Public, &older, NOW).unwrap();
        let mut by_id: Vec<String> = tied.iter().map(|e| e.id.to_hex()).collect();
        by_id.sort();
        let author: Vec<String> = {
            let mut ids: Vec<String> = tied
                .iter()
                .filter(|e| e.pubkey == keys[1].public_key())
                .map(|e| e.id.to_hex())
                .collect();
            ids.sort();
            ids
        };
        let many: Vec<String> = (0..40)
            .map(|n| format!("v-{n}"))
            .chain(["tie".to_owned()])
            .collect();
        for (filter, expected) in [
            (
                serde_json::json!({"limit": 6}),
                [vec![newer.id.to_hex()], by_id[..5].to_vec()].concat(),
            ),
            (
                serde_json::json!({"until": NOW - 10, "limit": 4}),
                by_id[..4].to_vec(),
            ),
            (
                serde_json::json!({"authors": [keys[1].public_key().to_hex()], "kinds": [1]}),
                author,
            ),
            (
                serde_json::json!({"#t": ["tie"], "limit": 6}),
                [vec![newer.id.to_hex()], by_id[..5].to_vec()].concat(),
            ),
            (
                serde_json::json!({"#t": ["tie"], "until": NOW - 10, "limit": 3}),
                by_id[..3].to_vec(),
            ),
            (
                serde_json::json!({"#t": ["tie", "other"], "limit": 6}),
                [vec![newer.id.to_hex()], by_id[..5].to_vec()].concat(),
            ),
            (
                serde_json::json!({"#t": many, "limit": 6}),
                [vec![newer.id.to_hex()], by_id[..5].to_vec()].concat(),
            ),
            (
                serde_json::json!({"kinds": [1], "#d": ["room"], "until": NOW - 10}),
                [by_id.clone(), vec![older.id.to_hex()]].concat(),
            ),
        ] {
            let filter: Filter = serde_json::from_value(filter).unwrap();
            assert_eq!(
                ids(&db, Visibility::Public, filter.clone(), NOW),
                expected,
                "{filter:?}"
            );
            assert_eq!(
                oracle(&db, Visibility::Public, &filter, NOW),
                expected,
                "{filter:?}"
            );
        }
    }

    /// A filter naming several ids, against an answer worked out by hand:
    /// with ids present the tag-driven and event-driven shapes build the
    /// same statement, so the usual oracle would compare it with itself.
    #[test]
    fn several_ids_answer_newest_first_from_their_own_partition() {
        use serde_json::json;
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        let old = event(&key, 1, NOW - 10, "old", &[]);
        let tie_a = event(&key, 1, NOW - 5, "tie a", &[]);
        let tie_b = event(&key, 1, NOW - 5, "tie b", &[]);
        let new = event(&key, 7, NOW - 1, "new", &[]);
        let expiring = event(&key, 1, NOW - 2, "soon", &[tag("expiration", NOW + 10)]);
        let hidden = event(&key, 1, NOW - 3, "sheltered", &[]);
        let absent = event(&key, 1, NOW - 4, "never stored", &[]);
        for e in [&old, &tie_a, &tie_b, &new, &expiring] {
            db.put(Visibility::Public, e, NOW).unwrap();
        }
        db.put(Visibility::Sheltered, &hidden, NOW).unwrap();
        // Other events on every side of them in time, which are not asked for.
        for n in 0..30u64 {
            let other = event(&key, 1, NOW - 20 + n, &format!("other {n}"), &[]);
            db.put(Visibility::Public, &other, NOW).unwrap();
        }
        let named: Vec<String> = [&old, &tie_a, &tie_b, &new, &expiring, &hidden, &absent]
            .iter()
            .map(|e| e.id.to_hex())
            .collect();
        let filter = |extra: serde_json::Value| {
            let mut value = json!({ "ids": named });
            for (k, v) in extra.as_object().unwrap() {
                value[k] = v.clone();
            }
            serde_json::from_value::<Filter>(value).unwrap()
        };
        // Equal times order by id, lowest first.
        let mut ties = [tie_a.id.to_hex(), tie_b.id.to_hex()];
        ties.sort();
        let [tie_first, tie_second] = ties;
        let (old, new, expiring, hidden) = (
            old.id.to_hex(),
            new.id.to_hex(),
            expiring.id.to_hex(),
            hidden.id.to_hex(),
        );
        let (old, new, expiring, hidden, tie_first, tie_second) = (
            old.as_str(),
            new.as_str(),
            expiring.as_str(),
            hidden.as_str(),
            tie_first.as_str(),
            tie_second.as_str(),
        );
        let later = NOW + 20;

        // While the expiring event lives it is answered in its place.
        assert_eq!(
            ids(&db, Visibility::Public, filter(json!({})), NOW),
            [new, expiring, tie_first, tie_second, old]
        );
        // Afterwards it is gone; the sheltered and the absent id never show.
        assert_eq!(
            ids(&db, Visibility::Public, filter(json!({})), later),
            [new, tie_first, tie_second, old]
        );
        // A limit below the number of ids keeps the newest.
        assert_eq!(
            ids(&db, Visibility::Public, filter(json!({"limit": 2})), later),
            [new, tie_first]
        );
        // The other conditions still narrow the answer.
        assert_eq!(
            ids(
                &db,
                Visibility::Public,
                filter(json!({"kinds": [1]})),
                later
            ),
            [tie_first, tie_second, old]
        );
        assert_eq!(
            ids(
                &db,
                Visibility::Public,
                filter(json!({"since": NOW - 5, "until": NOW - 2})),
                later
            ),
            [tie_first, tie_second]
        );
        // The other partition holds only its own event.
        assert_eq!(
            ids(&db, Visibility::Sheltered, filter(json!({})), later),
            [hidden]
        );
        // The counts agree.
        assert_eq!(
            db.count(Visibility::Public, &[filter(json!({}))], later)
                .unwrap(),
            4
        );
        assert_eq!(
            db.count(Visibility::Sheltered, &[filter(json!({}))], later)
                .unwrap(),
            1
        );
    }

    #[test]
    fn the_bench_queries_and_the_coordinate_statements_keep_their_indexes() {
        let tmp = TempDir::new().unwrap();
        let db = store(&tmp);
        let key = Keys::generate();
        for n in 0..50u64 {
            db.put(
                Visibility::Public,
                &event(
                    &key,
                    1,
                    NOW - 100 + n,
                    &format!("n{n}"),
                    &[tag("d", format!("room-{}", n % 5))],
                ),
                NOW,
            )
            .unwrap();
        }
        let plan_of = |filter: serde_json::Value| {
            let filter: Filter = serde_json::from_value(filter).unwrap();
            let limit = filter.limit.unwrap_or(MAX_QUERY_EVENTS);
            let (sql, values) = build_query(Visibility::Public, &filter, NOW, limit, true)
                .unwrap()
                .unwrap();
            db.with_reader(|conn| Ok(explain(conn, &sql, values)?))
                .unwrap()
                .join("\n")
        };
        let no_sort = |plan: &str| assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        let hex = key.public_key().to_hex();
        // The four bench sets, and the plain newest-first page.
        let plan = plan_of(serde_json::json!({"ids": [format!("{:064x}", 7)]}));
        assert!(
            plan.contains("USING INDEX events_id (visibility=? AND id=?)"),
            "{plan}"
        );
        // Several ids, alone and with every other condition: one seek for
        // each id, whatever else the filter carries. The sort that follows
        // is of at most that many rows, so it is not checked for here.
        let eight: Vec<String> = (0..8).map(|n| format!("{n:064x}")).collect();
        for filter in [
            serde_json::json!({"ids": eight}),
            serde_json::json!({"ids": eight, "limit": 2}),
            serde_json::json!({"ids": eight, "kinds": [1], "since": NOW - 80}),
            serde_json::json!({"ids": eight, "authors": [hex], "kinds": [1]}),
            serde_json::json!({"ids": eight, "#d": ["room-1"]}),
        ] {
            let plan = plan_of(filter.clone());
            assert!(
                plan.contains("USING INDEX events_id (visibility=? AND id=?)"),
                "{filter}: {plan}"
            );
            assert!(!plan.contains("events_time"), "{filter}: {plan}");
            assert!(!plan.contains("events_author_kind"), "{filter}: {plan}");
        }
        let plan = plan_of(serde_json::json!({"authors": [hex], "kinds": [1], "limit": 50}));
        assert!(
            plan.contains("USING INDEX events_author_kind (visibility=? AND author=? AND kind=?)"),
            "{plan}"
        );
        no_sort(&plan);
        let plan = plan_of(serde_json::json!({"since": NOW - 80, "until": NOW - 20, "limit": 50}));
        assert!(
            plan.contains(
                "USING INDEX events_time (visibility=? AND created_at>? AND created_at<?)"
            ),
            "{plan}"
        );
        no_sort(&plan);
        let plan = plan_of(serde_json::json!({"kinds": [1], "#d": ["room-1"], "limit": 50}));
        assert!(
            plan.contains("COVERING INDEX tags_by_time (visibility=? AND name=? AND value=?)"),
            "{plan}"
        );
        assert!(
            plan.contains("SEARCH e USING INTEGER PRIMARY KEY (rowid=?)"),
            "{plan}"
        );
        no_sort(&plan);
        let plan = plan_of(serde_json::json!({"limit": 50}));
        assert!(
            plan.contains("USING INDEX events_time (visibility=?)"),
            "{plan}"
        );
        no_sort(&plan);
        // The statements that name a coordinate use an index (the partial
        // one for a replacement), and the id statements the id index.
        let conn = db.lock().unwrap();
        for (sql, index) in [
            (
                "DELETE FROM events WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                "events_coordinate",
            ),
            (
                // A deletion's `a` tag: named, since SQLite would otherwise
                // take the author index and its time range.
                "DELETE FROM events INDEXED BY events_coordinate WHERE visibility=? AND author=? AND kind=? AND coordinate=? AND created_at<=?",
                "events_coordinate (visibility=? AND author=? AND kind=? AND coordinate=?)",
            ),
            (
                "DELETE FROM events WHERE visibility=? AND author=? AND id=? AND kind<>5",
                "events_id",
            ),
            (
                "SELECT 1 FROM events WHERE visibility=? AND id=?",
                "events_id",
            ),
            (
                "SELECT created_at,id FROM heads WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                "sqlite_autoindex_heads_1",
            ),
            (
                "SELECT through FROM deleted_coordinates WHERE visibility=? AND author=? AND kind=? AND coordinate=?",
                "sqlite_autoindex_deleted_coordinates_1",
            ),
            (
                "SELECT 1 FROM deleted_ids WHERE visibility=? AND author=? AND id=?",
                "sqlite_autoindex_deleted_ids_1",
            ),
            (
                "SELECT rowid FROM events INDEXED BY events_expiry WHERE expires_at IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT ?",
                "events_expiry",
            ),
            (
                "SELECT created_at,id,json FROM events WHERE visibility=?1 AND (expires_at IS NULL OR expires_at>?2) AND (created_at>?3 OR (created_at=?3 AND id>?4)) ORDER BY created_at ASC,id ASC LIMIT ?5",
                "events_time",
            ),
        ] {
            // The plan of a statement with every parameter unbound (NULL).
            let unbound = conn.prepare(sql).unwrap().parameter_count();
            let plan = explain(&conn, sql, vec![Value::Null; unbound])
                .unwrap()
                .join("\n");
            assert!(plan.contains(index), "{sql}: {plan}");
            assert!(!plan.contains("SCAN events"), "{sql}: {plan}");
        }
        // A count from the tag index, and an event-driven one.
        drop(conn);
        for (filter, index) in [
            (
                serde_json::json!({"kinds": [1], "#d": ["room-1"]}),
                "COVERING INDEX tags_by_time",
            ),
            (
                serde_json::json!({"authors": [hex], "#d": ["room-1"]}),
                "events_author_kind",
            ),
            // A count of several ids seeks each one too.
            (
                serde_json::json!({"ids": eight}),
                "USING INDEX events_id (visibility=? AND id=?)",
            ),
            (
                serde_json::json!({"ids": eight, "kinds": [1]}),
                "USING INDEX events_id (visibility=? AND id=?)",
            ),
        ] {
            let filter: Filter = serde_json::from_value(filter).unwrap();
            let (sql, values) = build_count(Visibility::Public, &[filter], NOW)
                .unwrap()
                .unwrap();
            let plan = db
                .with_reader(|conn| Ok(explain(conn, &sql, values)?))
                .unwrap()
                .join("\n");
            assert!(plan.contains(index), "{plan}");
        }
    }

    fn offline_store(tmp: &TempDir) -> SqliteEventStore {
        SqliteEventStore::open_with_options(
            &tmp.path().join("events.sqlite"),
            10_000_000,
            0,
            StoreOptions::offline(),
        )
        .unwrap()
    }

    /// Whether `marker` appears anywhere in the store's files on disk.
    fn on_disk(tmp: &TempDir, marker: &str) -> bool {
        ["events.sqlite", "events.sqlite-wal"].iter().any(|name| {
            std::fs::read(tmp.path().join(name))
                .map(|bytes| bytes.windows(marker.len()).any(|w| w == marker.as_bytes()))
                .unwrap_or(false)
        })
    }

    #[test]
    fn operator_removal_takes_an_event_its_tags_and_its_head_off_the_disk_and_bars_it() {
        let tmp = TempDir::new().unwrap();
        let member = Keys::generate();
        let stranger = Keys::generate();
        // Signed by a key that is nobody's member: the case an operator needs.
        let reported = event(
            &stranger,
            30023,
            NOW - 30,
            "REPORTED-CONTENT-7f3a",
            &[
                tag("d", "REPORTED-COORD-91c2"),
                tag("t", "REPORTED-TAG-5e8b"),
            ],
        );
        let kept = event(&member, 1, NOW - 20, "kept", &[tag("t", "kept")]);
        let elsewhere = event(&member, 1, NOW - 10, "public", &[]);
        let unknown = event(&member, 1, NOW - 5, "never stored", &[]).id;
        let db = offline_store(&tmp);
        db.put(Visibility::Sheltered, &reported, NOW).unwrap();
        db.put(Visibility::Sheltered, &kept, NOW).unwrap();
        db.put(Visibility::Public, &elsewhere, NOW).unwrap();
        db.put(Visibility::Public, &reported, NOW).unwrap();
        let before = db.logical_bytes().unwrap();

        let removal = db
            .remove(Visibility::Sheltered, &[reported.id, unknown])
            .unwrap();
        assert_eq!(
            removal.removed,
            vec![reported.id],
            "an unknown id is not removed"
        );
        assert!(removal.erased, "nothing else held the log");
        assert!(db.logical_bytes().unwrap() < before);
        assert!(
            ids(
                &db,
                Visibility::Sheltered,
                Filter::new().id(reported.id),
                NOW
            )
            .is_empty()
        );
        assert!(
            ids(
                &db,
                Visibility::Sheltered,
                Filter::new().hashtag("REPORTED-TAG-5e8b"),
                NOW
            )
            .is_empty()
        );
        assert_eq!(
            ids(&db, Visibility::Sheltered, Filter::new(), NOW),
            vec![kept.id.to_hex()]
        );
        // The other partition is not touched, so the copy there is not
        // removed or barred.
        assert_eq!(
            ids(&db, Visibility::Public, Filter::new().id(reported.id), NOW),
            vec![reported.id.to_hex()]
        );
        assert!(matches!(
            db.put(Visibility::Sheltered, &reported, NOW),
            Err(EventStoreError::Retired)
        ));
        assert!(matches!(
            db.put(Visibility::Sheltered, &kept, NOW),
            Ok(PutOutcome::Duplicate)
        ));
        let public = db.remove(Visibility::Public, &[reported.id]).unwrap();
        assert_eq!(public.removed, vec![reported.id]);
        drop(db);
        for marker in [
            "REPORTED-CONTENT-7f3a",
            "REPORTED-COORD-91c2",
            "REPORTED-TAG-5e8b",
        ] {
            assert!(
                !on_disk(&tmp, marker),
                "{marker} is still in the store's files"
            );
        }
        assert!(on_disk(&tmp, "kept") || on_disk(&tmp, "public"));
    }

    #[test]
    fn operator_removal_by_author_takes_every_event_of_that_key_in_bounded_passes() {
        let tmp = TempDir::new().unwrap();
        let flooder = Keys::generate();
        let member = Keys::generate();
        let db = offline_store(&tmp);
        let flood: Vec<Event> = (0..(MAX_EXPIRE_EVENTS as u64 * 2 + 7))
            .map(|i| event(&flooder, 1, NOW - 1000 + i, &format!("flood {i}"), &[]))
            .collect();
        for e in &flood {
            db.put(Visibility::Sheltered, e, NOW).unwrap();
        }
        let deletion = event(&flooder, 5, NOW - 1, "", &[tag("e", flood[0].id.to_hex())]);
        let kept = event(&member, 1, NOW - 1, "kept", &[]);
        db.put(Visibility::Sheltered, &kept, NOW).unwrap();
        let removal = db
            .remove_author(Visibility::Sheltered, &flooder.public_key())
            .unwrap();
        assert_eq!(removal.removed.len(), flood.len());
        assert!(removal.erased);
        assert_eq!(
            ids(&db, Visibility::Sheltered, Filter::new(), NOW),
            vec![kept.id.to_hex()]
        );
        assert!(matches!(
            db.put(Visibility::Sheltered, &flood[3], NOW),
            Err(EventStoreError::Retired)
        ));
        // A deletion event is removed like any other.
        db.put(Visibility::Sheltered, &deletion, NOW).unwrap();
        let removal = db.remove(Visibility::Sheltered, &[deletion.id]).unwrap();
        assert_eq!(removal.removed, vec![deletion.id]);
        // Nothing left of that key: a second pass removes nothing.
        let again = db
            .remove_author(Visibility::Sheltered, &flooder.public_key())
            .unwrap();
        assert!(again.removed.is_empty());
        assert!(!again.erased, "nothing removed, nothing truncated");
    }
}
