//! Read-only sampling of a SQLite WAL index (the `-shm` file), so that a
//! remote write run can show what the relay's write-ahead log did while the
//! relay runs exactly as it ships.
//!
//! The sampler opens the index read-only and takes no lock. About once a
//! millisecond it reads the checkpoint counters and both copies of the index
//! header, and keeps each state that changed. From those it reports commits,
//! frames appended, how far the log grew, restarts, how long checkpoint runs
//! took and each time the log reached the store's ceiling. It cannot tell the
//! checkpoint thread's PASSIVE runs from the writer's blocking FULL ones, and
//! it does not see the store's own counters.
//!
//! The index is in the writer's native byte order and the sampler reads it in
//! its own, so the two must share one. On POSIX systems closing any descriptor
//! on the file drops the process's locks on it, so in a real run the sampler
//! belongs in a process apart from the relay's, as the remote client is.

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::support::{ms, summarise};

/// `WALINDEX_MAX_VERSION`, the only index version SQLite opens.
const VERSION: u32 = 3_007_000;
/// One copy of the index header; the second copy follows it.
const HEADER: usize = 48;
/// The checkpoint counter `nBackfill`.
const BACKFILL_AT: usize = 96;
/// The lock bytes, 120 to 128, are never read: other connections lock them,
/// and on Windows a lock is mandatory. Byte 128, the first of
/// `nBackfillAttempted`, is also the dead-man-switch lock byte, which
/// connections hold shared once the index is open; a read is still allowed.
const LOCKS_AT: usize = 120;
/// The checkpoint counter `nBackfillAttempted`. It is read before the header,
/// so within one log it never runs ahead of the header's frame count.
const ATTEMPTED_AT: usize = 128;
const READ_BYTES: usize = 132;
const INTERVAL: Duration = Duration::from_millis(1);
const FIRST_READ_WAIT: Duration = Duration::from_secs(2);
const MAX_EPISODES: usize = 64;
const NOTE: &str = "sampled from the WAL index without a lock, about once a millisecond. A ceiling episode starts when the log reaches ceiling_pages frames; the store's writer then runs a blocking FULL checkpoint before its next batch, unless one it ran in the last second was held off by readers or another checkpoint. The sampler cannot tell that run from the checkpoint thread's PASSIVE one: an episode counts as blocking when the first commit after the crossing came only once the backfill had reached the crossing frame, which a natural pause between writes also gives; a run held off by readers shows instead as a long commits_resumed_after_ms with no backfilled_after_ms. commits_resumed_after_ms includes any wait for the next write. checkpoints.duration covers runs seen across two or more samples; within_one_sample counts those that started and finished between two reads. restarts counts logs that held frames and began again; a new salt on an empty log is not one, and salt_jumps counts new salts that did not follow from the last. frames_appended is a lower bound when the log restarts between two reads. could_reach_ceiling is false when the frames appended, with those in the log at the start, never came to ceiling_pages, so no episode was possible.";

/// Why one read gave no state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unreadable {
    Torn,
    Uninitialised,
    Checksum,
    Short,
}

/// One consistent read of the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    change: u32,
    mx_frame: u32,
    salt: [u8; 8],
    backfill: u32,
    attempted: u32,
}

impl State {
    /// The first salt, which SQLite stores big-endian and adds one to at each
    /// restart.
    fn salt0(&self) -> u32 {
        u32::from_be_bytes([self.salt[0], self.salt[1], self.salt[2], self.salt[3]])
    }
}

struct Sample {
    at: Instant,
    state: State,
}

/// Every state the sampler saw change, and how many reads it made.
pub(super) struct Samples {
    samples: Vec<Sample>,
    reads: u64,
    unreadable: u64,
}

/// A duration in whole nanoseconds, saturating.
pub(super) fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// SQLite's `walChecksumBytes` in native order from a zero start.
fn checksum(bytes: &[u8]) -> (u32, u32) {
    let (mut s1, mut s2) = (0u32, 0u32);
    for pair in bytes.chunks_exact(8) {
        s1 = s1.wrapping_add(word(pair, 0)).wrapping_add(s2);
        s2 = s2.wrapping_add(word(pair, 4)).wrapping_add(s1);
    }
    (s1, s2)
}

/// The state in one read, or why there is none. A version other than the
/// one known is an error: the layout read may not be the layout written.
fn parse(bytes: &[u8; READ_BYTES]) -> Result<Result<State, Unreadable>, String> {
    if bytes[..HEADER] != bytes[HEADER..2 * HEADER] {
        return Ok(Err(Unreadable::Torn));
    }
    let first = &bytes[..HEADER];
    if first[12] == 0 {
        return Ok(Err(Unreadable::Uninitialised));
    }
    if checksum(&first[..40]) != (word(first, 40), word(first, 44)) {
        return Ok(Err(Unreadable::Checksum));
    }
    let version = word(first, 0);
    if version != VERSION {
        return Err(format!("the WAL index is version {version}, not {VERSION}"));
    }
    let mut salt = [0; 8];
    salt.copy_from_slice(&first[32..40]);
    Ok(Ok(State {
        change: word(first, 8),
        mx_frame: word(first, 16),
        salt,
        backfill: word(bytes, BACKFILL_AT),
        attempted: word(bytes, ATTEMPTED_AT),
    }))
}

/// Reads `nBackfillAttempted` first, then everything before the lock bytes.
fn read_state(file: &mut File) -> Result<Result<State, Unreadable>, String> {
    let mut bytes = [0u8; READ_BYTES];
    for (from, to) in [(ATTEMPTED_AT, READ_BYTES), (0, LOCKS_AT)] {
        file.seek(SeekFrom::Start(from as u64))
            .map_err(|e| format!("seek the WAL index: {e}"))?;
        match file.read_exact(&mut bytes[from..to]) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                return Ok(Err(Unreadable::Short));
            }
            Err(e) => return Err(format!("read the WAL index: {e}")),
        }
    }
    parse(&bytes)
}

/// A thread reading the index until finished.
pub(super) struct Sampler {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<Samples, String>>>,
}

impl Sampler {
    pub(super) fn start(path: &Path) -> Result<Self, String> {
        let mut file =
            File::open(path).map_err(|e| format!("open the WAL index {}: {e}", path.display()))?;
        let began = Instant::now();
        let first = loop {
            match read_state(&mut file)? {
                Ok(state) => break (state, Instant::now()),
                Err(why) if began.elapsed() >= FIRST_READ_WAIT => {
                    return Err(format!(
                        "no consistent WAL index header in {} within {FIRST_READ_WAIT:?} ({why:?}); the sampler and the relay must share a byte order",
                        path.display()
                    ));
                }
                Err(_) => std::thread::sleep(INTERVAL),
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("wal-sampler".into())
            .spawn(move || sample(file, first, &flag))
            .map_err(|e| format!("start the WAL-index sampler: {e}"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    pub(super) fn finish(mut self) -> Result<Samples, String> {
        self.stop.store(true, Ordering::Release);
        let thread = self
            .thread
            .take()
            .ok_or_else(|| "the WAL-index sampler has already finished".to_string())?;
        thread
            .join()
            .map_err(|_| "the WAL-index sampler panicked".to_string())?
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn sample(
    mut file: File,
    (first, at): (State, Instant),
    stop: &AtomicBool,
) -> Result<Samples, String> {
    let mut found = Samples {
        samples: vec![Sample { at, state: first }],
        reads: 1,
        unreadable: 0,
    };
    let mut last = first;
    while !stop.load(Ordering::Acquire) {
        std::thread::sleep(INTERVAL);
        found.reads += 1;
        match read_state(&mut file)? {
            Ok(state) if state != last => {
                found.samples.push(Sample {
                    at: Instant::now(),
                    state,
                });
                last = state;
            }
            Ok(_) => {}
            Err(_) => found.unreadable += 1,
        }
    }
    Ok(found)
}

struct Episode {
    at: Instant,
    crossing: u32,
    peak: u32,
    resumed: Option<Instant>,
    backfilled: Option<Instant>,
    restarted: Option<Instant>,
}

fn offset_us(at: Instant, t0: Instant) -> i64 {
    let micros = |d: Duration| i64::try_from(d.as_micros()).unwrap_or(i64::MAX);
    if at >= t0 {
        micros(at.duration_since(t0))
    } else {
        -micros(t0.duration_since(at))
    }
}

fn after(from: Instant, to: Option<Instant>) -> Value {
    to.map_or(Value::Null, |to| {
        json!(ms(to.saturating_duration_since(from)))
    })
}

fn ratio(a: u64, b: u64) -> Value {
    if b == 0 {
        Value::Null
    } else {
        json!((a as f64 / b as f64 * 100.0).round() / 100.0)
    }
}

/// What the samples show, with times from `t0`. `events` is how many writes
/// the run made, for the per-event ratios.
pub(super) fn report(
    found: &Samples,
    t0: Instant,
    ceiling: u32,
    events: usize,
    trace: bool,
) -> Value {
    let (mut commits, mut appended, mut restarts, mut salt_jumps) = (0u64, 0u64, 0u64, 0u64);
    let mut peak = 0u32;
    let mut before_restart: Vec<u32> = Vec::new();
    let mut episodes: Vec<Episode> = Vec::new();
    let mut open: Option<usize> = None;
    let mut awaiting: Option<(usize, u32)> = None;
    let mut pending: Option<(Instant, u32)> = None;
    let (mut started, mut completed, mut within_one, mut unfinished) = (0u64, 0u64, 0u64, 0u64);
    let mut durations: Vec<u64> = Vec::new();
    let mut rows: Vec<Value> = Vec::new();
    let mut prev: Option<&State> = None;
    for sample in &found.samples {
        let (at, c) = (sample.at, &sample.state);
        let mx = c.mx_frame;
        let backfill = c.backfill.min(mx);
        let attempted = c.attempted.min(mx);
        let new_epoch = prev.is_some_and(|p| p.salt != c.salt);
        let restarted = new_epoch && prev.is_some_and(|p| p.mx_frame > 0);
        peak = peak.max(mx);
        if let Some(p) = prev {
            commits += u64::from(c.change.wrapping_sub(p.change));
            if new_epoch {
                if c.salt0() != p.salt0().wrapping_add(1) {
                    salt_jumps += 1;
                }
                if restarted {
                    restarts += 1;
                    before_restart.push(p.mx_frame);
                }
                appended += u64::from(mx);
            } else {
                appended += u64::from(mx.saturating_sub(p.mx_frame));
            }
        }
        if let Some((index, change)) = awaiting
            && c.change != change
        {
            episodes[index].resumed = Some(at);
            awaiting = None;
        }
        if restarted && let Some(index) = open.take() {
            let e = &mut episodes[index];
            e.restarted = Some(at);
            e.backfilled = e.backfilled.or(Some(at));
        }
        if let Some(index) = open {
            let e = &mut episodes[index];
            e.peak = e.peak.max(mx);
            if e.backfilled.is_none() && backfill >= e.crossing {
                e.backfilled = Some(at);
            }
        }
        if mx >= ceiling && open.is_none() && prev.is_none_or(|p| new_epoch || p.mx_frame < ceiling)
        {
            open = Some(episodes.len());
            awaiting = Some((episodes.len(), c.change));
            episodes.push(Episode {
                at,
                crossing: mx,
                peak: mx,
                resumed: None,
                backfilled: (backfill >= mx).then_some(at),
                restarted: None,
            });
        }
        if restarted && let Some((from, _)) = pending.take() {
            completed += 1;
            durations.push(nanos(at.saturating_duration_since(from)));
        }
        if let Some((from, target)) = pending
            && backfill >= target
        {
            completed += 1;
            durations.push(nanos(at.saturating_duration_since(from)));
            pending = None;
        }
        if let Some(p) = prev {
            let base = if new_epoch {
                0
            } else {
                p.attempted.min(p.mx_frame)
            };
            if attempted > base {
                started += 1;
                if pending.take().is_some() {
                    unfinished += 1;
                }
                if backfill >= attempted {
                    completed += 1;
                    within_one += 1;
                } else {
                    pending = Some((at, attempted));
                }
            }
        }
        if trace {
            rows.push(json!([
                offset_us(at, t0),
                c.mx_frame,
                c.backfill,
                c.attempted,
                c.salt0(),
                c.change
            ]));
        }
        prev = Some(c);
    }
    unfinished += u64::from(pending.is_some());
    let blocking = episodes
        .iter()
        .filter(|e| matches!((e.resumed, e.backfilled), (Some(r), Some(b)) if r >= b))
        .count();
    let first = found.samples.first().map_or(0, |s| s.state.mx_frame);
    let could_reach = u64::from(first) + appended >= u64::from(ceiling);
    before_restart.sort_unstable();
    let frames_before_restart = if before_restart.is_empty() {
        json!({"count": 0})
    } else {
        let n = before_restart.len();
        json!({
            "count": n,
            "min": before_restart[0],
            "p50": before_restart[n.div_ceil(2) - 1],
            "max": before_restart[n - 1],
        })
    };
    let mut result = json!({
        "interval_us": nanos(INTERVAL) / 1000,
        "ceiling_pages": ceiling,
        "reads": found.reads,
        "unreadable": found.unreadable,
        "samples": found.samples.len(),
        "first_frames": first,
        "peak_frames": peak,
        "commits": commits,
        "frames_appended": appended,
        "could_reach_ceiling": could_reach,
    });
    result["restarts"] = json!(restarts);
    result["salt_jumps"] = json!(salt_jumps);
    result["frames_per_event"] = ratio(appended, events as u64);
    result["frames_per_commit"] = ratio(appended, commits);
    result["events_per_commit"] = ratio(events as u64, commits);
    result["frames_before_restart"] = frames_before_restart;
    result["checkpoints"] = json!({
        "started": started,
        "completed": completed,
        "within_one_sample": within_one,
        "unfinished": unfinished,
        "duration": summarise(&mut durations),
    });
    result["ceiling_episodes"] = json!(episodes.len());
    result["episodes"] = Value::Array(
        episodes
            .iter()
            .take(MAX_EPISODES)
            .map(|e| {
                json!({
                    "at_ms": offset_us(e.at, t0) as f64 / 1000.0,
                    "crossing_frames": e.crossing,
                    "peak_frames": e.peak,
                    "commits_resumed_after_ms": after(e.at, e.resumed),
                    "backfilled_after_ms": after(e.at, e.backfilled),
                    "restarted_after_ms": after(e.at, e.restarted),
                })
            })
            .collect(),
    );
    result["blocking_checkpoints_inferred"] = json!(blocking);
    result["note"] = json!(NOTE);
    if trace {
        result["timeline"] = json!({
            "columns": ["offset_us", "mx_frame", "backfill", "attempted", "salt0", "change"],
            "rows": rows,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 8] = [0, 0, 0, 7, 1, 2, 3, 4];
    const NEXT: [u8; 8] = [0, 0, 0, 8, 9, 9, 9, 9];
    const JUMP: [u8; 8] = [0, 0, 0, 0x55, 5, 5, 5, 5];

    fn seal(h: &mut [u8; HEADER]) {
        let (s1, s2) = checksum(&h[..40]);
        h[40..44].copy_from_slice(&s1.to_ne_bytes());
        h[44..48].copy_from_slice(&s2.to_ne_bytes());
    }

    fn header(change: u32, mx: u32, salt: [u8; 8]) -> [u8; HEADER] {
        let mut h = [0u8; HEADER];
        h[0..4].copy_from_slice(&VERSION.to_ne_bytes());
        h[8..12].copy_from_slice(&change.to_ne_bytes());
        h[12] = 1;
        h[14..16].copy_from_slice(&4096u16.to_ne_bytes());
        h[16..20].copy_from_slice(&mx.to_ne_bytes());
        h[32..40].copy_from_slice(&salt);
        seal(&mut h);
        h
    }

    fn index(h: &[u8; HEADER], backfill: u32, attempted: u32) -> [u8; READ_BYTES] {
        let mut bytes = [0u8; READ_BYTES];
        bytes[..HEADER].copy_from_slice(h);
        bytes[HEADER..2 * HEADER].copy_from_slice(h);
        bytes[BACKFILL_AT..BACKFILL_AT + 4].copy_from_slice(&backfill.to_ne_bytes());
        bytes[ATTEMPTED_AT..ATTEMPTED_AT + 4].copy_from_slice(&attempted.to_ne_bytes());
        bytes
    }

    fn at(base: Instant, millis: u64) -> Instant {
        base + Duration::from_millis(millis)
    }

    /// One sample: (milliseconds, salt, change, frames, backfill, attempted).
    type Row = (u64, [u8; 8], u32, u32, u32, u32);

    fn samples(base: Instant, rows: &[Row]) -> Samples {
        Samples {
            samples: rows
                .iter()
                .map(
                    |&(millis, salt, change, mx_frame, backfill, attempted)| Sample {
                        at: at(base, millis),
                        state: State {
                            change,
                            mx_frame,
                            salt,
                            backfill,
                            attempted,
                        },
                    },
                )
                .collect(),
            reads: rows.len() as u64,
            unreadable: 0,
        }
    }

    #[test]
    fn headers_parse_only_when_whole_and_sealed() {
        let good = header(5, 12, SALT);
        let state = parse(&index(&good, 3, 4)).unwrap().unwrap();
        assert_eq!(
            state,
            State {
                change: 5,
                mx_frame: 12,
                salt: SALT,
                backfill: 3,
                attempted: 4,
            }
        );
        assert_eq!(state.salt0(), 7);
        let mut torn = index(&good, 3, 4);
        torn[HEADER + 8] ^= 1;
        assert_eq!(parse(&torn).unwrap(), Err(Unreadable::Torn));
        let mut blank = good;
        blank[12] = 0;
        seal(&mut blank);
        assert_eq!(
            parse(&index(&blank, 0, 0)).unwrap(),
            Err(Unreadable::Uninitialised)
        );
        let mut unsealed = good;
        unsealed[16] ^= 1;
        assert_eq!(
            parse(&index(&unsealed, 0, 0)).unwrap(),
            Err(Unreadable::Checksum)
        );
        let mut newer = good;
        newer[0..4].copy_from_slice(&(VERSION + 1).to_ne_bytes());
        seal(&mut newer);
        assert!(parse(&index(&newer, 0, 0)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn reads_a_real_index() {
        let dir = tempfile::tempdir().unwrap();
        let db = rusqlite::Connection::open(dir.path().join("t.sqlite")).unwrap();
        let mode: String = db
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        db.execute_batch(
            "CREATE TABLE t (x BLOB); INSERT INTO t VALUES (randomblob(5000)); INSERT INTO t VALUES (randomblob(5000));",
        )
        .unwrap();
        let mut file = File::open(dir.path().join("t.sqlite-shm")).unwrap();
        let grown = read_state(&mut file).unwrap().unwrap();
        assert!(grown.mx_frame > 0);
        assert_eq!(grown.backfill, 0);
        let (busy, log, done): (i64, i64, i64) = db
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!((busy, log), (0, done));
        let backfilled = read_state(&mut file).unwrap().unwrap();
        assert_eq!(backfilled.backfill, backfilled.mx_frame);
        assert_eq!(backfilled.attempted, backfilled.mx_frame);
        assert_eq!(backfilled.mx_frame, grown.mx_frame);
        db.execute("INSERT INTO t VALUES (1)", []).unwrap();
        let restarted = read_state(&mut file).unwrap().unwrap();
        assert_eq!(restarted.salt0(), grown.salt0().wrapping_add(1));
        assert!(restarted.mx_frame < grown.mx_frame);
        assert_eq!(restarted.change, backfilled.change.wrapping_add(1));
        assert_eq!(restarted.backfill, 0);
    }

    #[test]
    fn a_blocking_checkpoint_at_the_ceiling_is_reported() {
        let base = Instant::now();
        let found = samples(
            base,
            &[
                (0, SALT, 1, 90, 0, 0),
                (1, SALT, 2, 100, 0, 0),
                (2, SALT, 2, 100, 0, 100),
                (22, SALT, 2, 100, 100, 100),
                (25, NEXT, 3, 9, 0, 0),
                (30, NEXT, 4, 12, 0, 0),
            ],
        );
        let wal = report(&found, base, 100, 11, false);
        assert_eq!(wal["samples"], json!(6));
        assert_eq!(wal["commits"], json!(3));
        assert_eq!(wal["frames_appended"], json!(22));
        assert_eq!(wal["restarts"], json!(1));
        assert_eq!(wal["salt_jumps"], json!(0));
        assert_eq!(wal["first_frames"], json!(90));
        assert_eq!(wal["peak_frames"], json!(100));
        assert_eq!(wal["could_reach_ceiling"], json!(true));
        assert_eq!(wal["ceiling_episodes"], json!(1));
        let episode = &wal["episodes"][0];
        assert_eq!(episode["at_ms"], json!(1.0));
        assert_eq!(episode["crossing_frames"], json!(100));
        assert_eq!(episode["commits_resumed_after_ms"], json!(24.0));
        assert_eq!(episode["backfilled_after_ms"], json!(21.0));
        assert_eq!(episode["restarted_after_ms"], json!(24.0));
        assert_eq!(wal["blocking_checkpoints_inferred"], json!(1));
        let checkpoints = &wal["checkpoints"];
        assert_eq!(checkpoints["started"], json!(1));
        assert_eq!(checkpoints["completed"], json!(1));
        assert_eq!(checkpoints["within_one_sample"], json!(0));
        assert_eq!(checkpoints["unfinished"], json!(0));
        assert_eq!(checkpoints["duration"]["max_us"], json!(20000.0));
        assert_eq!(
            wal["frames_before_restart"],
            json!({"count": 1, "min": 100, "p50": 100, "max": 100})
        );
        assert_eq!(wal["frames_per_event"], json!(2.0));
        assert_eq!(wal["frames_per_commit"], json!(7.33));
        assert_eq!(wal["events_per_commit"], json!(3.67));
        assert!(wal.get("timeline").is_none());
    }

    #[test]
    fn a_ceiling_crossing_with_writes_still_flowing_is_not_blocking() {
        let base = Instant::now();
        let found = samples(
            base,
            &[
                (0, SALT, 1, 95, 0, 0),
                (1, SALT, 2, 100, 0, 0),
                (2, SALT, 3, 104, 0, 100),
                (20, SALT, 4, 108, 100, 100),
                (40, NEXT, 4, 0, 0, 0),
                (50, JUMP, 4, 0, 0, 0),
                (51, JUMP, 5, 3, 0, 0),
            ],
        );
        let wal = report(&found, base, 100, 4, false);
        assert_eq!(wal["commits"], json!(4));
        assert_eq!(wal["frames_appended"], json!(16));
        assert_eq!(wal["restarts"], json!(1));
        assert_eq!(wal["salt_jumps"], json!(1));
        assert_eq!(wal["peak_frames"], json!(108));
        assert_eq!(wal["could_reach_ceiling"], json!(true));
        assert_eq!(wal["ceiling_episodes"], json!(1));
        assert_eq!(wal["blocking_checkpoints_inferred"], json!(0));
        let episode = &wal["episodes"][0];
        assert_eq!(episode["peak_frames"], json!(108));
        assert_eq!(episode["commits_resumed_after_ms"], json!(1.0));
        assert_eq!(episode["backfilled_after_ms"], json!(19.0));
        assert_eq!(episode["restarted_after_ms"], json!(39.0));
        assert_eq!(wal["checkpoints"]["started"], json!(1));
        assert_eq!(wal["checkpoints"]["completed"], json!(1));
        assert_eq!(wal["checkpoints"]["duration"]["max_us"], json!(18000.0));
        assert_eq!(wal["frames_before_restart"]["max"], json!(108));
        assert_eq!(wal["frames_per_event"], json!(4.0));
        assert_eq!(wal["events_per_commit"], json!(1.0));
        let quiet = report(&found, base, 1000, 4, false);
        assert_eq!(quiet["could_reach_ceiling"], json!(false));
        assert_eq!(quiet["ceiling_episodes"], json!(0));
        let traced = report(&found, base, 100, 4, true);
        assert_eq!(traced["timeline"]["rows"].as_array().map(Vec::len), Some(7));
    }
}
