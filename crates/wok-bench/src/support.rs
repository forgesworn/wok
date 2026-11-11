//! Shared helpers: the RNG, latency statistics, store set-up, population
//! checks and the run header.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr::event::Event;
use nostr::filter::Filter;
use serde_json::{Value, json};
use tempfile::TempDir;
use wok_store::writer::WriterLimits;
use wok_store::{
    EventStore, EventStoreError, MAX_EXACT_COUNT, PreparedPut, PutOutcome, SqliteEventStore,
    StoreOptions, Visibility,
};

use crate::config::Config;
use crate::corpus::{Corpus, NOW};

/// The splitmix64 generator the corpus is drawn from.
pub struct SplitMix(pub u64);

impl SplitMix {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value below `n` (0 when `n` is 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }
}

/// Microseconds from nanoseconds, to one decimal place.
pub fn us(ns: u64) -> f64 {
    (ns as f64 / 100.0).round() / 10.0
}

/// Milliseconds, to three decimal places.
pub fn ms(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 1e6).round() / 1e3
}

/// Events (or anything counted) per second, to one decimal place.
pub fn per_second(count: usize, duration: Duration) -> f64 {
    let seconds = duration.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    (count as f64 / seconds * 10.0).round() / 10.0
}

/// Count, mean, p50, p90, p99 and max of `samples` (nanoseconds), in
/// microseconds. Percentiles are nearest-rank.
pub fn summarise(samples: &mut [u64]) -> Value {
    samples.sort_unstable();
    let samples: &[u64] = samples;
    let n = samples.len();
    if n == 0 {
        return json!({ "count": 0 });
    }
    let rank = |p: usize| samples[(n * p).div_ceil(100).clamp(1, n) - 1];
    let mean = samples.iter().map(|&s| s as f64).sum::<f64>() / n as f64;
    json!({
        "count": n,
        "mean_us": us(mean.round() as u64),
        "p50_us": us(rank(50)),
        "p90_us": us(rank(90)),
        "p99_us": us(rank(99)),
        "max_us": us(samples[n - 1]),
    })
}

/// A fresh store in a fresh temporary directory. The directory is returned
/// first: bind them as `(dir, store)` and the store drops before its files go.
pub fn fresh_store(
    cfg: &Config,
    events: usize,
) -> Result<(TempDir, Arc<SqliteEventStore>), String> {
    let dir = match &cfg.dir {
        Some(parent) => TempDir::new_in(parent),
        None => TempDir::new(),
    }
    .map_err(|e| format!("create a temporary directory: {e}"))?;
    let store = SqliteEventStore::open_with_options(
        &dir.path().join("events.sqlite"),
        cfg.max_bytes_for(events),
        0,
        cfg.store_options(),
    )
    .map_err(|e| format!("open the store: {e}"))?;
    Ok((dir, Arc::new(store)))
}

/// Check every corpus event into a `PreparedPut`, verifying its signature.
/// The events are copied before the clock starts, so the time is the check
/// itself. `PreparedPut::verified` is never used.
pub fn prepare(corpus: &Corpus) -> Result<(Vec<PreparedPut>, Duration), String> {
    let inputs: Vec<(Visibility, Event)> = corpus
        .items
        .iter()
        .map(|item| (item.visibility, item.event.clone()))
        .collect();
    let mut puts = Vec::with_capacity(inputs.len());
    let started = Instant::now();
    for (visibility, event) in inputs {
        let put = PreparedPut::new(visibility, event, NOW, false)
            .map_err(|e| format!("prepare an event: {e}"))?;
        puts.push(put);
    }
    Ok((puts, started.elapsed()))
}

/// Put `chunk` (the corpus items from index `first`) with one
/// `put_prepared_batch` call and require every put to be stored. Returns the
/// first call's duration in nanoseconds and how many puts had to be offered
/// again. A put the store deferred (its batch ran out of time) did nothing, so
/// it is prepared afresh, since a `PreparedPut` cannot be cloned, and offered
/// again; those re-offers are counted, and are rare.
pub fn put_chunk(
    store: &SqliteEventStore,
    corpus: &Corpus,
    first: usize,
    chunk: &[PreparedPut],
) -> Result<(u64, usize), String> {
    let call = Instant::now();
    let results = store.put_prepared_batch(chunk);
    let latency = call.elapsed().as_nanos() as u64;
    if results.len() != chunk.len() {
        return Err(format!(
            "the store answered {} puts for a batch of {}",
            results.len(),
            chunk.len()
        ));
    }
    let mut deferred = Vec::new();
    for (offset, result) in results.into_iter().enumerate() {
        match result {
            Ok(PutOutcome::Stored) => {}
            Err(EventStoreError::Deferred) => deferred.push(first + offset),
            other => return Err(format!("a put was not stored: {other:?}")),
        }
    }
    let mut reoffers = 0;
    while !deferred.is_empty() {
        reoffers += deferred.len();
        let again = deferred
            .iter()
            .map(|&i| {
                let item = &corpus.items[i];
                PreparedPut::new(item.visibility, item.event.clone(), NOW, false)
                    .map_err(|e| format!("prepare an event again: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let results = store.put_prepared_batch(&again);
        let mut still = Vec::new();
        for (&i, result) in deferred.iter().zip(results) {
            match result {
                Ok(PutOutcome::Stored) => {}
                Err(EventStoreError::Deferred) => still.push(i),
                other => return Err(format!("a put was not stored: {other:?}")),
            }
        }
        if still.len() == deferred.len() {
            return Err("the store deferred every put and made no progress".into());
        }
        deferred = still;
    }
    Ok((latency, reoffers))
}

pub fn prepare_json(duration: Duration, events: usize) -> Value {
    json!({
        "events": events,
        "total_ms": ms(duration),
        "per_event_us": us((duration.as_nanos() / events.max(1) as u128) as u64),
    })
}

/// The store holds exactly the corpus, partition by partition (counts above
/// the store's exact-count ceiling are compared as that ceiling plus one).
pub fn verify_population(store: &SqliteEventStore, corpus: &Corpus) -> Result<(), String> {
    for visibility in [Visibility::Public, Visibility::Sheltered] {
        let expected = corpus
            .items
            .iter()
            .filter(|item| item.visibility == visibility)
            .count()
            .min(MAX_EXACT_COUNT as usize + 1) as u64;
        let counted = store
            .count(visibility, &[Filter::new()], NOW)
            .map_err(|e| format!("count the {visibility:?} partition: {e}"))?;
        if counted != expected {
            return Err(format!(
                "the {visibility:?} partition holds {counted} events, expected {expected}"
            ));
        }
    }
    Ok(())
}

pub fn partition_name(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Sheltered => "sheltered",
    }
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// The one-, five- and fifteen-minute load averages, where they are cheap to
/// read (Linux and macOS).
#[cfg(target_os = "linux")]
pub fn load_average() -> Option<[f64; 3]> {
    parse_load(&std::fs::read_to_string("/proc/loadavg").ok()?)
}

#[cfg(target_os = "macos")]
pub fn load_average() -> Option<[f64; 3]> {
    let output = Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()?;
    parse_load(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn load_average() -> Option<[f64; 3]> {
    None
}

/// `0.52 0.58 0.59 1/467 1234` or `{ 2.34 2.10 2.05 }`: the first three numbers.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn parse_load(text: &str) -> Option<[f64; 3]> {
    let mut numbers = text
        .split(|c: char| c.is_whitespace() || c == '{' || c == '}')
        .filter(|part| !part.is_empty())
        .map(str::parse::<f64>);
    Some([
        numbers.next()?.ok()?,
        numbers.next()?.ok()?,
        numbers.next()?.ok()?,
    ])
}

pub fn load_json() -> Value {
    match load_average() {
        Some(load) => json!(load),
        None => Value::Null,
    }
}

fn options_json(profile: &str, options: &StoreOptions) -> Value {
    json!({
        "profile": profile,
        "writer_cache_kib": options.writer_cache_kib,
        "reader_cache_kib": options.reader_cache_kib,
        "checkpoint_cache_kib": options.checkpoint_cache_kib,
        "mmap_bytes": options.mmap_bytes,
        "reader_mmap_bytes": options.reader_mmap_bytes,
        "background_checkpoint": options.background_checkpoint,
        "checkpoint_pages": options.checkpoint_pages,
        "wal_ceiling_pages": options.wal_ceiling_pages,
        "idle_truncate_after_ms": options.idle_truncate_after.as_millis() as u64,
        "warm": options.warm,
        "warm_max_bytes": options.warm_max_bytes,
    })
}

pub fn writer_limits_json(limits: &WriterLimits) -> Value {
    json!({
        "queue_events": limits.queue_events,
        "queue_weight": limits.queue_weight,
        "batch_events": limits.batch_events,
        "batch_weight": limits.batch_weight,
        "write_wait_ms": limits.write_wait.map(|wait| wait.as_millis() as u64),
    })
}

/// The run header: where and on what the figures were taken, and every
/// parameter that shaped them. No host name and no path is recorded.
pub fn header(cfg: &Config) -> Value {
    let dirty = git(&["status", "--porcelain"]).map(|status| !status.is_empty());
    let threads: Vec<usize> = cfg.ingest_threads.clone();
    json!({
        "git_commit": git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into()),
        "git_dirty": dirty,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "load_average": load_json(),
        "sqlite_version": rusqlite::version(),
        "store_options": options_json(cfg.profile.name(), &cfg.store_options()),
        "writer_limits": writer_limits_json(&WriterLimits::default()),
        "store_max_bytes": cfg.max_bytes_for(cfg.events),
        "store_dir": if cfg.dir.is_some() { "custom" } else { "system temporary directory" },
        "scenarios": {
            "ingest": cfg.ingest,
            "query": cfg.query,
            "fanout": cfg.fanout,
            "engine": cfg.engine,
        },
        "allocations_counted": "every allocation of the process goes through a counting allocator (two relaxed atomic operations each), which every scenario pays",
        "params": {
            "seed": cfg.seed,
            "events": cfg.events,
            "authors": cfg.authors,
            "content_bytes": cfg.content_bytes,
            "ingest_threads": threads,
            "direct_batch": cfg.direct_batch,
            "queries": cfg.queries,
            "variants": cfg.variants,
            "query_mode": cfg.query_mode.name(),
            "settle_ms": cfg.settle().as_millis() as u64,
            "fanout_readers": cfg.fanout_readers,
            "fanout_events": cfg.fanout_events,
            "fanout_workers": cfg.fanout_workers,
            "fanout_window": cfg.fanout_window,
            "fanout_queue_bytes": cfg.fanout_queue_bytes,
            "fanout_total_bytes": cfg.fanout_total_bytes,
            "engine_connections": cfg.engine_connections,
            "engine_windows": cfg.engine_windows,
            "engine_workers": cfg.engine_workers,
            "engine_events": cfg.engine_events,
            "engine_subscribers": cfg.engine_subscribers,
            "engine_publish": cfg.engine_publish,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_nearest_rank() {
        let mut samples: Vec<u64> = (1..=100).map(|n| n * 1000).collect();
        let summary = summarise(&mut samples);
        assert_eq!(summary["count"], 100);
        assert_eq!(summary["p50_us"], 50.0);
        assert_eq!(summary["p90_us"], 90.0);
        assert_eq!(summary["p99_us"], 99.0);
        assert_eq!(summary["max_us"], 100.0);
        assert_eq!(summarise(&mut [])["count"], 0);
    }

    #[test]
    fn load_averages_parse_from_both_formats() {
        assert_eq!(
            parse_load("0.52 0.58 0.59 1/467 1234\n"),
            Some([0.52, 0.58, 0.59])
        );
        assert_eq!(parse_load("{ 2.34 2.10 2.05 }"), Some([2.34, 2.10, 2.05]));
        assert_eq!(parse_load("nonsense"), None);
    }

    #[test]
    fn the_rng_is_repeatable() {
        let (mut a, mut b) = (SplitMix(7), SplitMix(7));
        assert_eq!(a.next(), b.next());
        assert!(a.below(10) < 10);
        assert_eq!(a.below(0), 0);
    }
}
