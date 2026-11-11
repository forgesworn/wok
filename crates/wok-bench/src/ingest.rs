//! Ingest: pre-signed, pre-prepared events into a fresh store.
//!
//! Two paths, each on a fresh store:
//!
//! - through the [`EventWriter`] with a number of blocking submitters. The
//!   latency of a put is the time from submitting it to hearing it was
//!   committed, so it includes the queue and the group commit it rode in.
//! - straight into the store on one thread, with `put_prepared_batch`: one
//!   event per call (the floor, one commit per event), then `--direct-batch`
//!   events per call. The latency is that of the call.
//!
//! Signing and `PreparedPut::new` are outside every timed region. Every put
//! must come back `Stored`.

use std::sync::{Arc, Barrier};
use std::time::Instant;

use serde_json::{Value, json};
use wok_store::writer::{EventWriter, WriterLimits};
use wok_store::{EventStore, PreparedPut, PutOutcome, SqliteEventStore};

use crate::config::Config;
use crate::corpus::Corpus;
use crate::support::{
    fresh_store, ms, per_second, prepare, prepare_json, put_chunk, summarise, verify_population,
    writer_limits_json,
};

pub fn run(cfg: &Config, corpus: &Corpus) -> Result<Value, String> {
    let mut writer_runs = Vec::new();
    for &submitters in &cfg.ingest_threads {
        eprintln!("ingest: writer, {submitters} submitter(s)");
        writer_runs.push(through_writer(cfg, corpus, submitters)?);
    }
    let mut direct_runs = Vec::new();
    for batch in direct_sizes(cfg) {
        eprintln!("ingest: direct, {batch} event(s) per call");
        direct_runs.push(direct(cfg, corpus, batch)?);
    }
    Ok(json!({
        "latency_note": "writer latency is submit to acknowledgement; direct latency is one put_prepared_batch call",
        "writer_limits": writer_limits_json(&WriterLimits::default()),
        "writer": writer_runs,
        "direct": direct_runs,
    }))
}

/// One event per call always runs; `--direct-batch` adds a second size.
fn direct_sizes(cfg: &Config) -> Vec<usize> {
    let mut sizes = vec![1];
    if cfg.direct_batch > 1 {
        sizes.push(cfg.direct_batch);
    }
    sizes
}

fn through_writer(cfg: &Config, corpus: &Corpus, submitters: usize) -> Result<Value, String> {
    let (_dir, store) = fresh_store(cfg, corpus.items.len())?;
    let (puts, prepared_in) = prepare(corpus)?;
    let mut lanes: Vec<Vec<PreparedPut>> = (0..submitters).map(|_| Vec::new()).collect();
    for (i, put) in puts.into_iter().enumerate() {
        lanes[i % submitters].push(put);
    }
    let writer = EventWriter::new(
        Arc::clone(&store) as Arc<dyn EventStore>,
        |_, _, _| {},
        WriterLimits::default(),
    );
    let wait = writer.write_wait();
    let barrier = Barrier::new(submitters + 1);

    let (wall, results) = std::thread::scope(|scope| {
        let handles: Vec<_> = lanes
            .into_iter()
            .map(|lane| {
                let (barrier, writer) = (&barrier, &writer);
                scope.spawn(move || -> Result<Vec<u64>, String> {
                    let mut latencies = Vec::with_capacity(lane.len());
                    barrier.wait();
                    for put in lane {
                        let started = Instant::now();
                        let outcome = writer.submit_blocking(put, wait);
                        latencies.push(started.elapsed().as_nanos() as u64);
                        match outcome {
                            Ok(PutOutcome::Stored) => {}
                            other => return Err(format!("a put was not stored: {other:?}")),
                        }
                    }
                    Ok(latencies)
                })
            })
            .collect();
        barrier.wait();
        let started = Instant::now();
        let results: Vec<_> = handles.into_iter().map(|h| h.join()).collect();
        (started.elapsed(), results)
    });

    let mut latencies = Vec::with_capacity(corpus.items.len());
    for result in results {
        latencies.extend(result.map_err(|_| "a submitter thread panicked".to_string())??);
    }
    let stats = writer.stats();
    drop(writer);
    check_stored(&store, corpus, latencies.len())?;
    let events = latencies.len();
    Ok(json!({
        "submitters": submitters,
        "prepare": prepare_json(prepared_in, events),
        "wall_ms": ms(wall),
        "events_per_s": per_second(events, wall),
        "put_latency": summarise(&mut latencies),
        "commits": store.commits(),
        "writer_batches": stats.batches,
        "mean_batch_events": mean(stats.events, stats.batches),
        "largest_batch_events": stats.largest_batch,
        "logical_bytes": store.logical_bytes().map_err(|e| e.to_string())?,
    }))
}

fn direct(cfg: &Config, corpus: &Corpus, batch: usize) -> Result<Value, String> {
    let (_dir, store) = fresh_store(cfg, corpus.items.len())?;
    let (puts, prepared_in) = prepare(corpus)?;
    let mut latencies = Vec::with_capacity(puts.len().div_ceil(batch));
    let mut reoffers = 0usize;

    let started = Instant::now();
    for (chunk_index, chunk) in puts.chunks(batch).enumerate() {
        let (latency, again) = put_chunk(&store, corpus, chunk_index * batch, chunk)?;
        latencies.push(latency);
        reoffers += again;
    }
    let wall = started.elapsed();

    check_stored(&store, corpus, puts.len())?;
    let events = puts.len();
    Ok(json!({
        "batch_events": batch,
        "prepare": prepare_json(prepared_in, events),
        "wall_ms": ms(wall),
        "events_per_s": per_second(events, wall),
        "call_latency": summarise(&mut latencies),
        "commits": store.commits(),
        "mean_batch_events": mean(events as u64, latencies.len() as u64),
        "deferred_reoffers": reoffers,
        "logical_bytes": store.logical_bytes().map_err(|e| e.to_string())?,
    }))
}

fn mean(events: u64, batches: u64) -> f64 {
    if batches == 0 {
        return 0.0;
    }
    (events as f64 / batches as f64 * 100.0).round() / 100.0
}

/// Every event of the corpus is in the store, and nothing else.
fn check_stored(store: &SqliteEventStore, corpus: &Corpus, stored: usize) -> Result<(), String> {
    if stored != corpus.items.len() {
        return Err(format!(
            "{stored} puts were acknowledged for a corpus of {}",
            corpus.items.len()
        ));
    }
    verify_population(store, corpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_sizes_always_include_one_event_per_call() {
        let mut cfg = Config::default();
        assert_eq!(direct_sizes(&cfg), vec![1, 64]);
        cfg.direct_batch = 1;
        assert_eq!(direct_sizes(&cfg), vec![1]);
    }

    #[test]
    fn a_mean_of_nothing_is_zero() {
        assert_eq!(mean(0, 0), 0.0);
        assert_eq!(mean(10, 4), 2.5);
    }
}
