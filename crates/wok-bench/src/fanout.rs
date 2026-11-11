//! Fan-out: readers attached to a `LiveFanout`, events published to them,
//! every reader draining its queue.
//!
//! This scenario drives `LiveFanout` directly, so it measures the fan-out
//! alone. It does not go through the relay session engine, and its figures
//! say nothing about a session's own costs.
//!
//! The publisher is the calling thread. The readers are tasks on a
//! multi-thread runtime, each awaiting `LiveReceiver::recv`, so they wake the
//! way a connection task does. Every reader must see every event, in order,
//! and none may lag. Queue occupancy (the bytes held by the queues) is not
//! observable from outside `wok-store`, so the scenario reports the bytes the
//! readers received instead. Signing and `PreparedPut::new` happen before the clock
//! starts.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use nostr::event::EventId;
use serde_json::{Value, json};
use wok_store::live::{LiveEvent, LiveFanout};
use wok_store::{PreparedPut, Visibility};

use crate::config::Config;
use crate::corpus::{NOW, notes};
use crate::support::{ms, per_second, prepare_json};

/// The live module charges this much on top of an event's JSON for each
/// queued copy. It is private there, so the pre-check below mirrors it; the
/// run fails on a lagging reader whatever this says.
pub(crate) const CHARGE_OVERHEAD: usize = 512;
/// How long to wait for any reader, or for the slowest reader to move on.
const STALL: Duration = Duration::from_secs(120);

pub fn run(cfg: &Config) -> Result<Value, String> {
    let readers = cfg.fanout_readers;
    let count = cfg.fanout_events;
    eprintln!("fanout: {readers} readers, {count} events");

    // Outside the timed region: sign, check, and keep the JSON the store
    // would have written.
    let signed = notes(cfg.seed, count, cfg.content_bytes)?;
    let prepare_started = Instant::now();
    let mut live = Vec::with_capacity(count);
    let mut ids: Vec<EventId> = Vec::with_capacity(count);
    let mut costs = Vec::with_capacity(count);
    for event in signed {
        let prepared = PreparedPut::new(Visibility::Public, event, NOW, false)
            .map_err(|e| format!("prepare an event: {e}"))?;
        let (event, json) = prepared.into_parts();
        ids.push(event.id);
        costs.push(json.len() + CHARGE_OVERHEAD);
        live.push(LiveEvent::stored(Visibility::Public, Arc::new(event), json));
    }
    let prepared_in = prepare_started.elapsed();

    // The ceilings are sized so that the run fits: a reader may hold every
    // event it has not yet drained, and the queues together hold each event
    // once. Pacing bounds how far the publisher runs ahead.
    let total_cost: usize = costs.iter().sum();
    let largest = costs.iter().copied().max().unwrap_or(0);
    let behind = if cfg.fanout_window == 0 {
        total_cost
    } else {
        largest * (cfg.fanout_window + 1)
    };
    if cfg.fanout_queue_bytes < behind || cfg.fanout_total_bytes < behind {
        return Err(format!(
            "the fan-out ceilings are too small: a reader may need {behind} bytes queued \
             (queue {} bytes, total {} bytes). Raise --fanout-queue-bytes and \
             --fanout-total-bytes, lower --fanout-events, or set --fanout-window",
            cfg.fanout_queue_bytes, cfg.fanout_total_bytes
        ));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.fanout_workers)
        .enable_time()
        .build()
        .map_err(|e| format!("start the runtime: {e}"))?;
    let fanout = LiveFanout::new(cfg.fanout_queue_bytes, cfg.fanout_total_bytes);
    let ids = Arc::new(ids);
    let progress: Arc<Vec<AtomicUsize>> =
        Arc::new((0..readers).map(|_| AtomicUsize::new(0)).collect());

    let mut handles = Vec::with_capacity(readers);
    for reader in 0..readers {
        let mut receiver = fanout.attach(None);
        let (ids, progress) = (Arc::clone(&ids), Arc::clone(&progress));
        handles.push(runtime.spawn(async move {
            let mut bytes = 0usize;
            for (seen, expected) in ids.iter().enumerate() {
                match receiver.recv().await {
                    Ok(event) if event.event.id == *expected => bytes += event.json().len(),
                    Ok(_) => return Err(format!("reader {reader} received events out of order")),
                    Err(error) => {
                        return Err(format!(
                            "reader {reader} stopped after {seen} events: {error:?}"
                        ));
                    }
                }
                progress[reader].store(seen + 1, Ordering::Release);
            }
            Ok((Instant::now(), bytes))
        }));
    }
    if fanout.attached() != readers {
        return Err(format!(
            "{} readers are attached, expected {readers}",
            fanout.attached()
        ));
    }

    let started = Instant::now();
    for (published, event) in live.iter().enumerate() {
        if cfg.fanout_window > 0 {
            pace(&progress, published, cfg.fanout_window)?;
        }
        if published + 1 == count && fanout.attached() != readers {
            return Err(format!(
                "only {} of {readers} readers are still attached before the last event: \
                 one lagged",
                fanout.attached()
            ));
        }
        fanout.publish(event);
    }
    let published_in = started.elapsed();

    let mut finished = Vec::with_capacity(readers);
    let mut delivered_bytes = 0usize;
    for handle in handles {
        let joined = runtime.block_on(async { tokio::time::timeout(STALL, handle).await });
        match joined {
            Err(_) => return Err("a reader did not receive every event in time".into()),
            Ok(Err(_)) => return Err("a reader task panicked".into()),
            Ok(Ok(Err(message))) => return Err(message),
            Ok(Ok(Ok((at, bytes)))) => {
                finished.push(at.saturating_duration_since(started));
                delivered_bytes += bytes;
            }
        }
    }
    let all_done = finished.iter().copied().max().unwrap_or_default();
    let first_done = finished.iter().copied().min().unwrap_or_default();
    drop(runtime);
    if fanout.attached() != 0 {
        return Err(format!(
            "after every reader finished, {} are still attached",
            fanout.attached()
        ));
    }
    let deliveries = readers * count;
    Ok(json!({
        "readers": readers,
        "events": count,
        "workers": cfg.fanout_workers,
        "window": cfg.fanout_window,
        "queue_bytes": cfg.fanout_queue_bytes,
        "total_bytes": cfg.fanout_total_bytes,
        "charged_bytes_per_event": total_cost / count.max(1),
        "prepare": prepare_json(prepared_in, count),
        "deliveries": deliveries,
        "publish_ms": ms(published_in),
        "first_reader_complete_ms": ms(first_done),
        "all_readers_complete_ms": ms(all_done),
        "deliveries_per_s": per_second(deliveries, all_done),
        "delivered_json_bytes": delivered_bytes,
        "delivered_json_bytes_per_s": per_second(delivered_bytes, all_done),
        "queue_occupancy_note": "queue occupancy (held bytes) is not observable from outside wok-store, so it is not reported; delivered bytes are summed from the JSON the readers received",
    }))
}

/// Hold the publisher until it is at most `window` events ahead of the
/// slowest reader.
fn pace(progress: &[AtomicUsize], published: usize, window: usize) -> Result<(), String> {
    let mut waiting_since = Instant::now();
    let mut last = 0;
    loop {
        let slowest = progress
            .iter()
            .map(|p| p.load(Ordering::Acquire))
            .min()
            .unwrap_or(published);
        if published - slowest.min(published) <= window {
            return Ok(());
        }
        if slowest != last {
            last = slowest;
            waiting_since = Instant::now();
        } else if waiting_since.elapsed() > STALL {
            return Err("the slowest reader stopped making progress".into());
        }
        std::thread::sleep(Duration::from_micros(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_publisher_within_its_window_is_not_held() {
        let progress = [AtomicUsize::new(5), AtomicUsize::new(7)];
        assert!(pace(&progress, 8, 3).is_ok());
        assert!(pace(&progress, 5, 0).is_ok());
    }
}
