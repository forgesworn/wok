//! Subscribers: what many authenticated sessions, each with one open REQ and
//! an attached live receiver, hold in memory, and the cost of delivering a
//! published event to all of them.
//!
//! Only the public door is used. A sheltered session's live delivery asks the
//! keeper source for a verdict per event, which is a cost this scenario does
//! not measure.
//!
//! Memory is read from the counting global allocator, so it is Rust
//! allocations only: SQLite's own memory and the operating system's per-thread
//! and per-task overheads are not in it. A throwaway session goes through the
//! same steps first, so that anything allocated once for the process (and not
//! per subscriber) is already there before the first reading. The sessions and
//! receivers are boxed and their vectors sized in advance, so that what each
//! one holds is counted when it is made and not hidden in a vector's spare
//! room.
//!
//! Delivery: S tasks on a multi-thread runtime each wait on their receiver,
//! turn every live event into frames with `try_on_live` (falling back to
//! `on_live` when it answers `None`, which is counted) and require exactly one
//! EVENT frame per event, in publication order. The events are published
//! through a writing keeper session, all reserved in the writer's queue before
//! any is awaited, so the writer commits them in a few batches. A lagging or
//! closed receiver fails the run.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use nostr::key::Keys;
use serde_json::{Value, json};
use tokio::sync::Barrier;
use wok_store::relay::{Handled, LiveReceiver, PreparedFrame, RelaySession, frame, ok};
use wok_store::{EventStore, Visibility};

use super::{
    Keepers, STALL, authenticate, describe, event_text, reference_frame, relay_over, relay_url,
    runtime,
};
use crate::alloc::{live_bytes, peak_bytes, reset_peak};
use crate::config::Config;
use crate::corpus::{NOW, notes};
use crate::fanout::CHARGE_OVERHEAD;
use crate::support::{fresh_store, ms, per_second};

const SUBSCRIPTION: &str = "live";

struct Receipt {
    first: Instant,
    last: Instant,
    fallbacks: usize,
}

fn each(total: usize, subscribers: usize) -> f64 {
    (total as f64 / subscribers as f64 * 10.0).round() / 10.0
}

/// A signed difference of two readings, clamped at zero: a reading can fall a
/// little when another thread frees something.
fn grew(after: usize, before: usize) -> usize {
    after.saturating_sub(before)
}

async fn subscriber(
    index: usize,
    mut session: Box<RelaySession>,
    mut receiver: Box<LiveReceiver>,
    expected: Arc<Vec<String>>,
    parked: Arc<AtomicUsize>,
    start: Arc<Barrier>,
) -> Result<Receipt, String> {
    parked.fetch_add(1, Ordering::Release);
    start.wait().await;
    let mut first = None;
    let mut fallbacks = 0;
    for (n, want) in expected.iter().enumerate() {
        let live = receiver.recv().await.map_err(|error| {
            format!("subscriber {index} stopped after {n} events: {error:?} (a lagging reader fails the run)")
        })?;
        first.get_or_insert_with(Instant::now);
        let frames = match session.try_on_live(&live, NOW) {
            Some(frames) => frames,
            None => {
                fallbacks += 1;
                session.on_live(&live, NOW)
            }
        };
        if frames.len() != 1 || frames[0] != *want {
            return Err(format!(
                "subscriber {index}, event {n}: expected one EVENT frame in publication order, got {}",
                describe(&frames)
            ));
        }
    }
    Ok(Receipt {
        first: first.unwrap_or_else(Instant::now),
        last: Instant::now(),
        fallbacks,
    })
}

pub fn run(cfg: &Config, keepers: &Arc<Keepers>, notes_keys: &Keys) -> Result<Value, String> {
    let subscribers = cfg.engine_subscribers;
    let published = cfg.engine_publish;
    eprintln!("engine: subscribers, {subscribers} sessions, {published} events published");

    // Signed before any clock or reading.
    let signed = notes(cfg.seed, published, cfg.content_bytes)?;
    if signed
        .iter()
        .any(|event| event.pubkey != notes_keys.public_key())
    {
        return Err("the notes are not signed by the notes key".into());
    }
    let mut expected = Vec::with_capacity(published);
    let mut publish_frames = Vec::with_capacity(published);
    let mut cost = 0usize;
    for event in &signed {
        expected.push(reference_frame(SUBSCRIPTION, event)?);
        publish_frames.push(event_text(event)?);
        let json_len = serde_json::to_string(event)
            .map_err(|e| format!("serialise an event: {e}"))?
            .len();
        cost += json_len + CHARGE_OVERHEAD;
    }
    if cfg.fanout_queue_bytes < cost || cfg.fanout_total_bytes < cost {
        return Err(format!(
            "the live ceilings are too small: a subscriber may hold all {published} events \
             ({cost} bytes) before it drains them (queue {} bytes, total {} bytes). \
             Raise --fanout-queue-bytes and --fanout-total-bytes or lower --engine-publish",
            cfg.fanout_queue_bytes, cfg.fanout_total_bytes
        ));
    }
    let expected = Arc::new(expected);
    let req = serde_json::to_string(&json!([
        "REQ",
        SUBSCRIPTION,
        { "kinds": [1], "authors": [notes_keys.public_key().to_hex()], "limit": 10 }
    ]))
    .map_err(|e| format!("serialise a REQ: {e}"))?;
    let eose = frame(json!(["EOSE", SUBSCRIPTION]));

    let runtime = runtime(cfg.engine_workers)?;
    let (_dir, store) = fresh_store(cfg, published)?;
    let relay = relay_over(
        Arc::clone(&store) as Arc<dyn EventStore>,
        keepers,
        Some((cfg.fanout_queue_bytes, cfg.fanout_total_bytes)),
    );
    let url = relay_url()?;

    // The publishing keeper, made before the first reading.
    let mut keeper = relay.session(Visibility::Public, url.clone(), NOW);
    authenticate(&mut keeper, notes_keys, "publishing keeper")?;

    // The throwaway: the same steps as a subscriber, then dropped.
    {
        let mut session = relay.session(Visibility::Public, url.clone(), NOW);
        authenticate(&mut session, notes_keys, "warm-up session")?;
        let replies = session.handle(&req, NOW);
        if replies != [eose.clone()] {
            return Err(format!(
                "warm-up REQ: expected one EOSE, got {}",
                describe(&replies)
            ));
        }
        if !session.has_subscriptions() {
            return Err("warm-up REQ: the session holds no subscription".into());
        }
        let receiver = relay.subscribe_partition(Visibility::Public);
        drop(receiver);
        drop(session);
    }

    let mut sessions: Vec<Box<RelaySession>> = Vec::with_capacity(subscribers);
    let mut receivers: Vec<Box<LiveReceiver>> = Vec::with_capacity(subscribers);
    let mut handles = Vec::with_capacity(subscribers);

    let base = live_bytes();
    for index in 0..subscribers {
        let mut session = Box::new(relay.session(Visibility::Public, url.clone(), NOW));
        authenticate(&mut session, notes_keys, &format!("subscriber {index}"))?;
        sessions.push(session);
    }
    let after_auth = live_bytes();
    for (index, session) in sessions.iter_mut().enumerate() {
        let replies = session.handle(&req, NOW);
        if replies != [eose.clone()] {
            return Err(format!(
                "subscriber {index}: REQ expected one EOSE, got {}",
                describe(&replies)
            ));
        }
    }
    let after_req = live_bytes();
    for (index, session) in sessions.iter().enumerate() {
        // As a transport does: only while a REQ is open.
        if !session.has_subscriptions() {
            return Err(format!("subscriber {index}: no open subscription"));
        }
        receivers.push(Box::new(relay.subscribe_partition(Visibility::Public)));
    }
    let after_receivers = live_bytes();

    let parked = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(Barrier::new(subscribers + 1));
    for (index, (session, receiver)) in sessions.into_iter().zip(receivers).enumerate() {
        handles.push(runtime.spawn(subscriber(
            index,
            session,
            receiver,
            Arc::clone(&expected),
            Arc::clone(&parked),
            Arc::clone(&start),
        )));
    }
    let waiting = Instant::now();
    while parked.load(Ordering::Acquire) < subscribers {
        if waiting.elapsed() > STALL {
            return Err("the subscriber tasks did not all start".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // Let the last of them reach the barrier.
    std::thread::sleep(Duration::from_millis(100));
    let before_delivery = live_bytes();
    reset_peak();

    // Release the subscribers, then publish. The clock starts here.
    let started = Instant::now();
    runtime.block_on(start.wait());
    let publishing: Result<(), String> = runtime.block_on(async {
        let mut tickets = Vec::with_capacity(published);
        for (n, text) in publish_frames.into_iter().enumerate() {
            let prepared = PreparedFrame::parse(text);
            if !keeper.admit_frame(NOW) {
                return Err(format!("publish {n}: the frame allowance refused it"));
            }
            match keeper.begin_prepared(prepared, NOW) {
                Handled::Write(write) => {
                    let id = write.id().to_owned();
                    let ticket = write.reserve().await.map_err(|replies| {
                        format!(
                            "publish {n}: no place in the writer's queue: {}",
                            describe(&replies)
                        )
                    })?;
                    tickets.push((id, ticket));
                }
                Handled::Replies(replies) => {
                    return Err(format!(
                        "publish {n}: expected a write to queue, got {}",
                        describe(&replies)
                    ));
                }
            }
        }
        for (id, ticket) in tickets {
            let replies = ticket.wait().await;
            if replies != [ok(&id, true, "")] {
                return Err(format!(
                    "publish {id}: expected one OK true, got {}",
                    describe(&replies)
                ));
            }
        }
        Ok(())
    });
    let published_in = started.elapsed();
    publishing?;

    let mut first = None::<Instant>;
    let mut last = None::<Instant>;
    let mut fallbacks = 0usize;
    for handle in handles {
        let joined = runtime.block_on(async { tokio::time::timeout(STALL, handle).await });
        let receipt = match joined {
            Err(_) => return Err("a subscriber did not receive every event in time".into()),
            Ok(Err(_)) => return Err("a subscriber task panicked".into()),
            Ok(Ok(receipt)) => receipt?,
        };
        first = Some(first.map_or(receipt.first, |at| at.min(receipt.first)));
        last = Some(last.map_or(receipt.last, |at| at.max(receipt.last)));
        fallbacks += receipt.fallbacks;
    }
    let peak = peak_bytes();
    relay.flush();
    let stats = relay.writer_stats();
    if stats.events != published as u64 {
        return Err(format!(
            "the writer stored {} events, expected {published}",
            stats.events
        ));
    }
    let (first, last) = (
        first.ok_or("no subscriber reported")?,
        last.ok_or("no subscriber reported")?,
    );
    let wall = last.saturating_duration_since(started);
    let span = last.saturating_duration_since(first);
    let deliveries = subscribers * published;

    let stage =
        |total: usize| json!({ "total_bytes": total, "bytes_each": each(total, subscribers) });
    let session_bytes = grew(after_auth, base);
    let subscription_bytes = grew(after_req, after_auth);
    let receiver_bytes = grew(after_receivers, after_req);
    let task_bytes = grew(before_delivery, after_receivers);
    let held = session_bytes + subscription_bytes + receiver_bytes;
    Ok(json!({
        "door": "public",
        "door_note": "the public door only; the sheltered door's per-event keeper verdict is not measured",
        "subscribers": subscribers,
        "published": published,
        "settings": {
            "filter": "kinds [1], one author, limit 10, matching every published event",
            "live_queue_bytes": cfg.fanout_queue_bytes,
            "live_total_bytes": cfg.fanout_total_bytes,
            "workers": cfg.engine_workers,
            "content_bytes": cfg.content_bytes,
            "charged_bytes_for_all_events": cost,
            "publish_form": "every write reserved in arrival order in the writer's queue, then every ticket awaited",
        },
        "allocations": {
            "note": "Rust allocations only, read from the counting allocator; SQLite's memory and the operating system's per-thread and per-task costs are not in it. A warm-up session ran the same steps first.",
            "live_bytes_before": base,
            "session_after_auth": stage(session_bytes),
            "open_subscription": stage(subscription_bytes),
            "attached_receiver": stage(receiver_bytes),
            "session_subscription_receiver": stage(held),
            "parked_task": stage(task_bytes),
            "live_bytes_after_tasks_parked": before_delivery,
        },
        "delivery": {
            "events": published,
            "deliveries": deliveries,
            "wall_ms": ms(wall),
            "span_ms": ms(span),
            "deliveries_per_s_wall": per_second(deliveries, wall),
            "deliveries_per_s_span": per_second(deliveries, span),
            "publish_to_last_ok_ms": ms(published_in),
            "live_bytes_before_delivery": before_delivery,
            "peak_live_bytes_during_delivery": peak,
            "peak_growth_bytes": grew(peak, before_delivery),
            "peak_note": "the peak is the whole process's, so it includes the publishing thread's parsing and write tickets, the queued live events and the frames each subscriber builds",
            "try_on_live_fallbacks": fallbacks,
            "writer_batches": stats.batches,
        },
    }))
}
