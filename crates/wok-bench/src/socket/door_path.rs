//! Door path: a diagnostic that sets the sheltered door beside stand-ins for
//! parts of its per-frame path, to test whether the door's two blocking-pool
//! hops account for the gap between the door and the engine driven directly.
//!
//! One connection, the sheltered door, keepers only, the baseline server
//! variant ([`BASELINE`]) and the client's TCP_NODELAY on. Two cells, window 32
//! and window 1. Per round and cell, five arms run, each on a fresh store and
//! relay (the stand-in has neither), over the same pre-signed events:
//!
//! 1. `door`: the socket scenario's socket cell.
//! 2. `direct`: the socket scenario's direct arm (the engine lane).
//! 3. `direct_one_hop`: the engine lane with the parse on `spawn_blocking`.
//! 4. `direct_two_hops`: the engine lane with the door's `apply` as well: a
//!    work permit and `begin_prepared` on a second `spawn_blocking`.
//! 5. `socket_ack_only`: the same client lane against a stand-in that answers
//!    every EVENT with `OK true` and does nothing else ([`super::ack_only`]).
//!
//! Round `r` runs the arms in their listed order starting at arm index
//! `r mod 5` (indices from 0). The comparison rule, fixed before any figures
//! were seen, is [`compare`] and [`consistent_with_hops`]. Nothing here adds an
//! artificial cost, and the scenario runs only when it is named.

use std::sync::Arc;

use serde_json::{Map, Value, json};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{Barrier, Semaphore};
use wok_store::Visibility;
use wok_store::relay::MAX_RELAY_FRAME_BYTES;

use super::ack_only::{AckOnly, EVENT_PREFIX, READ_BUFFER_BYTES, WRITE_BUFFER_BYTES};
use super::client::{Frame, connect_plain, write_lane};
use super::{CLIENT_WORKERS, Shared, Spec, client_runtime, sign_notes, socket_cell};
use crate::config::{Config, DOOR_INFLIGHT_WRITES, Variant};
use crate::corpus::{KIND_NOTE, author_keys, notes_key};
use crate::engine::writes::{Cell, DOOR_PERMIT_WAIT, Hops, cell_json, drive, engine_cell_with};
use crate::engine::{Clock, Keepers, wall_seconds};

/// The baseline server variant: 2 workers, 8 blocking threads, permits 2/1,
/// the server's TCP_NODELAY off.
pub(crate) const BASELINE: Variant = Variant {
    workers: 2,
    blocking: 8,
    shared: 2,
    public: 1,
    nodelay: false,
};
/// The window of the first cell; the second is window 1.
const WIDE_WINDOW: usize = 32;
/// The round count the comparison rule was designed for.
const DESIGNED_ROUNDS: usize = 8;
/// `consistent_with_hops`: the largest gap between the median throughputs of
/// two hops and the door, as a share of the door's median, inclusive.
const THROUGHPUT_SHARE: f64 = 0.10;
/// `consistent_with_hops`: the largest gap between their median mean batches,
/// in events, inclusive.
const BATCH_GAP: f64 = 1.0;
/// An arm run is marked `stalled` when its longest wait for an OK passed
/// this, in microseconds. A marker to read the store's checkpoint counts
/// beside; no rule uses it.
const STALL_US: f64 = 200_000.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    Door,
    Direct,
    DirectOneHop,
    DirectTwoHops,
    SocketAckOnly,
}

const ARMS: [Arm; 5] = [
    Arm::Door,
    Arm::Direct,
    Arm::DirectOneHop,
    Arm::DirectTwoHops,
    Arm::SocketAckOnly,
];

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Door => "door",
            Self::Direct => "direct",
            Self::DirectOneHop => "direct_one_hop",
            Self::DirectTwoHops => "direct_two_hops",
            Self::SocketAckOnly => "socket_ack_only",
        }
    }

    fn has_store(self) -> bool {
        self != Self::SocketAckOnly
    }
}

/// Round `round`'s order: the arms in their listed order, starting at index
/// `round mod 5`.
fn arm_order(round: usize) -> Vec<Arm> {
    (0..ARMS.len())
        .map(|i| ARMS[(round % ARMS.len() + i) % ARMS.len()])
        .collect()
}

/// The runtime of arms 2 to 4, fresh per arm run: the door's server runtime's
/// shape (workers, blocking threads, I/O and time drivers).
fn direct_runtime() -> Result<Runtime, String> {
    Builder::new_multi_thread()
        .worker_threads(BASELINE.workers)
        .max_blocking_threads(BASELINE.blocking)
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| format!("start the direct runtime: {e}"))
}

/// Arms 2 to 4: the engine lane on one sheltered session, with `hops` when
/// given, each with a fresh work semaphore of the door's shared permits.
fn direct_arm(shared: &Shared, spec: &Spec, hops: Option<Hops>) -> Result<Value, String> {
    let rt = direct_runtime()?;
    let subset = shared.subset(spec);
    let cell = Cell {
        cfg: shared.cfg,
        runtime: &rt,
        visibility: Visibility::Sheltered,
        events: &subset,
        total_events: spec.events,
        connections: 1,
        window: spec.window,
        clock: Clock::Wall,
    };
    let hops = hops.map(|hops| (hops, Arc::new(Semaphore::new(BASELINE.shared))));
    let mut out = engine_cell_with(
        &cell,
        &shared.texts[..spec.events],
        shared.keepers,
        shared.keys,
        hops,
    )?;
    out["connections"] = json!(1);
    out["workers"] = json!(BASELINE.workers);
    out["max_blocking_threads"] = json!(BASELINE.blocking);
    Ok(out)
}

/// Arm 5: the client lane against the acknowledge-only stand-in, without
/// authenticating. Nothing is stored, so nothing is verified.
fn ack_only_arm(shared: &Shared, spec: &Spec) -> Result<Value, String> {
    let mut stand_in = AckOnly::start(&BASELINE)?;
    let label = format!("ack-only stand-in, {}", spec.label());
    let socket = shared.client.block_on(connect_plain(
        &label,
        &stand_in.url,
        shared.cfg.socket_client_nodelay,
    ))?;
    let start = Arc::new(Barrier::new(2));
    let task = shared.client.spawn(write_lane(
        label.clone(),
        socket,
        Arc::clone(shared.frames),
        (0..spec.events).collect(),
        spec.window,
        Arc::clone(&start),
    ));
    let mut merged = drive(shared.client, vec![task], &start)?;
    stand_in.stop()?;
    let mut out = cell_json(&mut merged, spec.events, spec.window);
    out["variant"] = json!(BASELINE.label());
    out["connections"] = json!(1);
    out["writer"] = Value::Null;
    out["checkpoints"] = Value::Null;
    out["verified"] = Value::Null;
    out["store"] = json!("none: the stand-in stores nothing, so there is nothing to verify");
    Ok(out)
}

fn run_arm(shared: &Shared, arm: Arm, spec: &Spec) -> Result<Value, String> {
    let mut out = match arm {
        Arm::Door => socket_cell(shared, Visibility::Sheltered, &BASELINE, spec)?,
        Arm::Direct => direct_arm(shared, spec, None)?,
        Arm::DirectOneHop => direct_arm(shared, spec, Some(Hops::Parse))?,
        Arm::DirectTwoHops => direct_arm(shared, spec, Some(Hops::ParseAndBegin))?,
        Arm::SocketAckOnly => ack_only_arm(shared, spec)?,
    };
    if arm.has_store() {
        // Each store arm returns only once its store has passed `verify_cell`.
        out["verified"] = json!(true);
    }
    out["stalled"] = json!(is_stalled(&out));
    Ok(out)
}

/// Whether an arm run's longest wait for an OK passed [`STALL_US`].
fn is_stalled(run: &Value) -> bool {
    run["ok_latency"]["max_us"]
        .as_f64()
        .is_some_and(|max| max > STALL_US)
}

/// The median: the middle value, or the mean of the two middle values of an
/// even count.
pub(crate) fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    if n == 0 {
        return f64::NAN;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// One pair's comparison, X against Y.
#[derive(Debug, PartialEq)]
pub(crate) struct Pair {
    pub(crate) verdict: &'static str,
    /// Rounds in which X < Y, and in which X > Y; ties count as neither.
    pub(crate) below: usize,
    pub(crate) above: usize,
    pub(crate) median_x: f64,
    pub(crate) median_y: f64,
    pub(crate) median_batch_x: Option<f64>,
    pub(crate) median_batch_y: Option<f64>,
}

/// The rule, fixed before any figures were seen. The rounds are paired by
/// round number. With `n` rounds, X is "below" Y if X < Y in at least `n - 1`
/// of them (7 of 8, the count it was designed for), "above" if X > Y in at
/// least `n - 1`, and otherwise "not separated"; if both reach `n - 1`, which
/// only two rounds or fewer allow, it is "not separated".
pub(crate) fn compare(
    x: &[f64],
    y: &[f64],
    batch_x: Option<&[f64]>,
    batch_y: Option<&[f64]>,
) -> Pair {
    let n = x.len().min(y.len());
    let threshold = n.saturating_sub(1);
    let below = x.iter().zip(y).filter(|(x, y)| x < y).count();
    let above = x.iter().zip(y).filter(|(x, y)| x > y).count();
    let verdict = match (below >= threshold, above >= threshold) {
        (true, false) => "below",
        (false, true) => "above",
        _ => "not separated",
    };
    Pair {
        verdict,
        below,
        above,
        median_x: median(x),
        median_y: median(y),
        median_batch_x: batch_x.map(median),
        median_batch_y: batch_y.map(median),
    }
}

/// True only if two hops against the door is "not separated", their median
/// throughputs are within 10% of the door's, and their median mean batches
/// are within 1.0 event, both bounds inclusive.
fn consistent_with_hops(two_hops_vs_door: &Pair) -> bool {
    let pair = two_hops_vs_door;
    let (Some(batch_x), Some(batch_y)) = (pair.median_batch_x, pair.median_batch_y) else {
        return false;
    };
    pair.verdict == "not separated"
        && (pair.median_x - pair.median_y).abs() <= THROUGHPUT_SHARE * pair.median_y
        && (batch_x - batch_y).abs() <= BATCH_GAP
}

fn pair_json(x: Arm, y: Arm, pair: &Pair) -> Value {
    named_pair_json(x.name(), y.name(), pair)
}

/// A pair's record, X and Y named by the caller. The two names must differ.
pub(crate) fn named_pair_json(x: &str, y: &str, pair: &Pair) -> Value {
    let mut writes = Map::new();
    writes.insert(x.into(), json!(pair.median_x));
    writes.insert(y.into(), json!(pair.median_y));
    let mut batches = Map::new();
    batches.insert(x.into(), json!(pair.median_batch_x));
    batches.insert(y.into(), json!(pair.median_batch_y));
    json!({
        "x": x,
        "y": y,
        "verdict": pair.verdict,
        "below": pair.below,
        "above": pair.above,
        "median_writes_per_s": writes,
        "median_mean_batch": batches,
    })
}

const PAIRS: [(&str, Arm, Arm); 5] = [
    ("two_hops_vs_door", Arm::DirectTwoHops, Arm::Door),
    ("one_hop_vs_door", Arm::DirectOneHop, Arm::Door),
    ("direct_vs_door", Arm::Direct, Arm::Door),
    ("ack_only_vs_door", Arm::SocketAckOnly, Arm::Door),
    ("two_hops_vs_direct", Arm::DirectTwoHops, Arm::Direct),
];

/// Per arm, its writes/s and its mean batches by round, the mean batches
/// `None` for an arm without a store.
type Figures = Vec<(Arm, Vec<f64>, Option<Vec<f64>>)>;

fn figures(records: &[Map<String, Value>]) -> Result<Figures, String> {
    ARMS.iter()
        .map(|&arm| {
            let mut writes = Vec::with_capacity(records.len());
            let mut batches = Vec::with_capacity(records.len());
            for record in records {
                let run = &record[arm.name()];
                writes.push(
                    run["acknowledged_per_s"]
                        .as_f64()
                        .ok_or_else(|| format!("{}: no acknowledged_per_s", arm.name()))?,
                );
                if arm.has_store() {
                    batches.push(
                        run["writer"]["mean_batch_events"]
                            .as_f64()
                            .ok_or_else(|| format!("{}: no mean batch", arm.name()))?,
                    );
                }
            }
            Ok((arm, writes, arm.has_store().then_some(batches)))
        })
        .collect()
}

/// A cell's comparison block, from its figures by round.
fn comparison(figures: &Figures, rounds: usize, window: usize) -> Value {
    let find = |arm: Arm| {
        figures
            .iter()
            .find(|(a, _, _)| *a == arm)
            .expect("every arm has figures")
    };
    let mut pairs = Map::new();
    let mut two_hops = None;
    for (name, x, y) in PAIRS {
        let (_, xw, xb) = find(x);
        let (_, yw, yb) = find(y);
        let pair = compare(xw, yw, xb.as_deref(), yb.as_deref());
        pairs.insert(name.into(), pair_json(x, y, &pair));
        if name == "two_hops_vs_door" {
            two_hops = Some(pair);
        }
    }
    let mut out = json!({
        "metric": "acknowledged_per_s (writes/s), paired by round number",
        "rounds": rounds,
        "threshold": rounds.saturating_sub(1),
        "rule_designed_for_rounds": DESIGNED_ROUNDS,
        "pairs": pairs,
    });
    if rounds != DESIGNED_ROUNDS {
        out["rule_note"] = json!(format!(
            "the rule was designed for {DESIGNED_ROUNDS} rounds (7 of 8); with {rounds} it is at least {} of {rounds}",
            rounds.saturating_sub(1)
        ));
    }
    if window == WIDE_WINDOW {
        let consistent = two_hops.as_ref().is_some_and(consistent_with_hops);
        out["consistent_with_hops"] = json!(consistent);
        out["conclusion"] = json!(if consistent {
            "consistent with the hops"
        } else {
            "not located"
        });
    }
    out
}

fn rule() -> Value {
    json!({
        "fixed": "before any figures were seen; it must not change after",
        "pairing": "rounds are paired by round number",
        "below": "X is below Y if X < Y in at least n - 1 of n rounds (7 of 8)",
        "above": "X is above Y if X > Y in at least n - 1 of n rounds",
        "not_separated": "anything else, and also when both below and above reach n - 1 (possible only with 2 rounds or fewer)",
        "ties": "a round with X = Y counts as neither below nor above",
        "designed_for_rounds": DESIGNED_ROUNDS,
        "median": "the middle value, or the mean of the two middle values of an even count; no other statistic is recorded",
        "consistent_with_hops": format!(
            "window {WIDE_WINDOW} cell only: true only if two_hops_vs_door is not separated, |median writes/s of direct_two_hops - median of door| <= {THROUGHPUT_SHARE} x median of door, and |median mean batch of direct_two_hops - median of door| <= {BATCH_GAP}, both bounds inclusive; anything else is \"not located\""
        ),
    })
}

fn stand_ins_omit() -> Value {
    let hop_arms = json!([
        "the socket and WebSocket framing: frames reach the lane as strings and no reply is serialised onto a socket",
        "the door's connection select loop (reading frames, the in-flight set, timers and shutdown in one select)",
        "OK delivery on the wire",
        "the `deliver` authority recheck the sheltered door makes before sending replies (`try_can_read`, or `can_read_live` through `apply`)",
        "the public allowance (the public door's own work permit), which the sheltered door does not take either",
        "`is_event_frame` and `refuse_unverified`; the door calls `admit_frame` before the parse hop, the lane after it, as the engine lane does",
        "the door's in-flight bookkeeping (`reserve` polled once with `now_or_never`, then ticket waits in a `FuturesUnordered`); the lane keeps the engine lane's commit forms, so at window 1 it uses `PendingWrite::commit`",
    ]);
    let mut one_hop = hop_arms.clone();
    if let Some(list) = one_hop.as_array_mut() {
        list.push(json!(
            "the second hop: the work permit and `begin_prepared` on the blocking pool (`begin_prepared` runs inline on the lane's task)"
        ));
    }
    json!({
        "direct": "everything the door adds: the socket and framing, both blocking-pool hops and the work permit, the select loop, OK delivery on the wire, the `deliver` recheck and the public allowance",
        "direct_one_hop": one_hop,
        "direct_two_hops": hop_arms,
        "socket_ack_only": "AUTH (no challenge is sent and none is answered), parsing, signature verification, the session engine and the store; the stand-in slices the id at a fixed offset and answers OK true. It is a benchmark stand-in, not a relay, and must never be used as one",
    })
}

fn runtimes() -> Value {
    json!({
        "door": format!(
            "the socket scenario's server runtime: multi-thread, worker_threads {}, max_blocking_threads {}, I/O and time drivers, fresh per cell; the client lane runs on the client runtime ({CLIENT_WORKERS} workers)",
            BASELINE.workers, BASELINE.blocking
        ),
        "direct_direct_one_hop_direct_two_hops": format!(
            "a fresh multi-thread runtime per arm run: worker_threads {}, max_blocking_threads {}, I/O and time drivers; the lane is a task spawned on it and the relay's writer is its own thread, as in every arm with a store",
            BASELINE.workers, BASELINE.blocking
        ),
        "differs_from_the_socket_scenario_direct_arm": format!(
            "the socket scenario's direct arm builds its runtime with worker_threads {} and the time driver only: no I/O driver and tokio's default blocking-thread cap (512). Here max_blocking_threads is {} and the I/O driver is enabled, as on the door's server runtime. The direct arm's lane code (`engine_lane`) is unchanged, and the socket scenario is unchanged",
            BASELINE.workers, BASELINE.blocking
        ),
        "socket_ack_only": format!(
            "the stand-in's own runtime, the same shape as the door's server runtime (worker_threads {}, max_blocking_threads {}, I/O and time drivers), fresh per cell; the client lane runs on the client runtime",
            BASELINE.workers, BASELINE.blocking
        ),
        "two_hops_semaphore": format!(
            "a fresh `tokio::sync::Semaphore` of {} permits per arm run, taken with `acquire_owned` under a {}s deadline, as the door's shared work permits are",
            BASELINE.shared,
            DOOR_PERMIT_WAIT.as_secs()
        ),
    })
}

pub fn run(cfg: &Config) -> Result<Value, String> {
    let mut cfg = cfg.clone();
    cfg.socket_client_nodelay = true;
    let cfg = &cfg;
    let specs = [
        Spec {
            connections: 1,
            window: WIDE_WINDOW,
            events: cfg.door_path_events,
        },
        Spec {
            connections: 1,
            window: 1,
            events: cfg.door_path_serial_events,
        },
    ];
    let signed = specs.iter().map(|spec| spec.events).max().unwrap_or(0);
    let rounds = cfg.door_path_rounds;
    eprintln!("door-path: 2 cells, 5 arms, {rounds} rounds, {signed} notes to sign");
    let keys = author_keys(cfg)?;
    if keys.is_empty() {
        return Err("the door-path scenario needs at least one author key".into());
    }
    let notes = notes_key(cfg.seed)?;
    let keepers = Arc::new(Keepers::new(
        keys.iter()
            .map(nostr::key::Keys::public_key)
            .chain([notes.public_key()]),
    ));
    let start = wall_seconds();
    let events = sign_notes(cfg, &keys, signed, start)?;
    let mut frames = Vec::with_capacity(events.len());
    let mut texts = Vec::with_capacity(events.len());
    for event in &events {
        let (frame, text) = Frame::new(event)?;
        frames.push(frame);
        texts.push(text);
    }
    let frames = Arc::new(frames);
    let client = client_runtime()?;
    let shared = Shared {
        cfg,
        keepers: &keepers,
        keys: &keys,
        client: &client,
        widest: 1,
        frames: &frames,
        texts: &texts,
        events: &events,
    };

    // Per cell, the arms' records by round.
    let mut by_cell: Vec<Vec<Map<String, Value>>> = specs.iter().map(|_| Vec::new()).collect();
    let mut round_records = Vec::with_capacity(rounds);
    for round in 1..=rounds {
        let order = arm_order(round);
        let mut cells = Vec::with_capacity(specs.len());
        for (index, spec) in specs.iter().enumerate() {
            let mut arms = Map::new();
            for &arm in &order {
                eprintln!(
                    "door-path round {round}, window {}: {}",
                    spec.window,
                    arm.name()
                );
                let out = run_arm(&shared, arm, spec)
                    .map_err(|e| format!("round {round}, {}, {}: {e}", arm.name(), spec.label()))?;
                arms.insert(arm.name().into(), out);
            }
            by_cell[index].push(arms.clone());
            cells.push(json!({
                "window": spec.window,
                "events": spec.events,
                "arms": arms,
            }));
        }
        round_records.push(json!({
            "round": round,
            "arm_order": order.iter().map(|arm| arm.name()).collect::<Vec<_>>(),
            "cells": cells,
        }));
    }

    let mut cells = Vec::with_capacity(specs.len());
    for (spec, records) in specs.iter().zip(&by_cell) {
        let figures = figures(records)?;
        cells.push(json!({
            "window": spec.window,
            "events": spec.events,
            "rounds": rounds,
            "comparison": comparison(&figures, rounds, spec.window),
        }));
    }

    Ok(json!({
        "note": "a diagnostic, not part of a default run: loopback figures, the client and the server in one process on one host, CPU not attributed to either side. It tests one explanation of the gap between the door and the direct engine lane and says nothing about a real network or any other relay",
        "settings": {
            "door": "sheltered",
            "connections": 1,
            "authors": "keepers only",
            "variant": BASELINE.label(),
            "variant_syntax": "workers:blocking:shared/public:nodelay",
            "client_nodelay": true,
            "client_workers": CLIENT_WORKERS,
            "windows": [WIDE_WINDOW, 1],
            "events_at_window_32": cfg.door_path_events,
            "events_at_window_1": cfg.door_path_serial_events,
            "rounds": rounds,
            "arms": ARMS.iter().map(|arm| arm.name()).collect::<Vec<_>>(),
            "round_order": "round r runs the cells window 32 then window 1, and in each the arms in the listed order starting at index r mod 5 (indices from 0)",
            "per_arm": "a fresh store and relay per arm run (the stand-in has neither), over the same pre-signed events",
            "door_inflight_writes": DOOR_INFLIGHT_WRITES,
            "listener": "127.0.0.1:0 only, for the door and the stand-in",
            "stand_in_socket": {
                "read_buffer_bytes": READ_BUFFER_BYTES,
                "write_buffer_bytes": WRITE_BUFFER_BYTES,
                "max_message_bytes": MAX_RELAY_FRAME_BYTES,
                "id_slice": format!("the 64 characters after {EVENT_PREFIX}"),
            },
        },
        "runtimes": runtimes(),
        "stand_ins_omit": stand_ins_omit(),
        "rule": rule(),
        "signing": {
            "kind": KIND_NOTE,
            "created_at": "start - 1000 - 10 * count + 10 * i, where start is wall time at the scenario's start",
            "start": start,
            "count": signed,
        },
        "rounds": round_records,
        "cells": cells,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Config {
        Config {
            authors: 4,
            content_bytes: 64,
            door_path: true,
            door_path_events: 40,
            door_path_serial_events: 6,
            door_path_rounds: 2,
            ..Config::default()
        }
    }

    /// Two rounds at tiny sizes: every arm of every cell comes back, every
    /// store verifies, the order rotates, and every comparison block is there.
    #[test]
    fn the_door_path_scenario_runs_at_tiny_sizes_and_reports_every_arm() {
        let document = run(&tiny()).unwrap_or_else(|e| panic!("the door-path run failed: {e}"));
        let rounds = document["rounds"].as_array().unwrap();
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0]["arm_order"][0], "direct");
        assert_eq!(rounds[1]["arm_order"][0], "direct_one_hop");
        for round in rounds {
            let cells = round["cells"].as_array().unwrap();
            assert_eq!(cells.len(), 2);
            assert_eq!(cells[0]["window"], 32);
            assert_eq!(cells[1]["window"], 1);
            for cell in cells {
                let events = cell["events"].as_u64().unwrap();
                for arm in ARMS {
                    let run = &cell["arms"][arm.name()];
                    assert_eq!(run["events"], events, "{}", arm.name());
                    assert_eq!(run["ok_latency"]["count"], events, "{}", arm.name());
                    assert!(run["acknowledged_per_s"].as_f64().unwrap() > 0.0);
                    if arm.has_store() {
                        assert_eq!(run["verified"], true, "{}", arm.name());
                        assert_eq!(run["writer"]["events"], events, "{}", arm.name());
                        assert!(run["writer"]["commits"].as_u64().unwrap() > 0);
                        assert!(run["checkpoints"]["peak_wal_pages"].as_u64().unwrap() > 0);
                        assert!(run["checkpoints"]["blocking_ms"].is_number());
                    } else {
                        assert!(run["writer"].is_null());
                        assert!(run["checkpoints"].is_null());
                    }
                    assert!(run["stalled"].is_boolean(), "{}", arm.name());
                }
                assert_eq!(cell["arms"]["direct_one_hop"]["hops"], "parse");
                assert_eq!(cell["arms"]["direct_two_hops"]["hops"], "parse_and_begin");
            }
        }
        let cells = document["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 2);
        for cell in cells {
            let comparison = &cell["comparison"];
            for (name, _, _) in PAIRS {
                let pair = &comparison["pairs"][name];
                assert!(pair["verdict"].is_string(), "{name}");
                assert!(pair["below"].is_u64() && pair["above"].is_u64(), "{name}");
            }
            assert!(comparison["rule_note"].is_string(), "2 rounds, not 8");
        }
        assert!(cells[0]["comparison"]["consistent_with_hops"].is_boolean());
        assert!(cells[0]["comparison"]["conclusion"].is_string());
        assert!(cells[1]["comparison"].get("consistent_with_hops").is_none());
        let text = document.to_string();
        assert!(!text.contains("0.0.0.0"));
    }

    const EIGHT: [f64; 8] = [100.0, 110.0, 120.0, 130.0, 140.0, 150.0, 160.0, 170.0];

    fn shifted(by: [f64; 8]) -> Vec<f64> {
        EIGHT.iter().zip(by).map(|(y, d)| y + d).collect()
    }

    #[test]
    fn below_needs_seven_rounds_of_eight() {
        let y = EIGHT.to_vec();
        let x = shifted([-5.0, -5.0, -5.0, -5.0, -5.0, -5.0, -5.0, 5.0]);
        let pair = compare(&x, &y, None, None);
        assert_eq!((pair.verdict, pair.below, pair.above), ("below", 7, 1));
        // A tie is neither, so six below and a tie is not enough.
        let x = shifted([-5.0, -5.0, -5.0, -5.0, -5.0, -5.0, 0.0, 5.0]);
        let pair = compare(&x, &y, None, None);
        assert_eq!(
            (pair.verdict, pair.below, pair.above),
            ("not separated", 6, 1)
        );
    }

    #[test]
    fn above_needs_seven_rounds_of_eight() {
        let y = EIGHT.to_vec();
        let x = shifted([5.0; 8]);
        let pair = compare(&x, &y, None, None);
        assert_eq!((pair.verdict, pair.below, pair.above), ("above", 0, 8));
        assert_eq!((pair.median_x, pair.median_y), (140.0, 135.0));
    }

    #[test]
    fn anything_else_is_not_separated() {
        let y = EIGHT.to_vec();
        let x = shifted([-5.0, 5.0, -5.0, 5.0, -5.0, 5.0, -5.0, 5.0]);
        let pair = compare(&x, &y, None, None);
        assert_eq!(
            (pair.verdict, pair.below, pair.above),
            ("not separated", 4, 4)
        );
        // Another round count: n - 1 of n.
        let pair = compare(&[1.0, 1.0, 1.0, 2.0], &[2.0, 2.0, 2.0, 1.0], None, None);
        assert_eq!(pair.verdict, "below");
        let pair = compare(&[1.0, 1.0, 2.0, 2.0], &[2.0, 2.0, 1.0, 1.0], None, None);
        assert_eq!(pair.verdict, "not separated");
    }

    #[test]
    fn consistent_with_hops_needs_all_three_conditions() {
        let door = EIGHT.to_vec();
        let near = shifted([-5.0, 5.0, -5.0, 5.0, -5.0, 5.0, -5.0, 5.0]);
        let batches = [4.0; 8];
        let close = [4.5; 8];
        let far = [5.5; 8];
        let pair = compare(&near, &door, Some(&close), Some(&batches));
        assert!(consistent_with_hops(&pair));
        // The batch bound is inclusive at 1.0.
        let pair = compare(&near, &door, Some(&[5.0; 8]), Some(&batches));
        assert!(consistent_with_hops(&pair));
        let pair = compare(&near, &door, Some(&far), Some(&batches));
        assert!(!consistent_with_hops(&pair), "the batches differ by 1.5");
        let below = shifted([-5.0; 8]);
        let pair = compare(&below, &door, Some(&close), Some(&batches));
        assert!(!consistent_with_hops(&pair), "separated");
        // Not separated, but the medians are more than 10% apart.
        let wide: Vec<f64> = EIGHT
            .iter()
            .enumerate()
            .map(|(i, y)| if i % 2 == 0 { y - 1.0 } else { y * 2.0 })
            .collect();
        let pair = compare(&wide, &door, Some(&close), Some(&batches));
        assert_eq!(pair.verdict, "not separated");
        assert!(!consistent_with_hops(&pair), "medians more than 10% apart");
        let pair = compare(&near, &door, None, Some(&batches));
        assert!(!consistent_with_hops(&pair), "no batches to compare");
    }

    #[test]
    fn only_the_window_32_cell_carries_the_conclusion() {
        let figures: Figures = ARMS
            .iter()
            .map(|&arm| (arm, EIGHT.to_vec(), arm.has_store().then(|| vec![4.0; 8])))
            .collect();
        let wide = comparison(&figures, 8, WIDE_WINDOW);
        assert_eq!(wide["consistent_with_hops"], true);
        assert_eq!(wide["conclusion"], "consistent with the hops");
        assert!(wide.get("rule_note").is_none());
        assert_eq!(
            wide["pairs"]["ack_only_vs_door"]["median_mean_batch"]["socket_ack_only"],
            Value::Null
        );
        let serial = comparison(&figures, 8, 1);
        assert!(serial.get("consistent_with_hops").is_none());
        assert!(serial.get("conclusion").is_none());
    }
}
