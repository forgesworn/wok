//! Socket: acknowledged writes through `wok-ws`'s WebSocket doors, over
//! loopback, set beside the engine driven directly on the same events.
//!
//! Per round, per door (sheltered, then public), per server variant and per
//! cell, a fresh `wok_ws::Door` over an `EventRelay` on a fresh empty store is
//! served by `axum::serve` on `127.0.0.1:0`, on its own multi-thread runtime.
//! Clients on a separate runtime connect, answer the AUTH challenge with a
//! real NIP-42 AUTH stamped with wall time, wait at a start barrier and then
//! keep a window of signed EVENT frames in flight, sending the next as each OK
//! returns. The relay keeps its own clock, as a door's relay does, so the
//! writer's recheck and the engine's checks see the wall time.
//!
//! The direct arm is the existing engine lane (no socket, no door, no
//! WebSocket framing) over the same events with the same runtime workers and
//! the same wall-time `now`. It runs once per (round, door, cell, distinct
//! server worker count), next to the first socket cell with that count.
//!
//! The scenario signs its own kind-1 notes by the keeper keys, so it builds no
//! corpus. Every frame is serialised before any clock starts, and the
//! relay verifies every signature itself.
//!
//! The figures are loopback figures. Client and server share one process and
//! one host, and CPU is not attributed to either side. The raised
//! allowances (frame limit, connection limits, work limits) are the only
//! differences from the production door's limits, and are recorded in the
//! result beside the production values. The figures say nothing about a real
//! network, TLS, a proxy, another host or any other relay.

mod ack_only;
mod client;
pub(crate) mod door_path;
mod server;

use std::collections::HashSet;
use std::sync::Arc;

use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind};
use nostr::filter::Filter;
use nostr::key::Keys;
use nostr::types::Timestamp;
use serde_json::{Value, json};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::Barrier;
use wok_store::relay::{PUBLIC_KINDS, ok};
use wok_store::{EventStore, Visibility};

use crate::config::{Config, DOOR_INFLIGHT_WRITES, Variant};
use crate::corpus::{KIND_NOTE, author_keys, notes_key};
use crate::engine::writes::{Cell, cell_json, drive, engine_cell, verify_cell, writer_json};
use crate::engine::{
    Clock, FRAME_LIMIT, Keepers, PRODUCTION_FRAME_LIMIT, runtime, tag, wall_seconds,
};
use crate::support::{SplitMix, partition_name};
use client::{Frame, connect_all, exchange, write_lane};
use server::Server;

/// Worker threads of the client runtime, fixed and recorded so that the load
/// the clients put on the host does not change from one cell to the next.
const CLIENT_WORKERS: usize = 4;
/// The door's own connection allowances (`CONNECTIONS` and `PUBLIC_CONNECTIONS`
/// in `wok-ws`, which are private), recorded beside the raised values.
const PRODUCTION_SHARED_CONNECTIONS: usize = 32;
const PRODUCTION_PUBLIC_CONNECTIONS: usize = 24;
/// The public door's own work permits (`PUBLIC_WORK_PERMITS` in `wok-ws`,
/// which is private). The shared ones are `wok_ws::WORK_PERMITS`.
const PRODUCTION_PUBLIC_WORK_PERMITS: usize = 1;
/// A kind the public door does not take (`PUBLIC_KINDS` lacks it).
const REFUSED_KIND: u16 = 30023;
/// What the engine answers an unauthenticated write on either door, from
/// `refusal_for` in `wok-store`'s relay engine.
const BEFORE_AUTH_REASON: &str = "auth-required: authenticate for sheltered access";
/// What the engine answers a keeper's event of a kind the public door does not
/// take, from the same place.
const OUT_OF_KIND_REASON: &str =
    "restricted: public door accepts keeper-authored public kinds only";

/// One cell: a connection count, a window and a number of events.
#[derive(Clone, Copy)]
struct Spec {
    connections: usize,
    window: usize,
    events: usize,
}

impl Spec {
    fn label(&self) -> String {
        format!(
            "{} connections, window {}, {} events",
            self.connections, self.window, self.events
        )
    }
}

fn cell_specs(cfg: &Config) -> Vec<Spec> {
    let mut specs: Vec<Spec> = cfg
        .socket_connections
        .iter()
        .map(|&connections| Spec {
            connections,
            window: cfg.socket_window,
            events: cfg.socket_events,
        })
        .collect();
    if cfg.socket_serial_events > 0 {
        specs.push(Spec {
            connections: 1,
            window: 1,
            events: cfg.socket_serial_events,
        });
    }
    specs
}

/// Note content: the index, then seeded letters, `bytes` long.
fn content(rng: &mut SplitMix, index: usize, bytes: usize) -> String {
    let mut out = format!("{index:08} ");
    while out.len() < bytes {
        out.push((b'a' + rng.below(26) as u8) as char);
    }
    out.truncate(bytes.max(9));
    out
}

/// `count` kind-1 notes, signed by the keeper keys in turn, with
/// `created_at = start - 1000 - 10 * count + 10 * i`: all in the past by the
/// wall clock, so that nothing is refused as future-dated and the same events
/// are valid for the socket and the direct arm.
fn sign_notes(cfg: &Config, keys: &[Keys], count: usize, start: u64) -> Result<Vec<Event>, String> {
    let mut rng = SplitMix(cfg.seed ^ 0x736F_636B_6574);
    let base = start
        .checked_sub(1000 + 10 * count as u64)
        .ok_or("the wall clock is too early to date the notes")?;
    (0..count)
        .map(|i| {
            EventBuilder::new(
                Kind::from(KIND_NOTE),
                content(&mut rng, i, cfg.content_bytes),
            )
            .custom_created_at(Timestamp::from_secs(base + 10 * i as u64))
            .finalize(&keys[i % keys.len()])
            .map_err(|e| format!("sign a note: {e}"))
        })
        .collect()
}

fn client_runtime() -> Result<Runtime, String> {
    Builder::new_multi_thread()
        .worker_threads(CLIENT_WORKERS)
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| format!("start the client runtime: {e}"))
}

/// What every cell shares.
struct Shared<'a> {
    cfg: &'a Config,
    keepers: &'a Arc<Keepers>,
    keys: &'a [Keys],
    client: &'a Runtime,
    /// The widest connection count of the grid: the connection limits are
    /// raised to it on every door.
    widest: usize,
    frames: &'a Arc<Vec<Frame>>,
    texts: &'a [String],
    events: &'a [Event],
}

impl Shared<'_> {
    fn subset(&self, spec: &Spec) -> Vec<&Event> {
        self.events[..spec.events].iter().collect()
    }
}

/// One socket cell on a fresh server.
fn socket_cell(
    shared: &Shared,
    visibility: Visibility,
    variant: &Variant,
    spec: &Spec,
) -> Result<Value, String> {
    let label = format!(
        "{} door, variant {}, {}",
        partition_name(visibility),
        variant.label(),
        spec.label()
    );
    let mut server = Server::start(
        shared.cfg,
        shared.keepers,
        visibility,
        variant,
        spec.events,
        shared.widest,
    )
    .map_err(|e| format!("{label}: {e}"))?;
    let sockets = shared.client.block_on(connect_all(
        &label,
        &server.url,
        shared.keys,
        spec.connections,
        shared.cfg.socket_client_nodelay,
    ))?;
    let start = Arc::new(Barrier::new(spec.connections + 1));
    let mut tasks = Vec::with_capacity(spec.connections);
    for (lane, socket) in sockets.into_iter().enumerate() {
        let indices: Vec<usize> = (lane..spec.events).step_by(spec.connections).collect();
        tasks.push(shared.client.spawn(write_lane(
            format!("{label}, connection {lane}"),
            socket,
            Arc::clone(shared.frames),
            indices,
            spec.window,
            Arc::clone(&start),
        )));
    }
    let mut merged = drive(shared.client, tasks, &start).map_err(|e| format!("{label}: {e}"))?;
    server.relay.flush();
    let stats = server.relay.writer_stats();
    let commits = server.store.commits();
    // The lanes have closed their connections; the door is shut down and the
    // server task must end before the store is read.
    server.stop().map_err(|e| format!("{label}: {e}"))?;
    let subset = shared.subset(spec);
    verify_cell(&server.store, visibility, &subset, stats, wall_seconds())
        .map_err(|e| format!("{label}: {e}"))?;
    let mut out = cell_json(&mut merged, spec.events, spec.window);
    out["variant"] = json!(variant.label());
    out["connections"] = json!(spec.connections);
    out["writer"] = writer_json(stats, commits);
    Ok(out)
}

/// The engine lane over the same events, with `workers` runtime workers and
/// the wall clock.
fn direct_cell(
    shared: &Shared,
    visibility: Visibility,
    workers: usize,
    spec: &Spec,
) -> Result<Value, String> {
    let rt = runtime(workers)?;
    let subset = shared.subset(spec);
    let cell = Cell {
        cfg: shared.cfg,
        runtime: &rt,
        visibility,
        events: &subset,
        total_events: spec.events,
        connections: spec.connections,
        window: spec.window,
        clock: Clock::Wall,
    };
    let mut out = engine_cell(
        &cell,
        &shared.texts[..spec.events],
        shared.keepers,
        shared.keys,
    )
    .map_err(|e| {
        format!(
            "{} door, direct arm with {workers} workers, {}: {e}",
            partition_name(visibility),
            spec.label()
        )
    })?;
    out["workers"] = json!(workers);
    out["connections"] = json!(spec.connections);
    Ok(out)
}

/// One door's cells for one round, the variants in `order`.
fn door_round(
    shared: &Shared,
    visibility: Visibility,
    specs: &[Spec],
    order: &[Variant],
    round: usize,
) -> Result<Value, String> {
    let name = partition_name(visibility);
    let mut cells: Vec<(Vec<Value>, Vec<Value>)> =
        specs.iter().map(|_| (Vec::new(), Vec::new())).collect();
    let mut direct_done: HashSet<(usize, usize)> = HashSet::new();
    for variant in order {
        for (index, spec) in specs.iter().enumerate() {
            if direct_done.insert((index, variant.workers)) {
                eprintln!(
                    "socket round {round}, {name}: direct arm, {} workers, {}",
                    variant.workers,
                    spec.label()
                );
                cells[index]
                    .0
                    .push(direct_cell(shared, visibility, variant.workers, spec)?);
            }
            eprintln!(
                "socket round {round}, {name}: {}, {}",
                variant.label(),
                spec.label()
            );
            cells[index]
                .1
                .push(socket_cell(shared, visibility, variant, spec)?);
        }
    }
    let cells: Vec<Value> = specs
        .iter()
        .zip(cells)
        .map(|(spec, (direct, socket))| {
            json!({
                "connections": spec.connections,
                "window": spec.window,
                "events": spec.events,
                "direct": direct,
                "socket": socket,
            })
        })
        .collect();
    Ok(json!({ "door": name, "cells": cells }))
}

/// The refusals the doors must give, outside the timed cells: an EVENT sent
/// before AUTH is refused on both doors, and on the public door a keeper's
/// event of a kind outside `PUBLIC_KINDS` is refused and not stored. Nothing
/// may be stored in either partition afterwards.
fn refusal_checks(
    shared: &Shared,
    visibility: Visibility,
    variant: &Variant,
) -> Result<Value, String> {
    let name = partition_name(visibility);
    let nodelay = shared.cfg.socket_client_nodelay;
    let mut server = Server::start(
        shared.cfg,
        shared.keepers,
        visibility,
        variant,
        16,
        shared.widest,
    )
    .map_err(|e| format!("refusal check, {name} door: {e}"))?;
    let note = &shared.events[0];
    let frame = &shared.frames[0];
    let expected = ok(&note.id.to_hex(), false, BEFORE_AUTH_REASON);
    let label = format!("refusal check, {name} door, EVENT before AUTH");
    let reply = shared.client.block_on(exchange(
        &label,
        &server.url,
        None,
        frame.text.as_str(),
        nodelay,
    ))?;
    if reply != expected {
        return Err(format!("{label}: expected {expected}, got {reply}"));
    }
    let mut out = json!({
        "door": name,
        "before_auth": { "reply": reply, "expected": expected },
    });
    if visibility == Visibility::Public {
        if PUBLIC_KINDS.contains(&REFUSED_KIND) {
            return Err(format!(
                "kind {REFUSED_KIND} is now a public kind; pick another"
            ));
        }
        let article = EventBuilder::new(Kind::from(REFUSED_KIND), "refusal check")
            .tags(vec![tag(["d", "refusal-check"])?])
            .custom_created_at(Timestamp::from_secs(wall_seconds().saturating_sub(1000)))
            .finalize(&shared.keys[0])
            .map_err(|e| format!("sign the out-of-kind event: {e}"))?;
        let article_frame = Frame::new(&article)?.0;
        let expected = ok(&article.id.to_hex(), false, OUT_OF_KIND_REASON);
        let label = format!("refusal check, {name} door, kind {REFUSED_KIND}");
        let reply = shared.client.block_on(exchange(
            &label,
            &server.url,
            Some(&shared.keys[0]),
            article_frame.text.as_str(),
            nodelay,
        ))?;
        if reply != expected {
            return Err(format!("{label}: expected {expected}, got {reply}"));
        }
        out["out_of_kind"] = json!({
            "kind": REFUSED_KIND,
            "reply": reply,
            "expected": expected,
        });
    }
    server.relay.flush();
    let now = wall_seconds();
    for partition in [Visibility::Public, Visibility::Sheltered] {
        let held = server
            .store
            .count(partition, &[Filter::new()], now)
            .map_err(|e| {
                format!(
                    "refusal check, {name} door: count the {} partition: {e}",
                    partition_name(partition)
                )
            })?;
        if held != 0 {
            return Err(format!(
                "refusal check, {name} door: a refused event was stored ({held} held in the {} partition)",
                partition_name(partition)
            ));
        }
    }
    out["stored"] = json!(0);
    server
        .stop()
        .map_err(|e| format!("refusal check, {name} door: {e}"))?;
    Ok(out)
}

fn allowances(widest: usize) -> Value {
    json!({
        "frame_limit": {
            "used": FRAME_LIMIT,
            "production": PRODUCTION_FRAME_LIMIT,
            "unit": "frames a minute on one session",
            "note": "the per-session allowance is raised through `EventRelay::with_frame_limit`; the check stays in the path of every frame",
        },
        "connection_limits": {
            "used_shared": widest,
            "used_public": widest,
            "production_shared": PRODUCTION_SHARED_CONNECTIONS,
            "production_public": PRODUCTION_PUBLIC_CONNECTIONS,
            "note": "raised through `Door::with_connection_limits` to the widest cell of the grid",
        },
        "work_limits": {
            "production_shared": wok_ws::WORK_PERMITS,
            "production_public": PRODUCTION_PUBLIC_WORK_PERMITS,
            "note": "each variant names its own shared/public permits, passed to `Door::with_work_limits`",
        },
        "unchanged": "signature verification, AUTH, kind and author rules, writer limits and durability are the production ones",
    })
}

pub fn run(cfg: &Config) -> Result<Value, String> {
    let specs = cell_specs(cfg);
    let widest = specs.iter().map(|spec| spec.connections).max().unwrap_or(1);
    let signed = specs.iter().map(|spec| spec.events).max().unwrap_or(0);
    eprintln!(
        "socket: {} cells, {} variants, {} rounds, {signed} notes to sign",
        specs.len(),
        cfg.socket_variants.len(),
        cfg.socket_rounds
    );
    let keys = author_keys(cfg)?;
    if keys.is_empty() {
        return Err("the socket scenario needs at least one author key".into());
    }
    let notes = notes_key(cfg.seed)?;
    let keepers = Arc::new(Keepers::new(
        keys.iter()
            .map(Keys::public_key)
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
        widest,
        frames: &frames,
        texts: &texts,
        events: &events,
    };
    let doors = [Visibility::Sheltered, Visibility::Public];

    let first = cfg
        .socket_variants
        .first()
        .ok_or("the socket scenario needs at least one variant")?;
    let mut refusals = Vec::new();
    for visibility in doors {
        eprintln!(
            "socket: refusal checks, {} door",
            partition_name(visibility)
        );
        refusals.push(refusal_checks(&shared, visibility, first)?);
    }

    let mut rounds = Vec::with_capacity(cfg.socket_rounds);
    for round in 1..=cfg.socket_rounds {
        let mut order = cfg.socket_variants.clone();
        if round % 2 == 0 {
            order.reverse();
        }
        let mut door_results = Vec::new();
        for visibility in doors {
            door_results.push(door_round(&shared, visibility, &specs, &order, round)?);
        }
        rounds.push(json!({
            "round": round,
            "variant_order": order.iter().map(Variant::label).collect::<Vec<_>>(),
            "doors": door_results,
        }));
    }

    Ok(json!({
        "note": "loopback figures: the client and the server share one process and one host, and CPU is not attributed to either side",
        "what_the_figures_do_not_show": "a real network, TLS, a proxy or another host; the cost of the clients as distinct from the server; reads, subscriptions or live delivery; any relay but this one. Each cell runs once per round on a fresh store, so a figure carries the variation of that run. No medians are computed here",
        "settings": {
            "connections": cfg.socket_connections,
            "window": cfg.socket_window,
            "events": cfg.socket_events,
            "serial_events": cfg.socket_serial_events,
            "variants": cfg.socket_variants.iter().map(Variant::label).collect::<Vec<_>>(),
            "variant_syntax": "workers:blocking:shared/public:nodelay",
            "client_nodelay": cfg.socket_client_nodelay,
            "rounds": cfg.socket_rounds,
            "round_order": "the variant order is reversed on even rounds; the doors run sheltered first, then public",
            "door_inflight_writes": DOOR_INFLIGHT_WRITES,
        },
        "client": {
            "workers": CLIENT_WORKERS,
            "runtime": "one multi-thread runtime, shared by every cell, separate from the server's",
            "nodelay": cfg.socket_client_nodelay,
        },
        "server": {
            "listener": "127.0.0.1:0 only",
            "relay_clock": "the relay's own (wall) clock; `with_clock` is not called",
            "per_cell": "a fresh temporary directory, store, relay, door and runtime",
            "sheltered_admission": "a bench-only admission that admits every connection; NIP-42 is still required to write",
        },
        "allowances": allowances(widest),
        "direct_arm": "the engine lane, with no socket and no door, over the same events, with the same runtime workers and the wall clock as `now`",
        "signing": {
            "kind": KIND_NOTE,
            "created_at": "start - 1000 - 10 * count + 10 * i, where start is wall time at the scenario's start",
            "start": start,
            "count": signed,
            "signers": "the corpus author keys in turn, all keepers",
            "auth": "a real kind 22242 event stamped with wall time, naming the door's own ws://127.0.0.1:<port>/events",
        },
        "flush": "after the last OK of a cell, `EventRelay::flush` runs outside the time, then the writer statistics are read",
        "refusal_checks": refusals,
        "rounds": rounds,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Config {
        Config {
            authors: 4,
            content_bytes: 64,
            socket_connections: vec![1, 2],
            socket_window: 4,
            socket_events: 24,
            socket_serial_events: 6,
            socket_variants: vec![
                "2:8:2/1:off".parse().unwrap(),
                "2:8:1/1:on".parse().unwrap(),
            ],
            socket_rounds: 2,
            ..Config::default()
        }
    }

    /// Both doors, two variants and two rounds at tiny sizes: every cell comes
    /// back with its socket and direct figures, the refusal checks ran, and
    /// the variant order is reversed on the second round.
    #[test]
    fn the_socket_scenario_runs_at_tiny_sizes_and_reports_every_cell() {
        let cfg = tiny();
        let document = run(&cfg).unwrap_or_else(|e| panic!("the socket run failed: {e}"));
        assert_eq!(document["refusal_checks"].as_array().unwrap().len(), 2);
        assert!(document["refusal_checks"][1]["out_of_kind"].is_object());
        let rounds = document["rounds"].as_array().unwrap();
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0]["variant_order"][0], "2:8:2/1:off");
        assert_eq!(rounds[1]["variant_order"][0], "2:8:1/1:on");
        for round in rounds {
            let doors = round["doors"].as_array().unwrap();
            assert_eq!(doors.len(), 2);
            assert_eq!(doors[0]["door"], "sheltered");
            assert_eq!(doors[1]["door"], "public");
            for door in doors {
                let cells = door["cells"].as_array().unwrap();
                assert_eq!(cells.len(), 3, "two connection counts and the serial cell");
                for cell in cells {
                    let events = cell["events"].as_u64().unwrap();
                    let socket = cell["socket"].as_array().unwrap();
                    assert_eq!(socket.len(), 2);
                    for run in socket {
                        assert_eq!(run["events"], events);
                        assert_eq!(run["ok_latency"]["count"], events);
                        assert_eq!(run["writer"]["events"], events);
                        assert!(run["acknowledged_per_s"].as_f64().unwrap() > 0.0);
                    }
                    // Both variants share a worker count: one direct run.
                    let direct = cell["direct"].as_array().unwrap();
                    assert_eq!(direct.len(), 1);
                    assert_eq!(direct[0]["workers"], 2);
                    assert_eq!(direct[0]["writer"]["events"], events);
                }
            }
        }
        // Nothing in the result names an address the listener was not on.
        let text = document.to_string();
        assert!(!text.contains("0.0.0.0"));
    }
}
