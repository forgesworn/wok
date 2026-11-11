//! Query: populate a store from the corpus, then time each query shape.
//!
//! Every shape is timed in both partitions. The expected rows of each filter
//! come from a reference matcher run over the in-memory corpus (NIP-01 rules
//! through `Filter::match_event`, newest first, ties lowest id first, capped
//! as the store caps). Before any timing, each variant is run once and its
//! answer compared with that expectation, ids and order; during timing each
//! answer's length is checked against it outside the timed region.

use std::time::Instant;

use nostr::event::Event;
use nostr::filter::{Filter, MatchEventOptions};
use serde_json::{Value, json};
use wok_store::{EventStore, MAX_EXACT_COUNT, MAX_QUERY_EVENTS, SqliteEventStore, Visibility};

use crate::config::{Config, QueryMode};
use crate::corpus::{Corpus, KIND_ARTICLE, KIND_METADATA, KIND_NOTE, KIND_REACTION, NOW};
use crate::support::{
    SplitMix, fresh_store, ms, partition_name, per_second, prepare, prepare_json, put_chunk,
    summarise, verify_population,
};

/// Events per population call.
const POPULATE_BATCH: usize = 128;

struct Variant {
    filter: Filter,
    /// The ids the store must return, in order (a query shape).
    ids: Vec<String>,
    /// The number the store must count (a count shape).
    count: u64,
}

struct Shape {
    name: &'static str,
    counts: bool,
    variants: Vec<Variant>,
}

pub fn run(cfg: &Config, corpus: &Corpus) -> Result<Value, String> {
    eprintln!("query: populating {} events", corpus.items.len());
    let (_dir, store) = fresh_store(cfg, corpus.items.len())?;
    let (puts, prepared_in) = prepare(corpus)?;
    let started = Instant::now();
    let mut reoffers = 0;
    for (index, chunk) in puts.chunks(POPULATE_BATCH).enumerate() {
        reoffers += put_chunk(&store, corpus, index * POPULATE_BATCH, chunk)?.1;
    }
    let populated_in = started.elapsed();
    verify_population(&store, corpus)?;
    drop(puts);
    // Let the checkpoint thread drain and truncate the WAL, so the first
    // shape is not timed against it.
    std::thread::sleep(cfg.settle());

    let mut partitions = serde_json::Map::new();
    for visibility in [Visibility::Public, Visibility::Sheltered] {
        let events: Vec<&Event> = corpus.events_in(visibility).collect();
        let shapes = shapes(cfg, &events, visibility)?;
        let mut results = serde_json::Map::new();
        for shape in &shapes {
            eprintln!("query: {} {}", partition_name(visibility), shape.name);
            results.insert(
                shape.name.to_string(),
                time_shape(cfg, &store, visibility, shape)?,
            );
        }
        partitions.insert(
            partition_name(visibility).to_string(),
            json!({ "events": events.len(), "shapes": results }),
        );
    }
    Ok(json!({
        "mode": cfg.query_mode.name(),
        "mode_note": "stored is query_stored (rows as stored JSON); events is query (rows built into events)",
        "partitions_note": "every shape runs in both partitions, over the half of the corpus each holds",
        "populate": {
            "prepare": prepare_json(prepared_in, corpus.items.len()),
            "wall_ms": ms(populated_in),
            "events_per_s": per_second(corpus.items.len(), populated_in),
            "batch_events": POPULATE_BATCH,
            "deferred_reoffers": reoffers,
            "logical_bytes": store.logical_bytes().map_err(|e| e.to_string())?,
        },
        "settle_ms": cfg.settle().as_millis() as u64,
        "partitions": partitions,
    }))
}

fn time_shape(
    cfg: &Config,
    store: &SqliteEventStore,
    visibility: Visibility,
    shape: &Shape,
) -> Result<Value, String> {
    // Untimed: every variant once, checked against the reference. This also
    // warms the statement and page caches, so the timings are warm ones.
    for (n, variant) in shape.variants.iter().enumerate() {
        if shape.counts {
            let counted = store
                .count(visibility, std::slice::from_ref(&variant.filter), NOW)
                .map_err(|e| format!("{}: count: {e}", shape.name))?;
            if counted != variant.count {
                return Err(format!(
                    "{} variant {n}: counted {counted}, expected {}",
                    shape.name, variant.count
                ));
            }
        } else {
            let got = fetch_ids(cfg.query_mode, store, visibility, &variant.filter)
                .map_err(|e| format!("{} variant {n}: {e}", shape.name))?;
            if got != variant.ids {
                return Err(format!(
                    "{} variant {n}: the store returned {} rows that differ from the {} expected",
                    shape.name,
                    got.len(),
                    variant.ids.len()
                ));
            }
        }
    }

    let mut samples = Vec::with_capacity(cfg.queries);
    let (mut rows_total, mut rows_min, mut rows_max) = (0u64, u64::MAX, 0u64);
    for q in 0..cfg.queries {
        let variant = &shape.variants[q % shape.variants.len()];
        let started = Instant::now();
        let rows = if shape.counts {
            store
                .count(visibility, std::slice::from_ref(&variant.filter), NOW)
                .map(|n| n as usize)
                .map_err(|e| e.to_string())
        } else {
            fetch_len(cfg.query_mode, store, visibility, &variant.filter)
        };
        samples.push(started.elapsed().as_nanos() as u64);
        let rows = rows.map_err(|e| format!("{}: {e}", shape.name))?;
        let expected = if shape.counts {
            variant.count as usize
        } else {
            variant.ids.len()
        };
        if rows != expected {
            return Err(format!(
                "{}: a timed query returned {rows}, expected {expected}",
                shape.name
            ));
        }
        let rows = if shape.counts {
            variant.count
        } else {
            rows as u64
        };
        rows_total += rows;
        rows_min = rows_min.min(rows);
        rows_max = rows_max.max(rows);
    }
    Ok(json!({
        "kind": if shape.counts { "count" } else { "query" },
        "variants": shape.variants.len(),
        "queries": cfg.queries,
        "rows_per_query": (rows_total as f64 / cfg.queries as f64 * 100.0).round() / 100.0,
        "rows_min": rows_min,
        "rows_max": rows_max,
        "latency": summarise(&mut samples),
    }))
}

fn fetch_ids(
    mode: QueryMode,
    store: &SqliteEventStore,
    visibility: Visibility,
    filter: &Filter,
) -> Result<Vec<String>, String> {
    match mode {
        QueryMode::Stored => store
            .query_stored(visibility, filter, NOW)
            .map(|rows| rows.into_iter().map(|row| row.id).collect())
            .map_err(|e| e.to_string()),
        QueryMode::Events => store
            .query(visibility, filter, NOW)
            .map(|rows| rows.iter().map(|event| event.id.to_hex()).collect())
            .map_err(|e| e.to_string()),
    }
}

fn fetch_len(
    mode: QueryMode,
    store: &SqliteEventStore,
    visibility: Visibility,
    filter: &Filter,
) -> Result<usize, String> {
    match mode {
        QueryMode::Stored => store
            .query_stored(visibility, filter, NOW)
            .map(|rows| rows.len())
            .map_err(|e| e.to_string()),
        QueryMode::Events => store
            .query(visibility, filter, NOW)
            .map(|rows| rows.len())
            .map_err(|e| e.to_string()),
    }
}

/// What the store must answer for `filter` over `events`: matches newest
/// first, ties lowest id first, at most the store's cap or the filter's limit.
fn expected_ids(events: &[&Event], filter: &Filter) -> Vec<String> {
    let mut hits: Vec<&Event> = events
        .iter()
        .copied()
        .filter(|event| filter.match_event(event, MatchEventOptions::default()))
        .collect();
    hits.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
    hits.truncate(
        filter
            .limit
            .unwrap_or(MAX_QUERY_EVENTS)
            .min(MAX_QUERY_EVENTS),
    );
    hits.iter().map(|event| event.id.to_hex()).collect()
}

fn expected_count(events: &[&Event], filter: &Filter) -> u64 {
    let matching = events
        .iter()
        .filter(|event| filter.match_event(event, MatchEventOptions::default()))
        .count() as u64;
    matching.min(MAX_EXACT_COUNT + 1)
}

fn filter_of(value: Value) -> Result<Filter, String> {
    serde_json::from_value(value).map_err(|e| format!("build a filter: {e}"))
}

fn tag_value(event: &Event, name: &str) -> Option<String> {
    event
        .tags
        .iter()
        .map(|tag| tag.as_slice())
        .find(|parts| parts.first().is_some_and(|first| first == name))
        .and_then(|parts| parts.get(1).cloned())
}

/// A random event of the partition satisfying `wanted`.
fn pick<'a>(
    rng: &mut SplitMix,
    events: &[&'a Event],
    what: &str,
    wanted: impl Fn(&Event) -> bool,
) -> Result<&'a Event, String> {
    let candidates: Vec<&Event> = events.iter().copied().filter(|e| wanted(e)).collect();
    if candidates.is_empty() {
        return Err(format!(
            "the corpus has no {what} in this partition; raise --events"
        ));
    }
    Ok(candidates[rng.below(candidates.len())])
}

/// The variants of every shape for one partition.
fn shapes(cfg: &Config, events: &[&Event], visibility: Visibility) -> Result<Vec<Shape>, String> {
    let mut rng =
        SplitMix(cfg.seed ^ 0x7368_6170_6573 ^ ((visibility == Visibility::Public) as u64));
    let n = cfg.variants;
    let first = events
        .iter()
        .map(|e| e.created_at.as_secs())
        .min()
        .unwrap_or(0);
    let last = events
        .iter()
        .map(|e| e.created_at.as_secs())
        .max()
        .unwrap_or(0);
    let window = ((last - first) / 10).max(1);

    let mut ids = Vec::new();
    let mut author_kind = Vec::new();
    let mut kind_recent = Vec::new();
    let mut since_until = Vec::new();
    let mut tag_e = Vec::new();
    let mut tag_p = Vec::new();
    let mut tag_d = Vec::new();
    let mut replaceable = Vec::new();
    let mut addressable = Vec::new();
    let mut count_kind = Vec::new();
    let mut count_narrow = Vec::new();

    for v in 0..n {
        // by ids: eight events, or all there are
        let mut chosen: Vec<String> = Vec::new();
        while chosen.len() < 8.min(events.len()) {
            let id = events[rng.below(events.len())].id.to_hex();
            if !chosen.contains(&id) {
                chosen.push(id);
            }
        }
        ids.push(json!({ "ids": chosen }));

        let note = pick(&mut rng, events, "note", |e| e.kind.as_u16() == KIND_NOTE)?;
        author_kind.push(json!({
            "authors": [note.pubkey.to_hex()], "kinds": [KIND_NOTE], "limit": 20
        }));

        let kind = if v % 2 == 0 { KIND_NOTE } else { KIND_REACTION };
        let limit = [10, 50, 100][v % 3];
        kind_recent.push(json!({ "kinds": [kind], "limit": limit }));

        let at = events[rng.below(events.len())].created_at.as_secs();
        since_until.push(json!({ "since": at, "until": at + window, "limit": 50 }));

        let with_e = pick(&mut rng, events, "event with an e tag", |e| {
            tag_value(e, "e").is_some()
        })?;
        tag_e.push(json!({ "#e": [tag_value(with_e, "e")], "limit": 50 }));

        let with_p = pick(&mut rng, events, "event with a p tag", |e| {
            tag_value(e, "p").is_some()
        })?;
        tag_p.push(json!({ "#p": [tag_value(with_p, "p")], "limit": 50 }));

        let article = pick(&mut rng, events, "article", |e| {
            e.kind.as_u16() == KIND_ARTICLE
        })?;
        let d = tag_value(article, "d");
        tag_d.push(json!({ "#d": [d] }));
        addressable.push(json!({
            "authors": [article.pubkey.to_hex()], "kinds": [KIND_ARTICLE], "#d": [d]
        }));

        let metadata = pick(&mut rng, events, "metadata event", |e| {
            e.kind.as_u16() == KIND_METADATA
        })?;
        replaceable.push(json!({
            "authors": [metadata.pubkey.to_hex()], "kinds": [KIND_METADATA]
        }));

        // Two count shapes, since their costs differ by orders of magnitude:
        // a whole kind (which reaches the store's exact-count bound in a
        // large corpus) and one author or one tag value. Timed together,
        // the median fell on either side from run to run.
        count_kind.push(if v % 2 == 0 {
            json!({ "kinds": [KIND_NOTE] })
        } else {
            json!({ "kinds": [KIND_REACTION] })
        });
        count_narrow.push(if v % 2 == 0 {
            json!({ "authors": [note.pubkey.to_hex()] })
        } else {
            json!({ "#p": [tag_value(with_p, "p")] })
        });
    }

    let mut out = Vec::new();
    for (name, filters, counting) in [
        ("ids", ids, false),
        ("author_kind_limit", author_kind, false),
        ("kind_recent_limit", kind_recent, false),
        ("since_until_window", since_until, false),
        ("tag_e", tag_e, false),
        ("tag_p", tag_p, false),
        ("tag_d", tag_d, false),
        ("replaceable_lookup", replaceable, false),
        ("addressable_lookup", addressable, false),
        ("count_kind", count_kind, true),
        ("count_narrow", count_narrow, true),
    ] {
        let mut variants = Vec::with_capacity(filters.len());
        for value in filters {
            let filter = filter_of(value)?;
            let (ids, count) = if counting {
                (Vec::new(), expected_count(events, &filter))
            } else {
                (expected_ids(events, &filter), 0)
            };
            if (counting && count == 0) || (!counting && ids.is_empty()) {
                return Err(format!(
                    "{name}: a filter matches nothing in the {} partition",
                    partition_name(visibility)
                ));
            }
            variants.push(Variant { filter, ids, count });
        }
        out.push(Shape {
            name,
            counts: counting,
            variants,
        });
    }
    Ok(out)
}
