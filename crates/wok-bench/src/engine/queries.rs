//! Queries: the `query` scenario's shapes sent through an authenticated
//! session (`["REQ", ...]` and `["COUNT", ...]`), and the same filters timed
//! straight on the store, over one populated store in one run.
//!
//! The shapes, filters and oracle are the `query` scenario's. A REQ must
//! answer exactly the expected EVENT frames in order and then EOSE; a COUNT
//! must answer the expected number. Anything else fails the run. A shape the
//! door refuses (a CLOSED reply to the first REQ) is skipped and the reason
//! recorded; none is expected.
//!
//! What is timed: `RelaySession::begin_prepared` alone, for a frame that has
//! already been parsed and admitted, so the session figure is the engine's
//! handling of a REQ (filter checks, `query_stored`, the merge, the frame
//! splice, the subscription bookkeeping). Parsing the frame, comparing the
//! replies and closing the subscription are outside the clock. The store side
//! is `query_stored` (or `count`) for the same filter, whatever `--query-mode`
//! says, since that is what the engine calls. Which of the two runs first
//! alternates, so that neither always finds the cache warmer.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use nostr::event::Event;
use nostr::key::Keys;
use serde_json::{Value, json};
use wok_store::relay::{Handled, PreparedFrame, frame};
use wok_store::{EventStore, MAX_EXACT_COUNT, SqliteEventStore, Visibility};

use super::{Keepers, authenticate, describe, reference_frame, relay_over, relay_url};
use crate::config::Config;
use crate::corpus::{Corpus, NOW};
use crate::query::{Shape, Variant, populated_store, shapes};
use crate::support::{partition_name, summarise};

const SUBSCRIPTION: &str = "bench";

/// One filter, ready to send and with its answer worked out.
struct Case {
    request: String,
    close: String,
    /// The replies a correct engine gives: EVENT frames and EOSE for a REQ,
    /// one COUNT frame for a COUNT.
    expected: Vec<String>,
    /// The rows the store must return for the filter (the count itself for a
    /// count shape).
    rows: usize,
}

fn eose() -> String {
    frame(json!(["EOSE", SUBSCRIPTION]))
}

fn count_frame(count: u64) -> String {
    if count > MAX_EXACT_COUNT {
        frame(json!(["COUNT", SUBSCRIPTION, {"count": MAX_EXACT_COUNT, "approximate": true}]))
    } else {
        frame(json!(["COUNT", SUBSCRIPTION, {"count": count}]))
    }
}

fn case(shape: &Shape, variant: &Variant, by_id: &HashMap<String, &Event>) -> Result<Case, String> {
    let verb = if shape.counts { "COUNT" } else { "REQ" };
    let request = serde_json::to_string(&json!([verb, SUBSCRIPTION, variant.raw]))
        .map_err(|e| format!("{}: serialise a {verb}: {e}", shape.name))?;
    let close = serde_json::to_string(&json!(["CLOSE", SUBSCRIPTION]))
        .map_err(|e| format!("serialise a CLOSE: {e}"))?;
    let (expected, rows) = if shape.counts {
        (vec![count_frame(variant.count)], variant.count as usize)
    } else {
        let mut expected = Vec::with_capacity(variant.ids.len() + 1);
        for id in &variant.ids {
            let event = by_id
                .get(id)
                .ok_or_else(|| format!("{}: an expected id is not in the partition", shape.name))?;
            expected.push(reference_frame(SUBSCRIPTION, event)?);
        }
        expected.push(eose());
        (expected, variant.ids.len())
    };
    Ok(Case {
        request,
        close,
        expected,
        rows,
    })
}

/// A frame as a transport hands it to the engine: parsed, and admitted.
fn admitted(
    session: &mut wok_store::relay::RelaySession,
    text: &str,
    what: &str,
) -> Result<PreparedFrame, String> {
    let prepared = PreparedFrame::parse(text.to_owned());
    if !session.admit_frame(NOW) {
        return Err(format!("{what}: the frame allowance refused a frame"));
    }
    Ok(prepared)
}

fn replies_of(handled: Handled, what: &str) -> Result<Vec<String>, String> {
    match handled {
        Handled::Replies(replies) => Ok(replies),
        Handled::Write(_) => Err(format!(
            "{what}: the engine queued a write for a query frame"
        )),
    }
}

/// CLOSE the subscription, untimed, and require the inline answer: an empty
/// reply set.
fn close(
    session: &mut wok_store::relay::RelaySession,
    case: &Case,
    what: &str,
) -> Result<(), String> {
    let prepared = admitted(session, &case.close, what)?;
    match session.try_close(&prepared) {
        Some(replies) if replies.is_empty() => Ok(()),
        other => Err(format!("{what}: CLOSE answered {other:?}")),
    }
}

fn check(case: &Case, replies: &[String], what: &str) -> Result<(), String> {
    if replies == case.expected.as_slice() {
        return Ok(());
    }
    let at = replies
        .iter()
        .zip(&case.expected)
        .position(|(got, want)| got != want);
    Err(format!(
        "{what}: the replies differ from the {} expected{}: {}",
        case.expected.len(),
        at.map(|n| format!(" (first difference at reply {n})"))
            .unwrap_or_default(),
        describe(replies)
    ))
}

fn store_rows(
    store: &SqliteEventStore,
    visibility: Visibility,
    variant: &Variant,
    counts: bool,
) -> Result<usize, String> {
    if counts {
        store
            .count(visibility, std::slice::from_ref(&variant.filter), NOW)
            .map(|n| n as usize)
            .map_err(|e| e.to_string())
    } else {
        store
            .query_stored(visibility, &variant.filter, NOW)
            .map(|rows| rows.len())
            .map_err(|e| e.to_string())
    }
}

fn difference(session: &Value, store: &Value, key: &str) -> Value {
    match (session[key].as_f64(), store[key].as_f64()) {
        (Some(a), Some(b)) => json!(((a - b) * 10.0).round() / 10.0),
        _ => Value::Null,
    }
}

fn time_shape(
    cfg: &Config,
    store: &SqliteEventStore,
    visibility: Visibility,
    session: &mut wok_store::relay::RelaySession,
    shape: &Shape,
    by_id: &HashMap<String, &Event>,
) -> Result<Value, String> {
    let name = format!("{} {}", partition_name(visibility), shape.name);
    let cases: Vec<Case> = shape
        .variants
        .iter()
        .map(|variant| case(shape, variant, by_id))
        .collect::<Result<_, _>>()?;

    // Untimed: every variant once through the session, compared in full, and
    // once on the store. This also warms both paths.
    for (n, (case, variant)) in cases.iter().zip(&shape.variants).enumerate() {
        let what = format!("{name} variant {n}");
        let prepared = admitted(session, &case.request, &what)?;
        let replies = replies_of(session.begin_prepared(prepared, NOW), &what)?;
        if !shape.counts
            && replies
                .first()
                .is_some_and(|r| r.starts_with("[\"CLOSED\""))
        {
            return Ok(json!({
                "skipped": format!("the door refused the REQ: {}", describe(&replies)),
            }));
        }
        check(case, &replies, &what)?;
        close(session, case, &what)?;
        let rows = store_rows(store, visibility, variant, shape.counts)
            .map_err(|e| format!("{what}: store: {e}"))?;
        if rows != case.rows {
            return Err(format!(
                "{what}: the store returned {rows}, expected {}",
                case.rows
            ));
        }
    }

    let mut through_session = Vec::with_capacity(cfg.queries);
    let mut on_store = Vec::with_capacity(cfg.queries);
    let (mut rows_total, mut rows_min, mut rows_max) = (0u64, u64::MAX, 0u64);
    for q in 0..cfg.queries {
        let n = q % cases.len();
        let (case, variant) = (&cases[n], &shape.variants[n]);
        let what = format!("{name} variant {n}");
        let mut session_ns = 0u64;
        let mut store_ns = 0u64;
        let mut replies = Vec::new();
        let mut store_len = 0usize;
        // Two steps, in an order that alternates.
        for step in 0..2 {
            if (step == 0) == (q % 2 == 0) {
                let prepared = admitted(session, &case.request, &what)?;
                let started = Instant::now();
                let handled = session.begin_prepared(prepared, NOW);
                session_ns = started.elapsed().as_nanos() as u64;
                replies = replies_of(handled, &what)?;
            } else {
                let started = Instant::now();
                let rows = store_rows(store, visibility, variant, shape.counts);
                store_ns = started.elapsed().as_nanos() as u64;
                store_len = rows.map_err(|e| format!("{what}: store: {e}"))?;
            }
        }
        check(case, &replies, &what)?;
        if store_len != case.rows {
            return Err(format!(
                "{what}: a timed store query returned {store_len}, expected {}",
                case.rows
            ));
        }
        if !shape.counts {
            close(session, case, &what)?;
        }
        through_session.push(session_ns);
        on_store.push(store_ns);
        let rows = case.rows as u64;
        rows_total += rows;
        rows_min = rows_min.min(rows);
        rows_max = rows_max.max(rows);
    }
    let session_summary = summarise(&mut through_session);
    let store_summary = summarise(&mut on_store);
    Ok(json!({
        "kind": if shape.counts { "count" } else { "query" },
        "variants": shape.variants.len(),
        "queries": cfg.queries,
        "rows_per_query": (rows_total as f64 / cfg.queries.max(1) as f64 * 100.0).round() / 100.0,
        "rows_min": rows_min,
        "rows_max": rows_max,
        "session": session_summary,
        "store": store_summary,
        "difference_us": {
            "p50": difference(&session_summary, &store_summary, "p50_us"),
            "p90": difference(&session_summary, &store_summary, "p90_us"),
            "p99": difference(&session_summary, &store_summary, "p99_us"),
            "mean": difference(&session_summary, &store_summary, "mean_us"),
        },
    }))
}

pub fn run(
    cfg: &Config,
    corpus: &Corpus,
    keepers: &Arc<Keepers>,
    keys: &[Keys],
) -> Result<Value, String> {
    eprintln!("engine: queries, populating {} events", corpus.items.len());
    let populated = populated_store(cfg, corpus)?;
    let store = &populated.store;
    let relay = relay_over(Arc::clone(store) as Arc<dyn EventStore>, keepers, None);
    // As the `query` scenario does: let the checkpoint thread drain first.
    std::thread::sleep(cfg.settle());

    let url = relay_url()?;
    let mut partitions = serde_json::Map::new();
    for visibility in [Visibility::Public, Visibility::Sheltered] {
        let events: Vec<&Event> = corpus.events_in(visibility).collect();
        let by_id: HashMap<String, &Event> = events
            .iter()
            .map(|event| (event.id.to_hex(), *event))
            .collect();
        let mut session = relay.session(visibility, url.clone(), NOW);
        authenticate(
            &mut session,
            &keys[0],
            &format!("queries, {} door", partition_name(visibility)),
        )?;
        let mut results = serde_json::Map::new();
        for shape in &shapes(cfg, &events, visibility)? {
            eprintln!(
                "engine: queries, {} {}",
                partition_name(visibility),
                shape.name
            );
            results.insert(
                shape.name.to_string(),
                time_shape(cfg, store, visibility, &mut session, shape, &by_id)?,
            );
        }
        partitions.insert(
            partition_name(visibility).to_string(),
            json!({ "events": events.len(), "shapes": results }),
        );
    }
    Ok(json!({
        "settings": {
            "queries_per_shape": cfg.queries,
            "variants_per_shape": cfg.variants,
            "settle_ms": cfg.settle().as_millis() as u64,
            "session": "one session per partition door, authenticated as a keeper with a real NIP-42 AUTH; the same store, the same filters and the same oracle as the query scenario",
        },
        "notes": [
            "session is RelaySession::begin_prepared alone, for a frame already parsed and admitted; the replies are compared with the expected frames, and the subscription closed, outside the clock",
            "store is query_stored (rows as stored JSON) for a REQ shape and count for a COUNT shape, whatever --query-mode says, since that is what the engine calls",
            "difference_us is the session figure minus the store figure at each percentile; it is the engine's own work on top of the store call, and is not a paired difference",
            "which of the two runs first alternates query by query",
        ],
        "partitions": partitions,
    }))
}
