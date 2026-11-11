//! Engine: the relay session engine, driven frame by frame, against the
//! store's writer and the raw store.
//!
//! There is no network. The driver stands in for a connection loop: it makes
//! a `RelaySession`, authenticates it with a real NIP-42 AUTH, then hands the
//! engine one frame at a time the way a transport would (`PreparedFrame::parse`,
//! `admit_frame`, `begin_prepared`). Every event is really signed, and the
//! engine verifies each signature itself: the bench never calls
//! `PreparedPut::verified`. Anything but the expected answer (an `OK false`, a
//! NOTICE, a CLOSED, a reply of the wrong shape, a missing reply, a lagging
//! subscriber) fails the run, naming what and where.
//!
//! Three parts, each on its own stores and each in the same run, so that its
//! figures can be set beside the figures it is compared with:
//!
//! - `writes`: acknowledged writes through the engine and through the bare
//!   `EventWriter`, per connection count and in-flight window.
//! - `queries`: REQ and COUNT through a session and straight on the store.
//! - `subscribers`: what an authenticated session with an open REQ and an
//!   attached live receiver holds, and live delivery to many of them.
//!
//! The figures are comparable only within one run on one host. They say
//! nothing about the costs of sockets, TLS or WebSocket framing.

mod queries;
mod subscribers;
mod writes;

use std::collections::BTreeSet;
use std::sync::Arc;

use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind, Tag};
use nostr::key::{Keys, PublicKey};
use nostr::types::Timestamp;
use serde_json::{Value, json};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use url::Url;
use wok_store::EventStore;
use wok_store::relay::{EventRelay, KeeperAccess, RelaySession, ok};
use wok_store::writer::WriterLimits;

use crate::config::Config;
use crate::corpus::{Corpus, NOW, author_keys, notes_key};
use crate::support::writer_limits_json;

/// The relay URL every session is opened for and every AUTH names.
const RELAY_URL: &str = "wss://bench.invalid/";
/// NIP-42's authentication event.
const KIND_AUTH: u16 = 22242;
/// The frames a session may take in a minute. The production allowance is
/// below; the bench keeps `admit_frame` in the path but raises the allowance
/// so that it never refuses a frame of the run.
const FRAME_LIMIT: u32 = u32::MAX;
/// The engine's own allowance, `MAX_FRAMES_PER_MINUTE`, which is private to
/// `wok-store`: recorded so that the figures can be read against it.
const PRODUCTION_FRAME_LIMIT: u32 = 120;
/// How long the bench waits on any task before it calls the run stuck.
const STALL: std::time::Duration = std::time::Duration::from_secs(600);

/// The keeper set: a fixed set of keys, with a live signal that never fires.
/// The engine's write fast path needs a source that can signal, so this one
/// does; nothing in the run changes the set.
pub(crate) struct Keepers {
    keys: BTreeSet<PublicKey>,
    /// Held so that `subscribe` has something to watch.
    changes: watch::Sender<u64>,
}

impl Keepers {
    fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        let (changes, _) = watch::channel(0);
        Self {
            keys: keys.into_iter().collect(),
            changes,
        }
    }
}

impl KeeperAccess for Keepers {
    fn owns(&self, key: &PublicKey) -> bool {
        self.keys.contains(key)
    }

    fn subscribe(&self) -> Option<watch::Receiver<u64>> {
        Some(self.changes.subscribe())
    }
}

/// A relay over `store`: the fixed clock (so that the writer's recheck sees
/// the time every frame carries) and the raised frame allowance.
fn relay_over(
    store: Arc<dyn EventStore>,
    keepers: &Arc<Keepers>,
    live_limits: Option<(usize, usize)>,
) -> Arc<EventRelay> {
    let access: Arc<dyn KeeperAccess> = Arc::clone(keepers) as Arc<dyn KeeperAccess>;
    let mut relay = EventRelay::new(store, access)
        .with_clock(|| NOW)
        .with_frame_limit(FRAME_LIMIT);
    if let Some((queue_bytes, total_bytes)) = live_limits {
        relay = relay.with_live_limits(queue_bytes, total_bytes);
    }
    Arc::new(relay)
}

fn runtime(workers: usize) -> Result<Runtime, String> {
    Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_time()
        .build()
        .map_err(|e| format!("start the runtime: {e}"))
}

fn relay_url() -> Result<Url, String> {
    Url::parse(RELAY_URL).map_err(|e| format!("the relay URL: {e}"))
}

fn tag(parts: [&str; 2]) -> Result<Tag, String> {
    Tag::parse(parts).map_err(|e| format!("build a tag: {e}"))
}

/// A real NIP-42 AUTH for `session`: kind 22242 carrying the session's
/// challenge and relay URL, signed by `keys` and sent as the first frame. The
/// answer must be exactly one `OK true`.
fn authenticate(session: &mut RelaySession, keys: &Keys, label: &str) -> Result<(), String> {
    let event = EventBuilder::new(Kind::from(KIND_AUTH), "")
        .tags(vec![
            tag(["relay", session.relay_url().as_str()])?,
            tag(["challenge", session.challenge()])?,
        ])
        .custom_created_at(Timestamp::from_secs(NOW))
        .finalize(keys)
        .map_err(|e| format!("{label}: sign the AUTH event: {e}"))?;
    let id = event.id.to_hex();
    let text = serde_json::to_string(&json!(["AUTH", event]))
        .map_err(|e| format!("{label}: serialise the AUTH frame: {e}"))?;
    let replies = session.handle(&text, NOW);
    if replies.len() == 1 && replies[0] == ok(&id, true, "") {
        if !session.is_authenticated() {
            return Err(format!(
                "{label}: AUTH was accepted but the session is not authenticated"
            ));
        }
        Ok(())
    } else {
        Err(format!(
            "{label}: AUTH was not accepted: {}",
            describe(&replies)
        ))
    }
}

/// `["EVENT", <event>]`, as a client sends it.
fn event_text(event: &Event) -> Result<String, String> {
    serde_json::to_string(&("EVENT", event)).map_err(|e| format!("serialise an EVENT frame: {e}"))
}

/// The frame a REQ or live delivery must carry for `event`, built here from
/// the event's own serialisation rather than by the engine's helpers.
fn reference_frame(subscription: &str, event: &Event) -> Result<String, String> {
    let json = serde_json::to_string(event).map_err(|e| format!("serialise an event: {e}"))?;
    let id = serde_json::to_string(subscription).map_err(|e| format!("serialise an id: {e}"))?;
    Ok(format!("[\"EVENT\",{id},{json}]"))
}

/// A short account of a reply set, for an error message.
fn describe(replies: &[String]) -> String {
    let first: String = replies
        .first()
        .map(|reply| reply.chars().take(160).collect())
        .unwrap_or_default();
    format!("{} replies, the first {first:?}", replies.len())
}

pub fn run(cfg: &Config, corpus: &Corpus) -> Result<Value, String> {
    eprintln!(
        "engine: {} session counts, windows {:?}, {} subscribers, {} published",
        cfg.engine_connections.len(),
        cfg.engine_windows,
        cfg.engine_subscribers,
        cfg.engine_publish
    );
    let keys = author_keys(cfg)?;
    if keys.iter().map(Keys::public_key).collect::<Vec<_>>() != corpus.authors {
        return Err("the corpus authors are not the keys the engine scenario holds".into());
    }
    let notes = notes_key(cfg.seed)?;
    let keepers = Arc::new(Keepers::new(
        keys.iter()
            .map(Keys::public_key)
            .chain([notes.public_key()]),
    ));

    let writes = writes::run(cfg, corpus, &keepers, &keys)?;
    let queries = queries::run(cfg, corpus, &keepers, &keys)?;
    let subscribers = subscribers::run(cfg, &keepers, &notes)?;
    Ok(json!({
        "note": "figures are only comparable within one run on one host, and say nothing about the cost of sockets, TLS or WebSocket framing: no network is involved and no connection task is run",
        "relay": {
            "url": RELAY_URL,
            "clock": format!("fixed at {NOW} for the relay's clock and for every frame's `now`"),
            "frame_limit_used": FRAME_LIMIT,
            "frame_limit_production_default": PRODUCTION_FRAME_LIMIT,
            "frame_limit_note": "admit_frame stays in the path of every frame; only the per-minute allowance is raised",
            "keeper_access": "a fixed key set (every corpus author and the notes key) whose change signal never fires, so the write fast path is the one a signalling source gets",
            "writer_limits": writer_limits_json(&WriterLimits::default()),
            "workers": cfg.engine_workers,
        },
        "writes": writes,
        "queries": queries,
        "subscribers": subscribers,
    }))
}
