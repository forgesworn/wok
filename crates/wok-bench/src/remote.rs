//! Remote-relay comparison workloads. The same signed corpus can seed Wok and
//! another Nostr relay; the clients then drive real WebSocket connections.
//! Fresh connections keep every workload inside wokd's production frame and
//! connection limits. These are not steady-state write-ceiling measurements.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt, future::try_join_all};
use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind};
use nostr::key::Keys;
use nostr::nips::nip19::ToBech32;
use nostr::types::Timestamp;
use serde_json::{Value, json};
use tokio::runtime::Builder;
use tokio::sync::Barrier;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use wok_store::{EventStore, SqliteEventStore, StoreOptions, Visibility};

use crate::config::Config;
use crate::corpus::{Corpus, Item, KIND_ARTICLE, KIND_NOTE, author_keys, build_at};
use crate::socket::client::{Frame, Socket, close_cleanly, connect_authenticated, connect_plain};
use crate::support::{SplitMix, ms, per_second, prepare, put_chunk, summarise, verify_population};

const LIVE_KIND: u16 = 1460;
const WAIT: Duration = Duration::from_secs(30);
const POPULATE_BATCH: usize = 64;

pub fn run(args: &[String]) -> Result<Value, String> {
    let Some(command) = args.first() else {
        return Err("relay needs a command: member, export, seed, query, write or fanout".into());
    };
    let opts = Opts::parse(&args[1..])?;
    match command.as_str() {
        "member" => member(opts),
        "export" => export(opts),
        "seed" => seed(opts),
        "query" => runtime()?.block_on(query(opts)),
        "write" => runtime()?.block_on(write(opts)),
        "fanout" => runtime()?.block_on(fanout(opts)),
        other => Err(format!("unknown relay command `{other}`")),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| format!("start the remote client runtime: {e}"))
}

struct Opts(BTreeMap<String, String>);

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut map = BTreeMap::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                return Err(format!("unexpected relay argument `{arg}`"));
            };
            let (name, inline) = flag
                .split_once('=')
                .map_or((flag, None), |(name, value)| (name, Some(value)));
            let value = match inline {
                Some(value) => value.to_owned(),
                None => args
                    .next()
                    .ok_or_else(|| format!("--{name} needs a value"))?
                    .clone(),
            };
            if map.insert(name.to_owned(), value).is_some() {
                return Err(format!("--{name} is given twice"));
            }
        }
        Ok(Self(map))
    }

    fn required(&mut self, name: &str) -> Result<String, String> {
        self.0
            .remove(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn text(&mut self, name: &str, default: &str) -> Result<String, String> {
        Ok(self.0.remove(name).unwrap_or_else(|| default.to_owned()))
    }

    fn number<T: std::str::FromStr>(&mut self, name: &str, default: T) -> Result<T, String> {
        self.0.remove(name).map_or(Ok(default), |value| {
            value
                .replace('_', "")
                .parse()
                .map_err(|_| format!("--{name} `{value}` is not a valid number"))
        })
    }

    fn path(&mut self, name: &str) -> Result<PathBuf, String> {
        self.required(name).map(PathBuf::from)
    }

    fn finish(self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "unknown relay option(s): {}",
                self.0
                    .keys()
                    .map(|k| format!("--{k}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    }
}

fn corpus_config(opts: &mut Opts) -> Result<Config, String> {
    let mut cfg = Config::default();
    cfg.seed = opts.number("seed", cfg.seed)?;
    cfg.events = opts.number("events", cfg.events)?;
    cfg.authors = opts.number("authors", cfg.authors)?;
    cfg.content_bytes = opts.number("content-bytes", cfg.content_bytes)?;
    Ok(cfg)
}

fn member(mut opts: Opts) -> Result<Value, String> {
    let cfg = corpus_config(&mut opts)?;
    opts.finish()?;
    let keys = author_keys(&cfg)?;
    Ok(json!({
        "member_npub": keys[0].public_key().to_bech32().map_err(|e| e.to_string())?,
        "seed": cfg.seed,
        "authors": cfg.authors,
    }))
}

fn wall_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("read the wall clock: {e}"))
}

fn export(mut opts: Opts) -> Result<Value, String> {
    let out = opts.path("out")?;
    let cfg = corpus_config(&mut opts)?;
    opts.finish()?;
    let now = wall_now()?;
    eprintln!("remote export: signing {} events", cfg.events);
    let corpus = build_at(&cfg, now)?;
    let file = std::fs::File::create(&out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let mut writer = BufWriter::new(file);
    for item in &corpus.items {
        serde_json::to_writer(&mut writer, &item.event)
            .map_err(|e| format!("serialise an exported event: {e}"))?;
        writer
            .write_all(b"\n")
            .map_err(|e| format!("write {}: {e}", out.display()))?;
    }
    writer
        .flush()
        .map_err(|e| format!("flush {}: {e}", out.display()))?;
    Ok(json!({
        "events": corpus.items.len(),
        "json_bytes": corpus.json_bytes,
        "digest": format!("{:016x}", corpus.digest),
        "clock": now,
        "member_npub": corpus.authors[0].to_bech32().map_err(|e| e.to_string())?,
    }))
}

fn read_corpus(path: &Path) -> Result<Corpus, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut items = Vec::new();
    let mut digest = 0xCBF2_9CE4_8422_2325u64;
    let mut json_bytes = 0;
    for (line, text) in BufReader::new(file).lines().enumerate() {
        let text = text.map_err(|e| format!("read {}: {e}", path.display()))?;
        if text.trim().is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(&text)
            .map_err(|e| format!("{} line {}: {e}", path.display(), line + 1))?;
        event
            .verify()
            .map_err(|e| format!("{} line {}: bad event: {e}", path.display(), line + 1))?;
        for byte in event.id.as_bytes().iter().chain([&1]) {
            digest = (digest ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3);
        }
        json_bytes += text.len();
        items.push(Item {
            visibility: Visibility::Sheltered,
            event,
        });
    }
    if items.is_empty() {
        return Err(format!("{} holds no events", path.display()));
    }
    Ok(Corpus {
        items,
        authors: Vec::new(),
        digest,
        json_bytes,
    })
}

fn seed(mut opts: Opts) -> Result<Value, String> {
    let input = opts.path("input")?;
    let data_dir = opts.path("data-dir")?;
    let max_bytes = opts.number("max-bytes", 4u64 << 30)?;
    opts.finish()?;
    let corpus = read_corpus(&input)?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let store = SqliteEventStore::open_with_options(
        &data_dir.join("events.sqlite"),
        max_bytes,
        0,
        StoreOptions::server(),
    )
    .map_err(|e| format!("open the Wok store: {e}"))?;
    let (puts, _) = prepare(&corpus)?;
    let started = Instant::now();
    let mut reoffers = 0;
    for (index, chunk) in puts.chunks(POPULATE_BATCH).enumerate() {
        reoffers += put_chunk(&store, &corpus, index * POPULATE_BATCH, chunk)?.1;
    }
    verify_population(&store, &corpus)?;
    Ok(json!({
        "events": corpus.items.len(),
        "digest": format!("{:016x}", corpus.digest),
        "wall_ms": ms(started.elapsed()),
        "events_per_s": per_second(corpus.items.len(), started.elapsed()),
        "deferred_reoffers": reoffers,
        "logical_bytes": store.logical_bytes().map_err(|e| e.to_string())?,
    }))
}

fn member_keys(opts: &mut Opts) -> Result<Option<Keys>, String> {
    let auth = opts.text("auth", "member")?;
    match auth.as_str() {
        "member" => {
            let cfg = corpus_config(opts)?;
            Ok(Some(author_keys(&cfg)?[0].clone()))
        }
        "none" => Ok(None),
        _ => Err("--auth must be `member` or `none`".into()),
    }
}

async fn open(url: &str, keys: Option<&Keys>, label: &str) -> Result<(Socket, u64), String> {
    let started = Instant::now();
    let socket = match keys {
        Some(keys) => connect_authenticated(label.to_owned(), url, keys, true).await?,
        None => connect_plain(label, url, true).await?,
    };
    Ok((socket, started.elapsed().as_nanos() as u64))
}

async fn next_json(label: &str, socket: &mut Socket) -> Result<Value, String> {
    loop {
        match timeout(WAIT, socket.next()).await {
            Err(_) => return Err(format!("{label}: no frame within {WAIT:?}")),
            Ok(None) => return Err(format!("{label}: the connection closed")),
            Ok(Some(Err(e))) => return Err(format!("{label}: socket error: {e}")),
            Ok(Some(Ok(Message::Text(text)))) => {
                return serde_json::from_str(text.as_str())
                    .map_err(|e| format!("{label}: non-JSON relay frame: {e}"));
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Close(frame)))) => {
                return Err(format!("{label}: relay closed: {frame:?}"));
            }
            Ok(Some(Ok(_))) => {}
        }
    }
}

async fn send_text(socket: &mut Socket, text: String, label: &str) -> Result<(), String> {
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| format!("{label}: send: {e}"))
}

fn fresh_events(keys: &Keys, count: usize, label: &str) -> Result<Vec<Event>, String> {
    let now = wall_now()?;
    (0..count)
        .map(|i| {
            EventBuilder::new(Kind::from(LIVE_KIND), format!("{label} {i}"))
                .custom_created_at(Timestamp::from_secs(now + i as u64 / 1_000_000))
                .finalize(keys)
                .map_err(|e| format!("sign a remote event: {e}"))
        })
        .collect()
}

fn query_sets(
    corpus: &Corpus,
    count: usize,
    seed: u64,
) -> Result<Vec<(&'static str, Vec<Value>)>, String> {
    let events: Vec<&Event> = corpus.items.iter().map(|item| &item.event).collect();
    let notes: Vec<&&Event> = events
        .iter()
        .filter(|e| e.kind == Kind::from(KIND_NOTE))
        .collect();
    let articles: Vec<&&Event> = events
        .iter()
        .filter(|e| e.kind == Kind::from(KIND_ARTICLE))
        .collect();
    if notes.is_empty() || articles.is_empty() {
        return Err("the corpus needs notes and addressable articles".into());
    }
    let mut rng = SplitMix(seed ^ 0x7265_6D6F_7465);
    let pick = |rng: &mut SplitMix| events[rng.below(events.len())];
    let mut ids = Vec::with_capacity(count);
    let mut ids8 = Vec::with_capacity(count);
    let mut ids64 = Vec::with_capacity(count);
    let mut authors_kinds = Vec::with_capacity(count);
    let mut since_until = Vec::with_capacity(count);
    let mut tag_d = Vec::with_capacity(count);
    for _ in 0..count {
        let event = pick(&mut rng);
        ids.push(json!({"ids": [event.id.to_hex()], "limit": 1}));
        for (size, salt, out) in [(8, 0x1D5_0008, &mut ids8), (64, 0x1D5_0064, &mut ids64)] {
            let mut multi = SplitMix(seed ^ salt ^ ids.len() as u64);
            let mut picked = Vec::with_capacity(size);
            while picked.len() < size {
                let id = pick(&mut multi).id.to_hex();
                if !picked.contains(&id) {
                    picked.push(id);
                }
            }
            out.push(json!({"ids": picked, "limit": size}));
        }
        let note = notes[rng.below(notes.len())];
        authors_kinds.push(json!({
            "authors": [note.pubkey.to_hex()], "kinds": [KIND_NOTE], "limit": 50
        }));
        let event = pick(&mut rng);
        let at = event.created_at.as_secs();
        since_until.push(json!({
            "since": at.saturating_sub(300), "until": at + 300, "limit": 50
        }));
        let article = articles[rng.below(articles.len())];
        let d = article
            .tags
            .iter()
            .map(|tag| tag.as_slice())
            .find(|parts| parts.first().is_some_and(|part| part == "d"))
            .and_then(|parts| parts.get(1))
            .ok_or_else(|| "an article has no d tag".to_string())?;
        tag_d.push(json!({"kinds": [KIND_ARTICLE], "#d": [d], "limit": 50}));
    }
    Ok(vec![
        ("ids", ids),
        ("ids8", ids8),
        ("ids64", ids64),
        ("authors_kinds", authors_kinds),
        ("since_until", since_until),
        ("tag_d", tag_d),
    ])
}

async fn one_query(
    url: &str,
    keys: Option<&Keys>,
    filter: &Value,
    number: usize,
) -> Result<(u64, u64, Vec<String>), String> {
    let label = format!("query {number}");
    let (mut socket, setup) = open(url, keys, &label).await?;
    let subscription = format!("bench-{number}");
    let text = serde_json::to_string(&json!(["REQ", subscription, filter]))
        .map_err(|e| format!("serialise a REQ: {e}"))?;
    let started = Instant::now();
    send_text(&mut socket, text, &label).await?;
    let mut event_ids = Vec::new();
    loop {
        let reply = next_json(&label, &mut socket).await?;
        match reply[0].as_str() {
            Some("EVENT") if reply[1].as_str() == Some(subscription.as_str()) => {
                let event: Event = serde_json::from_value(reply[2].clone())
                    .map_err(|e| format!("{label}: bad EVENT: {e}"))?;
                event_ids.push(event.id.to_hex());
            }
            Some("EOSE") if reply[1].as_str() == Some(subscription.as_str()) => break,
            Some("NOTICE" | "CLOSED") => return Err(format!("{label}: refused: {reply}")),
            _ => return Err(format!("{label}: unexpected reply: {reply}")),
        }
    }
    let latency = started.elapsed().as_nanos() as u64;
    close_cleanly(&label, &mut socket).await?;
    event_ids.sort_unstable();
    Ok((latency, setup, event_ids))
}

async fn query(mut opts: Opts) -> Result<Value, String> {
    let url = opts.required("url")?;
    let input = opts.path("input")?;
    let queries = opts.number("queries", 100usize)?;
    let warmup = opts.number("warmup", 10usize)?;
    let only = opts.text("set", "all")?;
    let keys = member_keys(&mut opts)?;
    opts.finish()?;
    if queries == 0 {
        return Err("--queries must be at least 1".into());
    }
    let corpus = read_corpus(&input)?;
    let seed = corpus.digest ^ 1;
    let mut results = serde_json::Map::new();
    for (name, filters) in query_sets(&corpus, queries + warmup, seed)? {
        if only != "all" && only != name {
            continue;
        }
        eprintln!("remote query: {name}, {warmup} warm-up + {queries} timed");
        let mut latencies = Vec::with_capacity(queries);
        let mut setups = Vec::with_capacity(queries);
        let mut counts = Vec::with_capacity(queries);
        let mut digest = 0xCBF2_9CE4_8422_2325u64;
        let mut total_events = 0usize;
        for (number, filter) in filters.iter().enumerate() {
            let (latency, setup, ids) = one_query(&url, keys.as_ref(), filter, number).await?;
            if number >= warmup {
                latencies.push(latency);
                setups.push(setup);
                counts.push(ids.len());
                total_events += ids.len();
                digest = (digest ^ ids.len() as u64).wrapping_mul(0x0000_0100_0000_01B3);
                for id in ids {
                    for byte in id.bytes() {
                        digest = (digest ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01B3);
                    }
                }
            }
        }
        results.insert(
            name.to_owned(),
            json!({
                "queries": queries,
                "latency": summarise(&mut latencies),
                "connection_setup": summarise(&mut setups),
                "counts": counts,
                "total_events": total_events,
                "empty_replies": counts.iter().filter(|&&n| n == 0).count(),
                "id_set_digest": format!("{digest:016x}"),
            }),
        );
    }
    if results.is_empty() {
        return Err(format!("unknown query set `{only}`"));
    }
    Ok(Value::Object(results))
}

async fn one_write(
    url: &str,
    keys: Option<&Keys>,
    event: &Event,
    label: &str,
) -> Result<(u64, u64), String> {
    let (mut socket, setup) = open(url, keys, label).await?;
    let (frame, _) = Frame::new(event)?;
    let started = Instant::now();
    socket
        .send(Message::Text(frame.text.clone()))
        .await
        .map_err(|e| format!("{label}: send EVENT: {e}"))?;
    let reply = next_json(label, &mut socket).await?;
    if reply[0].as_str() != Some("OK") || reply[1].as_str() != Some(frame.id.as_str()) {
        return Err(format!("{label}: unexpected write reply: {reply}"));
    }
    if reply[2].as_bool() != Some(true) {
        return Err(format!("{label}: write refused: {reply}"));
    }
    let latency = started.elapsed().as_nanos() as u64;
    close_cleanly(label, &mut socket).await?;
    Ok((latency, setup))
}

async fn write(mut opts: Opts) -> Result<Value, String> {
    let url = opts.required("url")?;
    let events = opts.number("events", 500usize)?;
    let connections = opts.number("connections", 8usize)?;
    let trace = match opts.text("trace", "off")?.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err("--trace must be `on` or `off`".into()),
    };
    let keys = member_keys(&mut opts)?;
    let signing = match &keys {
        Some(keys) => keys.clone(),
        None => {
            let cfg = corpus_config(&mut opts)?;
            author_keys(&cfg)?[0].clone()
        }
    };
    opts.finish()?;
    if events == 0 || events < connections || connections == 0 || connections > 32 {
        return Err("write needs events >= connections and 1..=32 connections".into());
    }
    let signed = fresh_events(&signing, events, "remote write")?;
    let started = Instant::now();
    let started_unix_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("read the wall clock: {e}"))?
        .as_micros() as u64;
    let lanes = (0..connections).map(|lane| {
        let url = url.clone();
        let keys = keys.clone();
        let events: Vec<Event> = signed
            .iter()
            .skip(lane)
            .step_by(connections)
            .cloned()
            .collect();
        async move {
            let mut latencies = Vec::with_capacity(events.len());
            let mut setups = Vec::with_capacity(events.len());
            let mut traced = Vec::new();
            for (i, event) in events.iter().enumerate() {
                let opened = started.elapsed().as_micros() as u64;
                let (latency, setup) = one_write(
                    &url,
                    keys.as_ref(),
                    event,
                    &format!("write lane {lane} event {i}"),
                )
                .await?;
                if trace {
                    traced.push(json!([
                        lane,
                        opened + setup / 1000,
                        latency / 1000,
                        setup / 1000
                    ]));
                }
                latencies.push(latency);
                setups.push(setup);
            }
            Ok::<_, String>((latencies, setups, traced))
        }
    });
    let completed = try_join_all(lanes).await?;
    let wall = started.elapsed();
    let mut latencies = Vec::with_capacity(events);
    let mut setups = Vec::with_capacity(events);
    let mut traced = Vec::new();
    for (mut lane, mut setup, mut lane_trace) in completed {
        latencies.append(&mut lane);
        setups.append(&mut setup);
        traced.append(&mut lane_trace);
    }
    let mut result = json!({
        "events": events,
        "connections": connections,
        "ok_true": latencies.len(),
        "wall_ms": ms(wall),
        "events_per_s": per_second(latencies.len(), wall),
        "send_to_ok": summarise(&mut latencies),
        "connection_setup": summarise(&mut setups),
        "method": "fresh connection per event; throughput includes connection and optional AUTH setup, send_to_ok excludes it",
    });
    if trace {
        result["trace"] = json!({
            "started_unix_us": started_unix_us,
            "columns": ["lane", "send_offset_us", "send_to_ok_us", "setup_us"],
            "writes": traced,
        });
    }
    Ok(result)
}

struct Subscriber {
    receipts: usize,
    latencies: Vec<u64>,
}

async fn subscriber(
    url: String,
    keys: Option<Keys>,
    number: usize,
    events: usize,
    start: Arc<Barrier>,
    sent: Arc<Mutex<BTreeMap<String, Instant>>>,
) -> Result<Subscriber, String> {
    let label = format!("subscriber {number}");
    let (mut socket, _) = open(&url, keys.as_ref(), &label).await?;
    let subscription = format!("fanout-{number}");
    send_text(
        &mut socket,
        serde_json::to_string(&json!(["REQ", subscription, {"kinds": [LIVE_KIND], "limit": 128}]))
            .map_err(|e| e.to_string())?,
        &label,
    )
    .await?;
    loop {
        let reply = next_json(&label, &mut socket).await?;
        if reply[0].as_str() == Some("EOSE") && reply[1].as_str() == Some(subscription.as_str()) {
            break;
        }
        if reply[0].as_str() != Some("EVENT") {
            return Err(format!("{label}: initial subscription failed: {reply}"));
        }
    }
    start.wait().await;
    let mut result = Subscriber {
        receipts: 0,
        latencies: Vec::with_capacity(events),
    };
    let mut seen = BTreeSet::new();
    while result.receipts < events {
        let reply = next_json(&label, &mut socket).await?;
        if reply[0].as_str() != Some("EVENT") || reply[1].as_str() != Some(subscription.as_str()) {
            return Err(format!("{label}: unexpected live reply: {reply}"));
        }
        let event: Event = serde_json::from_value(reply[2].clone())
            .map_err(|e| format!("{label}: bad live event: {e}"))?;
        let id = event.id.to_hex();
        if !seen.insert(id.clone()) {
            return Err(format!("{label}: duplicate live event {id}"));
        }
        let at = sent
            .lock()
            .map_err(|_| "the send-time map is poisoned".to_string())?
            .get(&id)
            .copied()
            .ok_or_else(|| format!("{label}: event {id} was not published by this run"))?;
        result.latencies.push(at.elapsed().as_nanos() as u64);
        result.receipts += 1;
    }
    close_cleanly(&label, &mut socket).await?;
    Ok(result)
}

async fn fanout(mut opts: Opts) -> Result<Value, String> {
    let url = opts.required("url")?;
    let subscribers = opts.number("subscribers", 16usize)?;
    let events = opts.number("events", 100usize)?;
    let rate = opts.number("rate", 2u32)?;
    let keys = member_keys(&mut opts)?;
    let signing = match &keys {
        Some(keys) => keys.clone(),
        None => {
            let cfg = corpus_config(&mut opts)?;
            author_keys(&cfg)?[0].clone()
        }
    };
    opts.finish()?;
    if subscribers == 0 || subscribers > 24 || events == 0 || rate == 0 {
        return Err(
            "fanout needs 1..=24 subscribers, at least one event and a non-zero rate".into(),
        );
    }
    let signed = fresh_events(&signing, events, "remote fanout")?;
    let sent = Arc::new(Mutex::new(BTreeMap::new()));
    let start = Arc::new(Barrier::new(subscribers + 1));
    let mut tasks = Vec::with_capacity(subscribers);
    for number in 0..subscribers {
        tasks.push(tokio::spawn(subscriber(
            url.clone(),
            keys.clone(),
            number,
            events,
            Arc::clone(&start),
            Arc::clone(&sent),
        )));
    }
    start.wait().await;
    let mut publisher_latencies = Vec::with_capacity(events);
    let mut publisher_setups = Vec::with_capacity(events);
    let interval = Duration::from_secs_f64(1.0 / f64::from(rate));
    let started = Instant::now();
    for (i, event) in signed.iter().enumerate() {
        let publish_at = started + interval * i as u32;
        tokio::time::sleep_until(tokio::time::Instant::from_std(publish_at)).await;
        let id = event.id.to_hex();
        sent.lock()
            .map_err(|_| "the send-time map is poisoned".to_string())?
            .insert(id, Instant::now());
        let (latency, setup) =
            one_write(&url, keys.as_ref(), event, &format!("fanout publish {i}")).await?;
        publisher_latencies.push(latency);
        publisher_setups.push(setup);
    }
    let waiting = timeout(Duration::from_secs(90), try_join_all(tasks))
        .await
        .map_err(|_| {
            "subscribers did not receive every event within 90 seconds of the last publish"
                .to_string()
        })?
        .map_err(|e| format!("a subscriber task panicked: {e}"))?;
    let mut receipts = 0;
    let mut latencies = Vec::with_capacity(subscribers * events);
    let mut per_subscriber = Vec::with_capacity(subscribers);
    for result in waiting {
        let result = result?;
        receipts += result.receipts;
        per_subscriber.push(result.receipts);
        latencies.extend(result.latencies);
    }
    if receipts != subscribers * events {
        return Err(format!(
            "received {receipts} of {} deliveries",
            subscribers * events
        ));
    }
    Ok(json!({
        "subscribers": subscribers,
        "events": events,
        "rate_per_s": rate,
        "expected": subscribers * events,
        "receipts": receipts,
        "missing": subscribers * events - receipts,
        "per_subscriber": per_subscriber,
        "delivery": summarise(&mut latencies),
        "publisher_send_to_ok": summarise(&mut publisher_latencies),
        "publisher_connection_setup": summarise(&mut publisher_setups),
        "method": "delivery is send to receipt; one fresh publisher connection per event keeps wokd inside its frame limit",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_options_reject_duplicates_and_unknown_names() {
        let args = |values: &[&str]| values.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(Opts::parse(&args(&["--events", "2", "--events", "3"])).is_err());
        let mut opts = Opts::parse(&args(&["--events", "2"])).unwrap();
        assert_eq!(opts.number::<usize>("events", 1).unwrap(), 2);
        opts.finish().unwrap();
        assert!(
            Opts::parse(&args(&["--bogus", "2"]))
                .unwrap()
                .finish()
                .is_err()
        );
    }

    #[test]
    fn query_sets_have_the_requested_shapes_and_limits() {
        let cfg = Config {
            events: 200,
            authors: 4,
            ..Config::default()
        };
        let corpus = crate::corpus::build(&cfg).unwrap();
        let sets = query_sets(&corpus, 10, 1).unwrap();
        assert_eq!(sets.len(), 6);
        for (name, filters) in sets {
            assert_eq!(filters.len(), 10, "{name}");
            for filter in filters {
                assert!(filter["limit"].as_u64().unwrap() <= 128);
            }
        }
    }

    #[test]
    fn exported_corpus_can_be_seeded_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            events: 120,
            authors: 4,
            ..Config::default()
        };
        let corpus = crate::corpus::build(&cfg).unwrap();
        let path = dir.path().join("events.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        for item in &corpus.items {
            serde_json::to_writer(&mut file, &item.event).unwrap();
            file.write_all(b"\n").unwrap();
        }
        drop(file);
        let read = read_corpus(&path).unwrap();
        assert_eq!(read.items.len(), corpus.items.len());
        assert_ne!(read.digest, 0);
        let store = SqliteEventStore::open_with_options(
            &dir.path().join("events.sqlite"),
            4u64 << 30,
            0,
            StoreOptions::server(),
        )
        .unwrap();
        let (puts, _) = prepare(&read).unwrap();
        store.put_prepared_batch(&puts);
        let count = store
            .count(
                Visibility::Sheltered,
                &[nostr::filter::Filter::new()],
                crate::corpus::NOW,
            )
            .unwrap();
        assert_eq!(count, corpus.items.len() as u64);
    }
}
