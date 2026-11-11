//! Command-line options, parsed by hand.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use wok_store::StoreOptions;
use wok_store::live::{LIVE_QUEUE_BYTES, LIVE_TOTAL_BYTES};
use wok_store::writer::BATCH_EVENTS;

pub const HELP: &str = "\
wok-bench: store-level baseline benchmark for wok-store.

USAGE
    wok-bench [SCENARIO] [OPTIONS]

SCENARIO
    ingest    pre-signed events into a fresh store: through the group-commit
              writer (one run per --ingest-threads value) and straight into
              the store on one thread
    query     populate a store, then time each query shape in both partitions
    fanout    attach readers to a live fan-out and publish events to them
    engine    the relay session engine against the store: acknowledged writes
              through sessions and through the writer alone, queries through a
              session and straight on the store, and the memory and delivery
              cost of subscribers (no network; counts allocations)
    socket    acknowledged-write throughput through the relay's WebSocket doors
              on 127.0.0.1, against fresh stores, beside the engine driven
              directly on the same events (writes only; client and server share
              one process and one host)
    door-path diagnostic, run only when named: one connection through the
              sheltered door beside stand-ins that add the door's blocking-pool
              hops to the direct engine lane, and an acknowledge-only socket
              stand-in; not part of `all`
    guest-path  diagnostic, run only when named: sheltered-door writes by
              keepers set beside guests whose scopes come from a bench-only
              authority (in memory, or a model on SQLite), on an empty and a
              seeded store; not part of `all`
    all       every scenario above but door-path and guest-path (default)

Results are one JSON document on stdout, or in the file named by --out.
Progress goes to stderr. Every figure is checked: a refused or duplicate put,
a short query answer or a lagging reader fails the run.

CORPUS (ingest, query and engine)
    --seed N              seed for keys and content (default 1)
    --events N            events in the corpus (default 2000)
    --authors N           distinct authors (default 16)
    --content-bytes N     bytes of text in a note (default 160)

INGEST
    --ingest-threads L    comma-separated submitter counts for the writer path
                          (default 1,4)
    --direct-batch N      events per call on the direct path; a run with one
                          event per call always runs too (default 64)

QUERY
    --queries N           timed queries per shape and partition (default 200)
    --variants N          distinct filters per shape (default 16)
    --query-mode M        stored (query_stored) or events (query); default stored
    --settle-ms N         pause after populating, so the WAL settles (default:
                          the store's idle truncate delay plus 500)

FANOUT
    --fanout-readers N    attached readers (default 8)
    --fanout-events N     events published (default 500)
    --fanout-workers N    runtime threads driving the readers (default 4)
    --fanout-window N     most events the publisher may be ahead of the slowest
                          reader; 0 publishes as fast as it can (default 0)
    --fanout-queue-bytes N  per-reader queue limit (default the live default)
    --fanout-total-bytes N  limit on distinct bytes held (default the live default)

ENGINE (the corpus sizes above apply; --queries and --variants shape its
queries, and --fanout-queue-bytes and --fanout-total-bytes size its live queues)
    --engine-connections L  comma-separated session counts for the writes
                            (default 1,4,16,64)
    --engine-windows L      comma-separated in-flight windows: 1 commits one
                            write at a time, more reserve in arrival order and
                            await that many together (default 1,32)
    --engine-workers N      runtime threads driving the sessions (default 4)
    --engine-events N       most events each write cell sends, taken from the
                            front of the door's admitted subset; 0 sends the
                            whole subset (default 0)
    --engine-subscribers N  sessions holding an open REQ and a live receiver
                            (default 1000)
    --engine-publish N      events published to those subscribers (default 200)

SOCKET (--content-bytes and --seed apply; no corpus is built)
    --socket-connections L  comma-separated connection counts (default 1,4,16,64)
    --socket-window N       EVENT frames each connection keeps in flight, at most
                            64, the door's own cap (default 32)
    --socket-events N       events per cell, split evenly across the connections
                            (default 20000)
    --socket-serial-events N  events for the one strictly serial cell, one
                            connection with a window of 1; 0 skips it
                            (default 2000)
    --socket-variants L     comma-separated server settings, each
                            WORKERS:BLOCKING:SHARED/PUBLIC:NODELAY, for example
                            2:8:2/1:off. WORKERS and BLOCKING size the server's
                            runtime, SHARED and PUBLIC are the door's work
                            permits, NODELAY is the server's TCP_NODELAY (on or
                            off). Default 2:8:2/1:off
    --socket-client-nodelay on|off  the client's TCP_NODELAY (default on)
    --socket-rounds N       run the whole grid N times in one process, the
                            variant order reversed on even rounds; each round is
                            reported separately (default 1)

DOOR-PATH (--content-bytes and --seed apply; no corpus is built; the server
setting is fixed at 2:8:2/1:off with the client's TCP_NODELAY on, and the
--socket-* options do not apply)
    --door-path-events N    events in the window-32 cell (default 20000)
    --door-path-serial-events N  events in the window-1 cell (default 2000)
    --door-path-rounds N    rounds, each running every arm of both cells once,
                            the arm order rotated each round (default 8)

GUEST-PATH (--content-bytes and --seed apply; no corpus is built; the server is
fixed at 2 workers and 8 blocking threads with its TCP_NODELAY off, the
client's TCP_NODELAY on, window 32, connections 1, 16 and 64, permits 2/1 and
8/8, and the --socket-* options do not apply)
    --guest-path-events N   events in each run, at least 64 (default 2000)
    --guest-path-seed-events N  events in the seeded store (default 2000)
    --guest-path-rounds N   rounds, each running every arm and permit setting
                            of every cell once (default 8)

STORE
    --profile P           server or phone StoreOptions (default server)
    --max-bytes N         the store's logical byte ceiling (default: sized
                          from the corpus, at least 256 MiB)
    --dir PATH            directory for the temporary stores (default: the
                          system temporary directory); never written to the results
    --out PATH            write the JSON here instead of stdout
    -h, --help            this text
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Server,
    Phone,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Phone => "phone",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryMode {
    Stored,
    Events,
}

impl QueryMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Events => "events",
        }
    }
}

/// The most EVENT frames the door keeps in flight on one connection
/// (`MAX_INFLIGHT_WRITES` in `wok-ws`, which is private): a larger window
/// would only queue behind it, so it is refused.
pub const DOOR_INFLIGHT_WRITES: usize = 64;
/// The fewest events a guest-path run may have: one for each connection of
/// its widest cell.
pub const GUEST_PATH_MIN_EVENTS: usize = 64;

/// One server setting of the socket scenario: the server runtime's workers
/// and blocking threads, the door's work permits, and the server listener's
/// TCP_NODELAY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variant {
    pub workers: usize,
    pub blocking: usize,
    pub shared: usize,
    pub public: usize,
    pub nodelay: bool,
}

impl Variant {
    /// The syntax it is parsed from, and the name it is reported under.
    pub fn label(&self) -> String {
        format!(
            "{}:{}:{}/{}:{}",
            self.workers,
            self.blocking,
            self.shared,
            self.public,
            if self.nodelay { "on" } else { "off" }
        )
    }
}

impl FromStr for Variant {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let bad = |why: &str| {
            format!(
                "--socket-variants: `{text}` is not WORKERS:BLOCKING:SHARED/PUBLIC:NODELAY ({why})"
            )
        };
        let parts: Vec<&str> = text.split(':').collect();
        let [workers, blocking, permits, nodelay] = parts.as_slice() else {
            return Err(bad("expected four parts"));
        };
        let (shared, public) = permits
            .split_once('/')
            .ok_or_else(|| bad("the work permits are SHARED/PUBLIC"))?;
        let count = |what: &str, value: &str| -> Result<usize, String> {
            let value: usize = value
                .trim()
                .parse()
                .map_err(|_| bad(&format!("{what} `{value}` is not a number")))?;
            // A zero is refused here: a door with no work permits would turn
            // every write into a 10 second BUSY instead of a clean error.
            if value == 0 {
                Err(bad(&format!("{what} must be at least 1")))
            } else {
                Ok(value)
            }
        };
        let variant = Self {
            workers: count("WORKERS", workers)?,
            blocking: count("BLOCKING", blocking)?,
            shared: count("SHARED", shared)?,
            public: count("PUBLIC", public)?,
            nodelay: switch("--socket-variants", nodelay.trim())?,
        };
        if variant.public > variant.shared {
            return Err(bad("PUBLIC is a share of SHARED, so at most SHARED"));
        }
        Ok(variant)
    }
}

/// `on` or `off`.
fn switch(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("{name}: `{value}` is `on` or `off`")),
    }
}

fn variants(value: &str) -> Result<Vec<Variant>, String> {
    let mut out: Vec<Variant> = Vec::new();
    for part in value.split(',') {
        let variant: Variant = part.trim().parse()?;
        if out.contains(&variant) {
            return Err(format!(
                "--socket-variants: `{}` is listed twice",
                variant.label()
            ));
        }
        out.push(variant);
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct Config {
    pub ingest: bool,
    pub query: bool,
    pub fanout: bool,
    pub engine: bool,
    pub socket: bool,
    pub seed: u64,
    pub events: usize,
    pub authors: usize,
    pub content_bytes: usize,
    pub ingest_threads: Vec<usize>,
    pub direct_batch: usize,
    pub queries: usize,
    pub variants: usize,
    pub query_mode: QueryMode,
    pub settle_ms: Option<u64>,
    pub fanout_readers: usize,
    pub fanout_events: usize,
    pub fanout_workers: usize,
    pub fanout_window: usize,
    pub fanout_queue_bytes: usize,
    pub fanout_total_bytes: usize,
    pub engine_connections: Vec<usize>,
    pub engine_windows: Vec<usize>,
    pub engine_workers: usize,
    pub engine_events: usize,
    pub engine_subscribers: usize,
    pub engine_publish: usize,
    pub socket_connections: Vec<usize>,
    pub socket_window: usize,
    pub socket_events: usize,
    pub socket_serial_events: usize,
    pub socket_variants: Vec<Variant>,
    pub socket_client_nodelay: bool,
    pub socket_rounds: usize,
    pub door_path: bool,
    pub door_path_events: usize,
    pub door_path_serial_events: usize,
    pub door_path_rounds: usize,
    pub guest_path: bool,
    pub guest_path_events: usize,
    pub guest_path_seed_events: usize,
    pub guest_path_rounds: usize,
    pub profile: Profile,
    pub max_bytes: Option<u64>,
    pub dir: Option<PathBuf>,
    pub out: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ingest: true,
            query: true,
            fanout: true,
            engine: true,
            socket: true,
            seed: 1,
            events: 2000,
            authors: 16,
            content_bytes: 160,
            ingest_threads: vec![1, 4],
            direct_batch: 64,
            queries: 200,
            variants: 16,
            query_mode: QueryMode::Stored,
            settle_ms: None,
            fanout_readers: 8,
            fanout_events: 500,
            fanout_workers: 4,
            fanout_window: 0,
            fanout_queue_bytes: LIVE_QUEUE_BYTES,
            fanout_total_bytes: LIVE_TOTAL_BYTES,
            engine_connections: vec![1, 4, 16, 64],
            engine_windows: vec![1, 32],
            engine_workers: 4,
            engine_events: 0,
            engine_subscribers: 1000,
            engine_publish: 200,
            socket_connections: vec![1, 4, 16, 64],
            socket_window: 32,
            socket_events: 20_000,
            socket_serial_events: 2000,
            socket_variants: vec![Variant {
                workers: 2,
                blocking: 8,
                shared: 2,
                public: 1,
                nodelay: false,
            }],
            socket_client_nodelay: true,
            socket_rounds: 1,
            door_path: false,
            door_path_events: 20_000,
            door_path_serial_events: 2000,
            door_path_rounds: 8,
            guest_path: false,
            guest_path_events: 2000,
            guest_path_seed_events: 2000,
            guest_path_rounds: 8,
            profile: Profile::Server,
            max_bytes: None,
            dir: None,
            out: None,
        }
    }
}

impl Config {
    pub fn store_options(&self) -> StoreOptions {
        match self.profile {
            Profile::Server => StoreOptions::server(),
            Profile::Phone => StoreOptions::phone(),
        }
    }

    /// The logical byte ceiling for a store that will hold `events` events:
    /// generous, so that no put is ever refused as full.
    pub fn max_bytes_for(&self, events: usize) -> u64 {
        self.max_bytes
            .unwrap_or_else(|| (256u64 << 20).max(events as u64 * 16 * 1024))
    }

    pub fn settle(&self) -> Duration {
        match self.settle_ms {
            Some(ms) => Duration::from_millis(ms),
            None => self.store_options().idle_truncate_after + Duration::from_millis(500),
        }
    }
}

fn number<T: FromStr>(name: &str, value: &str) -> Result<T, String> {
    value
        .replace('_', "")
        .parse::<T>()
        .map_err(|_| format!("--{name}: `{value}` is not a valid number"))
}

fn at_least_one(name: &str, value: usize) -> Result<usize, String> {
    if value == 0 {
        Err(format!("--{name} must be at least 1"))
    } else {
        Ok(value)
    }
}

fn counts(name: &str, value: &str) -> Result<Vec<usize>, String> {
    value
        .split(',')
        .map(|part| at_least_one(name, number(name, part.trim())?))
        .collect()
}

/// Parse the arguments after the program name. `Ok(None)` asks for the help text.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Config>, String> {
    let mut cfg = Config::default();
    let mut scenario: Option<String> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(None);
        }
        let Some(flag) = arg.strip_prefix("--") else {
            if scenario.is_some() {
                return Err(format!("unexpected argument `{arg}`"));
            }
            scenario = Some(arg);
            continue;
        };
        let (name, inline) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (flag, None),
        };
        let value = match inline {
            Some(value) => value,
            None => args
                .next()
                .ok_or_else(|| format!("--{name} needs a value"))?,
        };
        match name {
            "seed" => cfg.seed = number(name, &value)?,
            "events" => cfg.events = at_least_one(name, number(name, &value)?)?,
            "authors" => cfg.authors = at_least_one(name, number(name, &value)?)?,
            "content-bytes" => cfg.content_bytes = number(name, &value)?,
            "ingest-threads" => cfg.ingest_threads = counts(name, &value)?,
            "direct-batch" => {
                let batch = at_least_one(name, number(name, &value)?)?;
                if batch > BATCH_EVENTS {
                    return Err(format!(
                        "--direct-batch is at most {BATCH_EVENTS}, the writer's own batch limit"
                    ));
                }
                cfg.direct_batch = batch;
            }
            "queries" => cfg.queries = at_least_one(name, number(name, &value)?)?,
            "variants" => cfg.variants = at_least_one(name, number(name, &value)?)?,
            "query-mode" => {
                cfg.query_mode = match value.as_str() {
                    "stored" => QueryMode::Stored,
                    "events" => QueryMode::Events,
                    _ => return Err("--query-mode is `stored` or `events`".into()),
                }
            }
            "settle-ms" => cfg.settle_ms = Some(number(name, &value)?),
            "fanout-readers" => cfg.fanout_readers = at_least_one(name, number(name, &value)?)?,
            "fanout-events" => cfg.fanout_events = at_least_one(name, number(name, &value)?)?,
            "fanout-workers" => cfg.fanout_workers = at_least_one(name, number(name, &value)?)?,
            "fanout-window" => cfg.fanout_window = number(name, &value)?,
            "fanout-queue-bytes" => {
                cfg.fanout_queue_bytes = at_least_one(name, number(name, &value)?)?
            }
            "fanout-total-bytes" => {
                cfg.fanout_total_bytes = at_least_one(name, number(name, &value)?)?
            }
            "engine-connections" => cfg.engine_connections = counts(name, &value)?,
            "engine-windows" => cfg.engine_windows = counts(name, &value)?,
            "engine-workers" => cfg.engine_workers = at_least_one(name, number(name, &value)?)?,
            "engine-events" => cfg.engine_events = number(name, &value)?,
            "engine-subscribers" => {
                cfg.engine_subscribers = at_least_one(name, number(name, &value)?)?
            }
            "engine-publish" => cfg.engine_publish = at_least_one(name, number(name, &value)?)?,
            "socket-connections" => cfg.socket_connections = counts(name, &value)?,
            "socket-window" => {
                let window = at_least_one(name, number(name, &value)?)?;
                if window > DOOR_INFLIGHT_WRITES {
                    return Err(format!(
                        "--socket-window is at most {DOOR_INFLIGHT_WRITES}, the door's own cap on writes in flight per connection"
                    ));
                }
                cfg.socket_window = window;
            }
            "socket-events" => cfg.socket_events = at_least_one(name, number(name, &value)?)?,
            "socket-serial-events" => cfg.socket_serial_events = number(name, &value)?,
            "socket-variants" => cfg.socket_variants = variants(&value)?,
            "socket-client-nodelay" => {
                cfg.socket_client_nodelay = switch(&format!("--{name}"), &value)?
            }
            "socket-rounds" => cfg.socket_rounds = at_least_one(name, number(name, &value)?)?,
            "door-path-events" => cfg.door_path_events = at_least_one(name, number(name, &value)?)?,
            "door-path-serial-events" => {
                cfg.door_path_serial_events = at_least_one(name, number(name, &value)?)?
            }
            "door-path-rounds" => cfg.door_path_rounds = at_least_one(name, number(name, &value)?)?,
            "guest-path-events" => {
                let events = number(name, &value)?;
                if events < GUEST_PATH_MIN_EVENTS {
                    return Err(format!(
                        "--{name} must be at least {GUEST_PATH_MIN_EVENTS}, one event per connection"
                    ));
                }
                cfg.guest_path_events = events;
            }
            "guest-path-seed-events" => {
                cfg.guest_path_seed_events = at_least_one(name, number(name, &value)?)?
            }
            "guest-path-rounds" => {
                cfg.guest_path_rounds = at_least_one(name, number(name, &value)?)?
            }
            "profile" => {
                cfg.profile = match value.as_str() {
                    "server" => Profile::Server,
                    "phone" => Profile::Phone,
                    _ => return Err("--profile is `server` or `phone`".into()),
                }
            }
            "max-bytes" => cfg.max_bytes = Some(number(name, &value)?),
            "dir" => cfg.dir = Some(PathBuf::from(value)),
            "out" => cfg.out = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown option `--{name}`")),
        }
    }
    // `door-path` and `guest-path` are diagnostic: each runs only when it is
    // named, never in `all`.
    let (ingest, query, fanout, engine, socket, door_path, guest_path) = match scenario.as_deref() {
        None | Some("all") => (true, true, true, true, true, false, false),
        Some("ingest") => (true, false, false, false, false, false, false),
        Some("query") => (false, true, false, false, false, false, false),
        Some("fanout") => (false, false, true, false, false, false, false),
        Some("engine") => (false, false, false, true, false, false, false),
        Some("socket") => (false, false, false, false, true, false, false),
        Some("door-path") => (false, false, false, false, false, true, false),
        Some("guest-path") => (false, false, false, false, false, false, true),
        Some(other) => {
            return Err(format!(
                "unknown scenario `{other}` (ingest, query, fanout, engine, socket, door-path, guest-path or all)"
            ));
        }
    };
    cfg.ingest = ingest;
    cfg.query = query;
    cfg.fanout = fanout;
    cfg.engine = engine;
    cfg.socket = socket;
    cfg.door_path = door_path;
    cfg.guest_path = guest_path;
    if cfg.socket {
        let widest = cfg.socket_connections.iter().copied().max().unwrap_or(1);
        if cfg.socket_events < widest {
            return Err(format!(
                "--socket-events {} is below the widest --socket-connections {widest}: every connection needs an event",
                cfg.socket_events
            ));
        }
    }
    Ok(Some(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Option<Config>, String> {
        parse(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn no_arguments_run_everything_at_the_defaults() {
        let cfg = parsed(&[]).unwrap().unwrap();
        assert!(cfg.ingest && cfg.query && cfg.fanout && cfg.engine && cfg.socket);
        assert!(!cfg.door_path, "door-path is never part of a default run");
        assert!(!cfg.guest_path, "guest-path is never part of a default run");
        assert_eq!(cfg.events, 2000);
        assert_eq!(cfg.socket_connections, vec![1, 4, 16, 64]);
        assert_eq!(
            (
                cfg.socket_window,
                cfg.socket_events,
                cfg.socket_serial_events
            ),
            (32, 20_000, 2000)
        );
        assert_eq!(cfg.socket_variants.len(), 1);
        assert_eq!(cfg.socket_variants[0].label(), "2:8:2/1:off");
        assert!(cfg.socket_client_nodelay);
        assert_eq!(cfg.socket_rounds, 1);
        assert_eq!(cfg.ingest_threads, vec![1, 4]);
        assert_eq!(cfg.engine_connections, vec![1, 4, 16, 64]);
        assert_eq!(cfg.engine_windows, vec![1, 32]);
        assert_eq!((cfg.engine_subscribers, cfg.engine_publish), (1000, 200));
    }

    #[test]
    fn a_scenario_and_both_option_forms_parse() {
        let cfg = parsed(&[
            "query",
            "--events",
            "1_000",
            "--queries=7",
            "--ingest-threads",
            "2,8",
        ])
        .unwrap()
        .unwrap();
        assert!(!cfg.ingest && cfg.query && !cfg.fanout && !cfg.engine);
        assert_eq!((cfg.events, cfg.queries), (1000, 7));
        assert_eq!(cfg.ingest_threads, vec![2, 8]);
    }

    #[test]
    fn the_engine_scenario_and_its_options_parse() {
        let cfg = parsed(&[
            "engine",
            "--engine-connections",
            "2,8",
            "--engine-windows=1,4",
            "--engine-workers",
            "3",
            "--engine-events",
            "500",
            "--engine-subscribers=20",
            "--engine-publish",
            "7",
        ])
        .unwrap()
        .unwrap();
        assert!(cfg.engine && !cfg.ingest && !cfg.query && !cfg.fanout);
        assert_eq!(cfg.engine_connections, vec![2, 8]);
        assert_eq!(cfg.engine_windows, vec![1, 4]);
        assert_eq!(cfg.engine_workers, 3);
        assert_eq!(cfg.engine_events, 500);
        assert_eq!((cfg.engine_subscribers, cfg.engine_publish), (20, 7));
        assert!(parsed(&["--engine-windows", "0"]).is_err());
        assert!(parsed(&["--engine-connections", "1,,2"]).is_err());
    }

    #[test]
    fn the_socket_scenario_and_its_options_parse() {
        let cfg = parsed(&[
            "socket",
            "--socket-connections",
            "2,8",
            "--socket-window=4",
            "--socket-events",
            "1_000",
            "--socket-serial-events=0",
            "--socket-variants",
            "2:8:2/1:off, 4:16:8/8:on",
            "--socket-client-nodelay",
            "off",
            "--socket-rounds=3",
        ])
        .unwrap()
        .unwrap();
        assert!(cfg.socket && !cfg.engine && !cfg.ingest && !cfg.query && !cfg.fanout);
        assert_eq!(cfg.socket_connections, vec![2, 8]);
        assert_eq!(
            (
                cfg.socket_window,
                cfg.socket_events,
                cfg.socket_serial_events
            ),
            (4, 1000, 0)
        );
        let labels: Vec<String> = cfg.socket_variants.iter().map(Variant::label).collect();
        assert_eq!(labels, ["2:8:2/1:off", "4:16:8/8:on"]);
        assert!(cfg.socket_variants[1].nodelay);
        assert!(!cfg.socket_client_nodelay);
        assert_eq!(cfg.socket_rounds, 3);
    }

    #[test]
    fn the_door_path_scenario_runs_only_when_named_and_its_options_parse() {
        let cfg = parsed(&["door-path"]).unwrap().unwrap();
        assert!(cfg.door_path);
        assert!(!cfg.ingest && !cfg.query && !cfg.fanout && !cfg.engine && !cfg.socket);
        assert_eq!(
            (
                cfg.door_path_events,
                cfg.door_path_serial_events,
                cfg.door_path_rounds
            ),
            (20_000, 2000, 8)
        );
        let cfg = parsed(&[
            "door-path",
            "--door-path-events",
            "40_000",
            "--door-path-serial-events=4000",
            "--door-path-rounds",
            "3",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            (
                cfg.door_path_events,
                cfg.door_path_serial_events,
                cfg.door_path_rounds
            ),
            (40_000, 4000, 3)
        );
        // Neither `all` nor any other scenario runs it.
        for scenario in ["all", "socket", "engine", "ingest", "query", "fanout"] {
            assert!(
                !parsed(&[scenario]).unwrap().unwrap().door_path,
                "{scenario}"
            );
        }
        for (args, reason) in [
            (&["--door-path-events", "0"][..], "at least 1"),
            (&["--door-path-serial-events", "0"], "at least 1"),
            (&["--door-path-rounds", "0"], "at least 1"),
            (&["--door-path-rounds", "x"], "not a valid number"),
            (&["door-path", "socket"], "unexpected"),
        ] {
            let message = parsed(args).unwrap_err();
            assert!(
                message.contains(reason),
                "{args:?}: `{message}` lacks `{reason}`"
            );
        }
    }

    #[test]
    fn the_guest_path_scenario_runs_only_when_named_and_its_options_parse() {
        let cfg = parsed(&["guest-path"]).unwrap().unwrap();
        assert!(cfg.guest_path);
        assert!(!cfg.ingest && !cfg.query && !cfg.fanout && !cfg.engine && !cfg.socket);
        assert!(!cfg.door_path);
        assert_eq!(
            (
                cfg.guest_path_events,
                cfg.guest_path_seed_events,
                cfg.guest_path_rounds
            ),
            (2000, 2000, 8)
        );
        let cfg = parsed(&[
            "guest-path",
            "--guest-path-events",
            "40_000",
            "--guest-path-seed-events=100000",
            "--guest-path-rounds",
            "8",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            (
                cfg.guest_path_events,
                cfg.guest_path_seed_events,
                cfg.guest_path_rounds
            ),
            (40_000, 100_000, 8)
        );
        for scenario in [
            "all",
            "socket",
            "door-path",
            "engine",
            "ingest",
            "query",
            "fanout",
        ] {
            assert!(
                !parsed(&[scenario]).unwrap().unwrap().guest_path,
                "{scenario}"
            );
        }
        for (args, reason) in [
            (&["--guest-path-events", "63"][..], "at least 64"),
            (&["--guest-path-seed-events", "0"], "at least 1"),
            (&["--guest-path-rounds", "0"], "at least 1"),
            (&["--guest-path-rounds", "x"], "not a valid number"),
            (&["guest-path", "door-path"], "unexpected"),
        ] {
            let message = parsed(args).unwrap_err();
            assert!(
                message.contains(reason),
                "{args:?}: `{message}` lacks `{reason}`"
            );
        }
    }

    #[test]
    fn bad_socket_input_is_refused_with_a_reason() {
        for (args, reason) in [
            (&["--socket-window", "65"][..], "at most 64"),
            (&["--socket-window", "0"], "at least 1"),
            (&["--socket-rounds", "0"], "at least 1"),
            (&["--socket-connections", "1,0"], "at least 1"),
            (&["--socket-client-nodelay", "yes"], "on` or `off"),
            (&["--socket-variants", "2:8:2/1"], "four parts"),
            (&["--socket-variants", "2:8:2:off"], "SHARED/PUBLIC"),
            (&["--socket-variants", "0:8:2/1:off"], "at least 1"),
            (&["--socket-variants", "2:8:2/0:off"], "at least 1"),
            (&["--socket-variants", "2:8:1/2:off"], "at most SHARED"),
            (&["--socket-variants", "2:x:2/1:off"], "not a number"),
            (&["--socket-variants", "2:8:2/1:maybe"], "on` or `off"),
            (
                &["--socket-variants", "2:8:2/1:off,2:8:2/1:off"],
                "listed twice",
            ),
            (
                &[
                    "socket",
                    "--socket-connections",
                    "64",
                    "--socket-events",
                    "10",
                ],
                "below the widest",
            ),
        ] {
            let message = parsed(args).unwrap_err();
            assert!(
                message.contains(reason),
                "{args:?}: `{message}` lacks `{reason}`"
            );
        }
    }

    #[test]
    fn bad_input_is_refused_with_a_reason() {
        assert!(parsed(&["--help"]).unwrap().is_none());
        assert!(
            parsed(&["nothing"])
                .unwrap_err()
                .contains("unknown scenario")
        );
        assert!(parsed(&["--events"]).unwrap_err().contains("needs a value"));
        assert!(
            parsed(&["--events", "0"])
                .unwrap_err()
                .contains("at least 1")
        );
        assert!(
            parsed(&["--bogus", "1"])
                .unwrap_err()
                .contains("unknown option")
        );
        assert!(
            parsed(&["ingest", "query"])
                .unwrap_err()
                .contains("unexpected")
        );
        assert!(
            parsed(&["--direct-batch", "999999"])
                .unwrap_err()
                .contains("at most")
        );
    }
}
