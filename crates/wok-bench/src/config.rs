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
    all       every scenario (default)

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

#[derive(Clone, Debug)]
pub struct Config {
    pub ingest: bool,
    pub query: bool,
    pub fanout: bool,
    pub engine: bool,
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
    let (ingest, query, fanout, engine) = match scenario.as_deref() {
        None | Some("all") => (true, true, true, true),
        Some("ingest") => (true, false, false, false),
        Some("query") => (false, true, false, false),
        Some("fanout") => (false, false, true, false),
        Some("engine") => (false, false, false, true),
        Some(other) => {
            return Err(format!(
                "unknown scenario `{other}` (ingest, query, fanout, engine or all)"
            ));
        }
    };
    cfg.ingest = ingest;
    cfg.query = query;
    cfg.fanout = fanout;
    cfg.engine = engine;
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
        assert!(cfg.ingest && cfg.query && cfg.fanout && cfg.engine);
        assert_eq!(cfg.events, 2000);
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
