//! `wok-bench`: a store-level baseline benchmark for `wok-store`.
//!
//! Three scenarios, each a pure `wok-store` workload with no network:
//! `ingest` (puts through the group-commit writer and straight into the
//! store), `query` (every query shape over a seeded corpus, in both
//! partitions) and `fanout` (readers draining a `LiveFanout`). The corpus is
//! seeded, signed from fixed keys and prepared before any clock starts. The
//! result is one JSON document, and a refused put, a wrong answer or a
//! lagging reader fails the run instead of being reported.
//!
//! The figures are for holding later changes to "no slower" on one machine.
//! They say nothing about other relay implementations, and are only
//! comparable between runs with the same header and sizes.

mod config;
mod corpus;
mod fanout;
mod ingest;
mod query;
mod support;

use std::process::ExitCode;

use serde_json::{Map, Value, json};
use wok_store::Visibility;

use config::{Config, HELP};
use corpus::Corpus;

fn main() -> ExitCode {
    let cfg = match config::parse(std::env::args().skip(1)) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("wok-bench: {message}\n\nTry `wok-bench --help`.");
            return ExitCode::from(2);
        }
    };
    let outcome = run(&cfg).and_then(|document| emit(&cfg, &document));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("wok-bench: FAILED: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Run the selected scenarios and return the whole result document.
fn run(cfg: &Config) -> Result<Value, String> {
    let mut document = Map::new();
    document.insert("header".into(), support::header(cfg));

    let corpus = if cfg.ingest || cfg.query {
        eprintln!("corpus: signing {} events", cfg.events);
        let corpus = corpus::build(cfg)?;
        check_ceiling(cfg, &corpus)?;
        document.insert("corpus".into(), corpus_json(&corpus));
        Some(corpus)
    } else {
        None
    };
    if let Some(corpus) = &corpus {
        if cfg.ingest {
            document.insert("ingest".into(), ingest::run(cfg, corpus)?);
        }
        if cfg.query {
            document.insert("query".into(), query::run(cfg, corpus)?);
        }
    }
    if cfg.fanout {
        document.insert("fanout".into(), fanout::run(cfg)?);
    }
    Ok(Value::Object(document))
}

fn corpus_json(corpus: &Corpus) -> Value {
    json!({
        "events": corpus.items.len(),
        "authors": corpus.authors.len(),
        "public_events": corpus.count_in(Visibility::Public),
        "sheltered_events": corpus.count_in(Visibility::Sheltered),
        "json_bytes": corpus.json_bytes,
        "digest": format!("{:016x}", corpus.digest),
        "digest_note": "FNV-1a over event ids and partitions; signatures vary between runs",
    })
}

/// A ceiling given by hand must leave room for the corpus. The sized default
/// always does; every put also has to come back stored.
fn check_ceiling(cfg: &Config, corpus: &Corpus) -> Result<(), String> {
    let ceiling = cfg.max_bytes_for(corpus.items.len());
    let needed = corpus.json_bytes as u64 * 2;
    if ceiling < needed {
        return Err(format!(
            "--max-bytes {ceiling} is too small for a corpus of {} bytes of events \
             (at least {needed} are needed, allowing for indexes)",
            corpus.json_bytes
        ));
    }
    Ok(())
}

fn emit(cfg: &Config, document: &Value) -> Result<(), String> {
    let mut text =
        serde_json::to_string_pretty(document).map_err(|e| format!("write the results: {e}"))?;
    text.push('\n');
    match &cfg.out {
        Some(path) => std::fs::write(path, text)
            .map_err(|e| format!("write the results to {}: {e}", path.display())),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every scenario at tiny sizes: the document has every section and every
    /// figure the scenarios promise. The timings mean nothing at this size.
    #[test]
    fn every_scenario_runs_at_tiny_sizes_and_reports_its_sections() {
        let cfg = Config {
            events: 120,
            authors: 4,
            content_bytes: 64,
            ingest_threads: vec![1, 2],
            direct_batch: 16,
            queries: 8,
            variants: 4,
            settle_ms: Some(0),
            fanout_readers: 3,
            fanout_events: 20,
            fanout_workers: 2,
            ..Config::default()
        };
        let document = run(&cfg).unwrap_or_else(|e| panic!("the smoke run failed: {e}"));

        let header = &document["header"];
        for key in [
            "git_commit",
            "os",
            "arch",
            "cpus",
            "load_average",
            "sqlite_version",
            "store_options",
            "params",
        ] {
            assert!(header.get(key).is_some(), "header lacks {key}");
        }
        assert_eq!(header["params"]["events"], 120);
        assert_eq!(document["corpus"]["events"], 120);

        let writer = document["ingest"]["writer"].as_array().unwrap();
        assert_eq!(writer.len(), 2);
        for run in writer {
            assert_eq!(run["put_latency"]["count"], 120);
            assert!(run["commits"].as_u64().unwrap() >= 1);
            assert!(run["mean_batch_events"].as_f64().unwrap() >= 1.0);
            assert!(run["events_per_s"].as_f64().unwrap() > 0.0);
        }
        let direct = document["ingest"]["direct"].as_array().unwrap();
        assert_eq!(direct.len(), 2);
        assert_eq!(direct[0]["batch_events"], 1);
        assert_eq!(direct[0]["commits"], 120);
        assert_eq!(direct[1]["batch_events"], 16);

        for partition in ["public", "sheltered"] {
            let shapes = document["query"]["partitions"][partition]["shapes"]
                .as_object()
                .unwrap();
            assert_eq!(shapes.len(), 11, "{partition} shapes");
            for (name, shape) in shapes {
                assert_eq!(shape["latency"]["count"], 8, "{partition} {name}");
                assert!(
                    shape["rows_min"].as_u64().unwrap() >= 1,
                    "{partition} {name} returned nothing"
                );
                assert!(shape["latency"]["p99_us"].is_number());
            }
        }

        let fanout = &document["fanout"];
        assert_eq!(fanout["deliveries"], 60);
        assert!(fanout["delivered_json_bytes"].as_u64().unwrap() > 0);
        assert!(fanout["all_readers_complete_ms"].is_number());

        // Nothing identifies the machine or the person who ran it.
        let text = document.to_string();
        if let Some(home) = std::env::var_os("HOME").and_then(|h| h.into_string().ok())
            && home.len() > 1
        {
            assert!(!text.contains(&home), "the results name the home directory");
        }
        assert!(!text.contains("hostname"));
    }

    #[test]
    fn the_fan_out_also_runs_paced() {
        let cfg = Config {
            fanout_readers: 2,
            fanout_events: 30,
            fanout_workers: 2,
            fanout_window: 4,
            content_bytes: 64,
            ..Config::default()
        };
        let document = fanout::run(&cfg).unwrap();
        assert_eq!(document["deliveries"], 60);
        assert_eq!(document["window"], 4);
    }

    #[test]
    fn a_ceiling_that_cannot_hold_the_corpus_fails_before_running() {
        let cfg = Config {
            events: 120,
            authors: 4,
            max_bytes: Some(1000),
            ..Config::default()
        };
        let corpus = corpus::build(&cfg).unwrap();
        assert!(
            check_ceiling(&cfg, &corpus)
                .unwrap_err()
                .contains("too small")
        );
    }
}
