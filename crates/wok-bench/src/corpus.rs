//! The deterministic corpus: fixed secret keys, seeded content and tags, and
//! a fixed clock.
//!
//! The same seed and sizes give the same keys, ids, timestamps and tags. The
//! signatures differ from run to run (Schnorr signing mixes in fresh
//! randomness), so the corpus is compared by its digest over ids and
//! partitions, never over the stored bytes.
//!
//! Every replaceable or addressable coordinate (author, kind, `d` tag) is
//! used by exactly one event. Concurrent submitters can therefore never make
//! one event supersede another, and no put is refused as retired whatever
//! order the writer sees them in.

use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind, Tag};
use nostr::key::{Keys, PublicKey};
use nostr::types::Timestamp;
use wok_store::Visibility;

use crate::config::Config;
use crate::support::SplitMix;

/// The store's clock for every put and query: far enough from the wall clock
/// that nothing depends on it, and after every event's `created_at`.
pub const NOW: u64 = 1_900_000_000;

pub const KIND_METADATA: u16 = 0;
pub const KIND_NOTE: u16 = 1;
pub const KIND_REACTION: u16 = 7;
pub const KIND_ARTICLE: u16 = 30023;

/// Events an `e` tag may point at: the first few of the corpus.
const E_TARGETS: usize = 32;

#[derive(Debug)]
pub struct Item {
    pub visibility: Visibility,
    pub event: Event,
}

#[derive(Debug)]
pub struct Corpus {
    pub items: Vec<Item>,
    pub authors: Vec<PublicKey>,
    /// FNV-1a over every event id and its partition, in order.
    pub digest: u64,
    /// Total bytes of the events' JSON.
    pub json_bytes: usize,
}

impl Corpus {
    pub fn events_in(&self, visibility: Visibility) -> impl Iterator<Item = &Event> {
        self.items
            .iter()
            .filter(move |item| item.visibility == visibility)
            .map(|item| &item.event)
    }

    pub fn count_in(&self, visibility: Visibility) -> usize {
        self.events_in(visibility).count()
    }
}

/// The smallest corpus that gives every query shape something to find in
/// both partitions.
pub fn minimum_events(authors: usize) -> usize {
    authors * 2 + 40
}

fn secret_hex(seed: u64, author: usize) -> String {
    let mut rng =
        SplitMix(seed ^ 0x776F_6B2D_6B65_7973 ^ (author as u64).wrapping_mul(0x9E37_79B9));
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        rng.next(),
        rng.next(),
        rng.next(),
        rng.next()
    )
}

fn text(rng: &mut SplitMix, index: usize, bytes: usize) -> String {
    let mut out = format!("{index:08} ");
    while out.len() < bytes {
        out.push((b'a' + rng.below(26) as u8) as char);
    }
    out.truncate(bytes.max(9));
    out
}

fn tag(parts: &[&str]) -> Result<Tag, String> {
    Tag::parse(parts.iter().copied()).map_err(|e| format!("build a tag: {e}"))
}

/// The corpus authors' keys, in author order: the same keys `build` signs
/// with, so a scenario can authenticate as an author.
pub fn author_keys(cfg: &Config) -> Result<Vec<Keys>, String> {
    (0..cfg.authors)
        .map(|a| Keys::parse(&secret_hex(cfg.seed, a)).map_err(|e| format!("a corpus key: {e}")))
        .collect()
}

/// The key `notes` signs with.
pub fn notes_key(seed: u64) -> Result<Keys, String> {
    Keys::parse(&secret_hex(seed ^ 0x6661_6E6F_7574, 0)).map_err(|e| format!("a notes key: {e}"))
}

/// Build and sign the corpus on the fixed benchmark clock. Signing is the slow
/// part and is never timed.
pub fn build(cfg: &Config) -> Result<Corpus, String> {
    build_at(cfg, NOW)
}

/// Build the same corpus with its newest timestamps near `now`, for export to
/// relays that reject events too far in the future or too far in the past.
pub fn build_at(cfg: &Config, now: u64) -> Result<Corpus, String> {
    let events = cfg.events;
    let author_count = cfg.authors;
    if author_count < 2 {
        return Err(
            "--authors must be at least 2, so that both partitions hold a metadata event".into(),
        );
    }
    if events < minimum_events(author_count) {
        return Err(format!(
            "--events {events} is too small for {author_count} authors: at least {} are needed \
             so that every query shape finds something in both partitions",
            minimum_events(author_count)
        ));
    }
    let keys = author_keys(cfg)?;
    let authors: Vec<PublicKey> = keys.iter().map(Keys::public_key).collect();
    let mut rng = SplitMix(cfg.seed ^ 0x636F_7270_7573);
    // Distinct, increasing timestamps that all precede the chosen clock.
    let base = now - 10 * events as u64 - 1_000;

    let mut items: Vec<Item> = Vec::with_capacity(events);
    let mut ids: Vec<String> = Vec::with_capacity(E_TARGETS);
    let (mut digest, mut json_bytes) = (0xCBF2_9CE4_8422_2325u64, 0usize);
    for i in 0..events {
        let at = base + i as u64 * 10 + rng.below(10) as u64;
        let (author, kind, content, mut tags) = if i < author_count {
            // One metadata event per author: a replaceable coordinate of its own.
            (
                i,
                KIND_METADATA,
                format!("{{\"name\":\"bench-{i}\"}}"),
                Vec::new(),
            )
        } else {
            let author = rng.below(author_count);
            let content = text(&mut rng, i, cfg.content_bytes);
            match i % 10 {
                0..=5 | 9 => (author, KIND_NOTE, content, Vec::new()),
                6 | 7 => (author, KIND_REACTION, "+".to_string(), Vec::new()),
                _ => (author, KIND_ARTICLE, content, Vec::new()),
            }
        };
        let author_hex = authors[rng.below(author_count)].to_hex();
        match kind {
            KIND_NOTE => {
                if !ids.is_empty() && i % 10 != 9 {
                    tags.push(tag(&["e", &ids[rng.below(ids.len())]])?);
                }
                tags.push(tag(&["p", &author_hex])?);
                if rng.below(3) == 0 {
                    tags.push(tag(&["t", &format!("topic{}", rng.below(8))])?);
                }
            }
            KIND_REACTION => {
                if !ids.is_empty() {
                    tags.push(tag(&["e", &ids[rng.below(ids.len())]])?);
                }
                tags.push(tag(&["p", &author_hex])?);
            }
            KIND_ARTICLE => {
                // A `d` value no other event shares.
                tags.push(tag(&["d", &format!("article-{i}")])?);
                tags.push(tag(&["t", &format!("topic{}", rng.below(8))])?);
            }
            _ => {}
        }
        let event = EventBuilder::new(Kind::from(kind), content)
            .custom_created_at(Timestamp::from_secs(at))
            .tags(tags)
            .finalize(&keys[author])
            .map_err(|e| format!("sign an event: {e}"))?;
        // An even split that does not follow the kind pattern (which repeats
        // every ten events), so each kind appears in both partitions.
        let visibility = if (i + i / 10) % 2 == 0 {
            Visibility::Public
        } else {
            Visibility::Sheltered
        };
        if ids.len() < E_TARGETS {
            ids.push(event.id.to_hex());
        }
        let partition = u8::from(visibility == Visibility::Sheltered);
        for byte in event.id.as_bytes().iter().chain([&partition]) {
            digest = (digest ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3);
        }
        json_bytes += serde_json::to_string(&event)
            .map_err(|e| format!("serialise an event: {e}"))?
            .len();
        items.push(Item { visibility, event });
    }
    Ok(Corpus {
        items,
        authors,
        digest,
        json_bytes,
    })
}

/// `count` plain notes from one fixed key, for the fan-out scenario: it needs
/// events to publish, not a corpus to query, so it has no size floor.
pub fn notes(seed: u64, count: usize, content_bytes: usize) -> Result<Vec<Event>, String> {
    let keys = notes_key(seed)?;
    let mut rng = SplitMix(seed ^ 0x6661_6E6F_7574);
    let base = NOW - 10 * count as u64 - 1_000;
    (0..count)
        .map(|i| {
            EventBuilder::new(Kind::from(KIND_NOTE), text(&mut rng, i, content_bytes))
                .custom_created_at(Timestamp::from_secs(base + i as u64 * 10))
                .finalize(&keys)
                .map_err(|e| format!("sign an event: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Config {
        Config {
            events: 120,
            authors: 4,
            ..Config::default()
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_ids() {
        let (a, b) = (build(&small()).unwrap(), build(&small()).unwrap());
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.authors, b.authors);
        let other = build(&Config { seed: 2, ..small() }).unwrap();
        assert_ne!(a.digest, other.digest);
    }

    #[test]
    fn every_event_verifies_and_both_partitions_are_populated() {
        let corpus = build(&small()).unwrap();
        assert_eq!(corpus.items.len(), 120);
        assert!(corpus.items.iter().all(|i| i.event.verify().is_ok()));
        assert!(
            corpus
                .items
                .iter()
                .all(|i| i.event.created_at.as_secs() < NOW)
        );
        assert_eq!(corpus.count_in(Visibility::Public), 60);
        assert_eq!(corpus.count_in(Visibility::Sheltered), 60);
    }

    #[test]
    fn notes_are_repeatable_and_need_no_floor() {
        let (a, b) = (notes(1, 3, 100).unwrap(), notes(1, 3, 100).unwrap());
        assert_eq!(a.len(), 3);
        assert!(a.iter().zip(&b).all(|(x, y)| x.id == y.id));
        assert!(a.iter().all(|e| e.verify().is_ok()));
    }

    #[test]
    fn a_corpus_too_small_for_the_shapes_is_refused() {
        let cfg = Config {
            events: 10,
            authors: 4,
            ..Config::default()
        };
        assert!(build(&cfg).unwrap_err().contains("too small"));
    }
}
