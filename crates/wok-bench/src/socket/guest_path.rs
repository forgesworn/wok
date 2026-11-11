//! Guest path: a diagnostic that sets keeper writes through the sheltered door
//! beside guest writes, whose every publish asks a guest authority for the
//! guest's scopes while the door holds a work permit, on an empty and on a
//! seeded store.
//!
//! Real WebSocket connections on `127.0.0.1`, window 32, the server runtime at
//! 2 workers and 8 blocking threads with its TCP_NODELAY off, the client's
//! TCP_NODELAY on. Three arms:
//!
//! 1. `keeper`: each connection authenticates as a keeper and its events are
//!    signed by that keeper's key. No guest authority is installed.
//! 2. `guest_memory`: each connection authenticates as a guest persona and a
//!    separate device key signs every event; the scopes come from a map in
//!    memory ([`MemoryGrants`]), a lower bound.
//! 3. `guest_sqlite`: as `guest_memory`, but every lookup is an indexed read of
//!    the authority's own small SQLite file ([`SqliteGrants`]). It is a model,
//!    not any application's query.
//!
//! Both guest authorities are wrapped in [`Counted`], which counts and times
//! every call. Round `r` runs the stores in an order set by its parity, and in
//! each store and connection count the six (arm, permits) runs in their listed
//! order starting at index `r mod 6`. The comparison rule, fixed before any
//! figures were seen, is [`compare`] and [`permit_bound`]. Nothing here adds an
//! artificial cost, and the scenario runs only when it is named.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nostr::event::{Event, EventBuilder, EventId, FinalizeEvent, Kind};
use nostr::filter::Filter;
use nostr::key::{Keys, PublicKey};
use nostr::types::Timestamp;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::{Barrier, watch};
use wok_store::relay::{AuthorityUnavailable, GuestAuthority, GuestScope};
use wok_store::{
    EventStore, EventStoreError, MAX_EXACT_COUNT, PreparedPut, PutOutcome, SqliteEventStore,
    Visibility,
};

use super::client::{Frame, connect_all, write_lane};
use super::door_path::{Pair, compare, median, named_pair_json};
use super::server::Server;
use super::{CLIENT_WORKERS, allowances, client_runtime, content};
use crate::config::{Config, DOOR_INFLIGHT_WRITES, Variant};
use crate::corpus::KIND_NOTE;
use crate::engine::writes::{cell_json, drive, writer_json};
use crate::engine::{Keepers, tag, wall_seconds};
use crate::support::{SplitMix, fresh_store};

/// The window every connection keeps in flight.
const WINDOW: usize = 32;
/// The connection counts of the grid.
const CONNECTIONS: [usize; 3] = [1, 16, 64];
/// The widest cell: the door's connection limits are raised to it, and each
/// key family has this many keys.
const WIDEST: usize = 64;
/// The connection counts the permit-bound signature is judged at.
const SIGNATURE_CONNECTIONS: [usize; 2] = [16, 64];
const WORKERS: usize = 2;
const BLOCKING: usize = 8;
/// The door's work permits, shared/public.
const PERMITS: [(usize, usize); 2] = [(2, 1), (8, 8)];
/// The round count the comparison rule was designed for.
const DESIGNED_ROUNDS: usize = 8;
/// Grants held by personas that never connect, besides the measured ones.
const OTHER_PERSONAS: usize = 1000;
/// The name of the relay's writer thread (`wok-store`'s `writer.rs`).
const WRITER_THREAD: &str = "wok-event-writer";
/// The widest `created_at` span one exact count covers when a store is
/// verified. The events are one second apart, so no window holds more than
/// this many, below the store's exact-count bound.
const COUNT_WINDOW_SECONDS: u64 = 5000;
/// Ids looked up per query when a store is verified.
const ID_CHUNK: usize = 64;
/// Events per `put_prepared_batch` call when the seeded template is built.
const SEED_CHUNK: usize = 1000;
/// Seed authors, each with a room of its own.
const SEED_AUTHORS: usize = 64;
/// How far past the scenario's start every grant expires: far, but finite,
/// since the door turns `expires_at - now` into a deadline.
const GRANT_LIFETIME: u64 = 5 * 365 * 24 * 3600;
const STORE_FILE: &str = "events.sqlite";
const GRANTS_FILE: &str = "grants.sqlite";

/// Seeds of the key families, so that no two families share a key.
const FAMILY_KEEPERS: u64 = 0x6770_2D6B_6565_7065;
const FAMILY_PERSONAS: u64 = 0x6770_2D70_6572_736F;
const FAMILY_DEVICES: u64 = 0x6770_2D64_6576_6963;
const FAMILY_ISSUER: u64 = 0x6770_2D69_7373_7565;
const FAMILY_SEED_AUTHORS: u64 = 0x6770_2D73_6565_6461;
const FAMILY_OTHER_PERSONAS: u64 = 0x6770_2D6F_7468_6572;
const FAMILY_OTHER_DEVICES: u64 = 0x6770_2D6F_6465_7669;

/// The grants table of [`SqliteGrants`]: one row per scope.
const SCHEMA: &str = "CREATE TABLE grants (
    persona BLOB NOT NULL,
    issuer BLOB NOT NULL,
    grant_id TEXT NOT NULL,
    room TEXT NOT NULL,
    device BLOB NOT NULL,
    read_kinds TEXT NOT NULL,
    write_kinds TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX grants_by_persona ON grants (persona);
CREATE INDEX grants_by_device ON grants (device);";
/// What every `scopes` call of the SQLite arm runs.
const PERSONA_QUERY: &str = "SELECT issuer, grant_id, room, device, read_kinds, write_kinds, expires_at FROM grants WHERE persona = ?1 AND expires_at > ?2";
/// What a `device_scopes` call of the SQLite arm would run.
const DEVICE_QUERY: &str = "SELECT issuer, grant_id, room, device, read_kinds, write_kinds, expires_at FROM grants WHERE device = ?1 AND expires_at > ?2";
const INSERT: &str = "INSERT INTO grants (persona, issuer, grant_id, room, device, read_kinds, write_kinds, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    Keeper,
    GuestMemory,
    GuestSqlite,
}

const GUEST_ARMS: [Arm; 2] = [Arm::GuestMemory, Arm::GuestSqlite];

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Keeper => "keeper",
            Self::GuestMemory => "guest_memory",
            Self::GuestSqlite => "guest_sqlite",
        }
    }

    fn is_guest(self) -> bool {
        self != Self::Keeper
    }
}

/// The six (arm, permit setting) runs of a cell, in their listed order; the
/// permit setting is an index into [`PERMITS`].
const RUNS: [(Arm, usize); 6] = [
    (Arm::Keeper, 0),
    (Arm::GuestMemory, 0),
    (Arm::GuestSqlite, 0),
    (Arm::Keeper, 1),
    (Arm::GuestMemory, 1),
    (Arm::GuestSqlite, 1),
];

fn run_index(arm: Arm, permits: usize) -> usize {
    RUNS.iter()
        .position(|&run| run == (arm, permits))
        .expect("every arm runs at every permit setting")
}

fn permits_label(permits: usize) -> String {
    let (shared, public) = PERMITS[permits];
    format!("{shared}/{public}")
}

fn run_label(arm: Arm, permits: usize) -> String {
    format!("{} at {}", arm.name(), permits_label(permits))
}

/// Round `round`'s order: the runs in their listed order, starting at index
/// `round mod 6`.
fn run_order(round: usize) -> Vec<(Arm, usize)> {
    (0..RUNS.len())
        .map(|i| RUNS[(round % RUNS.len() + i) % RUNS.len()])
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoreKind {
    Empty,
    Seeded,
}

const STORES: [StoreKind; 2] = [StoreKind::Empty, StoreKind::Seeded];

impl StoreKind {
    fn name(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Seeded => "seeded",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Seeded => 1,
        }
    }
}

/// Odd rounds run the empty store first, even rounds the seeded one.
fn store_order(round: usize) -> [StoreKind; 2] {
    if round % 2 == 1 {
        [StoreKind::Empty, StoreKind::Seeded]
    } else {
        [StoreKind::Seeded, StoreKind::Empty]
    }
}

fn variant(permits: usize) -> Variant {
    let (shared, public) = PERMITS[permits];
    Variant {
        workers: WORKERS,
        blocking: BLOCKING,
        shared,
        public,
        nodelay: false,
    }
}

/// One kind of call to a guest authority, counted and timed.
#[derive(Default)]
struct Calls {
    calls: AtomicU64,
    writer_thread: AtomicU64,
    errors: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl Calls {
    /// Record one call that took `elapsed`. The thread is named here, outside
    /// the timed bracket.
    fn record(&self, elapsed: Duration, failed: bool) {
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.total_ns.fetch_add(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
        if failed {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if std::thread::current().name() == Some(WRITER_THREAD) {
            self.writer_thread.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn tally(&self) -> Tally {
        Tally {
            calls: self.calls.load(Ordering::Relaxed),
            writer_thread: self.writer_thread.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            total_ns: self.total_ns.load(Ordering::Relaxed),
            max_ns: self.max_ns.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    calls: u64,
    writer_thread: u64,
    errors: u64,
    total_ns: u64,
    max_ns: u64,
}

fn round_us(ns: f64) -> f64 {
    (ns / 1e3 * 1e3).round() / 1e3
}

impl Tally {
    fn mean_us(&self) -> Option<f64> {
        (self.calls > 0).then(|| round_us(self.total_ns as f64 / self.calls as f64))
    }

    fn json(&self) -> Value {
        json!({
            "calls": self.calls,
            "writer_thread_calls": self.writer_thread,
            "other_thread_calls": self.calls - self.writer_thread,
            "errors": self.errors,
            "total_us": round_us(self.total_ns as f64),
            "mean_us": self.mean_us(),
            "max_us": (self.calls > 0).then(|| round_us(self.max_ns as f64)),
        })
    }
}

#[derive(Default)]
struct Counters {
    scopes: Calls,
    device_scopes: Calls,
}

/// A lookup of the scopes the bench configured: the part of a guest
/// authority that differs between the two guest arms.
trait Lookup: Send + Sync {
    fn by_persona(
        &self,
        persona: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable>;
    fn by_device(
        &self,
        device: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable>;
}

/// A guest authority for this loopback benchmark only: it answers from a
/// [`Lookup`] of exactly the scopes the bench configured, and counts and
/// times every `scopes` and `device_scopes` call. Nothing ever changes, so
/// neither watcher is bumped; both senders are held for the authority's whole
/// life, so that neither channel closes. It must never be used by an
/// application: it grants whatever the bench put in its lookup.
struct Counted<L> {
    lookup: L,
    counters: Arc<Counters>,
    guests: watch::Sender<u64>,
    issuers: watch::Sender<u64>,
}

impl<L: Lookup> Counted<L> {
    fn new(lookup: L) -> (Arc<Self>, Arc<Counters>) {
        let counters = Arc::new(Counters::default());
        let authority = Arc::new(Self {
            lookup,
            counters: Arc::clone(&counters),
            guests: watch::channel(0).0,
            issuers: watch::channel(0).0,
        });
        (authority, counters)
    }
}

impl<L: Lookup> GuestAuthority for Counted<L> {
    fn scopes(
        &self,
        identity: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        let started = Instant::now();
        let answer = self.lookup.by_persona(identity, now);
        let elapsed = started.elapsed();
        self.counters.scopes.record(elapsed, answer.is_err());
        answer
    }

    fn device_scopes(
        &self,
        device: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        let started = Instant::now();
        let answer = self.lookup.by_device(device, now);
        let elapsed = started.elapsed();
        self.counters.device_scopes.record(elapsed, answer.is_err());
        answer
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.guests.subscribe()
    }

    fn subscribe_issuers(&self) -> watch::Receiver<u64> {
        self.issuers.subscribe()
    }
}

/// One configured grant: the persona that holds it and the scope it gives.
#[derive(Clone)]
struct Grant {
    persona: PublicKey,
    scope: GuestScope,
}

/// The in-memory lookup, for this loopback benchmark only: a map lookup and a
/// clone of exactly the scopes the bench configured, a lower bound on any real
/// lookup. It must never be used by an application.
struct MemoryGrants {
    by_persona: HashMap<PublicKey, Vec<GuestScope>>,
    by_device: HashMap<PublicKey, Vec<GuestScope>>,
}

impl MemoryGrants {
    fn new(grants: &[Grant]) -> Self {
        let mut by_persona: HashMap<PublicKey, Vec<GuestScope>> = HashMap::new();
        let mut by_device: HashMap<PublicKey, Vec<GuestScope>> = HashMap::new();
        for grant in grants {
            by_persona
                .entry(grant.persona)
                .or_default()
                .push(grant.scope.clone());
            by_device
                .entry(grant.scope.device)
                .or_default()
                .push(grant.scope.clone());
        }
        Self {
            by_persona,
            by_device,
        }
    }
}

fn unexpired(scopes: Option<&Vec<GuestScope>>, now: u64) -> Vec<GuestScope> {
    scopes
        .map(|scopes| {
            scopes
                .iter()
                .filter(|scope| scope.expires_at > now)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

impl Lookup for MemoryGrants {
    fn by_persona(
        &self,
        persona: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        Ok(unexpired(self.by_persona.get(persona), now))
    }

    fn by_device(
        &self,
        device: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        Ok(unexpired(self.by_device.get(device), now))
    }
}

/// The SQLite lookup, for this loopback benchmark only: a model of a lookup
/// that reads a grants table, not any application's query. Every call checks
/// a read-only connection out of a pool (opening another when none is free,
/// so that readers never wait on each other), runs one indexed query and
/// checks the connection back in. It reads exactly the grants the bench wrote
/// and must never be used by an application.
struct SqliteGrants {
    path: PathBuf,
    pool: Mutex<Vec<Connection>>,
    opened: Arc<AtomicU64>,
}

type GrantRow = (Vec<u8>, String, String, Vec<u8>, String, String, i64);

fn kinds_text(kinds: &BTreeSet<u16>) -> String {
    kinds
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn kinds_from(text: &str) -> Option<BTreeSet<u16>> {
    if text.is_empty() {
        return Some(BTreeSet::new());
    }
    text.split(',').map(|kind| kind.parse().ok()).collect()
}

fn scope_from(row: GrantRow) -> Option<GuestScope> {
    let (issuer, grant_id, room, device, read, write, expires_at) = row;
    Some(GuestScope {
        issuer: PublicKey::from_slice(&issuer).ok()?,
        grant_id,
        room,
        device: PublicKey::from_slice(&device).ok()?,
        read: kinds_from(&read)?,
        write: kinds_from(&write)?,
        expires_at: u64::try_from(expires_at).ok()?,
    })
}

fn read_grants(
    connection: &Connection,
    sql: &str,
    key: &PublicKey,
    now: u64,
) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
    let now = i64::try_from(now).map_err(|_| AuthorityUnavailable)?;
    let key = key.to_bytes();
    let mut statement = connection
        .prepare_cached(sql)
        .map_err(|_| AuthorityUnavailable)?;
    let rows = statement
        .query_map(params![&key[..], now], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(|_| AuthorityUnavailable)?;
    let mut scopes = Vec::new();
    for row in rows {
        let row: GrantRow = row.map_err(|_| AuthorityUnavailable)?;
        scopes.push(scope_from(row).ok_or(AuthorityUnavailable)?);
    }
    Ok(scopes)
}

impl SqliteGrants {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            pool: Mutex::new(Vec::new()),
            opened: Arc::new(AtomicU64::new(0)),
        }
    }

    fn read(
        &self,
        sql: &str,
        key: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        let free = self.pool.lock().map_err(|_| AuthorityUnavailable)?.pop();
        let connection = match free {
            Some(connection) => connection,
            None => {
                self.opened.fetch_add(1, Ordering::Relaxed);
                Connection::open_with_flags(
                    &self.path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .map_err(|_| AuthorityUnavailable)?
            }
        };
        let answer = read_grants(&connection, sql, key, now);
        if let Ok(mut pool) = self.pool.lock() {
            pool.push(connection);
        }
        answer
    }
}

impl Lookup for SqliteGrants {
    fn by_persona(
        &self,
        persona: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        self.read(PERSONA_QUERY, persona, now)
    }

    fn by_device(
        &self,
        device: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        self.read(DEVICE_QUERY, device, now)
    }
}

/// Write `grants` to a fresh grants file at `path` and close it, then read
/// back how SQLite plans the persona query.
fn write_grants(path: &Path, grants: &[Grant]) -> Result<Vec<String>, String> {
    let mut connection =
        Connection::open(path).map_err(|e| format!("create the grants file: {e}"))?;
    connection
        .execute_batch(SCHEMA)
        .map_err(|e| format!("create the grants table: {e}"))?;
    let transaction = connection
        .transaction()
        .map_err(|e| format!("begin the grants: {e}"))?;
    {
        let mut insert = transaction
            .prepare(INSERT)
            .map_err(|e| format!("prepare the grant insert: {e}"))?;
        for grant in grants {
            let scope = &grant.scope;
            let expires_at =
                i64::try_from(scope.expires_at).map_err(|_| "a grant's expiry is too large")?;
            insert
                .execute(params![
                    &grant.persona.to_bytes()[..],
                    &scope.issuer.to_bytes()[..],
                    scope.grant_id,
                    scope.room,
                    &scope.device.to_bytes()[..],
                    kinds_text(&scope.read),
                    kinds_text(&scope.write),
                    expires_at,
                ])
                .map_err(|e| format!("insert a grant: {e}"))?;
        }
    }
    transaction
        .commit()
        .map_err(|e| format!("commit the grants: {e}"))?;
    let plan = {
        let mut explain = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {PERSONA_QUERY}"))
            .map_err(|e| format!("explain the persona query: {e}"))?;
        let rows = explain
            .query_map(params![&[0u8; 32][..], 0i64], |row| row.get::<_, String>(3))
            .map_err(|e| format!("explain the persona query: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("explain the persona query: {e}"))?
    };
    connection
        .close()
        .map_err(|(_, e)| format!("close the grants file: {e}"))?;
    Ok(plan)
}

/// `count` keys of one family, drawn in turn from one generator.
fn family(seed: u64, tag: u64, count: usize) -> Result<Vec<Keys>, String> {
    let mut rng = SplitMix(seed ^ tag);
    (0..count)
        .map(|_| {
            let hex = format!(
                "{:016x}{:016x}{:016x}{:016x}",
                rng.next(),
                rng.next(),
                rng.next(),
                rng.next()
            );
            Keys::parse(&hex).map_err(|e| format!("derive a bench key: {e}"))
        })
        .collect()
}

/// Every key of the scenario.
struct KeySet {
    keepers: Vec<Keys>,
    personas: Vec<Keys>,
    devices: Vec<Keys>,
    issuer: Keys,
    seed_authors: Vec<Keys>,
    other_personas: Vec<Keys>,
    other_devices: Vec<Keys>,
}

impl KeySet {
    fn new(seed: u64) -> Result<Self, String> {
        let keys = Self {
            keepers: family(seed, FAMILY_KEEPERS, WIDEST)?,
            personas: family(seed, FAMILY_PERSONAS, WIDEST)?,
            devices: family(seed, FAMILY_DEVICES, WIDEST)?,
            issuer: family(seed, FAMILY_ISSUER, 1)?.remove(0),
            seed_authors: family(seed, FAMILY_SEED_AUTHORS, SEED_AUTHORS)?,
            other_personas: family(seed, FAMILY_OTHER_PERSONAS, OTHER_PERSONAS)?,
            other_devices: family(seed, FAMILY_OTHER_DEVICES, OTHER_PERSONAS)?,
        };
        let all: Vec<PublicKey> = keys
            .keepers
            .iter()
            .chain(&keys.personas)
            .chain(&keys.devices)
            .chain([&keys.issuer])
            .chain(&keys.seed_authors)
            .chain(&keys.other_personas)
            .chain(&keys.other_devices)
            .map(Keys::public_key)
            .collect();
        let distinct: HashSet<&PublicKey> = all.iter().collect();
        if distinct.len() != all.len() {
            return Err("two bench keys coincide; the key families must be disjoint".into());
        }
        Ok(keys)
    }

    /// The grants: one per measured persona, then one per other persona.
    fn grants(&self, expires_at: u64) -> Vec<Grant> {
        let kinds: BTreeSet<u16> = [KIND_NOTE].into();
        let grant = |persona: &Keys, device: &Keys, name: String, room: String| Grant {
            persona: persona.public_key(),
            scope: GuestScope {
                issuer: self.issuer.public_key(),
                grant_id: name,
                room,
                device: device.public_key(),
                read: kinds.clone(),
                write: kinds.clone(),
                expires_at,
            },
        };
        let measured = self
            .personas
            .iter()
            .zip(&self.devices)
            .enumerate()
            .map(|(i, (persona, device))| grant(persona, device, format!("grant-{i}"), room(i)));
        let others = self
            .other_personas
            .iter()
            .zip(&self.other_devices)
            .enumerate()
            .map(|(i, (persona, device))| {
                grant(
                    persona,
                    device,
                    format!("other-grant-{i}"),
                    format!("other-room-{i}"),
                )
            });
        measured.chain(others).collect()
    }
}

/// The room of connection `lane`.
fn room(lane: usize) -> String {
    format!("room-{lane}")
}

/// A kind-1 note in `room`, with exactly one `d` tag.
fn note(
    rng: &mut SplitMix,
    index: usize,
    bytes: usize,
    signer: &Keys,
    room: &str,
    created_at: u64,
) -> Result<Event, String> {
    EventBuilder::new(Kind::from(KIND_NOTE), content(rng, index, bytes))
        .tags(vec![tag(["d", room])?])
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(signer)
        .map_err(|e| format!("sign a note: {e}"))
}

/// One run's events, serialised before any clock starts.
struct Signed {
    frames: Arc<Vec<Frame>>,
    ids: Vec<EventId>,
}

/// `count` notes for `connections` connections: note `i` belongs to
/// connection `i mod connections`, is in that connection's room and is signed
/// by `signers[i mod connections]`, with `created_at = base + i`.
fn sign_run(
    cfg: &Config,
    signers: &[Keys],
    connections: usize,
    count: usize,
    base: u64,
) -> Result<Signed, String> {
    let mut rng = SplitMix(cfg.seed ^ 0x6775_6573_7470_6174 ^ connections as u64);
    let mut frames = Vec::with_capacity(count);
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let lane = i % connections;
        let event = note(
            &mut rng,
            i,
            cfg.content_bytes,
            &signers[lane],
            &room(lane),
            base + i as u64,
        )?;
        ids.push(event.id);
        frames.push(Frame::new(&event)?.0);
    }
    Ok(Signed {
        frames: Arc::new(frames),
        ids,
    })
}

/// The seeded events: note `j` by seed author `j mod 64`, in its own room,
/// with `created_at = base + j`.
fn seed_notes(
    cfg: &Config,
    authors: &[Keys],
    count: usize,
    base: u64,
) -> Result<Vec<Event>, String> {
    let mut rng = SplitMix(cfg.seed ^ 0x6770_7365_6564_6564);
    (0..count)
        .map(|j| {
            let author = j % authors.len();
            note(
                &mut rng,
                j,
                cfg.content_bytes,
                &authors[author],
                &format!("seed-room-{author}"),
                base + j as u64,
            )
        })
        .collect()
}

fn temp_dir(cfg: &Config) -> Result<TempDir, String> {
    match &cfg.dir {
        Some(parent) => TempDir::new_in(parent),
        None => TempDir::new(),
    }
    .map_err(|e| format!("create a temporary directory: {e}"))
}

/// Put `events` into the sheltered partition through the store's public API,
/// each checked and its signature verified by `PreparedPut::new`, and require
/// every one to be stored. A put the store deferred did nothing and is offered
/// again; the count of re-offers is returned.
fn put_all(store: &SqliteEventStore, events: &[Event], now: u64) -> Result<usize, String> {
    let mut pending: Vec<&Event> = events.iter().collect();
    let mut reoffers = 0;
    loop {
        let puts = pending
            .iter()
            .map(|&event| PreparedPut::new(Visibility::Sheltered, event.clone(), now, false))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("prepare a seeded event: {e}"))?;
        let results = store.put_prepared_batch(&puts);
        if results.len() != puts.len() {
            return Err(format!(
                "the store answered {} puts for a batch of {}",
                results.len(),
                puts.len()
            ));
        }
        let mut deferred = Vec::new();
        for (&event, result) in pending.iter().zip(results) {
            match result {
                Ok(PutOutcome::Stored) => {}
                Err(EventStoreError::Deferred) => deferred.push(event),
                other => return Err(format!("a seeded event was not stored: {other:?}")),
            }
        }
        if deferred.is_empty() {
            return Ok(reoffers);
        }
        if deferred.len() == pending.len() {
            return Err("the store deferred every seeded put and made no progress".into());
        }
        reoffers += deferred.len();
        pending = deferred;
    }
}

/// The seeded store, built once per scenario run and closed cleanly: its
/// write-ahead log is checked empty, so the main file alone is the store.
struct Template {
    dir: TempDir,
    events: usize,
    bytes: u64,
    seconds: f64,
    reoffers: usize,
}

fn build_template(cfg: &Config, events: &[Event], capacity: usize) -> Result<Template, String> {
    let started = Instant::now();
    let (dir, store) = fresh_store(cfg, capacity)?;
    let now = wall_seconds();
    let mut reoffers = 0;
    for chunk in events.chunks(SEED_CHUNK) {
        reoffers += put_all(&store, chunk, now)?;
    }
    let store = Arc::try_unwrap(store).map_err(|_| "the template store is still shared")?;
    // Dropping the store runs its final checkpoint and closes it.
    drop(store);
    let mut bytes = 0;
    let entries =
        std::fs::read_dir(dir.path()).map_err(|e| format!("list the template directory: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("list the template directory: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let len = entry
            .metadata()
            .map_err(|e| format!("read {name}'s size: {e}"))?
            .len();
        match name.as_str() {
            STORE_FILE => bytes = len,
            "events.sqlite-shm" => {}
            "events.sqlite-wal" if len == 0 => {}
            "events.sqlite-wal" => {
                return Err(format!(
                    "the template's write-ahead log still holds {len} bytes after the store closed"
                ));
            }
            other => {
                return Err(format!(
                    "the template directory holds an unexpected file `{other}`"
                ));
            }
        }
    }
    if bytes == 0 {
        return Err("the template store file is missing or empty".into());
    }
    Ok(Template {
        dir,
        events: events.len(),
        bytes,
        seconds: (started.elapsed().as_secs_f64() * 1e3).round() / 1e3,
        reoffers,
    })
}

/// A copy of the template's main file in a fresh directory, opened.
fn seeded_copy(
    cfg: &Config,
    template: &Template,
    capacity: usize,
) -> Result<(TempDir, Arc<SqliteEventStore>), String> {
    let dir = temp_dir(cfg)?;
    let path = dir.path().join(STORE_FILE);
    std::fs::copy(template.dir.path().join(STORE_FILE), &path)
        .map_err(|e| format!("copy the seeded template: {e}"))?;
    let store = SqliteEventStore::open_with_options(
        &path,
        cfg.max_bytes_for(capacity),
        0,
        cfg.store_options(),
    )
    .map_err(|e| format!("open the seeded copy: {e}"))?;
    Ok((dir, Arc::new(store)))
}

/// The store holds exactly `seeded + ids.len()` events in the sheltered
/// partition, none in the public one, and every id in `ids`, and the writer
/// stored exactly `ids.len()`. The total is counted exactly: the `created_at`
/// span `[lowest, highest]` is cut into windows of at most `window` seconds,
/// the first open below and the last open above, and each window's count
/// must be below the store's exact-count bound. Returns the total.
fn verify_run(
    store: &SqliteEventStore,
    seeded: u64,
    ids: &[EventId],
    writer_events: u64,
    (lowest, highest): (u64, u64),
    window: u64,
    now: u64,
) -> Result<u64, String> {
    let written = ids.len() as u64;
    if writer_events != written {
        return Err(format!(
            "the writer stored {writer_events} events for a run of {written}"
        ));
    }
    let window = window.max(1);
    let mut starts = Vec::new();
    let mut start = lowest;
    while start <= highest {
        starts.push(start);
        start = start.saturating_add(window);
    }
    let last = starts.len().saturating_sub(1);
    let mut total = 0;
    for (i, &start) in starts.iter().enumerate() {
        let mut filter = Filter::new();
        if i > 0 {
            filter = filter.since(Timestamp::from_secs(start));
        }
        if i < last {
            filter = filter.until(Timestamp::from_secs(start + window - 1));
        }
        let counted = store
            .count(Visibility::Sheltered, &[filter], now)
            .map_err(|e| format!("count a created_at window: {e}"))?;
        if counted > MAX_EXACT_COUNT {
            return Err(format!(
                "a created_at window from {start} holds {counted} events, above the exact-count bound"
            ));
        }
        total += counted;
    }
    if total != seeded + written {
        return Err(format!(
            "the sheltered partition holds {total} events, expected {} ({seeded} seeded and {written} written)",
            seeded + written
        ));
    }
    let strays = store
        .count(Visibility::Public, &[Filter::new()], now)
        .map_err(|e| format!("count the public partition: {e}"))?;
    if strays != 0 {
        return Err(format!(
            "the public partition holds {strays} events, expected none"
        ));
    }
    for chunk in ids.chunks(ID_CHUNK) {
        let filter = Filter::new().ids(chunk.iter().copied());
        let mut found: Vec<String> = store
            .query_stored(Visibility::Sheltered, &filter, now)
            .map_err(|e| format!("look up written ids: {e}"))?
            .into_iter()
            .map(|row| row.id)
            .collect();
        let mut wanted: Vec<String> = chunk.iter().map(EventId::to_hex).collect();
        found.sort_unstable();
        wanted.sort_unstable();
        if found != wanted {
            return Err(format!(
                "the sheltered partition does not hold every written event: {} found of {}",
                found.len(),
                wanted.len()
            ));
        }
    }
    Ok(total)
}

/// Check one guest run's calls against `expected_calls`: `scopes` calls are
/// `written + 2 x connections + 2 x heartbeats`, where the heartbeats are at
/// least the Ping frames the client lanes saw and at most `connections x
/// floor(lifetime / heartbeat)`; no `device_scopes` call, no call on the
/// writer thread and no failed call. A mismatch is an error naming both
/// figures.
fn check_calls(
    scopes: &Tally,
    device: &Tally,
    written: u64,
    connections: u64,
    pings: u64,
    lifetime: Duration,
    heartbeat: Duration,
) -> Result<Value, String> {
    let base = written + 2 * connections;
    let beats_each = (lifetime.as_nanos() / heartbeat.as_nanos().max(1)) as u64;
    let most = connections * beats_each;
    let excess = scopes.calls.checked_sub(base);
    let beats = excess
        .filter(|excess| excess % 2 == 0)
        .map(|excess| excess / 2);
    let calls_match = beats.is_some_and(|beats| beats >= pings && beats <= most);
    let clean = device.calls == 0
        && scopes.writer_thread == 0
        && device.writer_thread == 0
        && scopes.errors == 0
        && device.errors == 0;
    if !(calls_match && clean) {
        return Err(format!(
            "the authority calls do not match expected_calls: scopes expected {written} written + 2 x {connections} connections + 2 x heartbeats (heartbeats from {pings}, the Pings seen, to {most}, over a server lifetime of {:.3}s) = {base} + an even number from {} to {}, observed {}; device_scopes expected 0, observed {}; writer-thread calls expected 0, observed {} (scopes) and {} (device_scopes); failed calls expected 0, observed {} and {}",
            lifetime.as_secs_f64(),
            2 * pings,
            2 * most,
            scopes.calls,
            device.calls,
            scopes.writer_thread,
            device.writer_thread,
            scopes.errors,
            device.errors,
        ));
    }
    Ok(json!({
        "matched": true,
        "expected_without_heartbeats": base,
        "observed": scopes.calls,
        "heartbeat_calls": scopes.calls - base,
        "heartbeats_allowed": [pings, most],
    }))
}

/// What every run shares.
struct Context<'a> {
    cfg: &'a Config,
    keys: &'a KeySet,
    keepers: &'a Arc<Keepers>,
    client: &'a Runtime,
    /// Per connection count, the keeper arm's events and the guest arms'.
    signed: &'a [(usize, Signed, Signed)],
    grants: &'a [Grant],
    grants_path: &'a Path,
    template: &'a Template,
    /// The `created_at` span every store's events lie in.
    span: (u64, u64),
    heartbeat: Duration,
}

impl Context<'_> {
    fn signed(&self, arm: Arm, connections: usize) -> &Signed {
        let (_, keeper, guest) = self
            .signed
            .iter()
            .find(|(c, _, _)| *c == connections)
            .expect("every connection count is signed");
        if arm.is_guest() { guest } else { keeper }
    }
}

/// One run: a fresh store (empty, or a copy of the template), relay, door and
/// authority, its connections authenticated before the clock starts.
fn run_one(
    ctx: &Context,
    arm: Arm,
    permits: usize,
    store: StoreKind,
    connections: usize,
) -> Result<Value, String> {
    let cfg = ctx.cfg;
    let variant = variant(permits);
    let label = format!(
        "{} store, {connections} connections, {}",
        store.name(),
        run_label(arm, permits)
    );
    let signed = ctx.signed(arm, connections);
    let events = signed.ids.len();
    let (seeded, opened) = match store {
        StoreKind::Empty => (0, fresh_store(cfg, events)?),
        StoreKind::Seeded => (
            ctx.template.events,
            seeded_copy(cfg, ctx.template, ctx.template.events + events)?,
        ),
    };
    let mut sqlite_opened = None;
    let (authority, counters): (Option<Arc<dyn GuestAuthority>>, Option<Arc<Counters>>) = match arm
    {
        Arm::Keeper => (None, None),
        Arm::GuestMemory => {
            let (authority, counters) = Counted::new(MemoryGrants::new(ctx.grants));
            (Some(authority as Arc<dyn GuestAuthority>), Some(counters))
        }
        Arm::GuestSqlite => {
            let lookup = SqliteGrants::new(ctx.grants_path);
            sqlite_opened = Some(Arc::clone(&lookup.opened));
            let (authority, counters) = Counted::new(lookup);
            (Some(authority as Arc<dyn GuestAuthority>), Some(counters))
        }
    };
    let began = Instant::now();
    let mut server = Server::start_on(
        ctx.keepers,
        Visibility::Sheltered,
        &variant,
        opened,
        WIDEST,
        authority,
    )
    .map_err(|e| format!("{label}: {e}"))?;
    let signers = if arm.is_guest() {
        &ctx.keys.personas
    } else {
        &ctx.keys.keepers
    };
    let sockets =
        ctx.client
            .block_on(connect_all(&label, &server.url, signers, connections, true))?;
    let start = Arc::new(Barrier::new(connections + 1));
    let mut tasks = Vec::with_capacity(connections);
    for (lane, socket) in sockets.into_iter().enumerate() {
        let indices: Vec<usize> = (lane..events).step_by(connections).collect();
        tasks.push(ctx.client.spawn(write_lane(
            format!("{label}, connection {lane}"),
            socket,
            Arc::clone(&signed.frames),
            indices,
            WINDOW,
            Arc::clone(&start),
        )));
    }
    let mut merged = drive(ctx.client, tasks, &start).map_err(|e| format!("{label}: {e}"))?;
    server.relay.flush();
    let stats = server.relay.writer_stats();
    let commits = server.store.commits();
    server.stop().map_err(|e| format!("{label}: {e}"))?;
    let lifetime = began.elapsed();
    let stored = verify_run(
        &server.store,
        seeded as u64,
        &signed.ids,
        stats.events,
        ctx.span,
        COUNT_WINDOW_SECONDS,
        wall_seconds(),
    )
    .map_err(|e| format!("{label}: {e}"))?;
    let mut out = cell_json(&mut merged, events, WINDOW);
    out["arm"] = json!(arm.name());
    out["permits"] = json!(permits_label(permits));
    out["variant"] = json!(variant.label());
    out["store"] = json!(store.name());
    out["connections"] = json!(connections);
    out["writer"] = writer_json(stats, commits);
    out["stored_total"] = json!(stored);
    out["pings_seen"] = json!(merged.pings);
    out["server_lifetime_s"] = json!((lifetime.as_secs_f64() * 1e3).round() / 1e3);
    out["authority"] = match counters {
        None => Value::Null,
        Some(counters) => {
            let scopes = counters.scopes.tally();
            let device = counters.device_scopes.tally();
            let check = check_calls(
                &scopes,
                &device,
                events as u64,
                connections as u64,
                merged.pings,
                lifetime,
                ctx.heartbeat,
            )
            .map_err(|e| format!("{label}: {e}"))?;
            json!({
                "scopes": scopes.json(),
                "device_scopes": device.json(),
                "expected_calls_check": check,
                "sqlite_connections_opened": sqlite_opened.map(|opened| opened.load(Ordering::Relaxed)),
            })
        }
    };
    // Only a run whose store passed `verify_run` gets here.
    out["verified"] = json!(true);
    Ok(out)
}

/// Per (store index, connection count, run index), each round's acknowledged
/// writes/s and the writer's mean batch, in round order.
type Figures = BTreeMap<(usize, usize, usize), Vec<(f64, f64)>>;

fn series(
    figures: &Figures,
    store: StoreKind,
    connections: usize,
    run: usize,
) -> (Vec<f64>, Vec<f64>) {
    figures
        .get(&(store.index(), connections, run))
        .map(|rounds| rounds.iter().copied().unzip())
        .unwrap_or_default()
}

fn pair(
    figures: &Figures,
    (x_store, x_run): (StoreKind, usize),
    (y_store, y_run): (StoreKind, usize),
    connections: usize,
) -> Pair {
    let (xw, xb) = series(figures, x_store, connections, x_run);
    let (yw, yb) = series(figures, y_store, connections, y_run);
    compare(&xw, &yw, Some(&xb), Some(&yb))
}

/// The permit-bound signature, fixed before any figures were seen: true only
/// if (a) the guest arm is below keeper at 2/1, (b) the guest arm at 8/8 is
/// above itself at 2/1, and (c) keeper at 8/8 is not above itself at 2/1.
fn permit_bound(
    guest_vs_keeper_low: &Pair,
    guest_high_vs_low: &Pair,
    keeper_high_vs_low: &Pair,
) -> bool {
    guest_vs_keeper_low.verdict == "below"
        && guest_high_vs_low.verdict == "above"
        && keeper_high_vs_low.verdict != "above"
}

fn conclusion(present: bool) -> &'static str {
    if present {
        "permit-bound signature present in this model"
    } else {
        "permit-bound signature absent in this model"
    }
}

fn range(values: &[f64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    json!({ "min": min, "median": median(values), "max": max })
}

/// One store and connection count: its pairs, and at 16 and 64 connections
/// the permit-bound signature of each guest arm.
fn cell_comparison(figures: &Figures, store: StoreKind, connections: usize) -> Value {
    let mut pairs = Map::new();
    for guest in GUEST_ARMS {
        for permits in 0..PERMITS.len() {
            let p = pair(
                figures,
                (store, run_index(guest, permits)),
                (store, run_index(Arm::Keeper, permits)),
                connections,
            );
            pairs.insert(
                format!("{}_vs_keeper_at_{}", guest.name(), permits_label(permits)),
                named_pair_json(
                    &run_label(guest, permits),
                    &run_label(Arm::Keeper, permits),
                    &p,
                ),
            );
        }
    }
    for (arm, _) in RUNS.iter().take(3) {
        let p = pair(
            figures,
            (store, run_index(*arm, 1)),
            (store, run_index(*arm, 0)),
            connections,
        );
        pairs.insert(
            format!("{}_8/8_vs_2/1", arm.name()),
            named_pair_json(&run_label(*arm, 1), &run_label(*arm, 0), &p),
        );
    }
    let mut out = json!({ "pairs": pairs });
    if SIGNATURE_CONNECTIONS.contains(&connections) {
        let keeper_high_vs_low = pair(
            figures,
            (store, run_index(Arm::Keeper, 1)),
            (store, run_index(Arm::Keeper, 0)),
            connections,
        );
        let mut signatures = Map::new();
        for guest in GUEST_ARMS {
            let guest_vs_keeper = pair(
                figures,
                (store, run_index(guest, 0)),
                (store, run_index(Arm::Keeper, 0)),
                connections,
            );
            let guest_high_vs_low = pair(
                figures,
                (store, run_index(guest, 1)),
                (store, run_index(guest, 0)),
                connections,
            );
            let present = permit_bound(&guest_vs_keeper, &guest_high_vs_low, &keeper_high_vs_low);
            signatures.insert(
                guest.name().into(),
                json!({
                    "a_guest_vs_keeper_at_2/1": guest_vs_keeper.verdict,
                    "a_needs": "below",
                    "b_guest_8/8_vs_2/1": guest_high_vs_low.verdict,
                    "b_needs": "above",
                    "c_keeper_8/8_vs_2/1": keeper_high_vs_low.verdict,
                    "c_needs": "not above",
                    "present": present,
                    "conclusion": conclusion(present),
                }),
            );
        }
        out["permit_bound_signature"] = Value::Object(signatures);
    }
    let mut summary = Map::new();
    for (index, &(arm, permits)) in RUNS.iter().enumerate() {
        let (writes, batches) = series(figures, store, connections, index);
        summary.insert(
            run_label(arm, permits),
            json!({
                "writes_per_s": range(&writes),
                "mean_batch_events": range(&batches),
            }),
        );
    }
    out["summary"] = Value::Object(summary);
    out
}

/// Every comparison block, from the figures by round.
fn comparisons(figures: &Figures, rounds: usize) -> Value {
    let mut out = Map::new();
    for store in STORES {
        let mut cells = Map::new();
        for connections in CONNECTIONS {
            cells.insert(
                connections.to_string(),
                cell_comparison(figures, store, connections),
            );
        }
        out.insert(store.name().into(), Value::Object(cells));
    }
    let mut cross = Map::new();
    for connections in CONNECTIONS {
        let mut pairs = Map::new();
        for (index, &(arm, permits)) in RUNS.iter().enumerate() {
            let p = pair(
                figures,
                (StoreKind::Seeded, index),
                (StoreKind::Empty, index),
                connections,
            );
            let name = run_label(arm, permits);
            pairs.insert(
                format!(
                    "{}_seeded_vs_empty_at_{}",
                    arm.name(),
                    permits_label(permits)
                ),
                named_pair_json(&format!("{name}, seeded"), &format!("{name}, empty"), &p),
            );
        }
        cross.insert(connections.to_string(), json!({ "pairs": pairs }));
    }
    out.insert("seeded_vs_empty".into(), Value::Object(cross));
    let mut block = json!({
        "metric": "acknowledged_per_s (writes/s), paired by round number",
        "rounds": rounds,
        "threshold": rounds.saturating_sub(1),
        "rule_designed_for_rounds": DESIGNED_ROUNDS,
        "by_store": out,
    });
    if rounds != DESIGNED_ROUNDS {
        block["rule_note"] = json!(format!(
            "the rule was designed for {DESIGNED_ROUNDS} rounds (7 of 8); with {rounds} it is at least {} of {rounds}",
            rounds.saturating_sub(1)
        ));
    }
    block
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
        "median": "the middle value, or the mean of the two middle values of an even count",
        "pairs": "for every store and connection count: each guest arm against keeper at each permit setting, and each arm at 8/8 against itself at 2/1; for every connection count, each arm seeded against itself empty at each permit setting",
        "permit_bound_signature": "per guest arm and store, at 16 and 64 connections only: true only if (a) the guest arm is below keeper at 2/1, (b) the guest arm at 8/8 is above itself at 2/1, and (c) keeper at 8/8 is not above itself at 2/1",
        "conclusion": "\"permit-bound signature present in this model\" when true, \"permit-bound signature absent in this model\" otherwise",
    })
}

fn expected_calls(heartbeat: Duration) -> Value {
    json!({
        "derived_from": "the code of wok-store's relay engine and wok-ws's door, before any run",
        "scopes_per_guest_connection_apart_from_publishes": 2,
        "scopes_per_publish": 1,
        "scopes_per_heartbeat": 2,
        "device_scopes": 0,
        "writer_thread_calls": 0,
        "formula": "scopes calls = written + 2 x connections + 2 x heartbeats; device_scopes calls = 0; calls on the writer thread = 0",
        "heartbeat_seconds": heartbeat.as_secs(),
        "derivation": [
            "AUTH: `authenticate` reads the persona's scopes once (`guests.scopes`): 1",
            "the AUTH OK reply: the door's `deliver` asks `try_can_read`, which has no cached verdict yet since AUTH cleared it, so it runs `can_read_live` through `apply`; `live_access` reads the scopes once through `granted_scopes_checked` and caches them with the authority stamp and their `valid_until`: 1",
            "each publish: `begin_prepared` through `apply` runs `authorise_publish`, whose `guest_scopes` reads the scopes once through `granted_scopes_checked`: 1 per publish",
            "each OK reply: `try_can_read` answers from the cached verdict while the stamp is unchanged and now < valid_until: 0",
            "the writer's recheck (`unchanged_or_allowed`): 0 while the keeper source signals, the stamp is unchanged and the wall clock is before valid_until",
            "each sheltered heartbeat (the door's default heartbeat, first due that long after the connection opens): the Ping is sent, then `can_read_at` and `authority_is_current` each read the scopes once: 2",
            "`device_scopes` is asked only on the replica path, which no run takes: 0",
            "closing a connection makes no authority call",
            "nothing bumps either watcher, so the stamp never changes",
        ],
        "check": "every guest run: written + 2 x connections <= scopes calls, the difference even, and half of it from the Ping frames the client lanes saw while writing up to connections x floor(server lifetime / heartbeat), so exactly 0 when the server lived less than one heartbeat; device_scopes calls, calls on the writer thread and failed calls all 0. A mismatch fails the run with both figures",
        "keeper_arm": "no guest authority is installed, so its counts are null",
    })
}

fn does_not_show() -> Value {
    json!([
        "the in-memory arm is a lower bound: a map lookup and a clone, cheaper than any real lookup",
        "the SQLite arm is a model on native disk with a warm cache: a small grants file read through a pool of read-only connections, not any application's query, schema or storage",
        "neither measures the embedding application's own lookup, so an absent signature clears nothing about it",
        "the time a work permit is held is not measured directly, because wok-ws is not instrumented; only the time inside `scopes` and `device_scopes` is",
        "which tokio threads (workers or blocking) made the calls; only whether a call was on the writer thread is recorded",
        "one host, one process, loopback, macOS: the client and the server share the host and CPU is not attributed to either side",
    ])
}

pub fn run(cfg: &Config) -> Result<Value, String> {
    let mut cfg = cfg.clone();
    cfg.socket_client_nodelay = true;
    let cfg = &cfg;
    let events = cfg.guest_path_events;
    let seed = cfg.guest_path_seed_events;
    let rounds = cfg.guest_path_rounds;
    if events < WIDEST {
        return Err(format!(
            "the guest-path scenario needs at least {WIDEST} events a run"
        ));
    }
    let heartbeat = wok_ws::Timings::default().heartbeat();
    eprintln!(
        "guest-path: 2 stores x 3 connection counts x 6 runs, {rounds} rounds, {events} events a run, {seed} seeded"
    );
    let keys = KeySet::new(cfg.seed)?;
    let keepers = Arc::new(Keepers::new(keys.keepers.iter().map(Keys::public_key)));
    let start = wall_seconds();
    let written_base = start
        .checked_sub(1000 + events as u64)
        .ok_or("the wall clock is too early to date the notes")?;
    let seed_base = written_base
        .checked_sub(seed as u64 + 10)
        .ok_or("the wall clock is too early to date the seeded notes")?;
    let span = (seed_base, written_base + events as u64 - 1);
    let expires_at = start + GRANT_LIFETIME;

    eprintln!("guest-path: signing");
    let mut signed = Vec::with_capacity(CONNECTIONS.len());
    for connections in CONNECTIONS {
        let keeper = sign_run(cfg, &keys.keepers, connections, events, written_base)?;
        let guest = sign_run(cfg, &keys.devices, connections, events, written_base)?;
        signed.push((connections, keeper, guest));
    }
    eprintln!("guest-path: building the seeded template");
    let template = {
        let seeded = seed_notes(cfg, &keys.seed_authors, seed, seed_base)?;
        build_template(cfg, &seeded, seed + events)?
    };
    let grants = keys.grants(expires_at);
    let grants_dir = temp_dir(cfg)?;
    let grants_path = grants_dir.path().join(GRANTS_FILE);
    let plan = write_grants(&grants_path, &grants)?;
    let client = client_runtime()?;
    let ctx = Context {
        cfg,
        keys: &keys,
        keepers: &keepers,
        client: &client,
        signed: &signed,
        grants: &grants,
        grants_path: &grants_path,
        template: &template,
        span,
        heartbeat,
    };

    let mut figures: Figures = BTreeMap::new();
    let mut round_records = Vec::with_capacity(rounds);
    for round in 1..=rounds {
        let stores = store_order(round);
        let order = run_order(round);
        let mut store_records = Vec::with_capacity(stores.len());
        for store in stores {
            let mut cells = Vec::with_capacity(CONNECTIONS.len());
            for connections in CONNECTIONS {
                let mut runs = Map::new();
                for &(arm, permits) in &order {
                    eprintln!(
                        "guest-path round {round}, {} store, {connections} connections: {}",
                        store.name(),
                        run_label(arm, permits)
                    );
                    let out = run_one(&ctx, arm, permits, store, connections)
                        .map_err(|e| format!("round {round}: {e}"))?;
                    let writes = out["acknowledged_per_s"]
                        .as_f64()
                        .ok_or("a run has no acknowledged_per_s")?;
                    let batch = out["writer"]["mean_batch_events"]
                        .as_f64()
                        .ok_or("a run has no mean batch")?;
                    figures
                        .entry((store.index(), connections, run_index(arm, permits)))
                        .or_default()
                        .push((writes, batch));
                    runs.insert(run_label(arm, permits), out);
                }
                cells.push(json!({ "connections": connections, "runs": runs }));
            }
            store_records.push(json!({ "store": store.name(), "cells": cells }));
        }
        round_records.push(json!({
            "round": round,
            "store_order": stores.iter().map(|store| store.name()).collect::<Vec<_>>(),
            "run_order": order.iter().map(|&(arm, permits)| run_label(arm, permits)).collect::<Vec<_>>(),
            "stores": store_records,
        }));
    }

    Ok(json!({
        "note": "a diagnostic, not part of a default run: loopback figures, the client and the server in one process on one host, CPU not attributed to either side. It tests whether guest scope lookups made under a work permit, or a seeded store, lower acknowledged writes through the sheltered door, in this model only",
        "settings": {
            "door": "sheltered",
            "window": WINDOW,
            "connections": CONNECTIONS,
            "permits_shared_public": PERMITS.iter().map(|&(s, p)| format!("{s}/{p}")).collect::<Vec<_>>(),
            "variants": [variant(0).label(), variant(1).label()],
            "variant_syntax": "workers:blocking:shared/public:nodelay",
            "client_nodelay": true,
            "client_workers": CLIENT_WORKERS,
            "events_per_run": events,
            "seeded_events": seed,
            "rounds": rounds,
            "arms": [Arm::Keeper.name(), Arm::GuestMemory.name(), Arm::GuestSqlite.name()],
            "runs": RUNS.iter().map(|&(arm, permits)| run_label(arm, permits)).collect::<Vec<_>>(),
            "round_order": "odd rounds run the empty store first and even rounds the seeded one; in each store the connection counts run 1, 16, 64, and in each the six runs in their listed order starting at index r mod 6 (indices from 0)",
            "per_run": "a fresh store (empty, or a fresh copy of the seeded template), relay, door, server runtime and guest authority",
            "door_inflight_writes": DOOR_INFLIGHT_WRITES,
            "listener": "127.0.0.1:0 only",
        },
        "server": {
            "runtime": format!("multi-thread, worker_threads {WORKERS}, max_blocking_threads {BLOCKING}, I/O and time drivers, fresh per run"),
            "nodelay": false,
            "relay_clock": "the relay's own (wall) clock; `with_clock` is not called",
            "sheltered_admission": "the socket scenario's bench-only admission that admits every connection; NIP-42 is still required to write",
            "keepers": "the 64 keeper keys only, in every arm; no persona, device or issuer key is a keeper",
        },
        "allowances": allowances(WIDEST),
        "events": {
            "kind": KIND_NOTE,
            "shape": "every event in every arm and in the seeded store: kind 1, exactly one `d` tag naming a room, content of --content-bytes",
            "content_bytes": cfg.content_bytes,
            "connection_lane": "event i of a run belongs to connection i mod connections, in that connection's room `room-<lane>`",
            "keeper_signer": "the keeper key of the connection, which it also authenticates as",
            "guest_signer": "the device key of the connection; the connection authenticates as its persona",
            "created_at": "written events: start - 1000 - events + i; seeded events: that base - seeded - 10 + j; one second apart, so no two share a second within a store",
            "start": start,
            "signatures": "every event is signed and verified by the relay (or, for the seeded store, by `PreparedPut::new`)",
        },
        "grants": {
            "per_connection": "one persona, one device, one room and one scope: room `room-<lane>`, that device, write [1], read [1], expires_at below",
            "expires_at": expires_at,
            "measured_personas": WIDEST,
            "other_personas": OTHER_PERSONAS,
            "rows": grants.len(),
            "issuer": "one bench issuer key, not a keeper",
            "sqlite": {
                "model": "a model, not any application's query or schema",
                "schema": SCHEMA,
                "query": PERSONA_QUERY,
                "device_query": DEVICE_QUERY,
                "query_plan": plan,
                "pool": "read-only connections opened with SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX, checked out per call and returned after; another is opened whenever none is free, so readers never wait on one another; a fresh pool per run over the same file, so each run's first calls open its connections, and that opening is inside the timed call (see `sqlite_connections_opened`)",
                "statement": "`prepare_cached` on each connection",
                "file": "its own small file in a temporary directory on the host's disk, written once per scenario run, so the reads are warm",
            },
            "memory": "a HashMap from persona to its scopes, looked up and cloned, with the same expiry filter",
            "counting": "a wrapper counts and times every `scopes` and `device_scopes` call (the time inside the call only) and notes whether it ran on the writer thread",
        },
        "seeded_template": {
            "events": template.events,
            "authors": SEED_AUTHORS,
            "rooms": "seed-room-<author>",
            "partition": "sheltered",
            "built_with": "`put_prepared_batch` of `PreparedPut::new` puts, outside every timed window",
            "seconds": template.seconds,
            "reoffers": template.reoffers,
            "main_file_bytes": template.bytes,
            "copies": "the template is closed cleanly, its write-ahead log checked empty, and its main file copied into a fresh directory for each seeded run, deleted when the run ends",
        },
        "verification": format!("every run: the writer stored exactly the events sent; the sheltered partition holds exactly seeded + written, counted exactly in created_at windows of at most {COUNT_WINDOW_SECONDS} seconds; the public partition holds none; every written id is present"),
        "expected_calls": expected_calls(heartbeat),
        "rule": rule(),
        "does_not_show": does_not_show(),
        "rounds": round_records,
        "comparisons": comparisons(&figures, rounds),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Config {
        Config {
            content_bytes: 64,
            guest_path: true,
            guest_path_events: 128,
            guest_path_seed_events: 300,
            guest_path_rounds: 2,
            ..Config::default()
        }
    }

    /// Two rounds at tiny sizes: every run of every cell comes back verified,
    /// the guest runs make exactly the calls `expected_calls` gives (no run
    /// lasts a heartbeat), the orders rotate and every comparison is there.
    #[test]
    fn the_guest_path_scenario_runs_at_tiny_sizes_and_counts_every_call() {
        let cfg = tiny();
        let document = run(&cfg).unwrap_or_else(|e| panic!("the guest-path run failed: {e}"));
        let rounds = document["rounds"].as_array().unwrap();
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0]["store_order"], json!(["empty", "seeded"]));
        assert_eq!(rounds[1]["store_order"], json!(["seeded", "empty"]));
        assert_eq!(rounds[0]["run_order"][0], "guest_memory at 2/1");
        assert_eq!(rounds[1]["run_order"][0], "guest_sqlite at 2/1");
        let events = cfg.guest_path_events as u64;
        for round in rounds {
            for store in round["stores"].as_array().unwrap() {
                let seeded = if store["store"] == "seeded" { 300 } else { 0 };
                let cells = store["cells"].as_array().unwrap();
                assert_eq!(cells.len(), 3);
                for cell in cells {
                    let connections = cell["connections"].as_u64().unwrap();
                    let runs = cell["runs"].as_object().unwrap();
                    assert_eq!(runs.len(), 6);
                    for run in runs.values() {
                        assert_eq!(run["verified"], true);
                        assert_eq!(run["events"], events);
                        assert_eq!(run["ok_latency"]["count"], events);
                        assert_eq!(run["writer"]["events"], events);
                        assert_eq!(run["stored_total"], seeded + events);
                        assert_eq!(run["lanes_with_events"], connections);
                        if run["arm"] == "keeper" {
                            assert!(run["authority"].is_null());
                            continue;
                        }
                        let authority = &run["authority"];
                        assert_eq!(authority["scopes"]["calls"], events + 2 * connections);
                        assert_eq!(authority["scopes"]["writer_thread_calls"], 0);
                        assert_eq!(authority["device_scopes"]["calls"], 0);
                        assert_eq!(authority["expected_calls_check"]["heartbeat_calls"], 0);
                        if run["arm"] == "guest_sqlite" {
                            let opened = authority["sqlite_connections_opened"].as_u64().unwrap();
                            assert!(opened >= 1 && opened <= BLOCKING as u64 + WORKERS as u64);
                        } else {
                            assert!(authority["sqlite_connections_opened"].is_null());
                        }
                    }
                }
            }
        }
        let by_store = &document["comparisons"]["by_store"];
        for store in ["empty", "seeded"] {
            for connections in CONNECTIONS {
                let cell = &by_store[store][connections.to_string()];
                assert_eq!(cell["pairs"].as_object().unwrap().len(), 7);
                let signature = &cell["permit_bound_signature"];
                if SIGNATURE_CONNECTIONS.contains(&connections) {
                    for guest in GUEST_ARMS {
                        assert!(signature[guest.name()]["present"].is_boolean());
                        assert!(signature[guest.name()]["conclusion"].is_string());
                    }
                } else {
                    assert!(signature.is_null());
                }
            }
        }
        for connections in CONNECTIONS {
            let cross = &by_store["seeded_vs_empty"][connections.to_string()]["pairs"];
            assert_eq!(cross.as_object().unwrap().len(), 6);
        }
        assert!(document["comparisons"]["rule_note"].is_string());
        assert_eq!(document["grants"]["rows"], WIDEST + OTHER_PERSONAS);
        let plan = document["grants"]["sqlite"]["query_plan"].to_string();
        assert!(plan.contains("grants_by_persona"), "{plan}");
        let text = document.to_string();
        assert!(!text.contains("0.0.0.0"));
    }

    const EIGHT: [f64; 8] = [100.0, 110.0, 120.0, 130.0, 140.0, 150.0, 160.0, 170.0];

    fn shifted(by: f64) -> Vec<f64> {
        EIGHT.iter().map(|y| y + by).collect()
    }

    /// Figures for one store and connection count: each run's writes/s by
    /// round, a mean batch of 4 throughout.
    fn figures_for(store: StoreKind, connections: usize, runs: [Vec<f64>; 6]) -> Figures {
        let mut figures = Figures::new();
        for (index, writes) in runs.into_iter().enumerate() {
            figures.insert(
                (store.index(), connections, index),
                writes.into_iter().map(|w| (w, 4.0)).collect(),
            );
        }
        figures
    }

    fn signature(figures: &Figures, store: &str, connections: usize, guest: Arm) -> Value {
        comparisons(figures, 8)["by_store"][store][connections.to_string()]
            ["permit_bound_signature"][guest.name()]
            .clone()
    }

    #[test]
    fn the_signature_needs_all_three_conditions() {
        // keeper 2/1, memory 2/1, sqlite 2/1, keeper 8/8, memory 8/8, sqlite 8/8.
        let present = figures_for(
            StoreKind::Empty,
            16,
            [
                shifted(0.0),
                shifted(-20.0),
                shifted(-30.0),
                shifted(0.0),
                shifted(-5.0),
                shifted(-30.0),
            ],
        );
        let memory = signature(&present, "empty", 16, Arm::GuestMemory);
        assert_eq!(memory["present"], true);
        assert_eq!(
            memory["conclusion"],
            "permit-bound signature present in this model"
        );
        // The SQLite arm is below keeper but not above itself at 8/8.
        let sqlite = signature(&present, "empty", 16, Arm::GuestSqlite);
        assert_eq!(sqlite["present"], false);
        assert_eq!(sqlite["b_guest_8/8_vs_2/1"], "not separated");
        assert_eq!(
            sqlite["conclusion"],
            "permit-bound signature absent in this model"
        );

        // (c) fails: keeper itself gains from more permits.
        let keeper_gains = figures_for(
            StoreKind::Seeded,
            64,
            [
                shifted(0.0),
                shifted(-20.0),
                shifted(-20.0),
                shifted(10.0),
                shifted(-5.0),
                shifted(-5.0),
            ],
        );
        let memory = signature(&keeper_gains, "seeded", 64, Arm::GuestMemory);
        assert_eq!(memory["a_guest_vs_keeper_at_2/1"], "below");
        assert_eq!(memory["b_guest_8/8_vs_2/1"], "above");
        assert_eq!(memory["c_keeper_8/8_vs_2/1"], "above");
        assert_eq!(memory["present"], false);

        // (a) fails: the guest arm is not below keeper at 2/1.
        let level = figures_for(
            StoreKind::Empty,
            64,
            [
                shifted(0.0),
                shifted(0.0),
                shifted(0.0),
                shifted(0.0),
                shifted(10.0),
                shifted(10.0),
            ],
        );
        let memory = signature(&level, "empty", 64, Arm::GuestMemory);
        assert_eq!(memory["a_guest_vs_keeper_at_2/1"], "not separated");
        assert_eq!(memory["present"], false);
    }

    #[test]
    fn the_signature_is_judged_at_16_and_64_connections_only() {
        let runs = || {
            [
                shifted(0.0),
                shifted(-20.0),
                shifted(-20.0),
                shifted(0.0),
                shifted(-5.0),
                shifted(-5.0),
            ]
        };
        let mut figures = figures_for(StoreKind::Empty, 1, runs());
        figures.extend(figures_for(StoreKind::Empty, 16, runs()));
        let block = comparisons(&figures, 8);
        assert!(block.get("rule_note").is_none());
        let empty = &block["by_store"]["empty"];
        assert!(empty["1"]["permit_bound_signature"].is_null());
        assert_eq!(
            empty["16"]["permit_bound_signature"]["guest_memory"]["present"],
            true
        );
        let pair = &empty["1"]["pairs"]["guest_memory_vs_keeper_at_2/1"];
        assert_eq!(pair["verdict"], "below");
        assert_eq!(pair["below"], 8);
        assert_eq!(
            empty["1"]["pairs"]["keeper_8/8_vs_2/1"]["verdict"],
            "not separated"
        );
    }

    #[test]
    fn seeded_against_empty_pairs_each_run_with_itself() {
        let mut figures = figures_for(StoreKind::Empty, 16, std::array::from_fn(|_| shifted(0.0)));
        figures.extend(figures_for(
            StoreKind::Seeded,
            16,
            std::array::from_fn(|_| shifted(-10.0)),
        ));
        let cross = &comparisons(&figures, 8)["by_store"]["seeded_vs_empty"]["16"]["pairs"];
        let pair = &cross["guest_sqlite_seeded_vs_empty_at_8/8"];
        assert_eq!(pair["verdict"], "below");
        assert_eq!(pair["x"], "guest_sqlite at 8/8, seeded");
        assert_eq!(pair["y"], "guest_sqlite at 8/8, empty");
    }

    fn tally(calls: u64) -> Tally {
        Tally {
            calls,
            ..Tally::default()
        }
    }

    #[test]
    fn the_call_check_allows_only_whole_heartbeats_within_their_bounds() {
        let beat = Duration::from_secs(30);
        let short = Duration::from_secs(10);
        let long = Duration::from_secs(65);
        let none = tally(0);
        // 100 written on 4 connections: 108 without heartbeats.
        assert!(check_calls(&tally(108), &none, 100, 4, 0, short, beat).is_ok());
        let wrong = check_calls(&tally(109), &none, 100, 4, 0, short, beat).unwrap_err();
        assert!(
            wrong.contains("observed 109") && wrong.contains("= 108"),
            "{wrong}"
        );
        // Under one heartbeat, any excess is a mismatch.
        assert!(check_calls(&tally(110), &none, 100, 4, 0, short, beat).is_err());
        // 65 s allows two heartbeats on each of 4 connections: up to 16 more.
        assert!(check_calls(&tally(124), &none, 100, 4, 0, long, beat).is_ok());
        assert!(check_calls(&tally(126), &none, 100, 4, 0, long, beat).is_err());
        assert!(
            check_calls(&tally(123), &none, 100, 4, 0, long, beat).is_err(),
            "odd"
        );
        // The Pings seen are a floor.
        assert!(check_calls(&tally(110), &none, 100, 4, 2, long, beat).is_err());
        assert!(check_calls(&tally(112), &none, 100, 4, 2, long, beat).is_ok());
        // Too few calls, a device call, a writer-thread call or a failure.
        assert!(check_calls(&tally(107), &none, 100, 4, 0, short, beat).is_err());
        assert!(check_calls(&tally(108), &tally(1), 100, 4, 0, short, beat).is_err());
        let on_writer = Tally {
            writer_thread: 1,
            ..tally(108)
        };
        assert!(check_calls(&on_writer, &none, 100, 4, 0, short, beat).is_err());
        let failed = Tally {
            errors: 1,
            ..tally(108)
        };
        assert!(check_calls(&failed, &none, 100, 4, 0, short, beat).is_err());
    }

    #[test]
    fn the_sqlite_lookup_reads_through_its_index_and_filters_on_expiry() {
        let keys = KeySet::new(7).unwrap();
        let grants = keys.grants(5000);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(GRANTS_FILE);
        let plan = write_grants(&path, &grants).unwrap();
        assert!(
            plan.iter().any(|step| step.contains("grants_by_persona")),
            "{plan:?}"
        );
        let sqlite = SqliteGrants::new(&path);
        let memory = MemoryGrants::new(&grants);
        let persona = keys.personas[3].public_key();
        let from_sqlite = sqlite.by_persona(&persona, 4000).unwrap();
        assert_eq!(from_sqlite, memory.by_persona(&persona, 4000).unwrap());
        assert_eq!(from_sqlite.len(), 1);
        assert_eq!(from_sqlite[0].room, "room-3");
        assert_eq!(from_sqlite[0].device, keys.devices[3].public_key());
        assert_eq!(from_sqlite[0].write, [KIND_NOTE].into());
        // Expired at 5000, and nobody's grant for a key that holds none.
        assert!(sqlite.by_persona(&persona, 5000).unwrap().is_empty());
        assert!(memory.by_persona(&persona, 5000).unwrap().is_empty());
        let stranger = keys.keepers[0].public_key();
        assert!(sqlite.by_persona(&stranger, 4000).unwrap().is_empty());
        let device = keys.other_devices[9].public_key();
        assert_eq!(
            sqlite.by_device(&device, 4000).unwrap()[0].room,
            "other-room-9"
        );
        // One caller at a time reuses one connection.
        assert_eq!(sqlite.opened.load(Ordering::Relaxed), 1);
        // A counted wrapper counts both kinds of call.
        let (authority, counters) = Counted::new(memory);
        authority.scopes(&persona, 4000).unwrap();
        authority.scopes(&persona, 4000).unwrap();
        authority.device_scopes(&device, 4000).unwrap();
        assert_eq!(counters.scopes.tally().calls, 2);
        assert_eq!(counters.device_scopes.tally().calls, 1);
        assert_eq!(counters.scopes.tally().writer_thread, 0);
    }

    #[test]
    fn verification_counts_the_store_exactly_through_small_windows() {
        let cfg = Config {
            content_bytes: 32,
            ..Config::default()
        };
        let keys = KeySet::new(3).unwrap();
        let base = wall_seconds() - 10_000;
        let seeded = seed_notes(&cfg, &keys.seed_authors, 20, base).unwrap();
        let written = seed_notes(&cfg, &keys.keepers, 7, base + 30).unwrap();
        let (_dir, store) = fresh_store(&cfg, 64).unwrap();
        put_all(&store, &seeded, wall_seconds()).unwrap();
        put_all(&store, &written, wall_seconds()).unwrap();
        let ids: Vec<EventId> = written.iter().map(|event| event.id).collect();
        let span = (base, base + 36);
        let now = wall_seconds();
        assert_eq!(verify_run(&store, 20, &ids, 7, span, 3, now), Ok(27));
        assert_eq!(verify_run(&store, 20, &ids, 7, span, 1, now), Ok(27));
        // A window narrower than the span still counts what lies outside it.
        assert_eq!(
            verify_run(&store, 20, &ids, 7, (base + 10, base + 12), 2, now),
            Ok(27)
        );
        assert!(verify_run(&store, 19, &ids, 7, span, 3, now).is_err());
        assert!(verify_run(&store, 20, &ids, 6, span, 3, now).is_err());
        // Any 27 stored events pass when the split between seeded and written
        // matches; an id the store does not hold fails.
        assert!(verify_run(&store, 26, &[seeded[0].id], 1, span, 3, now).is_ok());
        let unknown = EventId::from_byte_array([0; 32]);
        assert!(verify_run(&store, 26, &[unknown], 1, span, 3, now).is_err());
    }

    #[test]
    fn the_orders_rotate_and_alternate() {
        assert_eq!(run_order(6), RUNS.to_vec());
        assert_eq!(run_order(1)[0], (Arm::GuestMemory, 0));
        assert_eq!(run_order(3)[0], (Arm::Keeper, 1));
        assert_eq!(store_order(1), [StoreKind::Empty, StoreKind::Seeded]);
        assert_eq!(store_order(8), [StoreKind::Seeded, StoreKind::Empty]);
    }

    #[test]
    fn the_key_families_are_disjoint_and_no_guest_is_a_keeper() {
        let keys = KeySet::new(1).unwrap();
        let keepers = Keepers::new(keys.keepers.iter().map(Keys::public_key));
        use wok_store::relay::KeeperAccess;
        for key in keys.personas.iter().chain(&keys.devices) {
            assert!(!keepers.owns(&key.public_key()));
        }
        assert!(keepers.owns(&keys.keepers[63].public_key()));
    }
}
