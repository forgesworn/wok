//! `wokd`: a members-only Nostr relay built on Wok.
//!
//! One server is one group. The operator lists the group's public keys; each
//! connection must authenticate (NIP-42) as one of them before it may read,
//! write, count or reconcile anything, and every member reads everything the
//! group has stored. There is no open mode. Only the sheltered door is
//! served, and the listener binds to loopback unless the operator says
//! otherwise.
//!
//! Membership is read from the configuration at start, and again whenever
//! [`serve`] is handed a reloaded configuration (the binary reloads on
//! SIGHUP). A removed key loses its open subscriptions and its connection;
//! every other setting takes a restart. Several groups means one instance
//! each.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::http::{Extensions, StatusCode};
use axum::serve::ListenerExt as _;
use nostr::event::EventId;
use nostr::key::PublicKey;
use nostr::nips::nip19::FromBech32;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc, watch};
use url::Url;
use wok_store::relay::{EventRelay, KeeperAccess};
use wok_store::{SqliteEventStore, StoreOptions, Visibility};
use wok_ws::{Admission, Admitted, Door, PATH, Timings};

/// Where the relay listens unless the configuration says otherwise.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7447";

/// Sockets one connecting address may hold at once, unless the
/// configuration says otherwise. Nothing identifies a client before it
/// authenticates, so without a cap a stranger could hold every connection
/// slot until the AUTH deadline. Behind a proxy every client shares the
/// proxy's address and the cap means little.
pub const SOCKETS_PER_ADDRESS: usize = 8;

/// How long a connection may stay unauthenticated, unless the configuration
/// says otherwise. A stock client answers the challenge at once; the grace
/// is for a remote signer that asks its owner first.
pub const AUTH_DEADLINE_SECS: u64 = 15;

/// Whether the relay serves a NIP-11 relay information document, unless the
/// configuration says otherwise. The document is static and the same for
/// everyone: the NIPs it supports, its limits, and that every read and write
/// needs NIP-42. It names no member, operator or address. Anyone who can
/// reach the relay can already open a socket and be sent the AUTH challenge,
/// which says as much; the document lets a client know before it connects.
pub const RELAY_INFORMATION: bool = true;

/// The runtime's worker threads, unless the configuration says otherwise.
/// tokio's own default is one per core, and every worker keeps buffers and
/// allocator state of its own. Store work runs on the blocking pool and the
/// store's own threads, not on the workers, and a door holds at most 32
/// connections, so a group's relay needs few. Only the `wokd` binary applies
/// it, when it builds its runtime; [`run`] and [`serve`] use whatever
/// runtime calls them.
pub const WORKERS: usize = 2;

/// The writer connection's page cache, in KiB: a quarter of
/// [`StoreOptions::server`]'s. The relay's other store settings are the
/// server profile's.
const WRITER_CACHE_KIB: u32 = 256;

/// How often expired events are swept (NIP-40).
const EXPIRY_INTERVAL: Duration = Duration::from_secs(60);

/// How long a shutdown waits for every socket to finish closing.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How often the count of AUTH events that named another relay URL is read.
const MISMATCH_POLL: Duration = Duration::from_secs(1);

/// The least time between two warnings about AUTH events that named another
/// relay URL. The first is logged at once.
const MISMATCH_LOG_EVERY: Duration = Duration::from_secs(60);

/// When to warn that AUTH events named another relay URL than `url`: at the
/// first, so an operator watching the log sees it while the client fails,
/// then at most once every [`MISMATCH_LOG_EVERY`] with what came since.
#[derive(Debug, Default)]
struct MismatchLog {
    reported: u64,
    last: Option<std::time::Instant>,
}

impl MismatchLog {
    /// Given the relay's count so far, the attempts to warn about now, if any.
    fn due(&mut self, count: u64, now: std::time::Instant) -> Option<u64> {
        if count <= self.reported {
            return None;
        }
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < MISMATCH_LOG_EVERY)
        {
            return None;
        }
        let attempts = count - self.reported;
        self.reported = count;
        self.last = Some(now);
        Some(attempts)
    }
}

/// The group: the keys that may authenticate. Asked on every operation, and
/// replaced whole on a reload ([`Members::replace`]).
pub struct Members {
    keys: RwLock<HashSet<PublicKey>>,
    /// Moved after every change. The engine trusts a verdict it has checked
    /// until this moves, so it must move after the swap, never before, and
    /// live as long as the set does.
    changes: watch::Sender<u64>,
}

/// What [`Members::replace`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberChange {
    /// Keys in the new set that were not in the old one.
    pub added: usize,
    /// Keys in the old set that are not in the new one.
    pub removed: usize,
    /// Keys in the set now.
    pub members: usize,
}

impl MemberChange {
    /// Whether the set is the same as before.
    pub fn unchanged(&self) -> bool {
        self.added == 0 && self.removed == 0
    }
}

impl Members {
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            keys: RwLock::new(keys.into_iter().collect()),
            changes: watch::channel(0).0,
        }
    }

    /// Make `keys` the group. Any change is announced to open connections:
    /// a removed key's subscriptions are closed with `CLOSED` and then its
    /// connection, and nothing more is read or stored for it. Events it
    /// stored or was sent stay where they are. An added key can
    /// authenticate from then on, on any socket that has not yet
    /// authenticated. The same set again announces nothing.
    pub fn replace(&self, keys: impl IntoIterator<Item = PublicKey>) -> MemberChange {
        let next: HashSet<PublicKey> = keys.into_iter().collect();
        let change = {
            let mut current = self.keys.write().expect("members");
            let change = MemberChange {
                added: next.difference(&current).count(),
                removed: current.difference(&next).count(),
                members: next.len(),
            };
            if !change.unchanged() {
                *current = next;
            }
            change
        };
        if !change.unchanged() {
            self.changes.send_modify(|generation| *generation += 1);
        }
        change
    }
}

impl KeeperAccess for Members {
    fn owns(&self, key: &PublicKey) -> bool {
        self.keys.read().expect("members").contains(key)
    }

    fn subscribe(&self) -> Option<watch::Receiver<u64>> {
        Some(self.changes.subscribe())
    }
}

/// Admits a connection by its connecting address, at most `limit` at once
/// for each. A loopback peer is not capped here (the door's own connection
/// budget still holds): with the default loopback bind, every local client
/// and everything behind a local proxy shares one address. That leaves a
/// local proxy's clients uncapped by address, so the AUTH deadline is what
/// stops a stranger holding a slot for long. A request with no connecting
/// address is refused.
pub struct PerAddress {
    limit: usize,
    slots: Mutex<HashMap<IpAddr, Arc<Semaphore>>>,
    /// One clone in every admission, so the count shows open connections.
    live: Arc<()>,
}

impl PerAddress {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            slots: Mutex::new(HashMap::new()),
            live: Arc::new(()),
        }
    }

    /// Connections admitted and not yet ended.
    pub fn open_connections(&self) -> usize {
        Arc::strong_count(&self.live) - 1
    }
}

impl Admission for PerAddress {
    fn admit(&self, extensions: &Extensions) -> Result<Admitted, StatusCode> {
        let Some(ConnectInfo(address)) = extensions.get::<ConnectInfo<SocketAddr>>() else {
            return Err(StatusCode::FORBIDDEN);
        };
        if address.ip().is_loopback() {
            return Ok(Admitted::holding(Arc::clone(&self.live)));
        }
        let slot = {
            let mut slots = self.slots.lock().expect("address slots");
            // Forget addresses with nothing open, so the map holds only the
            // addresses connected now.
            let limit = self.limit;
            slots.retain(|_, slot| slot.available_permits() < limit);
            Arc::clone(
                slots
                    .entry(address.ip())
                    .or_insert_with(|| Arc::new(Semaphore::new(limit))),
            )
        };
        let live = Arc::clone(&self.live);
        slot.try_acquire_owned()
            .map(|permit| Admitted::holding((permit, live)))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// The configuration file, as written. Every field is checked in
/// [`Config::from_toml`]; nothing here is trusted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    listen: Option<String>,
    url: String,
    data_dir: PathBuf,
    max_store_bytes: u64,
    min_free_bytes: u64,
    members: Vec<String>,
    sockets_per_address: Option<usize>,
    auth_deadline_secs: Option<u64>,
    relay_information: Option<bool>,
    workers: Option<usize>,
}

/// A checked configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where to listen.
    pub listen: SocketAddr,
    /// The address clients connect to, which their NIP-42 AUTH must name.
    pub url: Url,
    /// Where the event store lives.
    pub data_dir: PathBuf,
    /// The store's size limit, in bytes.
    pub max_store_bytes: u64,
    /// Free disk space the store leaves, in bytes.
    pub min_free_bytes: u64,
    /// The group's public keys.
    pub members: Vec<PublicKey>,
    /// See [`SOCKETS_PER_ADDRESS`].
    pub sockets_per_address: usize,
    /// See [`AUTH_DEADLINE_SECS`].
    pub auth_deadline: Duration,
    /// See [`RELAY_INFORMATION`].
    pub relay_information: bool,
    /// See [`WORKERS`].
    pub workers: usize,
}

/// Why a configuration was refused. No message repeats a value from the
/// file: a member entry may be a secret key pasted by mistake.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("the configuration could not be read at line {line}: {reason}")]
    Parse { line: usize, reason: String },
    #[error("members: none listed; a members-only relay needs at least one")]
    NoMembers,
    #[error(
        "members[{0}] looks like a secret key (nsec); list public keys (npub) only, \
         and treat that secret key as exposed"
    )]
    SecretKey(usize),
    #[error("members[{0}] is not an npub public key")]
    NotNpub(usize),
    #[error("url must be a ws:// or wss:// URL ending in {PATH}: the address clients connect to")]
    Url,
    #[error("listen must be an IP address and port, such as {DEFAULT_LISTEN}")]
    Listen,
    #[error("sockets_per_address must be at least 1")]
    SocketsPerAddress,
    #[error("max_store_bytes must be more than 0")]
    MaxStoreBytes,
    #[error("auth_deadline_secs must be from 1 to 300")]
    AuthDeadline,
    #[error("workers must be at least 1")]
    Workers,
}

impl Config {
    /// Parse and check a configuration file's text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|error| {
            let line = error
                .span()
                .map(|span| text[..span.start.min(text.len())].lines().count().max(1))
                .unwrap_or(1);
            // Field names only: a message about a value could repeat it.
            let message = error.message();
            let reason = if message.starts_with("unknown field")
                || message.starts_with("missing field")
                || message.starts_with("duplicate key")
            {
                message
                    .split(", expected")
                    .next()
                    .unwrap_or(message)
                    .to_owned()
            } else {
                "not valid TOML, or a value of the wrong type".to_owned()
            };
            ConfigError::Parse { line, reason }
        })?;
        let listen = file
            .listen
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN)
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Listen)?;
        let url = Url::parse(&file.url).map_err(|_| ConfigError::Url)?;
        if !matches!(url.scheme(), "ws" | "wss")
            || url.host_str().is_none()
            || url.path() != PATH
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigError::Url);
        }
        if file.members.is_empty() {
            return Err(ConfigError::NoMembers);
        }
        let members = file
            .members
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let entry = entry.trim();
                if entry.starts_with("nsec1") {
                    return Err(ConfigError::SecretKey(index));
                }
                if !entry.starts_with("npub1") {
                    return Err(ConfigError::NotNpub(index));
                }
                PublicKey::from_bech32(entry).map_err(|_| ConfigError::NotNpub(index))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sockets_per_address = file.sockets_per_address.unwrap_or(SOCKETS_PER_ADDRESS);
        if sockets_per_address == 0 {
            return Err(ConfigError::SocketsPerAddress);
        }
        if file.max_store_bytes == 0 {
            return Err(ConfigError::MaxStoreBytes);
        }
        let auth_deadline_secs = file.auth_deadline_secs.unwrap_or(AUTH_DEADLINE_SECS);
        if !(1..=300).contains(&auth_deadline_secs) {
            return Err(ConfigError::AuthDeadline);
        }
        let workers = file.workers.unwrap_or(WORKERS);
        if workers == 0 {
            return Err(ConfigError::Workers);
        }
        Ok(Self {
            listen,
            url,
            data_dir: file.data_dir,
            max_store_bytes: file.max_store_bytes,
            min_free_bytes: file.min_free_bytes,
            members,
            sockets_per_address,
            auth_deadline: Duration::from_secs(auth_deadline_secs),
            relay_information: file.relay_information.unwrap_or(RELAY_INFORMATION),
            workers,
        })
    }
}

/// Why the relay stopped other than by being asked to.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("could not listen on {0}: {1}")]
    Listen(SocketAddr, std::io::Error),
    #[error("could not create the data directory: {0}")]
    DataDir(std::io::Error),
    #[error("another wokd, or a removal, is using this data directory")]
    Locked,
    #[error("could not lock the data directory: {0}")]
    Lock(std::io::Error),
    #[error("could not open the event store: {0}")]
    Store(String),
    #[error("the server stopped: {0}")]
    Serve(std::io::Error),
}

/// What a reload did: the membership change, and the settings that differ
/// from the ones the relay started with, which only a restart applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloaded {
    pub members: MemberChange,
    pub restart_only: Vec<&'static str>,
}

/// Apply `next`'s members, and name the settings in `next` that differ from
/// `running` (the configuration the relay started with, so a setting still
/// waiting for a restart is named on every reload).
pub fn reload(running: &Config, members: &Members, next: Config) -> Reloaded {
    let mut restart_only = Vec::new();
    let mut differs = |field, changed: bool| {
        if changed {
            restart_only.push(field);
        }
    };
    differs("listen", running.listen != next.listen);
    differs("url", running.url != next.url);
    differs("data_dir", running.data_dir != next.data_dir);
    differs(
        "max_store_bytes",
        running.max_store_bytes != next.max_store_bytes,
    );
    differs(
        "min_free_bytes",
        running.min_free_bytes != next.min_free_bytes,
    );
    differs(
        "sockets_per_address",
        running.sockets_per_address != next.sockets_per_address,
    );
    differs(
        "auth_deadline_secs",
        running.auth_deadline != next.auth_deadline,
    );
    differs(
        "relay_information",
        running.relay_information != next.relay_information,
    );
    differs("workers", running.workers != next.workers);
    Reloaded {
        members: members.replace(next.members),
        restart_only,
    }
}

/// Bind `config.listen` and serve until `shutdown` completes, taking each
/// configuration `reloads` delivers as a reload ([`reload`]).
pub async fn run(
    config: Config,
    reloads: mpsc::Receiver<Config>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), RunError> {
    let listen = config.listen;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| RunError::Listen(listen, error))?;
    if !listen.ip().is_loopback() {
        tracing::warn!(
            %listen,
            "listening beyond loopback: anyone who can reach this address can connect, \
             though only members can authenticate"
        );
    }
    serve(config, listener, reloads, shutdown).await
}

/// Serve on `listener` until `shutdown` completes: open the store, sweep
/// expired events every minute, apply each configuration `reloads` delivers
/// ([`reload`]; a closed channel means no more reloads), and on shutdown
/// close every socket and let the server drain.
pub async fn serve(
    config: Config,
    listener: TcpListener,
    mut reloads: mpsc::Receiver<Config>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), RunError> {
    private_dir(&config.data_dir).map_err(RunError::DataDir)?;
    // Held until this returns: a removal takes the same lock, so it never
    // edits the store under a running relay.
    let _held = lock_data_dir(&config.data_dir).map_err(|error| match error {
        LockError::Held => RunError::Locked,
        LockError::Io(error) => RunError::Lock(error),
    })?;
    let path = config.data_dir.join("events.sqlite");
    let (max_bytes, min_free_bytes) = (config.max_store_bytes, config.min_free_bytes);
    let store = tokio::task::spawn_blocking(move || {
        SqliteEventStore::open_with_options(
            &path,
            max_bytes,
            min_free_bytes,
            StoreOptions {
                writer_cache_kib: WRITER_CACHE_KIB,
                ..StoreOptions::server()
            },
        )
    })
    .await
    .map_err(|error| RunError::Store(error.to_string()))?
    .map_err(|error| RunError::Store(error.to_string()))?;
    let members = Arc::new(Members::new(config.members.iter().copied()));
    let running = config.clone();
    // A non-member's refused AUTH is final, and so is one that names another
    // relay URL than `url`: a stock client would otherwise be sent a fresh
    // challenge and sign it, over and over.
    let relay = Arc::new(
        EventRelay::new(
            Arc::new(store),
            Arc::clone(&members) as Arc<dyn KeeperAccess>,
        )
        .with_final_access_refusal()
        .with_final_url_refusal(),
    );
    let defaults = Timings::default();
    let door = Door::with_timings(
        Arc::clone(&relay),
        Timings::new(
            config.auth_deadline,
            defaults.heartbeat(),
            defaults.idle_deadline(),
        ),
    );
    let admission = Arc::new(PerAddress::new(config.sockets_per_address));
    let admitting = Arc::clone(&admission) as Arc<dyn Admission>;
    let app = if config.relay_information {
        door.sheltered_router_with_information(config.url, admitting)
    } else {
        door.sheltered_router(config.url, admitting)
    };
    let sweeper = door.clone();
    let expiry = tokio::spawn(async move {
        let mut tick = tokio::time::interval(EXPIRY_INTERVAL);
        loop {
            tick.tick().await;
            sweeper.expire().await;
        }
    });
    let reloader = tokio::spawn(async move {
        while let Some(next) = reloads.recv().await {
            // Counts and field names only: never a key.
            let done = reload(&running, &members, next);
            if done.members.unchanged() {
                tracing::info!(
                    members = done.members.members,
                    "configuration reloaded; membership unchanged"
                );
            } else {
                tracing::info!(
                    members = done.members.members,
                    added = done.members.added,
                    removed = done.members.removed,
                    "configuration reloaded; membership changed"
                );
            }
            for field in done.restart_only {
                tracing::warn!(field, "changed, but only a restart applies it");
            }
        }
    });
    // A client that names another URL in its AUTH is refused like any bad
    // AUTH, and the reply does not say why. Say it here, in counts only:
    // nothing a client sent reaches the log.
    let mismatches = tokio::spawn(async move {
        let mut log = MismatchLog::default();
        let mut tick = tokio::time::interval(MISMATCH_POLL);
        loop {
            tick.tick().await;
            if let Some(attempts) =
                log.due(relay.auth_relay_mismatches(), std::time::Instant::now())
            {
                tracing::warn!(
                    attempts,
                    "AUTH named a relay URL other than `url`; if these are your members' \
                     clients, `url` must be the address they connect to"
                );
            }
        }
    });
    tracing::info!(members = config.members.len(), "wokd serving its members");
    let stopping = door.clone();
    // A reply is one small frame; do not let Nagle hold it back.
    let listener = listener.tap_io(|stream| {
        let _ = stream.set_nodelay(true);
    });
    let served = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        stopping.shutdown();
    })
    .await;
    // An upgraded socket outlives the HTTP connection the server waited
    // for: give each one the time to answer what it has read and send its
    // close frame before the runtime that drives it goes.
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    while admission.open_connections() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let left = admission.open_connections();
    if left > 0 {
        tracing::warn!(left, "sockets still open at the end of the shutdown grace");
    }
    expiry.abort();
    reloader.abort();
    mismatches.abort();
    tracing::info!("wokd stopped");
    served.map_err(RunError::Serve)
}

/// What an operator removes ([`remove`]).
#[derive(Debug, Clone)]
pub enum Target {
    /// These events, whoever signed them.
    Ids(Vec<EventId>),
    /// Every event this key signed.
    Author(PublicKey),
}

/// What a removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    /// The events removed, each barred from being stored again.
    pub removed: Vec<EventId>,
    /// Ids asked for that were not stored. Nothing is barred for them: the
    /// bar is kept by author, which only a stored event gives.
    pub not_found: Vec<EventId>,
    /// Whether the removed bytes are gone from the write-ahead log as well
    /// as the database file.
    pub erased: bool,
}

/// Why a removal did not run.
#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    #[error("wokd is running on this data directory: stop it first, then remove")]
    Running,
    #[error("no event store in the data directory")]
    NoStore,
    #[error("could not lock the data directory: {0}")]
    Lock(std::io::Error),
    #[error("the event store: {0}")]
    Store(String),
}

/// An operator's removal, with the relay stopped: take `target` out of the
/// group's store and bar each removed event from being stored again.
/// Refused while a relay holds the data directory. It clears this store
/// only: backups, a proxy's logs and members' own clients keep their copies.
/// The bar is per event, so a re-signed copy is a new event; removing the
/// member who stores it is the remedy for that.
pub fn remove(config: &Config, target: &Target) -> Result<Removed, RemoveError> {
    let path = config.data_dir.join("events.sqlite");
    if !path.exists() {
        return Err(RemoveError::NoStore);
    }
    let _held = lock_data_dir(&config.data_dir).map_err(|error| match error {
        LockError::Held => RemoveError::Running,
        LockError::Io(error) => RemoveError::Lock(error),
    })?;
    // No free-space floor: a removal frees space, and an operator may need
    // it most when the disk is full.
    let store = SqliteEventStore::open_with_options(
        &path,
        config.max_store_bytes,
        0,
        StoreOptions::offline(),
    )
    .map_err(|error| RemoveError::Store(error.to_string()))?;
    let removal = match target {
        Target::Ids(ids) => store.remove(Visibility::Sheltered, ids),
        Target::Author(author) => store.remove_author(Visibility::Sheltered, author),
    }
    .map_err(|error| RemoveError::Store(error.to_string()))?;
    let not_found = match target {
        Target::Ids(ids) => {
            let mut missing: Vec<EventId> = ids
                .iter()
                .filter(|id| !removal.removed.contains(id))
                .copied()
                .collect();
            missing.dedup();
            missing
        }
        Target::Author(_) => Vec::new(),
    };
    Ok(Removed {
        removed: removal.removed,
        not_found,
        erased: removal.erased,
    })
}

enum LockError {
    Held,
    Io(std::io::Error),
}

/// Take the data directory's lock file, held until the file is dropped.
fn lock_data_dir(dir: &std::path::Path) -> Result<std::fs::File, LockError> {
    use fs2::FileExt as _;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(dir.join("wokd.lock")).map_err(LockError::Io)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        // The raw OS code, not the kind: on Windows a held lock's kind is a
        // catch-all that other I/O errors share.
        Err(error)
            if error.raw_os_error().is_some()
                && error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
        {
            Err(LockError::Held)
        }
        Err(error) => Err(LockError::Io(error)),
    }
}

/// Create `path` readable by its owner only, if it does not exist; warn if
/// an existing one is open to others.
fn private_dir(path: &std::path::Path) -> std::io::Result<()> {
    if !path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            return std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path);
        }
        #[cfg(not(unix))]
        return std::fs::create_dir_all(path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            tracing::warn!("the data directory is open to other local users; consider chmod 700");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::key::Keys;
    use nostr::nips::nip19::ToBech32;

    fn npub(keys: &Keys) -> String {
        keys.public_key().to_bech32().unwrap()
    }

    fn file(members: &str, extra: &str) -> String {
        format!(
            "url = \"ws://relay.example:7447/events\"\ndata_dir = \"/tmp/wokd\"\n\
             max_store_bytes = 1000000\nmin_free_bytes = 0\nmembers = [{members}]\n{extra}"
        )
    }

    #[test]
    fn the_defaults_are_loopback_and_eight_sockets_an_address() {
        let alice = Keys::generate();
        let config = Config::from_toml(&file(&format!("\"{}\"", npub(&alice)), "")).unwrap();
        assert_eq!(config.listen, DEFAULT_LISTEN.parse().unwrap());
        assert!(config.listen.ip().is_loopback());
        assert_eq!(config.sockets_per_address, SOCKETS_PER_ADDRESS);
        assert_eq!(
            config.auth_deadline,
            Duration::from_secs(AUTH_DEADLINE_SECS)
        );
        assert_eq!(config.members, vec![alice.public_key()]);
        assert_eq!(config.relay_information, RELAY_INFORMATION);
        assert_eq!(config.workers, WORKERS);
    }

    #[test]
    fn the_worker_count_is_at_least_one() {
        let alice = Keys::generate();
        let members = format!("\"{}\"", npub(&alice));
        let config = Config::from_toml(&file(&members, "workers = 4")).unwrap();
        assert_eq!(config.workers, 4);
        assert_eq!(
            Config::from_toml(&file(&members, "workers = 0")).unwrap_err(),
            ConfigError::Workers
        );
        assert!(matches!(
            Config::from_toml(&file(&members, "workers = -1")).unwrap_err(),
            ConfigError::Parse { .. }
        ));
    }

    #[test]
    fn the_relay_information_document_can_be_turned_off() {
        let alice = Keys::generate();
        let members = format!("\"{}\"", npub(&alice));
        for (line, expected) in [
            ("relay_information = false", false),
            ("relay_information = true", true),
        ] {
            let config = Config::from_toml(&file(&members, line)).unwrap();
            assert_eq!(config.relay_information, expected, "{line}");
        }
        let error =
            Config::from_toml(&file(&members, "relay_information = \"nsec1x\"")).unwrap_err();
        assert!(matches!(error, ConfigError::Parse { .. }), "{error}");
        assert!(!error.to_string().contains("nsec1x"), "{error}");
    }

    #[test]
    fn a_secret_key_is_refused_and_never_repeated() {
        let alice = Keys::generate();
        let secret = alice.secret_key().to_bech32().unwrap();
        let error = Config::from_toml(&file(&format!("\"{}\", \"{secret}\"", npub(&alice)), ""))
            .unwrap_err();
        assert_eq!(error, ConfigError::SecretKey(1));
        assert!(!error.to_string().contains(&secret));
    }

    #[test]
    fn only_npub_keys_are_members() {
        let alice = Keys::generate();
        let hex = alice.public_key().to_hex();
        assert_eq!(
            Config::from_toml(&file(&format!("\"{hex}\""), "")).unwrap_err(),
            ConfigError::NotNpub(0)
        );
        assert_eq!(
            Config::from_toml(&file("\"npub1notakey\"", "")).unwrap_err(),
            ConfigError::NotNpub(0)
        );
        assert_eq!(
            Config::from_toml(&file("", "")).unwrap_err(),
            ConfigError::NoMembers
        );
    }

    #[test]
    fn unknown_and_missing_fields_are_refused_by_name_only() {
        let alice = Keys::generate();
        let members = format!("\"{}\"", npub(&alice));
        let error = Config::from_toml(&file(&members, "open = true")).unwrap_err();
        assert!(
            matches!(&error, ConfigError::Parse { reason, .. } if reason.contains("unknown field `open`")),
            "{error}"
        );
        let missing = file(&members, "").replace("max_store_bytes = 1000000\n", "");
        let error = Config::from_toml(&missing).unwrap_err();
        assert!(
            matches!(&error, ConfigError::Parse { reason, .. } if reason.contains("max_store_bytes")),
            "{error}"
        );
        let wrong = file(&members, "").replace("min_free_bytes = 0", "min_free_bytes = \"nsec1x\"");
        let error = Config::from_toml(&wrong).unwrap_err();
        assert!(!error.to_string().contains("nsec1x"), "{error}");
    }

    #[test]
    fn the_url_must_be_a_websocket_url_for_the_door() {
        let alice = Keys::generate();
        let members = format!("\"{}\"", npub(&alice));
        for url in [
            "http://relay.example/events",
            "ws://relay.example/",
            "ws://relay.example/events?x=1",
            "not a url",
        ] {
            let text = file(&members, "").replace("ws://relay.example:7447/events", url);
            assert_eq!(
                Config::from_toml(&text).unwrap_err(),
                ConfigError::Url,
                "{url}"
            );
        }
        let text = file(&members, "").replace(
            "ws://relay.example:7447/events",
            "wss://relay.example/events",
        );
        assert!(Config::from_toml(&text).is_ok());
    }

    fn from(address: &str) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(ConnectInfo(address.parse::<SocketAddr>().unwrap()));
        extensions
    }

    #[test]
    fn a_remote_address_is_capped_and_loopback_is_not() {
        let admission = PerAddress::new(2);
        let first = admission.admit(&from("203.0.113.5:1000")).unwrap();
        let _second = admission.admit(&from("203.0.113.5:1001")).unwrap();
        assert_eq!(
            admission.admit(&from("203.0.113.5:1002")).err(),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        // Another address has its own allowance.
        assert!(admission.admit(&from("203.0.113.6:1000")).is_ok());
        drop(first);
        assert!(admission.admit(&from("203.0.113.5:1003")).is_ok());
        let local: Vec<_> = (0..10)
            .map(|port| admission.admit(&from(&format!("127.0.0.1:{}", 2000 + port))))
            .collect();
        assert!(local.iter().all(Result::is_ok));
    }

    #[test]
    fn a_replaced_set_is_announced_after_the_swap_and_the_same_set_is_not() {
        let (alice, bob, carol) = (Keys::generate(), Keys::generate(), Keys::generate());
        let members = Members::new([alice.public_key(), bob.public_key()]);
        let mut changes = members.subscribe().expect("wokd's members signal changes");
        assert!(members.owns(&alice.public_key()));

        // One key for another: the count stays, the set does not.
        let change = members.replace([alice.public_key(), carol.public_key()]);
        assert_eq!(
            change,
            MemberChange {
                added: 1,
                removed: 1,
                members: 2
            }
        );
        assert!(changes.has_changed().unwrap(), "a swap is announced");
        changes.mark_unchanged();
        assert!(!members.owns(&bob.public_key()));
        assert!(members.owns(&carol.public_key()));

        let same = members.replace([carol.public_key(), alice.public_key()]);
        assert!(same.unchanged(), "{same:?}");
        assert!(!changes.has_changed().unwrap(), "the same set is not");

        let removed = members.replace([carol.public_key()]);
        assert_eq!((removed.added, removed.removed), (0, 1));
        assert!(changes.has_changed().unwrap());
        assert!(!members.owns(&alice.public_key()));
    }

    #[test]
    fn a_reload_names_every_setting_only_a_restart_applies() {
        let (alice, bob) = (Keys::generate(), Keys::generate());
        let running = Config::from_toml(&file(&format!("\"{}\"", npub(&alice)), "")).unwrap();
        let members = Members::new(running.members.iter().copied());

        let next = Config::from_toml(&file(&format!("\"{}\"", npub(&bob)), "")).unwrap();
        let done = reload(&running, &members, next);
        assert!(done.restart_only.is_empty(), "{done:?}");
        assert_eq!((done.members.added, done.members.removed), (1, 1));
        assert!(members.owns(&bob.public_key()));

        let changed = file(
            &format!("\"{}\"", npub(&bob)),
            "listen = \"127.0.0.1:7448\"\nsockets_per_address = 2\nauth_deadline_secs = 30\n\
             relay_information = false\nworkers = 3",
        )
        .replace(
            "ws://relay.example:7447/events",
            "wss://relay.example/events",
        )
        .replace("/tmp/wokd", "/tmp/elsewhere")
        .replace("max_store_bytes = 1000000", "max_store_bytes = 2000000")
        .replace("min_free_bytes = 0", "min_free_bytes = 1");
        let done = reload(&running, &members, Config::from_toml(&changed).unwrap());
        assert_eq!(
            done.restart_only,
            vec![
                "listen",
                "url",
                "data_dir",
                "max_store_bytes",
                "min_free_bytes",
                "sockets_per_address",
                "auth_deadline_secs",
                "relay_information",
                "workers",
            ]
        );
        assert!(done.members.unchanged());
    }

    #[test]
    fn a_url_mismatch_is_reported_at_once_then_at_most_once_a_minute() {
        let start = std::time::Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut log = MismatchLog::default();
        assert_eq!(log.due(0, at(0)), None, "nothing yet");
        assert_eq!(log.due(1, at(1)), Some(1), "the first at once");
        assert_eq!(log.due(5, at(2)), None, "more within the minute wait");
        assert_eq!(log.due(9, at(60)), None);
        assert_eq!(log.due(9, at(61)), Some(8), "then together");
        assert_eq!(log.due(9, at(200)), None, "nothing new, nothing said");
        assert_eq!(
            log.due(10, at(201)),
            Some(1),
            "a new one after a quiet spell"
        );
    }

    #[test]
    fn a_request_with_no_connecting_address_is_refused() {
        let admission = PerAddress::new(2);
        assert_eq!(
            admission.admit(&Extensions::new()).err(),
            Some(StatusCode::FORBIDDEN)
        );
    }
}
