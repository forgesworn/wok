//! `wokd`: a members-only Nostr relay built on Wok.
//!
//! One server is one group. The operator lists the group's public keys; each
//! connection must authenticate (NIP-42) as one of them before it may read,
//! write, count or reconcile anything, and every member reads everything the
//! group has stored. There is no open mode. Only the sheltered door is
//! served, and the listener binds to loopback unless the operator says
//! otherwise.
//!
//! Membership is read from the configuration at start: adding or removing a
//! key takes a restart. Several groups means one instance each.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::http::{Extensions, StatusCode};
use axum::serve::ListenerExt as _;
use nostr::event::EventId;
use nostr::key::PublicKey;
use nostr::nips::nip19::FromBech32;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
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

/// How often expired events are swept (NIP-40).
const EXPIRY_INTERVAL: Duration = Duration::from_secs(60);

/// How long a shutdown waits for every socket to finish closing.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// The group: the keys that may authenticate. Asked on every operation.
pub struct Members(HashSet<PublicKey>);

impl Members {
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self(keys.into_iter().collect())
    }
}

impl KeeperAccess for Members {
    fn owns(&self, key: &PublicKey) -> bool {
        self.0.contains(key)
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
        Ok(Self {
            listen,
            url,
            data_dir: file.data_dir,
            max_store_bytes: file.max_store_bytes,
            min_free_bytes: file.min_free_bytes,
            members,
            sockets_per_address,
            auth_deadline: Duration::from_secs(auth_deadline_secs),
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

/// Bind `config.listen` and serve until `shutdown` completes.
pub async fn run(
    config: Config,
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
    serve(config, listener, shutdown).await
}

/// Serve on `listener` until `shutdown` completes: open the store, sweep
/// expired events every minute, and on shutdown close every socket and let
/// the server drain.
pub async fn serve(
    config: Config,
    listener: TcpListener,
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
            StoreOptions::server(),
        )
    })
    .await
    .map_err(|error| RunError::Store(error.to_string()))?
    .map_err(|error| RunError::Store(error.to_string()))?;
    let members = config.members.len();
    // A non-member's refused AUTH is final: a stock client would otherwise
    // be sent a fresh challenge and sign it, over and over.
    let relay = EventRelay::new(Arc::new(store), Arc::new(Members::new(config.members)))
        .with_final_access_refusal();
    let defaults = Timings::default();
    let door = Door::with_timings(
        Arc::new(relay),
        Timings::new(
            config.auth_deadline,
            defaults.heartbeat(),
            defaults.idle_deadline(),
        ),
    );
    let admission = Arc::new(PerAddress::new(config.sockets_per_address));
    let app = door.sheltered_router(config.url, Arc::clone(&admission) as Arc<dyn Admission>);
    let sweeper = door.clone();
    let expiry = tokio::spawn(async move {
        let mut tick = tokio::time::interval(EXPIRY_INTERVAL);
        loop {
            tick.tick().await;
            sweeper.expire().await;
        }
    });
    tracing::info!(members, "wokd serving its members");
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
    fn a_request_with_no_connecting_address_is_refused() {
        let admission = PerAddress::new(2);
        assert_eq!(
            admission.admit(&Extensions::new()).err(),
            Some(StatusCode::FORBIDDEN)
        );
    }
}
