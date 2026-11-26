//! Keeper-controlled room relay. A connection selects a room at NIP-42
//! authentication; event authors and derived stream tags never select its
//! storage partition. Each room has a dedicated event database, so deletion
//! removes its replacement heads and barriers without touching another room.
//!
//! This is the core, with no socket of its own: [`crate::host`] puts it
//! behind a loopback WebSocket listener and a local control socket.
use nostr::{event::Event, filter::Filter};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use thiserror::Error;
use wok_store::relay::{AUTH_WINDOW_SECS, names_relay};
use wok_store::{
    EventStore, EventStoreError, MAX_EXPIRE_EVENTS, PutOutcome, SqliteEventStore, StoreOptions,
    Visibility,
};

/// How long one snapshot from the supervisor stays in force. Without a newer
/// one, every door refuses until the next arrives.
pub const LEASE_SECONDS: u64 = 15;
/// The most rooms a relay can be opened for.
pub const MAX_ROOMS: usize = 64;
/// The most device grants one snapshot may carry.
pub const MAX_DEVICES: usize = 1024;
/// The furthest ahead a stored event may expire, and how long a closed room's
/// tombstone is kept.
const HORIZON: u64 = 30 * 86400;
/// How long an ask, and the right to answer it, lasts.
const ASK_SECONDS: u64 = 600;

/// Why a request was refused. The text is what a client or the supervisor is
/// told, so it names no room, key or address.
#[derive(Debug, Error)]
pub enum RoomError {
    #[error("invalid request")]
    Invalid,
    #[error("room closed")]
    Closed,
    #[error("access removed")]
    Removed,
    #[error("access expired")]
    Expired,
    #[error("node reconnecting")]
    Unavailable,
    #[error("room relay is full")]
    Full,
    #[error("room store unavailable")]
    Store(#[from] EventStoreError),
    #[error("room metadata unavailable")]
    Metadata(#[from] rusqlite::Error),
    #[error("room files unavailable")]
    Io(#[from] std::io::Error),
}
type Result<T> = std::result::Result<T, RoomError>;

/// One room in the supervisor's snapshot. Keys and room ids are 64 lower-case
/// hex characters.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomSpec {
    pub room: String,
    /// The one key that reads asks for this room, answers them, and may sign
    /// its closing events.
    pub inviter: String,
    /// When the room ends, in Unix seconds, if it does.
    pub ends: Option<u64>,
    /// Set only by the supervisor for a keeper-authorised migration.
    /// Existing room events keep their original signed retention policy.
    #[serde(default)]
    pub existing: bool,
}
/// One admitted device in the supervisor's snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGrant {
    pub room: String,
    pub device: String,
    /// Unix seconds, at most 90 days ahead.
    pub expires: u64,
    pub read: bool,
    pub write: bool,
}
/// Which door a connection came in by. It is chosen once, at authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Door {
    /// An admitted device, reading and writing its room.
    Room,
    /// A key that has not been admitted, asking the room's inviter.
    Ask,
}
/// What one authenticated connection may reach: a room, a key and a door.
#[derive(Clone, Debug)]
pub struct Access {
    room: String,
    key: String,
    door: Door,
}
impl Access {
    pub fn door(&self) -> Door {
        self.door
    }
}
/// A stored event on its way to the connections attached to the same room
/// and door.
#[derive(Clone)]
pub struct Live {
    pub room: String,
    pub door: Door,
    pub event: Event,
}

/// No room keys, authority secrets or participant names enter this type.
pub struct RoomRelay {
    root: PathBuf,
    salt: [u8; 32],
    metadata: Connection,
    stores: BTreeMap<String, SqliteEventStore>,
    rooms: HashMap<String, RoomSpec>,
    grants: HashMap<(String, String), DeviceGrant>,
    asks: HashMap<(String, String), u64>,
    max_bytes: u64,
    min_free_bytes: u64,
    max_rooms: usize,
    lease: Option<Instant>,
    // Last to drop: another process cannot reopen while stores are closing.
    _lock: fs::File,
}

fn key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sql_time(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| RoomError::Invalid)
}
/// The room relay's own address is a CLI argument, so it may not parse.
fn same_relay(given: &str, relay: &str) -> bool {
    match url::Url::parse(relay) {
        Ok(relay) => names_relay(given, &relay),
        Err(_) => given == relay,
    }
}

fn tag(event: &Event, name: &str) -> Result<String> {
    let mut tags = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|t| t == name));
    let value = tags
        .next()
        .filter(|tag| tag.as_slice().len() == 2)
        .ok_or(RoomError::Invalid)?;
    if tags.next().is_some() {
        return Err(RoomError::Invalid);
    }
    Ok(value.as_slice()[1].clone())
}

impl RoomRelay {
    pub fn open(
        root: &Path,
        max_bytes: u64,
        min_free_bytes: u64,
        max_rooms: usize,
    ) -> Result<Self> {
        if max_bytes == 0 || !(1..=MAX_ROOMS).contains(&max_rooms) {
            return Err(RoomError::Invalid);
        }
        fs::create_dir_all(root)?;
        if fs::symlink_metadata(root)?.file_type().is_symlink() {
            return Err(RoomError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        let salt_path = root.join("room-salt");
        let mut salt = [0; 32];
        let lock = if salt_path.exists() {
            if !fs::symlink_metadata(&salt_path)?.is_file() {
                return Err(RoomError::Invalid);
            }
            let mut file = fs::File::open(&salt_path)?;
            fs2::FileExt::try_lock_exclusive(&file).map_err(|_| RoomError::Unavailable)?;
            if file.metadata()?.len() != 32 {
                return Err(RoomError::Invalid);
            }
            file.read_exact(&mut salt)?;
            file
        } else {
            if fs::read_dir(root)?.next().is_some() {
                return Err(RoomError::Invalid);
            }
            getrandom::fill(&mut salt).map_err(|_| RoomError::Unavailable)?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&salt_path)?;
            fs2::FileExt::try_lock_exclusive(&file).map_err(|_| RoomError::Unavailable)?;
            file.write_all(&salt)?;
            file.sync_all()?;
            fs::File::open(root)?.sync_all()?;
            file
        };
        let metadata = Connection::open(root.join("closed.sqlite"))?;
        metadata.execute_batch("PRAGMA secure_delete=ON; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS closed(room_hash TEXT PRIMARY KEY, closed_at INTEGER NOT NULL);")?;
        let mut relay = Self {
            root: root.into(),
            salt,
            metadata,
            stores: BTreeMap::new(),
            rooms: HashMap::new(),
            grants: HashMap::new(),
            asks: HashMap::new(),
            max_bytes,
            min_free_bytes,
            max_rooms,
            lease: None,
            _lock: lock,
        };
        // Recover all dedicated stores for quota accounting and NIP-40 sweeping,
        // including a room whose close was interrupted part way.
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(hash) = name
                .strip_prefix("room-")
                .and_then(|n| n.strip_suffix(".sqlite"))
            {
                if !key(hash) || !entry.file_type()?.is_file() {
                    return Err(RoomError::Invalid);
                }
                if relay.stores.len() >= max_rooms {
                    return Err(RoomError::Full);
                }
                relay.stores.insert(hash.into(), relay.open_store(hash)?);
            }
        }
        Ok(relay)
    }
    fn hash(&self, room: &str) -> String {
        hex::encode(Sha256::digest(
            [self.salt.as_slice(), room.as_bytes()].concat(),
        ))
    }
    fn path(&self, hash: &str) -> PathBuf {
        self.root.join(format!("room-{hash}.sqlite"))
    }
    fn open_store(&self, hash: &str) -> Result<SqliteEventStore> {
        let path = self.path(hash);
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
            return Err(RoomError::Invalid);
        }
        Ok(SqliteEventStore::open_with_options(
            &path,
            self.max_bytes,
            self.min_free_bytes,
            StoreOptions {
                writer_cache_kib: 64,
                reader_cache_kib: 64,
                checkpoint_cache_kib: 64,
                mmap_bytes: 0,
                reader_mmap_bytes: 0,
                background_checkpoint: false,
                warm: false,
                ..StoreOptions::phone()
            },
        )?)
    }
    fn closed(&self, room: &str, now: u64) -> Result<bool> {
        Ok(self.metadata.query_row(
            "SELECT count(*) FROM closed WHERE room_hash=? AND closed_at>?",
            params![self.hash(room), sql_time(now.saturating_sub(HORIZON))?],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }
    /// The supervisor sends its whole current snapshot. Validation and opening
    /// any new store finish before the allowlist and short lease change.
    pub fn synchronise(
        &mut self,
        rooms: Vec<RoomSpec>,
        grants: Vec<DeviceGrant>,
        now: u64,
    ) -> Result<()> {
        if rooms.len() > self.max_rooms || grants.len() > MAX_DEVICES {
            return Err(RoomError::Full);
        }
        let mut next_rooms = HashMap::new();
        let mut next_grants = HashMap::new();
        for room in rooms {
            if !key(&room.room)
                || !key(&room.inviter)
                || room
                    .ends
                    .is_some_and(|end| end <= now || end > now.saturating_add(HORIZON))
                || next_rooms.contains_key(&room.room)
            {
                return Err(RoomError::Invalid);
            }
            if self.closed(&room.room, now)? {
                return Err(RoomError::Closed);
            }
            next_rooms.insert(room.room.clone(), room);
        }
        for grant in grants {
            let id = (grant.room.clone(), grant.device.clone());
            if !next_rooms.contains_key(&grant.room)
                || !key(&grant.device)
                || (!grant.read && !grant.write)
                || grant.expires <= now
                || grant.expires > now.saturating_add(90 * 86400)
                || next_grants.contains_key(&id)
            {
                return Err(RoomError::Invalid);
            }
            next_grants.insert(id, grant);
        }
        for room in next_rooms.keys() {
            let hash = self.hash(room);
            if !self.stores.contains_key(&hash) {
                if self.stores.len() >= self.max_rooms {
                    return Err(RoomError::Full);
                }
                self.stores.insert(hash.clone(), self.open_store(&hash)?);
            }
        }
        self.rooms = next_rooms;
        self.grants = next_grants;
        self.asks
            .retain(|(room, _), end| self.rooms.contains_key(room) && *end > now);
        self.lease = Some(Instant::now() + Duration::from_secs(LEASE_SECONDS));
        Ok(())
    }
    fn live(&self) -> Result<()> {
        if self.lease.is_some_and(|until| until > Instant::now()) {
            Ok(())
        } else {
            Err(RoomError::Unavailable)
        }
    }
    fn check(&self, access: &Access, now: u64, write: bool) -> Result<()> {
        self.live()?;
        if self.closed(&access.room, now)? {
            return Err(RoomError::Closed);
        }
        let room = self.rooms.get(&access.room).ok_or(RoomError::Removed)?;
        if room.ends.is_some_and(|end| end <= now) {
            return Err(RoomError::Closed);
        }
        if access.door == Door::Room {
            let grant = self
                .grants
                .get(&(access.room.clone(), access.key.clone()))
                .ok_or(RoomError::Removed)?;
            if grant.expires <= now {
                return Err(RoomError::Expired);
            }
            if if write { !grant.write } else { !grant.read } {
                return Err(RoomError::Removed);
            }
        }
        Ok(())
    }
    /// `room` and `mode` are signed extension tags on a normal NIP-42 event.
    /// The AUTH window and relay match are the event relay's.
    /// A refused room login never silently becomes an ask-door login.
    pub fn authenticate(
        &self,
        event: &Event,
        challenge: &str,
        relay: &str,
        now: u64,
    ) -> Result<Access> {
        if event.kind.as_u16() != 22242
            || !event.content.is_empty()
            || event.tags.len() > 8
            || event.created_at.as_secs().abs_diff(now) > AUTH_WINDOW_SECS
            || event.verify().is_err()
            || tag(event, "challenge")? != challenge
            || !same_relay(&tag(event, "relay")?, relay)
        {
            return Err(RoomError::Invalid);
        }
        let room = tag(event, "room")?;
        if !key(&room) {
            return Err(RoomError::Invalid);
        }
        let door = match tag(event, "mode")?.as_str() {
            "room" => Door::Room,
            "ask" => Door::Ask,
            _ => return Err(RoomError::Invalid),
        };
        let access = Access {
            room,
            key: event.pubkey.to_hex(),
            door,
        };
        self.check(&access, now, false)?;
        Ok(access)
    }
    pub fn still_authorised(&self, access: &Access, now: u64) -> bool {
        self.check(access, now, false).is_ok()
    }
    pub fn status(&self) -> Result<Value> {
        let used = self.stores.values().try_fold(0u64, |total, store| {
            store.logical_bytes().map(|n| total.saturating_add(n))
        })?;
        Ok(
            json!({"rooms":self.rooms.len(),"devices":self.grants.len(),"usedBytes":used,"leaseActive":self.live().is_ok()}),
        )
    }
    pub fn publish(
        &mut self,
        access: &Access,
        event: &Event,
        now: u64,
    ) -> Result<(PutOutcome, Live)> {
        self.check(access, now, true)?;
        self.ingest(access, event, now)
    }
    /// The supervisor can forward the keeper's already-signed closing pair
    /// without holding a device or authority secret. The node profile uses
    /// the room authority as its inviter; no other author or kind is accepted.
    pub fn publish_closing(
        &mut self,
        room: &str,
        event: &Event,
        now: u64,
    ) -> Result<(PutOutcome, Live)> {
        self.live()?;
        let spec = self.rooms.get(room).ok_or(RoomError::Removed)?;
        if event.pubkey.to_hex() != spec.inviter || !matches!(event.kind.as_u16(), 1461 | 1462) {
            return Err(RoomError::Invalid);
        }
        let access = Access {
            room: room.into(),
            key: spec.inviter.clone(),
            door: Door::Room,
        };
        self.ingest(&access, event, now)
    }
    fn ingest(&mut self, access: &Access, event: &Event, now: u64) -> Result<(PutOutcome, Live)> {
        if event.verify().is_err() || event.kind.as_u16() == 22242 {
            return Err(RoomError::Invalid);
        }
        let room = self.rooms.get(&access.room).ok_or(RoomError::Removed)?;
        let existing_room = room.existing && access.door == Door::Room;
        let has_expiration = event
            .tags
            .iter()
            .any(|t| t.as_slice().first().is_some_and(|s| s == "expiration"));
        // Missing expiry is allowed only on the authenticated room door of
        // an existing room. A malformed or duplicate expiry is never absence.
        let expiration = if existing_room && !has_expiration {
            None
        } else {
            let value = tag(event, "expiration")?;
            let parsed = value.parse::<u64>().map_err(|_| RoomError::Invalid)?;
            if parsed.to_string() != value {
                return Err(RoomError::Invalid);
            }
            Some(parsed)
        };
        let limit = if access.door == Door::Ask {
            now.saturating_add(ASK_SECONDS)
        } else if existing_room {
            room.ends.unwrap_or(u64::MAX)
        } else {
            room.ends
                .unwrap_or(event.created_at.as_secs().saturating_add(HORIZON))
        };
        if expiration.is_some_and(|end| end <= now || end > limit) {
            return Err(RoomError::Invalid);
        }
        if access.door == Door::Ask {
            // The sealed wrapper is persistent kind 1059. Ephemeral 20466/20467
            // admission statements travel inside it, never as stored outer events.
            if event.kind.as_u16() != 1059 {
                return Err(RoomError::Invalid);
            }
            let recipient = tag(event, "p")?;
            if access.key == room.inviter {
                if self
                    .asks
                    .get(&(access.room.clone(), recipient))
                    .is_none_or(|end| *end <= now)
                {
                    return Err(RoomError::Invalid);
                }
            } else {
                if recipient != room.inviter {
                    return Err(RoomError::Invalid);
                }
                let id = (access.room.clone(), access.key.clone());
                if self.asks.len() >= 1024 && !self.asks.contains_key(&id) {
                    return Err(RoomError::Full);
                }
                self.asks.insert(id, expiration.ok_or(RoomError::Invalid)?);
            }
        }
        let hash = self.hash(&access.room);
        let other_bytes = self
            .stores
            .iter()
            .filter(|(id, _)| **id != hash)
            .try_fold(0u64, |total, (_, store)| {
                store.logical_bytes().map(|n| total.saturating_add(n))
            })?;
        let store = self.stores.get_mut(&hash).ok_or(RoomError::Unavailable)?;
        store.set_byte_ceiling(self.max_bytes.saturating_sub(other_bytes));
        let visibility = if access.door == Door::Room {
            Visibility::Sheltered
        } else {
            Visibility::Public
        };
        let outcome = store.put(visibility, event, now)?;
        Ok((
            outcome,
            Live {
                room: access.room.clone(),
                door: access.door,
                event: event.clone(),
            },
        ))
    }
    fn filter(&self, access: &Access, mut filter: Value) -> Result<Filter> {
        if access.door == Door::Ask {
            let object = filter.as_object_mut().ok_or(RoomError::Invalid)?;
            object.insert("#p".into(), json!([access.key]));
            object.insert("kinds".into(), json!([1059]));
        }
        serde_json::from_value(filter).map_err(|_| RoomError::Invalid)
    }
    pub fn query(&self, access: &Access, filter: Value, now: u64) -> Result<Vec<Event>> {
        self.check(access, now, false)?;
        let filter = self.filter(access, filter)?;
        let store = self
            .stores
            .get(&self.hash(&access.room))
            .ok_or(RoomError::Unavailable)?;
        Ok(store.query(
            if access.door == Door::Room {
                Visibility::Sheltered
            } else {
                Visibility::Public
            },
            &filter,
            now,
        )?)
    }
    pub fn delivers(&self, access: &Access, live: &Live, filter: Value, now: u64) -> bool {
        use nostr::filter::MatchEventOptions;
        self.still_authorised(access, now)
            && live.room == access.room
            && live.door == access.door
            && self
                .filter(access, filter)
                .is_ok_and(|filter| filter.match_event(&live.event, MatchEventOptions::default()))
    }
    pub fn purge(&mut self, room: &str, now: u64) -> Result<u64> {
        if !key(room) {
            return Err(RoomError::Invalid);
        }
        let hash = self.hash(room);
        self.metadata.execute(
            "INSERT OR IGNORE INTO closed(room_hash,closed_at) VALUES(?,?)",
            params![hash, sql_time(now)?],
        )?;
        self.rooms.remove(room);
        self.grants.retain(|(r, _), _| r != room);
        self.asks.retain(|(r, _), _| r != room);
        if !self.stores.contains_key(&hash) && self.path(&hash).exists() {
            self.stores.insert(hash.clone(), self.open_store(&hash)?);
        }
        let count = match self.stores.get(&hash) {
            Some(store) => store.purge_room_database()?,
            None => 0,
        };
        self.stores.remove(&hash);
        match fs::remove_file(self.path(&hash)) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        Ok(count)
    }
    pub fn expire(&mut self, now: u64) -> Result<()> {
        for store in self.stores.values() {
            for _ in 0..32 {
                if store.expire(now)? < MAX_EXPIRE_EVENTS {
                    break;
                }
            }
        }
        self.asks.retain(|_, end| *end > now);
        self.metadata.execute(
            "DELETE FROM closed WHERE closed_at<=?",
            [sql_time(now.saturating_sub(HORIZON))?],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{
        event::{EventBuilder, FinalizeEvent, Kind, Tag},
        key::Keys,
        types::Timestamp,
    };
    use tempfile::TempDir;
    const NOW: u64 = 1_900_000_000;
    const URL: &str = "wss://node.example/events";
    fn event(keys: &Keys, kind: u16, content: &str, tags: Vec<Vec<String>>) -> Event {
        EventBuilder::new(Kind::from(kind), content)
            .custom_created_at(Timestamp::from_secs(NOW))
            .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
            .finalize(keys)
            .unwrap()
    }
    fn auth(relay: &RoomRelay, room: &str, keys: &Keys, mode: &str) -> Result<Access> {
        let event = event(
            keys,
            22242,
            "",
            vec![
                vec!["relay".into(), URL.into()],
                vec!["challenge".into(), "fixture".into()],
                vec!["room".into(), room.into()],
                vec!["mode".into(), mode.into()],
            ],
        );
        relay.authenticate(&event, "fixture", URL, NOW)
    }
    fn spec(room: &str, inviter: &Keys) -> RoomSpec {
        RoomSpec {
            room: room.into(),
            inviter: inviter.public_key().to_hex(),
            ends: None,
            existing: false,
        }
    }
    fn grant(room: &str, device: &Keys) -> DeviceGrant {
        DeviceGrant {
            room: room.into(),
            device: device.public_key().to_hex(),
            expires: NOW + 3600,
            read: true,
            write: true,
        }
    }
    fn message(keys: &Keys, kind: u16, recipient: Option<String>) -> Event {
        let mut tags = vec![vec!["expiration".into(), (NOW + 600).to_string()]];
        if let Some(recipient) = recipient {
            tags.push(vec!["p".into(), recipient]);
        }
        event(keys, kind, "ciphertext fixture", tags)
    }
    /// A room's store is named by SHA-256 of the salt followed by the room id.
    /// Data directories written before this crate existed depend on that
    /// name: a different one would leave their stores unread and uncounted.
    #[test]
    fn a_room_store_is_named_by_the_salted_hash_of_its_room_id() {
        let temp = TempDir::new().unwrap();
        let salt: Vec<u8> = (0..32).collect();
        fs::write(temp.path().join("room-salt"), salt).unwrap();
        let room = "01".repeat(32);
        let mut relay = RoomRelay::open(temp.path(), 1_000_000, 0, 4).unwrap();
        relay
            .synchronise(vec![spec(&room, &Keys::generate())], vec![], NOW)
            .unwrap();
        let name = "room-34a0f4af64dc727a0bf19d6aec1e720cf553b7dbe433b69b0f5aa4eb41956b21.sqlite";
        assert!(temp.path().join(name).is_file());
    }

    #[test]
    fn existing_rooms_keep_original_signed_history_without_requiring_a_new_expiry() {
        let temp = TempDir::new().unwrap();
        let inviter = Keys::generate();
        let device = Keys::generate();
        let room = "07".repeat(32);
        let mut relay = RoomRelay::open(temp.path(), 16 * 1024 * 1024, 0, 4).unwrap();
        let existing: RoomSpec = serde_json::from_value(serde_json::json!({
            "room": room, "inviter": inviter.public_key().to_hex(), "ends": null, "existing": true
        }))
        .unwrap();
        relay
            .synchronise(vec![existing], vec![grant(&room, &device)], NOW)
            .unwrap();
        let access = auth(&relay, &room, &device, "room").unwrap();
        let original = event(
            &Keys::generate(),
            1460,
            "original encrypted history",
            vec![],
        );
        relay.publish(&access, &original, NOW).unwrap();
        let read = relay
            .query(&access, json!({"ids": [original.id.to_hex()]}), NOW)
            .unwrap();
        assert_eq!(read, vec![original.clone()]);
        assert!(
            relay
                .publish(
                    &access,
                    &event(
                        &device,
                        1460,
                        "expired",
                        vec![vec!["expiration".into(), (NOW - 1).to_string()]]
                    ),
                    NOW
                )
                .is_err()
        );
        for tags in [
            vec![
                vec!["expiration".into(), (NOW + 60).to_string()],
                vec!["expiration".into(), (NOW + 60).to_string()],
            ],
            vec![vec!["expiration".into(), "invalid".into()]],
        ] {
            assert!(
                relay
                    .publish(&access, &event(&device, 1460, "invalid expiry", tags), NOW)
                    .is_err()
            );
        }
        let asker = Keys::generate();
        let ask_access = auth(&relay, &room, &asker, "ask").unwrap();
        assert!(
            relay
                .publish(
                    &ask_access,
                    &event(
                        &asker,
                        1059,
                        "ask without expiry",
                        vec![vec!["p".into(), inviter.public_key().to_hex()]]
                    ),
                    NOW
                )
                .is_err()
        );
        let strict = "08".repeat(32);
        relay
            .synchronise(
                vec![spec(&strict, &inviter)],
                vec![grant(&strict, &device)],
                NOW,
            )
            .unwrap();
        let strict_access = auth(&relay, &strict, &device, "room").unwrap();
        assert!(relay.publish(&strict_access, &original, NOW).is_err());
    }

    #[test]
    fn intake_uses_the_connections_room_even_for_throwaway_authors_and_purge_is_isolated() {
        let temp = TempDir::new().unwrap();
        let inviter = Keys::generate();
        let a = "01".repeat(32);
        let b = "02".repeat(32);
        let device_a = Keys::generate();
        let device_b = Keys::generate();
        let specs = vec![spec(&a, &inviter), spec(&b, &inviter)];
        let grants = vec![grant(&a, &device_a), grant(&b, &device_b)];
        let mut relay = RoomRelay::open(temp.path(), 1_000_000, 0, 4).unwrap();
        relay
            .synchronise(specs.clone(), grants.clone(), NOW)
            .unwrap();
        let access_a = auth(&relay, &a, &device_a, "room").unwrap();
        let access_b = auth(&relay, &b, &device_b, "room").unwrap();
        assert!(matches!(
            auth(&relay, &a, &Keys::generate(), "room"),
            Err(RoomError::Removed)
        ));
        let other_author = Keys::generate();
        for kind in [1464, 1059, 20472] {
            let event = message(&other_author, kind, None);
            relay.publish(&access_a, &event, NOW).unwrap();
            assert!(relay.query(&access_b, json!({}), NOW).unwrap().is_empty());
        }
        let common = message(&other_author, 1, None);
        relay.publish(&access_a, &common, NOW).unwrap();
        relay.publish(&access_b, &common, NOW).unwrap();
        assert_eq!(relay.purge(&a, NOW).unwrap(), 3);
        assert!(!relay.still_authorised(&access_a, NOW));
        assert_eq!(
            relay.query(&access_b, json!({}), NOW).unwrap()[0].id,
            common.id
        );
        assert!(matches!(
            auth(&relay, &a, &device_a, "room"),
            Err(RoomError::Closed)
        ));
        assert_eq!(relay.purge(&a, NOW).unwrap(), 0);
        drop(relay);
        let mut relay = RoomRelay::open(temp.path(), 1_000_000, 0, 4).unwrap();
        relay
            .synchronise(vec![spec(&b, &inviter)], vec![grant(&b, &device_b)], NOW)
            .unwrap();
        assert!(matches!(
            auth(&relay, &a, &device_a, "room"),
            Err(RoomError::Closed)
        ));
        assert_eq!(
            relay
                .query(
                    &auth(&relay, &b, &device_b, "room").unwrap(),
                    json!({}),
                    NOW
                )
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn askers_read_only_their_addressed_answers_and_cannot_read_room_content() {
        let temp = TempDir::new().unwrap();
        let inviter = Keys::generate();
        let asker = Keys::generate();
        let stranger = Keys::generate();
        let room = "01".repeat(32);
        let mut relay = RoomRelay::open(temp.path(), 1_000_000, 0, 4).unwrap();
        relay
            .synchronise(vec![spec(&room, &inviter)], vec![], NOW)
            .unwrap();
        let ask = auth(&relay, &room, &asker, "ask").unwrap();
        let inbox = auth(&relay, &room, &inviter, "ask").unwrap();
        let other = auth(&relay, &room, &stranger, "ask").unwrap();
        let request = message(&Keys::generate(), 1059, Some(inviter.public_key().to_hex()));
        relay.publish(&ask, &request, NOW).unwrap();
        assert!(relay.query(&ask, json!({}), NOW).unwrap().is_empty());
        assert_eq!(
            relay.query(&inbox, json!({}), NOW).unwrap()[0].id,
            request.id
        );
        assert!(
            relay
                .query(&other, json!({"#p":[inviter.public_key().to_hex()]}), NOW)
                .unwrap()
                .is_empty()
        );
        let answer = message(&Keys::generate(), 1059, Some(asker.public_key().to_hex()));
        relay.publish(&inbox, &answer, NOW).unwrap();
        assert_eq!(relay.query(&ask, json!({}), NOW).unwrap()[0].id, answer.id);
        assert!(relay.query(&other, json!({}), NOW).unwrap().is_empty());
        assert!(
            relay
                .publish(
                    &other,
                    &message(&stranger, 1059, Some(asker.public_key().to_hex())),
                    NOW
                )
                .is_err()
        );
        assert!(
            relay
                .publish(
                    &ask,
                    &message(&asker, 20466, Some(inviter.public_key().to_hex())),
                    NOW
                )
                .is_err()
        );
        assert!(relay.query(&ask, json!({}), NOW + 601).unwrap().is_empty());
    }
    #[test]
    fn changed_grants_and_expired_leases_revoke_old_sessions_and_expiration_is_required() {
        let temp = TempDir::new().unwrap();
        let inviter = Keys::generate();
        let device = Keys::generate();
        let room = "01".repeat(32);
        let mut relay = RoomRelay::open(temp.path(), 1_000_000, 0, 4).unwrap();
        relay
            .synchronise(
                vec![spec(&room, &inviter)],
                vec![grant(&room, &device)],
                NOW,
            )
            .unwrap();
        let access = auth(&relay, &room, &device, "room").unwrap();
        assert!(
            relay
                .publish(&access, &event(&device, 1, "no expiry", vec![]), NOW)
                .is_err()
        );
        assert!(
            relay
                .publish(
                    &access,
                    &event(
                        &device,
                        1,
                        "too long",
                        vec![vec!["expiration".into(), (NOW + HORIZON + 1).to_string()]]
                    ),
                    NOW
                )
                .is_err()
        );
        assert!(!relay.still_authorised(&access, NOW + 3600));
        relay.lease = Some(Instant::now() - Duration::from_secs(1));
        assert!(!relay.still_authorised(&access, NOW));
        relay
            .synchronise(vec![spec(&room, &inviter)], vec![], NOW)
            .unwrap();
        assert!(!relay.still_authorised(&access, NOW));
        assert!(matches!(
            auth(&relay, &room, &device, "room"),
            Err(RoomError::Removed)
        ));
    }
    /// A connection's live batch is matched under the lock with `delivers`
    /// and written without a further access check, so `delivers` itself
    /// must refuse a session whose access has ended.
    #[test]
    fn a_live_event_is_delivered_only_while_the_session_is_still_authorised() {
        let temp = TempDir::new().unwrap();
        let inviter = Keys::generate();
        let device = Keys::generate();
        let other = Keys::generate();
        let room = "01".repeat(32);
        let mut relay = RoomRelay::open(temp.path(), 1_000_000, 0, 4).unwrap();
        let grants = vec![grant(&room, &device), grant(&room, &other)];
        relay
            .synchronise(vec![spec(&room, &inviter)], grants, NOW)
            .unwrap();
        let access = auth(&relay, &room, &device, "room").unwrap();
        let writer = auth(&relay, &room, &other, "room").unwrap();
        let (_, live) = relay
            .publish(&writer, &message(&other, 1464, None), NOW)
            .unwrap();
        assert!(relay.delivers(&access, &live, json!({}), NOW));
        assert!(!relay.delivers(&access, &live, json!({}), NOW + 3600));
        relay
            .synchronise(vec![spec(&room, &inviter)], vec![grant(&room, &other)], NOW)
            .unwrap();
        assert!(!relay.delivers(&access, &live, json!({}), NOW));
        assert!(relay.delivers(&writer, &live, json!({}), NOW));
    }
}
