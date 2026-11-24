use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use nostr::event::Event;
use nostr::key::PublicKey;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use tokio::sync::watch;
use wok_store::Visibility;
use wok_store::relay::{
    AuthorityEvents, AuthorityUnavailable, GuestAuthority, GuestScope, InstallRequest,
    KeeperAccess, SignatureCheck,
};

use crate::Members;

pub(crate) const ROOM_GRANT_KIND: u16 = 24242;
const MAX_GRANT_LIFETIME: u64 = 400 * 86_400;
const MAX_FUTURE_SKEW: u64 = 300;
const READ_KINDS: [u16; 3] = [1460, 1462, 20461];
const WRITE_KINDS: [u16; 2] = [1460, 20461];
const KNOWN_TAGS: [&str; 10] = [
    "t",
    "server",
    "d",
    "p",
    "device",
    "grant",
    "read",
    "write",
    "expiration",
    "status",
];

/// A guest's current grants, by the persona it authenticates as and by the
/// device key it signs with. Each is compiled once and kept: a guest's every
/// write and read asks one of them.
const SCOPES_BY_PERSONA: &str =
    "SELECT issuer, grant_id, room, device, read_kinds, write_kinds, expires_at
     FROM room_grants
     WHERE server = ?1 AND persona = ?2 AND active = 1 AND expires_at > ?3
     ORDER BY created_at";
const SCOPES_BY_DEVICE: &str =
    "SELECT issuer, grant_id, room, device, read_kinds, write_kinds, expires_at
     FROM room_grants
     WHERE server = ?1 AND device = ?2 AND active = 1 AND expires_at > ?3
     ORDER BY created_at";

pub(crate) struct RoomAuthority {
    conn: Mutex<Connection>,
    server: String,
    members: Arc<Members>,
    changes: watch::Sender<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Active,
    Revoked,
}

impl Status {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
    fn stored(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug)]
struct Grant {
    issuer: PublicKey,
    room: String,
    persona: PublicKey,
    device: PublicKey,
    grant_id: String,
    read: BTreeSet<u16>,
    write: BTreeSet<u16>,
    expiration: u64,
    high_water: u64,
    status: Status,
    created_at: u64,
}

#[derive(Clone, Debug)]
struct Stored {
    room: String,
    persona: PublicKey,
    device: PublicKey,
    status: Status,
    expiration: u64,
    high_water: u64,
    created_at: u64,
    event_json: String,
}

impl RoomAuthority {
    pub(crate) fn open(
        path: &Path,
        server: String,
        members: Arc<Members>,
    ) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        // Plans come from the statement alone, never from the values bound
        // to it. SQLite otherwise compiles a kept statement again whenever
        // such a value has changed, which made keeping one slower than
        // compiling it afresh (8.6 µs a lookup against 5.0, and 1.8 with
        // this; measured on 24 November 2026).
        conn.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG,
            true,
        )?;
        let version: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if version == 0 {
            conn.execute_batch(
                "CREATE TABLE room_grants (
                   issuer TEXT NOT NULL,
                   grant_id TEXT NOT NULL,
                   server TEXT NOT NULL,
                   room TEXT NOT NULL,
                   persona TEXT NOT NULL,
                   device TEXT NOT NULL,
                   read_kinds TEXT NOT NULL,
                   write_kinds TEXT NOT NULL,
                   status TEXT NOT NULL,
                   active INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL,
                   created_at INTEGER NOT NULL,
                   event_json TEXT NOT NULL,
                   high_water INTEGER NOT NULL,
                   PRIMARY KEY (issuer, grant_id)
                 );
                 CREATE INDEX room_grants_by_persona
                   ON room_grants(server, persona, active, expires_at);
                 CREATE INDEX room_grants_by_device
                   ON room_grants(server, device, active, expires_at);
                 CREATE UNIQUE INDEX room_grants_active_scope
                   ON room_grants(server, room, persona, device) WHERE active = 1;
                 PRAGMA user_version = 1;",
            )?;
        }
        let (changes, _) = watch::channel(0);
        Ok(Self {
            conn: Mutex::new(conn),
            server,
            members,
            changes,
        })
    }

    fn install(&self, event: &Event, now: u64) -> Result<(), String> {
        let parsed = parse(event, now, &self.server, self.members.as_ref())?;
        let event_json = serde_json::to_string(event).map_err(|_| "invalid grant".to_owned())?;
        let changed = {
            let mut conn = self
                .conn
                .lock()
                .map_err(|_| "authority unavailable".to_owned())?;
            let tx = conn
                .transaction()
                .map_err(|_| "authority unavailable".to_owned())?;
            let expired = tx
                .execute(
                    "UPDATE room_grants SET active = 0 WHERE active = 1 AND expires_at <= ?1",
                    [sql_time(now)],
                )
                .map_err(|_| "authority unavailable".to_owned())?;
            let previous = stored(&tx, &parsed.issuer, &parsed.grant_id)
                .map_err(|_| "authority unavailable".to_owned())?;
            let replay = previous
                .as_ref()
                .is_some_and(|stored| stored.event_json == event_json);
            let accepted = accept(
                parsed,
                now,
                previous.as_ref(),
                &tx,
                &self.server,
                &event_json,
            )?;
            if !replay {
                let read =
                    serde_json::to_string(&accepted.read.iter().copied().collect::<Vec<_>>())
                        .map_err(|_| "invalid grant".to_owned())?;
                let write =
                    serde_json::to_string(&accepted.write.iter().copied().collect::<Vec<_>>())
                        .map_err(|_| "invalid grant".to_owned())?;
                tx.execute(
                    "INSERT INTO room_grants
                     (issuer, grant_id, server, room, persona, device, read_kinds, write_kinds,
                      status, active, expires_at, created_at, event_json, high_water)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                     ON CONFLICT(issuer, grant_id) DO UPDATE SET
                       room = excluded.room, persona = excluded.persona, device = excluded.device,
                       read_kinds = excluded.read_kinds, write_kinds = excluded.write_kinds,
                       status = excluded.status, active = excluded.active,
                       expires_at = excluded.expires_at, created_at = excluded.created_at,
                       event_json = excluded.event_json, high_water = excluded.high_water",
                    params![
                        accepted.issuer.to_hex(),
                        accepted.grant_id,
                        self.server,
                        accepted.room,
                        accepted.persona.to_hex(),
                        accepted.device.to_hex(),
                        read,
                        write,
                        accepted.status.stored(),
                        accepted.status == Status::Active,
                        sql_time(accepted.expiration),
                        sql_time(accepted.created_at),
                        event_json,
                        sql_time(accepted.high_water),
                    ],
                )
                .map_err(|_| "invalid: a different grant owns this active scope".to_owned())?;
            }
            tx.commit()
                .map_err(|_| "authority unavailable".to_owned())?;
            expired > 0 || !replay
        };
        if changed {
            self.changes.send_modify(|generation| *generation += 1);
        }
        Ok(())
    }

    fn scopes_for(
        &self,
        sql: &'static str,
        identity: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        let conn = self.conn.lock().map_err(|_| AuthorityUnavailable)?;
        let mut statement = conn.prepare_cached(sql).map_err(|_| AuthorityUnavailable)?;
        let rows = statement
            .query_map(
                params![self.server, identity.to_hex(), sql_time(now)],
                |row| {
                    let issuer = key(row, 0)?;
                    let grant_id: String = row.get(1)?;
                    let room = row.get(2)?;
                    let device = key(row, 3)?;
                    let read = kinds_from_json(row.get::<_, String>(4)?)?;
                    let write = kinds_from_json(row.get::<_, String>(5)?)?;
                    let expires_at = time(row, 6)?;
                    Ok((issuer, grant_id, room, device, read, write, expires_at))
                },
            )
            .map_err(|_| AuthorityUnavailable)?;
        let mut scopes = Vec::new();
        for row in rows {
            let (issuer, grant_id, room, device, read, write, expires_at) =
                row.map_err(|_| AuthorityUnavailable)?;
            if self.members.owns(&issuer) {
                scopes.push(GuestScope {
                    issuer,
                    grant_id,
                    room,
                    device,
                    read,
                    write,
                    expires_at,
                });
            }
        }
        Ok(scopes)
    }
}

impl GuestAuthority for RoomAuthority {
    fn scopes(
        &self,
        identity: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        self.scopes_for(SCOPES_BY_PERSONA, identity, now)
    }

    fn device_scopes(
        &self,
        device: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
        self.scopes_for(SCOPES_BY_DEVICE, device, now)
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn subscribe_issuers(&self) -> watch::Receiver<u64> {
        self.members
            .subscribe()
            .expect("member changes are signalled")
    }
}

impl AuthorityEvents for RoomAuthority {
    fn is_authority(&self, event: &Event) -> bool {
        event.kind.as_u16() == ROOM_GRANT_KIND
            && event.tags.iter().any(|tag| {
                let fields = tag.as_slice();
                fields.first().is_some_and(|name| name == "t")
                    && fields.get(1).is_some_and(|value| value == "event-grant")
            })
    }

    fn install(&self, request: &InstallRequest<'_>) -> Option<Result<(), String>> {
        if request.visibility != Visibility::Sheltered || !self.is_authority(request.event) {
            return None;
        }
        if !request.keeper() || request.identity() != Some(request.event.pubkey) {
            return Some(Err(
                "restricted: grant installer must be its keeper signer".to_owned()
            ));
        }
        if request.signature == SignatureCheck::Failed {
            return Some(Err("invalid: circle grant refused".to_owned()));
        }
        Some(
            RoomAuthority::install(self, request.event, request.now)
                .map_err(|_| "invalid: circle grant refused".to_owned()),
        )
    }
}

fn key(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<PublicKey> {
    let value: String = row.get(index)?;
    PublicKey::from_hex(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn sql_time(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn time(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn kinds_from_json(value: String) -> rusqlite::Result<BTreeSet<u16>> {
    serde_json::from_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn one<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    let values = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|field| field == name))
        .collect::<Vec<_>>();
    (values.len() == 1 && values[0].as_slice().len() == 2).then(|| values[0].as_slice()[1].as_str())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn kinds(
    event: &Event,
    name: &str,
    minimum: usize,
    allowed: &[u16],
) -> Result<BTreeSet<u16>, String> {
    let values = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|field| field == name))
        .collect::<Vec<_>>();
    if values.len() < minimum
        || values.len() > 8
        || values.iter().any(|tag| tag.as_slice().len() != 2)
    {
        return Err("invalid grant kinds".to_owned());
    }
    let mut result = BTreeSet::new();
    for tag in values {
        let kind = tag.as_slice()[1]
            .parse::<u16>()
            .map_err(|_| "invalid grant kinds".to_owned())?;
        if !allowed.contains(&kind) || !result.insert(kind) {
            return Err("invalid grant kinds".to_owned());
        }
    }
    Ok(result)
}

fn parse(event: &Event, now: u64, server: &str, members: &Members) -> Result<Grant, String> {
    if event.kind.as_u16() != ROOM_GRANT_KIND || event.verify().is_err() {
        return Err("invalid grant".to_owned());
    }
    if !members.owns(&event.pubkey) || !event.content.is_empty() {
        return Err("invalid grant".to_owned());
    }
    if event.created_at.as_secs() > now.saturating_add(MAX_FUTURE_SKEW) {
        return Err("invalid grant time".to_owned());
    }
    if event.tags.iter().any(|tag| {
        tag.as_slice()
            .first()
            .is_none_or(|name| !KNOWN_TAGS.contains(&name.as_str()))
    }) {
        return Err("unknown grant tag".to_owned());
    }
    if one(event, "t") != Some("event-grant") || one(event, "server") != Some(server) {
        return Err("wrong grant server".to_owned());
    }
    let room = one(event, "d")
        .filter(|value| lower_hex(value, 64))
        .ok_or("invalid room")?;
    let persona = one(event, "p")
        .filter(|value| lower_hex(value, 64))
        .ok_or("invalid persona")?;
    let device = one(event, "device")
        .filter(|value| lower_hex(value, 64))
        .ok_or("invalid device")?;
    let grant_id = one(event, "grant")
        .filter(|value| lower_hex(value, 32))
        .ok_or("invalid grant id")?;
    let read = kinds(event, "read", 1, &READ_KINDS)?;
    let write = kinds(event, "write", 0, &WRITE_KINDS)?;
    if !write.is_subset(&read) {
        return Err("write is not readable".to_owned());
    }
    let expiration = one(event, "expiration")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|expiration| *expiration <= now.saturating_add(MAX_GRANT_LIFETIME))
        .ok_or("invalid expiration")?;
    let status = one(event, "status")
        .and_then(Status::parse)
        .ok_or("invalid status")?;
    if status == Status::Active && expiration <= now {
        return Err("expired grant".to_owned());
    }
    Ok(Grant {
        issuer: event.pubkey,
        room: room.to_owned(),
        persona: PublicKey::from_hex(persona).map_err(|_| "invalid persona")?,
        device: PublicKey::from_hex(device).map_err(|_| "invalid device")?,
        grant_id: grant_id.to_owned(),
        read,
        write,
        expiration,
        high_water: if status == Status::Active {
            expiration
        } else {
            0
        },
        status,
        created_at: event.created_at.as_secs(),
    })
}

fn stored(
    tx: &Transaction<'_>,
    issuer: &PublicKey,
    grant_id: &str,
) -> rusqlite::Result<Option<Stored>> {
    tx.query_row(
        "SELECT room, persona, device, status, expires_at, high_water, created_at, event_json
         FROM room_grants WHERE issuer = ?1 AND grant_id = ?2",
        params![issuer.to_hex(), grant_id],
        |row| {
            let status = match row.get::<_, String>(3)?.as_str() {
                "active" => Status::Active,
                "revoked" => Status::Revoked,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok(Stored {
                room: row.get(0)?,
                persona: key(row, 1)?,
                device: key(row, 2)?,
                status,
                expiration: time(row, 4)?,
                high_water: time(row, 5)?,
                created_at: time(row, 6)?,
                event_json: row.get(7)?,
            })
        },
    )
    .optional()
}

fn accept(
    mut grant: Grant,
    now: u64,
    previous: Option<&Stored>,
    tx: &Transaction<'_>,
    server: &str,
    event_json: &str,
) -> Result<Grant, String> {
    if grant.expiration <= now && (grant.status != Status::Revoked || previous.is_none()) {
        return Err("expired grant".to_owned());
    }
    if let Some(previous) = previous {
        if previous.room != grant.room
            || previous.persona != grant.persona
            || previous.device != grant.device
        {
            return Err("grant scope is immutable".to_owned());
        }
        if previous.event_json == event_json {
            if previous.created_at != grant.created_at
                || previous.status != grant.status
                || previous.expiration != grant.expiration
                || (grant.status == Status::Revoked && grant.expiration < previous.high_water)
            {
                return Err("invalid receipt".to_owned());
            }
            grant.high_water = previous.high_water;
            return Ok(grant);
        }
        if grant.created_at <= previous.created_at {
            return Err("stale grant".to_owned());
        }
        if previous.status == Status::Revoked && grant.status == Status::Active {
            return Err("revoked grant is terminal".to_owned());
        }
        if grant.status == Status::Revoked && grant.expiration < previous.high_water {
            return Err("revocation undercuts expiration".to_owned());
        }
        grant.high_water = if grant.status == Status::Active {
            previous.high_water.max(grant.expiration)
        } else {
            previous.high_water
        };
    }
    if grant.status == Status::Active {
        let active = tx
            .query_row(
                "SELECT grant_id FROM room_grants
                 WHERE server = ?1 AND room = ?2 AND persona = ?3 AND device = ?4
                   AND active = 1 AND expires_at > ?5",
                params![
                    server,
                    grant.room,
                    grant.persona.to_hex(),
                    grant.device.to_hex(),
                    sql_time(now)
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| "authority unavailable".to_owned())?;
        if active.is_some_and(|id| id != grant.grant_id) {
            return Err("a different grant owns this active scope".to_owned());
        }
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::key::Keys;
    use tempfile::TempDir;

    const NOW: u64 = 1_900_000_000;

    #[allow(clippy::too_many_arguments)]
    fn event(
        keeper: &Keys,
        server: &str,
        persona: &Keys,
        device: &Keys,
        id: &str,
        created: u64,
        status: &str,
        expires: u64,
    ) -> Event {
        EventBuilder::new(Kind::from(ROOM_GRANT_KIND), "")
            .tags([
                Tag::parse(["t", "event-grant"]).unwrap(),
                Tag::parse(["server", server]).unwrap(),
                Tag::parse(["d", &"11".repeat(32)]).unwrap(),
                Tag::parse(["p", &persona.public_key().to_hex()]).unwrap(),
                Tag::parse(["device", &device.public_key().to_hex()]).unwrap(),
                Tag::parse(["grant", id]).unwrap(),
                Tag::parse(["read", "1460"]).unwrap(),
                Tag::parse(["read", "1462"]).unwrap(),
                Tag::parse(["read", "20461"]).unwrap(),
                Tag::parse(["write", "1460"]).unwrap(),
                Tag::parse(["write", "20461"]).unwrap(),
                Tag::parse(["expiration", &expires.to_string()]).unwrap(),
                Tag::parse(["status", status]).unwrap(),
            ])
            .custom_created_at(created.into())
            .finalize(keeper)
            .unwrap()
    }

    use nostr::event::Tag;

    #[test]
    fn vennel_room_admission_vectors() {
        #[derive(serde::Deserialize)]
        struct Vectors {
            now: u64,
            server: String,
            keeper: String,
            guest: String,
            events: std::collections::BTreeMap<String, serde_json::Value>,
        }
        let vectors: Vectors =
            serde_json::from_str(include_str!("../tests/room-grant-vectors.json")).unwrap();
        let keeper = PublicKey::from_hex(&vectors.keeper).unwrap();
        let guest = PublicKey::from_hex(&vectors.guest).unwrap();
        let members = Arc::new(Members::new([keeper]));
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("authority.sqlite");
        let authority =
            RoomAuthority::open(&path, vectors.server.clone(), Arc::clone(&members)).unwrap();
        let install = |authority: &RoomAuthority, name: &str, expected: bool| {
            let event: Event = serde_json::from_value(vectors.events[name].clone()).unwrap();
            assert_eq!(
                authority.install(&event, vectors.now).is_ok(),
                expected,
                "{name}"
            );
        };
        install(&authority, "active", true);
        install(&authority, "active", true);
        install(&authority, "otherScope", false);
        install(&authority, "wrongServer", false);
        install(&authority, "expired", false);
        install(&authority, "vmls", false);
        install(&authority, "foreign", false);
        install(&authority, "renewal", true);
        assert_eq!(authority.scopes(&guest, vectors.now).unwrap().len(), 1);
        install(&authority, "active", false);
        install(&authority, "changedScope", false);
        install(&authority, "revocation", true);
        install(&authority, "renewal", false);
        assert!(authority.scopes(&guest, vectors.now).unwrap().is_empty());
        drop(authority);
        let authority = RoomAuthority::open(&path, vectors.server, members).unwrap();
        install(&authority, "revocation", true);
        assert!(authority.scopes(&guest, vectors.now).unwrap().is_empty());
    }

    #[test]
    fn grant_lifecycle_survives_restart_and_keeper_removal() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("authority.sqlite");
        let server = "wss://relay.example.org/events".to_owned();
        let keeper = Keys::generate();
        let guest = Keys::generate();
        let device = Keys::generate();
        let members = Arc::new(Members::new([keeper.public_key()]));
        let active = event(
            &keeper,
            &server,
            &guest,
            &device,
            &"ab".repeat(16),
            NOW,
            "active",
            NOW + 1000,
        );
        let revoked = event(
            &keeper,
            &server,
            &guest,
            &device,
            &"ab".repeat(16),
            NOW + 1,
            "revoked",
            NOW + 1000,
        );
        {
            let authority =
                RoomAuthority::open(&path, server.clone(), Arc::clone(&members)).unwrap();
            authority.install(&active, NOW).unwrap();
            authority.install(&active, NOW).unwrap();
            assert_eq!(authority.scopes(&guest.public_key(), NOW).unwrap().len(), 1);
            let stale = event(
                &keeper,
                &server,
                &guest,
                &device,
                &"ab".repeat(16),
                NOW,
                "active",
                NOW + 1001,
            );
            assert!(authority.install(&stale, NOW + 1).is_err());
            authority.install(&revoked, NOW + 1).unwrap();
            assert!(
                authority
                    .scopes(&guest.public_key(), NOW + 1)
                    .unwrap()
                    .is_empty()
            );
            assert!(authority.install(&active, NOW + 2).is_err());
        }
        let authority = RoomAuthority::open(&path, server.clone(), Arc::clone(&members)).unwrap();
        authority.install(&revoked, NOW + 2).unwrap();
        assert!(
            authority
                .scopes(&guest.public_key(), NOW + 2)
                .unwrap()
                .is_empty()
        );
        let replacement = event(
            &keeper,
            &server,
            &guest,
            &device,
            &"cd".repeat(16),
            NOW + 3,
            "active",
            NOW + 1000,
        );
        authority.install(&replacement, NOW + 3).unwrap();
        assert_eq!(
            authority
                .scopes(&guest.public_key(), NOW + 3)
                .unwrap()
                .len(),
            1
        );
        members.replace([]);
        assert!(
            authority
                .scopes(&guest.public_key(), NOW + 3)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn active_scope_and_expiry_are_enforced() {
        let dir = TempDir::new().unwrap();
        let keeper = Keys::generate();
        let guest = Keys::generate();
        let device = Keys::generate();
        let server = "wss://relay.example.org/events".to_owned();
        let members = Arc::new(Members::new([keeper.public_key()]));
        let authority = RoomAuthority::open(
            &dir.path().join("authority.sqlite"),
            server.clone(),
            members,
        )
        .unwrap();
        let active = event(
            &keeper,
            &server,
            &guest,
            &device,
            &"ab".repeat(16),
            NOW,
            "active",
            NOW + 10,
        );
        authority.install(&active, NOW).unwrap();
        let other = event(
            &keeper,
            &server,
            &guest,
            &device,
            &"cd".repeat(16),
            NOW + 1,
            "active",
            NOW + 20,
        );
        assert!(authority.install(&other, NOW + 1).is_err());
        assert!(
            authority
                .scopes(&guest.public_key(), NOW + 10)
                .unwrap()
                .is_empty()
        );
        let replacement = event(
            &keeper,
            &server,
            &guest,
            &device,
            &"cd".repeat(16),
            NOW + 11,
            "active",
            NOW + 30,
        );
        authority.install(&replacement, NOW + 11).unwrap();
        assert_eq!(
            authority
                .device_scopes(&device.public_key(), NOW + 11)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_newer_authority_schema_is_refused_without_changing_it() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("authority.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA user_version = 2").unwrap();
        }
        let keeper = Keys::generate();
        let members = Arc::new(Members::new([keeper.public_key()]));
        assert!(
            RoomAuthority::open(&path, "wss://relay.example.org/events".to_owned(), members)
                .is_err()
        );
        let conn = Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn foreign_server_and_non_keeper_are_refused() {
        let dir = TempDir::new().unwrap();
        let keeper = Keys::generate();
        let stranger = Keys::generate();
        let guest = Keys::generate();
        let device = Keys::generate();
        let server = "wss://relay.example.org/events".to_owned();
        let members = Arc::new(Members::new([keeper.public_key()]));
        let authority = RoomAuthority::open(
            &dir.path().join("authority.sqlite"),
            server.clone(),
            members,
        )
        .unwrap();
        let wrong = event(
            &keeper,
            "wss://other.example.org/events",
            &guest,
            &device,
            &"ab".repeat(16),
            NOW,
            "active",
            NOW + 10,
        );
        assert!(authority.install(&wrong, NOW).is_err());
        let foreign = event(
            &stranger,
            &server,
            &guest,
            &device,
            &"ab".repeat(16),
            NOW,
            "active",
            NOW + 10,
        );
        assert!(authority.install(&foreign, NOW).is_err());
    }

    #[test]
    fn scope_lookups_keep_one_compiled_statement_and_its_plan() {
        use rusqlite::StatementStatus::{RePrepare, Run};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("authority.sqlite");
        let server = "wss://relay.example.org/events".to_owned();
        let keeper = Keys::generate();
        let guest = Keys::generate();
        let device = Keys::generate();
        let members = Arc::new(Members::new([keeper.public_key()]));
        let authority = RoomAuthority::open(&path, server.clone(), members).unwrap();
        let grant = event(
            &keeper,
            &server,
            &guest,
            &device,
            &"ab".repeat(16),
            NOW,
            "active",
            NOW + 1000,
        );
        authority.install(&grant, NOW).unwrap();
        for later in 0..3 {
            let by_persona = authority.scopes(&guest.public_key(), NOW + later);
            assert_eq!(by_persona.unwrap().len(), 1);
            let by_device = authority.device_scopes(&device.public_key(), NOW + later);
            assert_eq!(by_device.unwrap().len(), 1);
        }
        let conn = authority.conn.lock().unwrap();
        // A second connection as SQLite opens one, which plans from the
        // values it is given: the kept statement's plan must be that plan.
        let from_values = Connection::open(&path).unwrap();
        for sql in [SCOPES_BY_PERSONA, SCOPES_BY_DEVICE] {
            let kept = conn.prepare_cached(sql).unwrap();
            assert_eq!(kept.get_status(Run), 3, "{sql}");
            assert_eq!(kept.get_status(RePrepare), 0, "{sql}");
            drop(kept);
            let plan = |conn: &Connection| -> Vec<String> {
                conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .unwrap()
                    .query_map(
                        params![server, guest.public_key().to_hex(), sql_time(NOW)],
                        |row| row.get(3),
                    )
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap()
            };
            assert_eq!(plan(&conn), plan(&from_values), "{sql}");
        }
    }
}
