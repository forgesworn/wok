//! NIP-01/NIP-42 sessions over the durable event store.
//!
//! The compatibility door is public-read / keeper-authenticated-write and
//! has an explicit public-kind allowlist. Sheltered sessions require NIP-42
//! authentication as a keeper or as a guest holding scopes from a
//! [`GuestAuthority`]. A guest scope names one room, the kinds it may read
//! and write there and one device key; it is never inferred.
//!
//! The engine holds no policy of its own about who the keepers are, who may
//! be a guest, or which events carry authority rather than content: those
//! come in through [`KeeperAccess`], [`GuestAuthority`] and
//! [`AuthorityEvents`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use negentropy::{Id as NegentropyId, Negentropy, NegentropyStorageVector};
use nostr::event::Event;
use nostr::filter::{Filter, MatchEventOptions};
use nostr::key::{Keys, PublicKey};
use serde_json::{Value, json};
use url::Url;

use crate::live::{LIVE_QUEUE_BYTES, LIVE_TOTAL_BYTES, LiveFanout, event_frame};
pub use crate::live::{LiveEvent, LiveReceiver, LiveRecvError, LiveTryRecvError};
pub use crate::writer::Cancel as WriteCancel;
use crate::writer::{EventWriter, Reserved, WriterLimits};
use crate::{
    EventStore, EventStoreError, MAX_EVENT_BYTES, MAX_EXACT_COUNT, MAX_QUERY_EVENTS, PreparedPut,
    PutOutcome, PutResult, Recheck, Visibility, single_d_value,
};

pub const MAX_RELAY_FRAME_BYTES: usize = MAX_EVENT_BYTES + 1024;
pub const MAX_SUBSCRIPTIONS: usize = 16;
pub const MAX_FILTERS: usize = 8;
/// The longest subscription id a REQ, COUNT or NEG-OPEN may name, in chars.
pub const MAX_SUBSCRIPTION_ID_CHARS: usize = 64;
/// How far a NIP-42 AUTH event's `created_at` may be from the relay's clock,
/// either way, in seconds.
pub const AUTH_WINDOW_SECS: u64 = 600;
/// What the public door's NIP-11 document advertises. Kept beside the
/// dispatcher so the list cannot drift from what [`RelaySession`] handles.
pub const SUPPORTED_NIPS: [u16; 8] = [1, 9, 11, 40, 42, 45, 70, 77];
const MAX_FRAMES_PER_MINUTE: u32 = 120;
// NIP-77 reconciles IDs, not event bodies. Limit a session to a small number
// of independent conversations and reject a result that may have been
// truncated by the store; a false "in sync" answer is worse than asking a
// client to narrow its time window.
const MAX_NEGENTROPY_SUBSCRIPTIONS: usize = 4;
/// The reply to a filter the store refuses for its size: more values across
/// its lists than one statement binds.
const TOO_LARGE: &str = "restricted: filter too large; split it";
pub const MAX_NEGENTROPY_EVENTS: usize = MAX_QUERY_EVENTS - 1;
pub const MAX_NEGENTROPY_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_NEGENTROPY_MESSAGE_HEX: usize = MAX_NEGENTROPY_MESSAGE_BYTES * 2;
/// The most a single REQ reply releases before `EOSE`, in frame bytes.
pub const MAX_REQ_REPLY_BYTES: usize = 2 * 1024 * 1024;
/// Deliberate public formats only: what the compatibility door accepts from
/// the keeper, and what a replica pull accepts into the public partition.
pub const PUBLIC_KINDS: [u16; 9] = [0, 1, 3, 5, 6, 7, 10002, 10050, 10063];
const MAX_NEGENTROPY_ROUNDS_PER_MINUTE: u32 = 16;

/// Queried on each operation and live delivery, so authentication cannot
/// retain authority after a key stops being a keeper.
pub trait KeeperAccess: Send + Sync {
    fn owns(&self, key: &PublicKey) -> bool;

    /// [`Self::owns`] if it can be answered without storage or any wait:
    /// `None` means a refresh is due and the caller must make it somewhere
    /// that may block (a work permit), not on an async task. The default is
    /// for sources whose `owns` is already a memory read.
    fn try_owns(&self, key: &PublicKey) -> Option<bool> {
        Some(self.owns(key))
    }

    /// [`Self::owns`], telling "not a keeper" from "the keeper set could not be
    /// read". `owns` fails closed on a store error, which is right for one
    /// decision but must not be taken for an answer that is then kept: a
    /// verdict cached from it would outlive the error. The default is for
    /// sources whose `owns` cannot fail.
    fn owns_checked(&self, key: &PublicKey) -> Result<bool, AuthorityUnavailable> {
        Ok(self.owns(key))
    }

    fn subscribe(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        None
    }
}

/// An authority source (the keeper set or the guest scopes) could not be read.
/// Never an answer: callers fail closed for the operation and cache nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityUnavailable;

/// One scope a guest holds on the sheltered partition: in `room` (an event's
/// single `d` tag), `device` may write the `write` kinds and the guest may
/// read the `read` kinds, until `expires_at`. `issuer` and `grant_id` say
/// which grant it came from, so a replaced grant with the same reach is still
/// a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestScope {
    pub issuer: PublicKey,
    pub grant_id: String,
    pub room: String,
    pub device: PublicKey,
    pub read: BTreeSet<u16>,
    pub write: BTreeSet<u16>,
    pub expires_at: u64,
}

/// Who besides the keepers may use the sheltered partition, and how far.
/// Asked on every operation, as [`KeeperAccess`] is, so a withdrawn scope
/// stops working at once.
///
/// Both watchers must be bumped after the change they report commits, and
/// their senders must live as long as the authority: a closed channel reads
/// as a change on every wait.
pub trait GuestAuthority: Send + Sync {
    /// The scopes `identity` (the key a session authenticated as) holds at
    /// `now`. `Err` is "could not be read", never "no scopes".
    fn scopes(
        &self,
        identity: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable>;

    /// The scopes naming `device` as their device at `now`, whoever holds
    /// them: what that device could write here directly. Judges copies
    /// pulled from a sibling relay.
    fn device_scopes(
        &self,
        device: &PublicKey,
        now: u64,
    ) -> Result<Vec<GuestScope>, AuthorityUnavailable>;

    /// Bumped after any scope is installed, replaced or withdrawn.
    fn subscribe(&self) -> tokio::sync::watch::Receiver<u64>;

    /// Bumped after a change to whatever decides which issuers count.
    fn subscribe_issuers(&self) -> tokio::sync::watch::Receiver<u64>;
}

/// Events that carry authority rather than content, such as a grant, which
/// a door installs instead of storing.
pub trait AuthorityEvents: Send + Sync {
    /// Whether `event` is authority. Such an event is never stored on either
    /// partition: not from a sibling relay, and not through a write's recheck.
    fn is_authority(&self, event: &Event) -> bool;

    /// Answer an authority event sent in an EVENT frame. `Some` is the reply,
    /// sent as the `OK` (`Err` carries its reason), and nothing reaches the
    /// store or the live channel. `None` leaves the event to the door's
    /// ordinary rules.
    fn install(&self, request: &InstallRequest<'_>) -> Option<Result<(), String>>;
}

/// An authority event and the session it arrived on.
pub struct InstallRequest<'a> {
    pub event: &'a Event,
    pub visibility: Visibility,
    pub signature: SignatureCheck,
    pub now: u64,
    authenticated: &'a BTreeSet<PublicKey>,
    access_refused: bool,
    access: &'a dyn KeeperAccess,
}

impl InstallRequest<'_> {
    /// Whether the session is authenticated as a current keeper.
    pub fn keeper(&self) -> bool {
        self.authenticated.iter().any(|key| self.access.owns(key))
    }

    /// Whether `key` is a keeper now.
    pub fn owns(&self, key: &PublicKey) -> bool {
        self.access.owns(key)
    }

    /// The identity the session authenticated as, if it has.
    pub fn identity(&self) -> Option<PublicKey> {
        self.authenticated.iter().next().copied()
    }

    /// Whether the session authenticated as `key`.
    pub fn is_authenticated_as(&self, key: &PublicKey) -> bool {
        self.authenticated.contains(key)
    }

    /// The door's refusal for a session without the authority to act.
    pub fn refusal(&self) -> &'static str {
        refusal_for(self.authenticated, self.access_refused)
    }
}

/// What the relay knows of an EVENT's signature when it reaches the checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    /// Not checked: the store verifies it.
    Unchecked,
    /// Checked by the transport's own verification, and good.
    Verified,
    /// Checked by the transport, and bad.
    Failed,
}

/// Sees every event announced live, after the fan-out, on the announcing
/// thread: the writer's after a commit, or the door's for a direct ephemeral
/// event. Attached once ([`EventRelay::attach_announce_hook`]).
pub trait AnnounceHook: Send + Sync {
    /// `event` has just been announced to live subscribers.
    fn announced(&self, event: &Event);
}

#[derive(Clone)]
pub struct AuthorityChanges {
    guests: Option<tokio::sync::watch::Receiver<u64>>,
    keepers: Option<tokio::sync::watch::Receiver<u64>>,
    issuers: Option<tokio::sync::watch::Receiver<u64>>,
}

async fn watch_change(receiver: &mut Option<tokio::sync::watch::Receiver<u64>>) {
    match receiver {
        Some(receiver) => {
            let _ = receiver.changed().await;
        }
        None => std::future::pending().await,
    }
}

impl AuthorityChanges {
    /// Whether the keeper access source can say when it changes. Without
    /// that, a keeper-set change cannot invalidate a cached verdict.
    fn signals_keepers(&self) -> bool {
        self.keepers.is_some()
    }

    /// The generation each watched source has reached (guest scopes, keepers,
    /// issuers; 0 for one that cannot signal). A source bumps its generation
    /// after its write commits, so a stamp read before a query can only be
    /// older than that query's view, never newer.
    pub fn stamp(&self) -> [u64; 3] {
        let read = |receiver: &Option<tokio::sync::watch::Receiver<u64>>| {
            receiver.as_ref().map_or(0, |receiver| *receiver.borrow())
        };
        [read(&self.guests), read(&self.keepers), read(&self.issuers)]
    }

    pub async fn changed(&mut self) {
        tokio::select! {
            _ = watch_change(&mut self.guests) => {},
            _ = watch_change(&mut self.keepers) => {},
            _ = watch_change(&mut self.issuers) => {},
        }
    }
}

pub struct EventRelay {
    store: Arc<dyn EventStore>,
    access: Arc<dyn KeeperAccess>,
    guests: Option<Arc<dyn GuestAuthority>>,
    /// Events that are installed rather than stored
    /// ([`Self::with_authority_events`]).
    authority_events: Option<Arc<dyn AuthorityEvents>>,
    /// Every event announced live is handed to this after the fan-out
    /// ([`Self::attach_announce_hook`]), by the writer on its own thread after
    /// a commit, or by the door's handler for a direct ephemeral event.
    /// Shared with the writer's closure, which the `with_*` builders rebuild.
    hook: Arc<HookSlot>,
    public_kinds: Arc<BTreeSet<u16>>,
    live: Arc<LiveFanout>,
    /// Every event write goes through this one thread, which commits whatever
    /// is queued together and announces after the commit.
    writer: Arc<EventWriter>,
    /// Frames a session may send in a rolling minute.
    frame_limit: u32,
    /// See [`Self::with_final_access_refusal`].
    final_access_refusal: bool,
    /// The wall clock a queued write is judged by when the writer reaches it.
    clock: Clock,
    /// See [`Self::auth_relay_mismatches`].
    auth_relay_mismatches: std::sync::atomic::AtomicU64,
}

/// Seconds since the epoch, read when a queued write's grants are re-judged.
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The announce hook, attached once.
type HookSlot = std::sync::OnceLock<Arc<dyn AnnounceHook>>;

/// Fan a committed event out to attached connections, with the JSON the
/// store wrote for it, so it is not serialised again and a live frame is
/// byte for byte what a REQ sends. With none attached it builds nothing.
/// Then the announce hook, when one is attached, sees the event: committed
/// and fanned out, on the calling thread.
fn announce_on(
    live: &LiveFanout,
    hook: &HookSlot,
    visibility: Visibility,
    event: Event,
    json: Arc<str>,
) {
    let hook = hook.get();
    let attached = live.attached() > 0;
    if !attached && hook.is_none() {
        return;
    }
    let event = Arc::new(event);
    if attached {
        live.publish(&LiveEvent::stored(visibility, Arc::clone(&event), json));
    }
    if let Some(hook) = hook {
        hook.announced(&event);
    }
}

fn start_writer(
    store: &Arc<dyn EventStore>,
    live: &Arc<LiveFanout>,
    hook: &Arc<HookSlot>,
    limits: WriterLimits,
) -> Arc<EventWriter> {
    let live = Arc::clone(live);
    let hook = Arc::clone(hook);
    Arc::new(EventWriter::new(
        Arc::clone(store),
        move |visibility, event, json| announce_on(&live, &hook, visibility, event, json),
        limits,
    ))
}

impl EventRelay {
    /// Deliberate public formats only. Private rails, wraps and unknown kinds
    /// cannot be published through the compatibility door by accident.
    pub fn new(store: Arc<dyn EventStore>, access: Arc<dyn KeeperAccess>) -> Self {
        let live = LiveFanout::new(LIVE_QUEUE_BYTES, LIVE_TOTAL_BYTES);
        let hook = Arc::new(HookSlot::new());
        let writer = start_writer(&store, &live, &hook, WriterLimits::default());
        Self {
            store,
            access,
            guests: None,
            authority_events: None,
            hook,
            public_kinds: Arc::new(PUBLIC_KINDS.into()),
            live,
            writer,
            frame_limit: MAX_FRAMES_PER_MINUTE,
            final_access_refusal: false,
            clock: Arc::new(wall_clock),
            auth_relay_mismatches: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// AUTH events refused only because their one `relay` tag named another
    /// relay than the session's URL: the kind, signature, time and challenge
    /// were all good. Counted since this relay was built, for every door and
    /// session it serves, and before any access check, so anyone who can open
    /// a socket can raise it with a throwaway key. Real clients raising it
    /// usually means the address they connect to is not the URL this relay
    /// was given. The reply is the same generic refusal as for any other bad
    /// AUTH.
    pub fn auth_relay_mismatches(&self) -> u64 {
        self.auth_relay_mismatches
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Replace the wall clock (seconds since the epoch) that re-judges a
    /// queued write's authority when the writer reaches it, so a test can let
    /// a scope lapse while a write waits.
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// `hook` sees every event announced live, after the fan-out, on the
    /// announcing thread ([`AnnounceHook`]). Once: a second attachment is
    /// refused and reported `false`.
    pub fn attach_announce_hook(&self, hook: Arc<dyn AnnounceHook>) -> bool {
        self.hook.set(hook).is_ok()
    }

    /// Replace the per-session frame allowance (default 120 a minute). A
    /// client that pipelines bursts of events needs more; so do the benches.
    pub fn with_frame_limit(mut self, frames_per_minute: u32) -> Self {
        self.frame_limit = frames_per_minute;
        self
    }

    /// Make an AUTH refused only because its key has no access final for
    /// that key: its signature, challenge, relay and time were good, but the
    /// key is neither a keeper nor a guest with scopes. The refusal sends no
    /// replacement challenge, and until an AUTH succeeds every frame that
    /// needs authority is answered `restricted:` rather than
    /// `auth-required:`. A stock NIP-42 client signs every challenge it is
    /// sent, so without this a refused key is prompted again and signs
    /// again, as fast as the frame allowance lets it. The challenge it
    /// answered stays the one to answer, so a key with access can still
    /// authenticate on the same connection. An AUTH refused for anything
    /// else is unchanged. Off by default.
    pub fn with_final_access_refusal(mut self) -> Self {
        self.final_access_refusal = true;
        self
    }

    /// Replace the per-connection live queue budget (default
    /// [`LIVE_QUEUE_BYTES`]). Call before any connection attaches.
    pub fn with_live_queue_bytes(self, bytes: usize) -> Self {
        self.with_live_limits(bytes, LIVE_TOTAL_BYTES)
    }

    /// Replace both live budgets: bytes per connection queue and bytes of
    /// distinct events across all of them (defaults [`LIVE_QUEUE_BYTES`] and
    /// [`LIVE_TOTAL_BYTES`]). Call before any connection attaches.
    pub fn with_live_limits(mut self, queue_bytes: usize, total_bytes: usize) -> Self {
        self.live = LiveFanout::new(queue_bytes, total_bytes);
        self.writer = start_writer(&self.store, &self.live, &self.hook, WriterLimits::default());
        self
    }

    /// Replace the writer's queue and batch bounds. Call before any
    /// connection attaches.
    pub fn with_writer_limits(mut self, limits: WriterLimits) -> Self {
        self.writer = start_writer(&self.store, &self.live, &self.hook, limits);
        self
    }

    /// Block until every write queued so far has been committed, answered and
    /// announced. Live delivery follows the `OK` by design, so a caller that
    /// wants to look at it straight after one waits here.
    pub fn flush(&self) {
        self.writer.flush();
    }

    /// Events and weight waiting for the writer, for tests and diagnostics.
    pub fn writer_queued(&self) -> (usize, usize) {
        self.writer.queued()
    }

    /// What the writer has batched so far, for tests and diagnostics.
    pub fn writer_stats(&self) -> crate::writer::WriterStats {
        self.writer.stats()
    }

    /// Let guests holding scopes from `authority` use the sheltered door.
    pub fn with_guest_authority(mut self, authority: Arc<dyn GuestAuthority>) -> Self {
        self.guests = Some(authority);
        self
    }

    /// Install the events `events` names as authority instead of storing
    /// them, on both doors and on every other way in.
    pub fn with_authority_events(mut self, events: Arc<dyn AuthorityEvents>) -> Self {
        self.authority_events = Some(events);
        self
    }
    pub fn expire(&self, now: u64) -> Result<usize, EventStoreError> {
        self.store.expire(now)
    }

    /// A live queue for every partition. Connections use
    /// [`Self::subscribe_partition`]; this is for tests and diagnostics.
    pub fn subscribe(&self) -> LiveReceiver {
        self.live.attach(None)
    }

    /// A live queue for one partition, attached now. Attach before running
    /// the REQ's stored query so nothing committed in between is missed.
    pub fn subscribe_partition(&self, visibility: Visibility) -> LiveReceiver {
        self.live.attach(Some(visibility))
    }

    pub fn authority_changes(&self) -> AuthorityChanges {
        AuthorityChanges {
            guests: self.guests.as_ref().map(|authority| authority.subscribe()),
            keepers: self.access.subscribe(),
            issuers: self
                .guests
                .as_ref()
                .map(|authority| authority.subscribe_issuers()),
        }
    }
    pub fn session(
        self: &Arc<Self>,
        visibility: Visibility,
        relay_url: Url,
        now: u64,
    ) -> RelaySession {
        RelaySession {
            relay: Arc::clone(self),
            visibility,
            relay_url,
            // Fresh CSPRNG-derived public randomness, never a reusable node identity.
            challenge: fresh_challenge(None),
            authenticated: BTreeSet::new(),
            authenticated_as_keeper: false,
            access_refused: false,
            guest_snapshot: None,
            live_cache: None,
            authority: self.authority_changes(),
            write_authority: None,
            subscriptions: BTreeMap::new(),
            negentropy: BTreeMap::new(),
            window: now,
            frames: 0,
            negentropy_window: now,
            negentropy_rounds: 0,
        }
    }

    /// The store this relay reads and writes.
    pub fn store(&self) -> &Arc<dyn EventStore> {
        &self.store
    }

    /// Who this relay takes as its keepers.
    pub fn access(&self) -> &Arc<dyn KeeperAccess> {
        &self.access
    }

    /// This node's own `(created_at, id)` index for the half-open window
    /// `[since, until_exclusive)`, capped by the store's query bound. The
    /// replica puller reconciles against it; a capped local index can only
    /// make it fetch an event it already holds, never skip one it lacks.
    pub fn replica_index(
        &self,
        visibility: Visibility,
        since: u64,
        until_exclusive: u64,
        now: u64,
    ) -> Result<Vec<(u64, [u8; 32])>, EventStoreError> {
        if until_exclusive <= since {
            return Ok(Vec::new());
        }
        let filter = Filter::new()
            .since(nostr::types::Timestamp::from_secs(since))
            .until(nostr::types::Timestamp::from_secs(until_exclusive - 1));
        Ok(self
            .store
            .query(visibility, &filter, now)?
            .into_iter()
            .map(|event| (event.created_at.as_secs(), event.id.to_bytes()))
            .collect())
    }

    /// Store one event pulled from a sibling relay of the same keepers.
    ///
    /// The puller has already checked the signature, that the event was asked
    /// for and that it lies in the window it asked about. A sibling is still
    /// only another machine whose key sits on a disk, so this admits nothing
    /// this relay could not have been given directly, on its own authority:
    ///
    /// * **public:** keeper-authored allowlisted kinds, exactly as the
    ///   compatibility door takes them;
    /// * **sheltered:** an event authored by a current keeper key; a kind 1059
    ///   gift wrap, whose outer key is ephemeral by design and which no guest
    ///   can read; or a guest device's event that one of **this relay's own**
    ///   guest scopes lets that device write, in that room and kind. Scopes
    ///   held only by the sibling are not carried or trusted, so such guest
    ///   events are not replicated.
    ///
    /// Neither partition takes an authority event ([`AuthorityEvents`]),
    /// which is never stored. Storage is [`EventStore::put_replicated`]: NIP-09 deletion and
    /// replacement barriers hold for copies as for direct writes, and copies
    /// can never spend the reserve the keeper's own writes need.
    ///
    /// The rule is applied again when the writer reaches the event, so a key
    /// or grant withdrawn while the copy waited for its batch is refused.
    pub fn admit_replicated(
        &self,
        visibility: Visibility,
        event: &Event,
        now: u64,
    ) -> Result<ReplicaAdmission, EventStoreError> {
        let mut outcomes =
            self.admit_replicated_batch(visibility, std::slice::from_ref(event), now)?;
        // One event in, one answer out; an empty answer admits nothing.
        Ok(outcomes.pop().unwrap_or(ReplicaAdmission::Rejected))
    }

    /// [`Self::admit_replicated`] for several events, in order, stopping after
    /// the first `Full`: all prepared first, then queued for the writer
    /// together, so they share its batches rather than committing one by one.
    /// Blocks the calling thread while they commit.
    pub fn admit_replicated_batch(
        &self,
        visibility: Visibility,
        events: &[Event],
        now: u64,
    ) -> Result<Vec<ReplicaAdmission>, EventStoreError> {
        let prepared = self.prepare_replicated(visibility, events, now)?;
        self.submit_replicated_blocking(prepared)
    }

    /// The part of intake that needs a work permit: the intake rule, which
    /// may read the keeper set and the guest scopes, and the event's own checks. What
    /// comes back needs only the writer, so it is committed without a permit
    /// held ([`Self::submit_replicated`]).
    pub fn prepare_replicated(
        &self,
        visibility: Visibility,
        events: &[Event],
        now: u64,
    ) -> Result<Vec<ReplicaPrepared>, EventStoreError> {
        let authority = Arc::new(WriteAuthority {
            access: Arc::clone(&self.access),
            guests: self.guests.clone(),
            authority_events: self.authority_events.clone(),
            public_kinds: Arc::clone(&self.public_kinds),
            visibility,
            keys: None,
            generations: self.authority_changes(),
            clock: Arc::clone(&self.clock),
        });
        // Read before the checks, so it can only be older than they are.
        let stamp = authority.generations.stamp();
        let mut prepared = Vec::with_capacity(events.len());
        for event in events {
            let Some(valid_until) = authority.replica_valid_until(event, now) else {
                prepared.push(ReplicaPrepared::Settled(ReplicaAdmission::Rejected));
                continue;
            };
            match PreparedPut::new(visibility, event.clone(), now, true) {
                // Ephemeral kinds are never held, so there is nothing to copy
                // and nothing for the writer to do.
                Ok(put) if put.is_ephemeral() => {
                    prepared.push(ReplicaPrepared::Settled(ReplicaAdmission::Rejected));
                }
                Ok(put) => prepared.push(ReplicaPrepared::Put(Box::new(
                    put.with_recheck(authority.recheck(stamp, valid_until, now)),
                ))),
                Err(EventStoreError::Expired) => {
                    prepared.push(ReplicaPrepared::Settled(ReplicaAdmission::Expired));
                }
                Err(EventStoreError::Invalid | EventStoreError::Oversize) => {
                    prepared.push(ReplicaPrepared::Settled(ReplicaAdmission::Rejected));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(prepared)
    }

    /// Queue what [`Self::prepare_replicated`] left for the writer, all of it
    /// before waiting for any, and answer each in order, stopping after the
    /// first `Full`. No work permit is held while this waits. Events behind a
    /// `Full` that are still waiting for a batch are taken back; one already
    /// in a batch commits, and a later pass finds it a duplicate.
    pub async fn submit_replicated(
        &self,
        prepared: Vec<ReplicaPrepared>,
    ) -> Result<Vec<ReplicaAdmission>, EventStoreError> {
        let wait = self.writer.write_wait();
        let mut slots = Vec::with_capacity(prepared.len());
        for item in prepared {
            match item {
                ReplicaPrepared::Settled(admission) => slots.push(Slot::Settled(admission)),
                ReplicaPrepared::Put(put) => {
                    let deadline = tokio::time::Instant::now() + wait;
                    match self.writer.reserve_until(*put, deadline).await {
                        Ok(reserved) => slots.push(Slot::Waiting(reserved, deadline)),
                        Err(error) => {
                            slots.push(Slot::Failed(error));
                            break;
                        }
                    }
                }
            }
        }
        let mut outcomes = Vec::with_capacity(slots.len());
        let mut slots = slots.into_iter();
        while let Some(slot) = slots.next() {
            let result = match slot {
                Slot::Settled(admission) => Ok(admission),
                Slot::Failed(error) => Err(error),
                Slot::Waiting(reserved, deadline) => {
                    admission_of(reserved.wait_until(deadline).await)
                }
            };
            match result {
                Ok(ReplicaAdmission::Full) => {
                    outcomes.push(ReplicaAdmission::Full);
                    cancel_rest(slots);
                    return Ok(outcomes);
                }
                Ok(admission) => outcomes.push(admission),
                Err(error) => {
                    cancel_rest(slots);
                    return Err(error);
                }
            }
        }
        Ok(outcomes)
    }

    /// [`Self::submit_replicated`] for a thread that may block.
    pub fn submit_replicated_blocking(
        &self,
        prepared: Vec<ReplicaPrepared>,
    ) -> Result<Vec<ReplicaAdmission>, EventStoreError> {
        let wait = self.writer.write_wait();
        let mut slots = Vec::with_capacity(prepared.len());
        for item in prepared {
            match item {
                ReplicaPrepared::Settled(admission) => slots.push(BlockingSlot::Settled(admission)),
                ReplicaPrepared::Put(put) => {
                    let deadline = std::time::Instant::now() + wait;
                    match self.writer.reserve_blocking(*put, deadline) {
                        Ok(reserved) => slots.push(BlockingSlot::Waiting(reserved, deadline)),
                        Err(error) => {
                            slots.push(BlockingSlot::Failed(error));
                            break;
                        }
                    }
                }
            }
        }
        let mut outcomes = Vec::with_capacity(slots.len());
        let mut slots = slots.into_iter();
        while let Some(slot) = slots.next() {
            let result = match slot {
                BlockingSlot::Settled(admission) => Ok(admission),
                BlockingSlot::Failed(error) => Err(error),
                BlockingSlot::Waiting(reserved, deadline) => {
                    admission_of(reserved.wait_until(deadline))
                }
            };
            match result {
                Ok(ReplicaAdmission::Full) => {
                    outcomes.push(ReplicaAdmission::Full);
                    for rest in slots {
                        if let BlockingSlot::Waiting(reserved, _) = rest {
                            reserved.canceller().cancel();
                        }
                    }
                    return Ok(outcomes);
                }
                Ok(admission) => outcomes.push(admission),
                Err(error) => {
                    for rest in slots {
                        if let BlockingSlot::Waiting(reserved, _) = rest {
                            reserved.canceller().cancel();
                        }
                    }
                    return Err(error);
                }
            }
        }
        Ok(outcomes)
    }
}

/// One pulled event after [`EventRelay::prepare_replicated`].
pub enum ReplicaPrepared {
    /// Settled without the writer: refused by the intake rule, or never held.
    Settled(ReplicaAdmission),
    /// Passed every check; needs the writer.
    Put(Box<PreparedPut>),
}

enum Slot {
    Settled(ReplicaAdmission),
    Waiting(Reserved, tokio::time::Instant),
    Failed(EventStoreError),
}

enum BlockingSlot {
    Settled(ReplicaAdmission),
    Waiting(crate::writer::ReservedBlocking, std::time::Instant),
    Failed(EventStoreError),
}

fn cancel_rest(rest: impl Iterator<Item = Slot>) {
    for slot in rest {
        if let Slot::Waiting(reserved, _) = slot {
            reserved.canceller().cancel();
        }
    }
}

/// How a copy's fate is told to the puller.
fn admission_of(result: PutResult) -> Result<ReplicaAdmission, EventStoreError> {
    match result {
        Ok(PutOutcome::Stored) => Ok(ReplicaAdmission::Stored),
        Ok(PutOutcome::Duplicate) => Ok(ReplicaAdmission::Duplicate),
        // Ephemeral kinds are never held, so there is nothing to copy.
        Ok(PutOutcome::Ephemeral) => Ok(ReplicaAdmission::Rejected),
        Err(EventStoreError::Retired) => Ok(ReplicaAdmission::Retired),
        Err(EventStoreError::Expired) => Ok(ReplicaAdmission::Expired),
        Err(EventStoreError::Full) => Ok(ReplicaAdmission::Full),
        // No longer admitted by this node's own authority.
        Err(EventStoreError::Unauthorised) => Ok(ReplicaAdmission::Rejected),
        Err(EventStoreError::Invalid | EventStoreError::Oversize) => Ok(ReplicaAdmission::Rejected),
        Err(error) => Err(error),
    }
}

/// Seconds since the epoch on the wall clock.
fn wall_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What a write was authorised on, kept so the store can ask again at the
/// moment it applies the event. The relay checks authority before an event is
/// queued, but a batch may commit some seconds later, so a key or grant
/// withdrawn in between must not still be able to store and announce.
///
/// The common case is a comparison: the write carries the generation each
/// source of authority had reached when it was checked, and nothing is read
/// again unless one has moved. A keeper source that cannot signal its changes
/// is read again every time. Anything that cannot be read refuses.
struct WriteAuthority {
    access: Arc<dyn KeeperAccess>,
    guests: Option<Arc<dyn GuestAuthority>>,
    authority_events: Option<Arc<dyn AuthorityEvents>>,
    public_kinds: Arc<BTreeSet<u16>>,
    visibility: Visibility,
    /// The keys a session authenticated with, to judge its own writes. `None`
    /// judges a replicated copy as [`EventRelay::admit_replicated`] does.
    keys: Option<BTreeSet<PublicKey>>,
    generations: AuthorityChanges,
    clock: Clock,
}

impl WriteAuthority {
    /// What the store asks, for an event authorised when the sources of
    /// authority stood at `stamp`, on grants that all hold until
    /// `valid_until` (`u64::MAX` when nothing time-bound admitted it).
    fn recheck(self: &Arc<Self>, stamp: [u64; 3], valid_until: u64, now: u64) -> Recheck {
        let authority = Arc::clone(self);
        Arc::new(move |event: &Event| {
            authority.unchanged_or_allowed(event, stamp, valid_until, now)
        })
    }

    fn unchanged_or_allowed(
        &self,
        event: &Event,
        stamp: [u64; 3],
        valid_until: u64,
        now: u64,
    ) -> bool {
        let wall = (self.clock)();
        if self.generations.signals_keepers()
            && self.generations.stamp() == stamp
            && wall < valid_until
        {
            return true;
        }
        // The grant may also have lapsed in the meantime, so never judge by a
        // clock older than the wall clock.
        let now = now.max(wall);
        match &self.keys {
            Some(keys) => self.session_allowed(keys, event, now),
            None => self.replica_valid_until(event, now).is_some(),
        }
    }

    /// The checks [`RelaySession::authorise_publish`] makes after the
    /// authority-event branch, for the keys the session authenticated with.
    fn session_allowed(&self, keys: &BTreeSet<PublicKey>, event: &Event, now: u64) -> bool {
        if self.is_authority(event) {
            return false;
        }
        let Ok(keeper) = authorised_checked(self.access.as_ref(), keys) else {
            return false;
        };
        let scopes = if self.visibility == Visibility::Sheltered && !keeper {
            match (keys.iter().next(), &self.guests) {
                (Some(identity), Some(guests)) => guests
                    .scopes(identity, now)
                    .ok()
                    .filter(|scopes| !scopes.is_empty()),
                _ => None,
            }
        } else {
            None
        };
        if !keeper && scopes.is_none() {
            return false;
        }
        if self.visibility == Visibility::Public
            && (!self.access.owns(&event.pubkey)
                || !self.public_kinds.contains(&event.kind.as_u16()))
        {
            return false;
        }
        scopes
            .as_ref()
            .is_none_or(|scopes| guest_event_allowed(event, scopes))
    }

    /// The intake rule for an event pulled from a sibling relay: `None` refuses
    /// it, `Some(until)` admits it while the clock is before `until`
    /// (`u64::MAX` when no grant is involved).
    fn replica_valid_until(&self, event: &Event, now: u64) -> Option<u64> {
        if self.is_authority(event) {
            return None;
        }
        match self.visibility {
            Visibility::Public => (self.access.owns(&event.pubkey)
                && self.public_kinds.contains(&event.kind.as_u16()))
            .then_some(u64::MAX),
            Visibility::Sheltered => {
                if self.access.owns(&event.pubkey) || event.kind.as_u16() == GIFT_WRAP_KIND {
                    return Some(u64::MAX);
                }
                let (Some(guests), Some(room)) = (&self.guests, event_room(event)) else {
                    return None;
                };
                // Fail closed: an authority store this node cannot read
                // admits nobody.
                let scopes = guests.device_scopes(&event.pubkey, now).ok()?;
                guest_valid_until(event, room, &scopes)
            }
        }
    }

    fn is_authority(&self, event: &Event) -> bool {
        self.authority_events
            .as_ref()
            .is_some_and(|events| events.is_authority(event))
    }
}

/// Whether any of `keys` is a keeper, with a keeper set that could not be read
/// reported as such rather than as "not a keeper". A key that is a keeper wins
/// over an error on another.
fn authorised_checked(
    access: &dyn KeeperAccess,
    keys: &BTreeSet<PublicKey>,
) -> Result<bool, AuthorityUnavailable> {
    let mut unavailable = false;
    for key in keys {
        match access.owns_checked(key) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(AuthorityUnavailable) => unavailable = true,
        }
    }
    if unavailable {
        Err(AuthorityUnavailable)
    } else {
        Ok(false)
    }
}

/// NIP-59 gift wraps: signed by a one-off outer key, so never keeper-authored.
const GIFT_WRAP_KIND: u16 = 1059;

/// What [`EventRelay::admit_replicated`] did with one pulled event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaAdmission {
    /// Newly held, and delivered to live subscribers of its partition.
    Stored,
    /// Already held.
    Duplicate,
    /// Behind a deletion or replacement barrier here; not reintroduced.
    Retired,
    /// Its NIP-40 expiry has passed.
    Expired,
    /// Outside this partition's intake rule.
    Rejected,
    /// The store's byte ceiling or disk headroom refused it.
    Full,
}

/// What a session may read from the live channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveAccess {
    /// A keeper, or the public door: nothing narrows what it reads.
    Open,
    /// A guest: reads only what its scopes cover.
    Guest,
    /// No sheltered authority left.
    Denied,
    /// The authority could not be read just now. Fails closed for this event
    /// (the subscriptions are closed, so the client queries again) and is
    /// never cached: the next event reads the store afresh.
    Unavailable,
}

impl LiveAccess {
    /// Whether anything may reach the wire under this verdict.
    fn permits(self) -> bool {
        matches!(self, Self::Open | Self::Guest)
    }
}

/// A non-keeper's live-delivery verdict, so each stored event does not cost
/// the authority database two queries per connected guest. It is valid only
/// while no watched authority source has moved (`stamp`) and no grant it
/// rests on has expired (`valid_until`). Keepers are never cached.
struct LiveAccessCache {
    stamp: [u64; 3],
    valid_until: u64,
    /// `None` is [`LiveAccess::Denied`].
    scopes: Option<Vec<GuestScope>>,
}

pub struct RelaySession {
    relay: Arc<EventRelay>,
    visibility: Visibility,
    relay_url: Url,
    challenge: String,
    authenticated: BTreeSet<PublicKey>,
    authenticated_as_keeper: bool,
    /// An AUTH was refused for its key's access, under
    /// [`EventRelay::with_final_access_refusal`].
    access_refused: bool,
    guest_snapshot: Option<Vec<GuestScope>>,
    /// Verdict for live delivery; see [`LiveAccessCache`].
    live_cache: Option<LiveAccessCache>,
    /// This session's own watchers, read only to validate `live_cache`.
    authority: AuthorityChanges,
    /// What this session's writes are re-checked against; see
    /// [`WriteAuthority`]. Rebuilt after every AUTH.
    write_authority: Option<Arc<WriteAuthority>>,
    subscriptions: BTreeMap<String, Vec<Filter>>,
    negentropy: BTreeMap<String, NegentropySubscription>,
    window: u64,
    frames: u32,
    negentropy_window: u64,
    negentropy_rounds: u32,
}

/// State belongs to one NIP-77 reconciliation ID and is discarded on every
/// malformed continuation, close, or authority loss. `raw_filter` is kept so
/// a changed guest scope can be checked again before every response.
struct NegentropySubscription {
    state: Negentropy<'static, NegentropyStorageVector>,
    raw_filter: Value,
}

/// An inbound text frame after the checks that need neither session state
/// nor a work permit: an EVENT frame is parsed once and its signature
/// verified, so a malformed or forged one costs no permit and no store time.
pub struct PreparedFrame {
    text: String,
    event: Option<PreparedEvent>,
}

struct PreparedEvent {
    id: String,
    event: Event,
    signature_ok: bool,
}

impl PreparedEvent {
    /// The event with its signature verified once.
    fn checked(id: String, event: Event) -> Self {
        let signature_ok = event.verify().is_ok();
        Self {
            id,
            event,
            signature_ok,
        }
    }

    fn signature(&self) -> SignatureCheck {
        if self.signature_ok {
            SignatureCheck::Verified
        } else {
            SignatureCheck::Failed
        }
    }
}

/// An EVENT that passed every authority check and now needs only the store.
/// Queue it with [`PendingWrite::reserve`] on the connection's own task (so
/// events enter the writer in the order they arrived) and wait on the
/// [`WriteTicket`], holding no work permit; or [`PendingWrite::commit`] it in
/// one step.
pub struct PendingWrite {
    id: String,
    put: PreparedPut,
    writer: Arc<EventWriter>,
}

/// An EVENT that is in the writer's queue. It holds the receiver for the
/// answer and nothing else: the event is the writer's, and commits whether or
/// not the connection is still waiting. Dropping the ticket abandons the
/// wait; [`WriteTicket::canceller`] takes the event back out of the queue if no
/// batch has it yet.
pub struct WriteTicket {
    id: String,
    weight: usize,
    reserved: Reserved,
    deadline: tokio::time::Instant,
}

impl WriteTicket {
    /// The event id as the client sent it (empty if it was malformed).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// What this write holds in the queue, in the writer's own measure.
    pub fn weight(&self) -> usize {
        self.weight
    }

    pub fn canceller(&self) -> WriteCancel {
        self.reserved.canceller()
    }

    /// Wait for the commit, as the `OK` to send. A wait that runs out is
    /// answered as "still pending" even though the event may yet commit; a
    /// resend is then a duplicate.
    pub async fn wait(self) -> Vec<String> {
        let result = self.reserved.wait_until(self.deadline).await;
        write_replies(&self.id, result)
    }
}

impl PendingWrite {
    /// The event id as the client sent it (empty if it was malformed).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// What this write holds in memory, in the writer's own measure.
    pub fn weight(&self) -> usize {
        self.put.weight()
    }

    /// Take a place in the writer's queue, waiting while it is full (bounded
    /// by the writer's wait). `Err` is the `OK` to send when no place was
    /// found: nothing was queued and nothing is stored.
    pub async fn reserve(self) -> Result<WriteTicket, Vec<String>> {
        let Self { id, put, writer } = self;
        let weight = put.weight();
        let deadline = tokio::time::Instant::now() + writer.write_wait();
        match writer.reserve_until(put, deadline).await {
            Ok(reserved) => Ok(WriteTicket {
                id,
                weight,
                reserved,
                deadline,
            }),
            Err(error) => Err(reserve_replies(&id, error)),
        }
    }

    /// Queue the event for the writer and wait for its commit (bounded by the
    /// writer's wait), then answer as `OK`.
    pub async fn commit(self) -> Vec<String> {
        match self.reserve().await {
            Ok(ticket) => ticket.wait().await,
            Err(replies) => replies,
        }
    }

    /// [`Self::commit`] from a thread that may block.
    pub fn commit_blocking(self) -> Vec<String> {
        let Self { id, put, writer } = self;
        let deadline = std::time::Instant::now() + writer.write_wait();
        match writer.reserve_blocking(put, deadline) {
            Ok(reserved) => write_replies(&id, reserved.wait_until(deadline)),
            Err(error) => reserve_replies(&id, error),
        }
    }
}

/// A frame handled as far as it can go without the store.
pub enum Handled {
    Replies(Vec<String>),
    Write(Box<PendingWrite>),
}

/// The `OK` for an event that never got a place in the queue.
fn reserve_replies(id: &str, error: EventStoreError) -> Vec<String> {
    match error {
        EventStoreError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            vec![ok(
                id,
                false,
                "error: event store busy; event not stored, resend it",
            )]
        }
        other => write_replies(id, Err(other)),
    }
}

fn write_replies(id: &str, result: PutResult) -> Vec<String> {
    match result {
        Ok(PutOutcome::Duplicate) => vec![ok(id, true, "duplicate: already stored")],
        // The writer has already announced it, after the commit.
        Ok(PutOutcome::Stored | PutOutcome::Ephemeral) => vec![ok(id, true, "")],
        Err(error) => {
            let reason = match error {
                EventStoreError::Invalid => "invalid: event shape or signature",
                EventStoreError::Oversize => "restricted: event too large",
                EventStoreError::Expired => "invalid: expired event",
                EventStoreError::Retired => "blocked: deleted or superseded event",
                EventStoreError::Full => "restricted: event store full; existing events retained",
                EventStoreError::Unauthorised => {
                    "restricted: this identity is no longer authorised to write"
                }
                EventStoreError::Cancelled => {
                    "error: write cancelled before it was stored; resend it"
                }
                // The wait ran out. The event is queued or in a batch, so it
                // may yet be stored: a resend is answered "duplicate" if so.
                EventStoreError::Io(ref error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    "error: write still pending; it may be stored, resend to confirm"
                }
                _ => "error: event could not be committed",
            };
            vec![ok(id, false, reason)]
        }
    }
}

impl PreparedFrame {
    /// Whether `text` is an EVENT frame worth preparing. Anything else goes
    /// to the session unparsed.
    pub fn is_event_frame(text: &str) -> bool {
        frame_head(text).starts_with("\"EVENT\"") && text.len() <= MAX_RELAY_FRAME_BYTES
    }

    /// CPU only, so it may run off the connection's task without a permit.
    /// A frame that does not parse as an EVENT is left for the session to
    /// answer exactly as before.
    pub fn parse(text: String) -> Self {
        let event = Self::parse_event(&text);
        Self { text, event }
    }

    /// Parse the frame once, straight into its typed parts, with no `Value`
    /// tree: exactly a two-element array whose first element is `"EVENT"`,
    /// then the event from the second element's text. A frame the typed
    /// parse refuses (malformed, or with a duplicate key, which a `Value` map
    /// collapses but the event's own parse refuses) takes the `Value` route
    /// it always took, so every frame gets exactly the answer it got before.
    fn parse_event(text: &str) -> Option<PreparedEvent> {
        if !Self::is_event_frame(text) {
            return None;
        }
        Self::parse_event_typed(text).or_else(|| Self::parse_event_value(text))
    }

    /// The typed parse, or `None` to leave the frame to the `Value` route.
    /// It never accepts a frame that route refused: every member the event
    /// reads is fully parsed by the same parser either way, and a frame with
    /// any other member goes to the `Value` route, because serde skims an
    /// unknown member (no depth limit, no number range or surrogate checks)
    /// where the `Value` route parses it in full.
    fn parse_event_typed(text: &str) -> Option<PreparedEvent> {
        let (name, raw): (std::borrow::Cow<'_, str>, &serde_json::value::RawValue) =
            serde_json::from_str(text).ok()?;
        if name != "EVENT" {
            return None;
        }
        // The id exactly as the frame spelt it (as `value.get("id")` read
        // it): only an object has one, and only a 64-character string counts.
        let probe = serde_json::from_str::<FrameId>(raw.get()).unwrap_or_default();
        if probe.unknown {
            return None;
        }
        let event = serde_json::from_str::<Event>(raw.get()).ok()?;
        let id = probe.id.filter(|id| id.len() == 64).unwrap_or_default();
        Some(PreparedEvent::checked(id, event))
    }

    /// The route every frame took before: a `Value` tree, then the event.
    fn parse_event_value(text: &str) -> Option<PreparedEvent> {
        let Value::Array(mut parts) = serde_json::from_str::<Value>(text).ok()? else {
            return None;
        };
        if parts.len() != 2 || parts[0].as_str() != Some("EVENT") {
            return None;
        }
        let value = parts.pop()?;
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| s.len() == 64)
            .unwrap_or("")
            .to_owned();
        let event = serde_json::from_value::<Event>(value).ok()?;
        Some(PreparedEvent::checked(id, event))
    }

    /// Whether the frame parsed as an EVENT.
    pub fn is_event(&self) -> bool {
        self.event.is_some()
    }

    /// Whether the frame parsed as an EVENT whose signature failed.
    pub fn has_bad_signature(&self) -> bool {
        self.event.as_ref().is_some_and(|event| !event.signature_ok)
    }
}

/// The `id` member of an event object, if it is a string, and whether the
/// object has members the event does not read. Only a JSON object has an id:
/// an event in array form has none, as `Value::get` found none.
#[derive(Default)]
struct FrameId {
    id: Option<String>,
    /// Whether the object has a member the event does not read.
    unknown: bool,
}

/// The members an event object has; anything else is unknown.
const EVENT_MEMBERS: [&str; 7] = [
    "id",
    "pubkey",
    "created_at",
    "kind",
    "tags",
    "content",
    "sig",
];

impl<'de> serde::Deserialize<'de> for FrameId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = FrameId;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an event object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                // With duplicate keys the last wins, as in a `Value` map;
                // the event itself refuses duplicates in any case.
                let mut probe = FrameId::default();
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    if key == "id" {
                        probe.id = map.next_value::<Value>()?.as_str().map(str::to_owned);
                    } else {
                        probe.unknown |= !EVENT_MEMBERS.contains(&key.as_ref());
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(probe)
            }
        }
        deserializer.deserialize_map(Visit)
    }
}

/// Longest CLOSE frame [`RelaySession::try_close`] answers on the caller's
/// thread. A subscription id is at most 64 characters, so a real CLOSE is far
/// shorter; a longer one is parsed under a work permit, as before.
pub const MAX_INLINE_CLOSE_BYTES: usize = 1024;

/// What follows the opening `[` of a frame, past any JSON whitespace on
/// either side of it: the start of the message name. Anything that is not an
/// array gives the empty string.
fn frame_head(text: &str) -> &str {
    text.trim_start()
        .strip_prefix('[')
        .map_or("", str::trim_start)
}

/// Whether a text frame could open a live subscription. Conservative: only
/// frames whose first element is literally `"EVENT"`, `"AUTH"`, `"CLOSE"`
/// or `"COUNT"` (with any spacing) are ruled out, so escaped spellings still
/// attach to the live channel.
pub fn frame_may_subscribe(text: &str) -> bool {
    let head = frame_head(text);
    !["\"EVENT\"", "\"AUTH\"", "\"CLOSE\"", "\"COUNT\""]
        .iter()
        .any(|prefix| head.starts_with(prefix))
}

pub fn frame(value: Value) -> String {
    value.to_string()
}
pub fn ok(id: &str, accepted: bool, reason: &str) -> String {
    frame(json!(["OK", id, accepted, reason]))
}
pub fn closed(id: &str, reason: &str) -> String {
    frame(json!(["CLOSED", id, reason]))
}
pub fn notice(reason: &str) -> String {
    frame(json!(["NOTICE", reason]))
}
pub fn neg_err(id: &str, reason: &str) -> String {
    frame(json!(["NEG-ERR", id, reason]))
}
fn fresh_challenge(previous: Option<&str>) -> String {
    loop {
        let challenge = Keys::generate().public_key().to_hex();
        if previous != Some(challenge.as_str()) {
            return challenge;
        }
    }
}

pub fn subscription_id(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|id| !id.is_empty() && id.chars().count() <= MAX_SUBSCRIPTION_ID_CHARS)
}

/// NIP-77 carries the negentropy binary protocol as lower-case hex. Keeping
/// parsing stricter than a general hex decoder gives a cheap, deterministic
/// frame bound before any reconciliation state is touched.
pub fn decode_negentropy_message(value: &Value) -> Option<Vec<u8>> {
    let text = value.as_str()?;
    if text.len() > MAX_NEGENTROPY_MESSAGE_HEX
        || text.len() % 2 != 0
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(text).ok()
}

impl RelaySession {
    pub fn challenge_frame(&self) -> String {
        frame(json!(["AUTH", self.challenge]))
    }

    /// The NIP-42 challenge an AUTH must answer next: what
    /// [`Self::challenge_frame`] sends.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// The URL an AUTH's `relay` tag must name.
    pub fn relay_url(&self) -> &Url {
        &self.relay_url
    }

    /// The relay this session belongs to.
    pub fn relay(&self) -> &Arc<EventRelay> {
        &self.relay
    }

    /// Whether a guest's live-delivery verdict is cached, for tests and
    /// diagnostics. Keepers and the public door are never cached.
    pub fn has_cached_live_verdict(&self) -> bool {
        self.live_cache.is_some()
    }
    fn auth_failure(&self, id: &str, reason: &str) -> Vec<String> {
        let mut replies = vec![ok(id, false, reason)];
        // A client that has not authenticated yet may retry only with the
        // replacement challenge. Once an AUTH has succeeded, emitting it
        // again would spur an unnecessary signer prompt on an open socket.
        if self.authenticated.is_empty() {
            replies.push(self.challenge_frame());
        }
        replies
    }
    fn authorised(&self) -> bool {
        self.authenticated.iter().any(|k| self.relay.access.owns(k))
    }

    /// [`Self::authorised`] without storage: `None` when the keeper set is
    /// due a refresh, which the caller makes under a work permit.
    fn try_authorised(&self) -> Option<bool> {
        let mut stale = false;
        for key in &self.authenticated {
            match self.relay.access.try_owns(key) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => stale = true,
            }
        }
        (!stale).then_some(false)
    }

    fn identity(&self) -> Option<PublicKey> {
        self.authenticated.iter().next().copied()
    }

    /// [`Self::authorised`], with a keeper set that could not be read reported as
    /// such rather than as "not a keeper". A key that is a keeper wins over
    /// an error on another.
    fn authorised_checked(&self) -> Result<bool, AuthorityUnavailable> {
        authorised_checked(self.relay.access.as_ref(), &self.authenticated)
    }

    fn guest_scopes(&self, now: u64) -> Option<Vec<GuestScope>> {
        // Failing closed: an authority that cannot be read grants nothing.
        self.guest_scopes_checked(now).ok().flatten()
    }

    /// The scopes a non-keeper holds, or `Err` if the keeper set or
    /// the scopes could not be read (which is not "no scopes").
    fn guest_scopes_checked(
        &self,
        now: u64,
    ) -> Result<Option<Vec<GuestScope>>, AuthorityUnavailable> {
        if self.visibility != Visibility::Sheltered || self.authorised_checked()? {
            return Ok(None);
        }
        self.granted_scopes_checked(now)
    }

    /// The grant half of [`Self::guest_scopes_checked`], for a caller that
    /// has just established the identity is not a keeper.
    fn granted_scopes_checked(
        &self,
        now: u64,
    ) -> Result<Option<Vec<GuestScope>>, AuthorityUnavailable> {
        let (Some(identity), Some(guests)) = (self.identity(), self.relay.guests.as_ref()) else {
            return Ok(None);
        };
        let scopes = guests.scopes(&identity, now)?;
        Ok(Some(scopes).filter(|scopes| !scopes.is_empty()))
    }
    fn refusal(&self) -> &'static str {
        refusal_for(&self.authenticated, self.access_refused)
    }
    /// Used by the socket adapter before sending a private batch. Revocation
    /// invalidates existing subscriptions as well as new requests.
    pub fn can_read(&self) -> bool {
        self.visibility == Visibility::Public || self.authorised()
    }

    pub fn can_read_at(&self, now: u64) -> bool {
        self.can_read() || self.guest_scopes(now).is_some()
    }

    /// A locked non-keeper identity. This remains true after its final grant
    /// is revoked, so a change notification can retire the socket.
    pub fn is_guest_identity(&self) -> bool {
        self.visibility == Visibility::Sheltered && self.identity().is_some() && !self.authorised()
    }

    /// When the guest's authority lapses, from the grants it authenticated
    /// on, with no storage read. The snapshot is also the authority: every
    /// authority change and heartbeat compares it with the stored grants
    /// ([`Self::authority_is_current`]) and retires the socket on any
    /// difference, so while this session lives its earliest grant expiry is
    /// the one it authenticated with. `None` for keepers and the public door.
    pub fn guest_expiry(&self) -> Option<u64> {
        self.guest_snapshot
            .as_ref()?
            .iter()
            .map(|scope| scope.expires_at)
            .min()
    }

    pub fn authority_is_current(&self, now: u64) -> bool {
        let Some(_) = self.identity() else {
            return true;
        };
        if self.authenticated_as_keeper {
            self.authorised()
        } else {
            !self.authorised() && self.guest_snapshot == self.guest_scopes(now)
        }
    }

    /// Whether any REQ is open. The transport attaches to the live channel
    /// only while this is true.
    pub fn has_subscriptions(&self) -> bool {
        !self.subscriptions.is_empty()
    }

    /// Forget the cached live verdict. The transport calls this when an
    /// authority change fires; the stamp check already notices it, so this
    /// is a second guard rather than the only one.
    pub fn invalidate_live_access(&mut self) {
        self.live_cache = None;
    }

    pub fn close_subscriptions(&mut self, reason: &str) -> Vec<String> {
        self.live_cache = None;
        let replies = self
            .subscriptions
            .keys()
            .map(|id| closed(id, reason))
            .collect();
        self.subscriptions.clear();
        replies
    }

    /// Whether this socket has completed a successful keeper AUTH.
    pub fn is_authenticated(&self) -> bool {
        !self.authenticated.is_empty()
    }

    /// Spend one inbound WebSocket frame from the rolling minute allowance.
    ///
    /// The transport calls this for control and malformed frames as well as
    /// text. Keeping the counter on the session makes all frame types share
    /// the same budget as NIP-01 messages.
    pub fn admit_frame(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.window) >= 60 {
            self.window = now;
            self.frames = 0;
        }
        if self.frames >= self.relay.frame_limit {
            return false;
        }
        self.frames += 1;
        true
    }

    /// NIP-77 frames trigger set reconciliation rather than simple event
    /// lookup. Keep a tighter independent budget so ordinary NIP-01 traffic
    /// cannot turn a permitted socket into a sustained CPU work queue.
    fn admit_negentropy_round(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.negentropy_window) >= 60 {
            self.negentropy_window = now;
            self.negentropy_rounds = 0;
        }
        if self.negentropy_rounds >= MAX_NEGENTROPY_ROUNDS_PER_MINUTE {
            return false;
        }
        self.negentropy_rounds += 1;
        true
    }

    pub fn handle(&mut self, text: &str, now: u64) -> Vec<String> {
        if !self.admit_frame(now) {
            return vec![notice("rate-limited: slow down")];
        }
        self.handle_admitted(text, now)
    }

    /// An EVENT frame the transport has already parsed and verified, whose
    /// signature failed, from a session that is authenticated: the refusal,
    /// without a work permit. A session that has not authenticated gets the
    /// ordinary path, which answers with the authentication refusal.
    pub fn refuse_unverified(&self, prepared: &PreparedFrame) -> Option<Vec<String>> {
        let event = prepared.event.as_ref()?;
        (!event.signature_ok && self.is_authenticated())
            .then(|| vec![ok(&event.id, false, "invalid: event shape or signature")])
    }

    /// Handle a frame prepared by [`PreparedFrame::parse`], already admitted.
    pub fn handle_prepared(&mut self, prepared: PreparedFrame, now: u64) -> Vec<String> {
        match self.begin_prepared(prepared, now) {
            Handled::Replies(replies) => replies,
            Handled::Write(write) => write.commit_blocking(),
        }
    }

    /// [`Self::handle_prepared`] up to the store write. An EVENT that passes
    /// every check comes back as a [`PendingWrite`], to be committed without
    /// any work permit held; everything else is already answered.
    pub fn begin_prepared(&mut self, prepared: PreparedFrame, now: u64) -> Handled {
        match prepared.event {
            Some(event) => {
                let signature = event.signature();
                self.begin_publish(event.event, &event.id, signature, now)
            }
            // Whatever the spelling of the frame, an EVENT still comes back
            // as a pending write, to be committed with no permit held.
            None => self.dispatch(&prepared.text, now),
        }
    }

    /// A CLOSE frame, already admitted, answered on the caller's thread: it
    /// needs no store, no authority check and no work permit, and only removes
    /// a subscription. `None` for any other frame, and for a CLOSE frame
    /// longer than [`MAX_INLINE_CLOSE_BYTES`] or spelt with escapes, which
    /// take the ordinary path and are answered exactly as there.
    pub fn try_close(&mut self, prepared: &PreparedFrame) -> Option<Vec<String>> {
        let text = prepared.text.as_str();
        if prepared.event.is_some()
            || text.len() > MAX_INLINE_CLOSE_BYTES
            || !frame_head(text).starts_with("\"CLOSE\"")
        {
            return None;
        }
        let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(text) else {
            return None;
        };
        if parts.len() != 2 || parts[0].as_str() != Some("CLOSE") {
            return None;
        }
        Some(self.close(&parts[1]))
    }

    /// `["CLOSE", id]`: forget the subscription, with no reply.
    fn close(&mut self, id: &Value) -> Vec<String> {
        if let Some(id) = id.as_str() {
            self.subscriptions.remove(id);
        }
        vec![]
    }

    /// Handle a text frame whose transport has already admitted it.
    pub fn handle_admitted(&mut self, text: &str, now: u64) -> Vec<String> {
        match self.dispatch(text, now) {
            Handled::Replies(replies) => replies,
            Handled::Write(write) => write.commit_blocking(),
        }
    }

    /// [`Self::handle_admitted`] up to the store write.
    fn dispatch(&mut self, text: &str, now: u64) -> Handled {
        if text.len() > MAX_RELAY_FRAME_BYTES {
            return Handled::Replies(vec![notice("restricted: frame too large")]);
        }
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return Handled::Replies(vec![notice("invalid: expected JSON")]);
        };
        let Some(parts) = value.as_array() else {
            return Handled::Replies(vec![notice("invalid: expected a message array")]);
        };
        let replies = match parts.first().and_then(Value::as_str) {
            Some("AUTH") if parts.len() == 2 => self.authenticate(&parts[1], now),
            Some("EVENT") if parts.len() == 2 => return self.publish(&parts[1], now),
            Some("REQ") if parts.len() >= 3 => self.request(parts, now),
            Some("COUNT") if parts.len() >= 3 => self.count(parts, now),
            Some(verb @ ("REQ" | "COUNT")) if parts.len() == 2 => {
                match subscription_id(&parts[1]) {
                    Some(id) => {
                        // As for any refused REQ, an old subscription of that id ends.
                        if verb == "REQ" {
                            self.subscriptions.remove(id);
                        }
                        vec![closed(id, "invalid: at least one filter is required")]
                    }
                    None => vec![notice("invalid: subscription id")],
                }
            }
            Some("NEG-OPEN") if parts.len() == 4 => self.neg_open(parts, now),
            Some("NEG-MSG") if parts.len() == 3 => self.neg_msg(parts, now),
            Some("NEG-CLOSE") if parts.len() == 2 => self.neg_close(&parts[1]),
            Some("CLOSE") if parts.len() == 2 => self.close(&parts[1]),
            _ => vec![notice(
                "unsupported: use AUTH, EVENT, REQ, COUNT, CLOSE, NEG-OPEN, NEG-MSG or NEG-CLOSE",
            )],
        };
        Handled::Replies(replies)
    }

    fn authenticate(&mut self, value: &Value, now: u64) -> Vec<String> {
        // AUTH consumes its challenge before any parsing or authority result.
        // The replacement is retained after success, so replay cannot reuse
        // the signed event but an authenticated client sees no second AUTH.
        let next = fresh_challenge(Some(&self.challenge));
        let consumed_challenge = std::mem::replace(&mut self.challenge, next);
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| s.len() == 64)
            .unwrap_or("");
        let Ok(event) = serde_json::from_value::<Event>(value.clone()) else {
            return self.auth_failure(id, "invalid: authentication event");
        };
        let tags = |name: &str| {
            event
                .tags
                .iter()
                .filter(|t| t.as_slice().first().is_some_and(|n| n == name))
                .map(|t| t.as_slice())
                .collect::<Vec<_>>()
        };
        let challenge = tags("challenge");
        let relay = tags("relay");
        let matched_challenge = challenge.len() == 1
            && challenge[0].len() == 2
            && challenge[0][1] == consumed_challenge;
        let one_relay = relay.len() == 1 && relay[0].len() == 2;
        let matched_relay = one_relay && names_relay(&relay[0][1], &self.relay_url);
        // In the order the checks have always run: the signature only for
        // the right kind, and once.
        let sound = event.kind.as_u16() == 22242
            && event.verify().is_ok()
            && event.created_at.as_secs().abs_diff(now) <= AUTH_WINDOW_SECS
            && matched_challenge;
        if !sound || !matched_relay {
            // Only its one relay tag let it down, so the URL the client
            // connected to may not be the one this relay was given.
            if sound && one_relay {
                self.relay
                    .auth_relay_mismatches
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return self.auth_failure(
                id,
                "invalid: authentication challenge, relay, time or signature",
            );
        }
        if self
            .identity()
            .is_some_and(|authenticated| authenticated != event.pubkey)
        {
            return self.auth_failure(id, "restricted: this socket is locked to another identity");
        }
        let keeper = self.relay.access.owns(&event.pubkey);
        let guest_scopes = (self.visibility == Visibility::Sheltered && !keeper)
            .then(|| {
                self.relay
                    .guests
                    .as_ref()?
                    .scopes(&event.pubkey, now)
                    .ok()
                    .filter(|scopes| !scopes.is_empty())
            })
            .flatten();
        if !keeper && guest_scopes.is_none() {
            if self.relay.final_access_refusal && self.authenticated.is_empty() {
                // Nothing prompts a stock client to sign again, and the
                // challenge it answered is still the one to answer.
                self.challenge = consumed_challenge;
                self.access_refused = true;
                return vec![ok(id, false, NO_ACCESS)];
            }
            return self.auth_failure(id, NO_ACCESS);
        }
        self.access_refused = false;
        self.authenticated.insert(event.pubkey);
        self.authenticated_as_keeper = keeper;
        self.guest_snapshot = guest_scopes;
        self.live_cache = None;
        self.write_authority = None;
        vec![ok(id, true, "")]
    }

    fn publish(&mut self, value: &Value, now: u64) -> Handled {
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| s.len() == 64)
            .unwrap_or("");
        let Ok(event) = serde_json::from_value::<Event>(value.clone()) else {
            return Handled::Replies(vec![ok(id, false, "invalid: event")]);
        };
        self.begin_publish(event, id, SignatureCheck::Unchecked, now)
    }

    /// Everything after an EVENT frame's parse, up to the store write. A
    /// `Failed` signature means the transport already verified it and it was
    /// bad; such an event still meets the authority checks first, so a
    /// stranger is told to authenticate rather than that the event is bad.
    fn begin_publish(
        &mut self,
        event: Event,
        id: &str,
        signature: SignatureCheck,
        now: u64,
    ) -> Handled {
        // Read before the checks: a source bumps its generation after its
        // write commits, so this can only be older than what they see, and a
        // write whose stamp is still current was judged on current authority.
        let stamp = self.authority.stamp();
        let mut valid_until = u64::MAX;
        match self.authorise_publish(&event, id, signature, now, &mut valid_until) {
            Some(replies) => Handled::Replies(replies),
            None => self.queue_publish(event, id, signature, now, (stamp, valid_until)),
        }
    }

    fn write_authority(&mut self) -> Arc<WriteAuthority> {
        if self.write_authority.is_none() {
            self.write_authority = Some(Arc::new(WriteAuthority {
                access: Arc::clone(&self.relay.access),
                guests: self.relay.guests.clone(),
                authority_events: self.relay.authority_events.clone(),
                public_kinds: Arc::clone(&self.relay.public_kinds),
                visibility: self.visibility,
                keys: Some(self.authenticated.clone()),
                generations: self.authority.clone(),
                clock: Arc::clone(&self.relay.clock),
            }));
        }
        self.write_authority
            .as_ref()
            .map(Arc::clone)
            .expect("set just above")
    }

    fn queue_publish(
        &mut self,
        event: Event,
        id: &str,
        signature: SignatureCheck,
        now: u64,
        (stamp, valid_until): ([u64; 3], u64),
    ) -> Handled {
        let put = match signature {
            SignatureCheck::Verified => PreparedPut::verified(self.visibility, event, now, false),
            _ => PreparedPut::new(self.visibility, event, now, false),
        };
        match put {
            // Never stored, so nothing for the writer to commit: no queue
            // place and no wait for a sync. It goes live as it always did,
            // after the checks above and before the reply.
            Ok(put) if put.is_ephemeral() => {
                let (event, json) = put.into_parts();
                announce_on(
                    &self.relay.live,
                    &self.relay.hook,
                    self.visibility,
                    event,
                    json,
                );
                Handled::Replies(vec![ok(id, true, "")])
            }
            Ok(put) => {
                let recheck = self.write_authority().recheck(stamp, valid_until, now);
                Handled::Write(Box::new(PendingWrite {
                    id: id.to_owned(),
                    put: put.with_recheck(recheck),
                    writer: Arc::clone(&self.relay.writer),
                }))
            }
            Err(error) => Handled::Replies(write_replies(id, Err(error))),
        }
    }

    /// The checks before the write: `Some(replies)` is a refusal (or a handled
    /// grant), `None` lets the event through to the store, with `valid_until`
    /// lowered to the earliest expiry of the grants that admitted it.
    fn authorise_publish(
        &mut self,
        event: &Event,
        id: &str,
        signature: SignatureCheck,
        now: u64,
        valid_until: &mut u64,
    ) -> Option<Vec<String>> {
        if let Some(events) = &self.relay.authority_events
            && events.is_authority(event)
        {
            let request = InstallRequest {
                event,
                visibility: self.visibility,
                signature,
                now,
                authenticated: &self.authenticated,
                access_refused: self.access_refused,
                access: self.relay.access.as_ref(),
            };
            if let Some(answer) = events.install(&request) {
                return Some(vec![match answer {
                    Ok(()) => ok(id, true, ""),
                    Err(reason) => ok(id, false, &reason),
                }]);
            }
        }
        let guest_scopes = self.guest_scopes(now);
        if !self.authorised() && guest_scopes.is_none() {
            return Some(vec![ok(id, false, self.refusal())]);
        }
        // NIP-70: a protected event is taken only from its own author,
        // authenticated on this connection. Neither door's other rules
        // amount to that: the public door takes any keeper key's events and
        // the sheltered door keeps events under any outer key. A guest signs
        // as its device but authenticates as its persona, so it never can.
        if is_protected(event) && !self.authenticated.contains(&event.pubkey) {
            return Some(vec![ok(
                id,
                false,
                "restricted: a protected event must be published by its author",
            )]);
        }
        if self.visibility == Visibility::Public
            && (!self.relay.access.owns(&event.pubkey)
                || !self.relay.public_kinds.contains(&event.kind.as_u16()))
        {
            return Some(vec![ok(
                id,
                false,
                "restricted: public door accepts keeper-authored public kinds only",
            )]);
        }
        if let Some(scopes) = guest_scopes {
            match event_room(event).and_then(|room| guest_valid_until(event, room, &scopes)) {
                Some(until) => *valid_until = until,
                None => {
                    return Some(vec![ok(
                        id,
                        false,
                        "restricted: event is outside the circle grant",
                    )]);
                }
            }
        }
        if signature == SignatureCheck::Failed {
            return Some(vec![ok(id, false, "invalid: event shape or signature")]);
        }
        None
    }

    fn request(&mut self, parts: &[Value], now: u64) -> Vec<String> {
        let Some(id) = subscription_id(&parts[1]) else {
            return vec![notice("invalid: subscription id")];
        };
        // A rejected replacement must not leave the old subscription active.
        self.subscriptions.remove(id);
        if !self.can_read_at(now) {
            return vec![closed(id, self.refusal())];
        }
        if self.subscriptions.len() >= MAX_SUBSCRIPTIONS || parts.len() - 2 > MAX_FILTERS {
            return vec![closed(id, "restricted: too many subscriptions or filters")];
        }
        let raw_filters = &parts[2..];
        let mut filters = Vec::new();
        let guest_scopes = self.guest_scopes(now);
        for raw in raw_filters {
            if let Some(fault) = filter_fault(raw) {
                return vec![closed(id, fault)];
            }
            if let Some(scopes) = &guest_scopes
                && !guest_filter_allowed(raw, scopes)
            {
                return vec![closed(id, "restricted: filter is outside the circle grant")];
            }
            let Ok(filter) = serde_json::from_value::<Filter>(raw.clone()) else {
                return vec![closed(id, "invalid: filter")];
            };
            filters.push(filter);
        }
        // Each event as stored, keyed newest first and then by id, as the
        // built events were: lowercase hex orders as the id's bytes do.
        let mut found = BTreeMap::new();
        for filter in &filters {
            match self.relay.store.query_stored(self.visibility, filter, now) {
                Ok(events) => {
                    for event in events {
                        found.insert(
                            (std::cmp::Reverse(event.created_at), event.id.clone()),
                            event,
                        );
                        if found.len() > MAX_QUERY_EVENTS {
                            found.pop_last();
                        }
                    }
                }
                Err(EventStoreError::Query) => return vec![closed(id, TOO_LARGE)],
                Err(_) => return vec![closed(id, "error: stored events unavailable")],
            }
        }
        if !self.can_read_at(now) {
            return vec![closed(id, self.refusal())];
        }
        // Re-evaluate the exact scope after storage work. This prevents a
        // replacement grant, expiry, or keeper-set change from releasing a
        // batch or retaining a subscription built under the old authority.
        let guest_scopes = self.guest_scopes(now);
        if let Some(scopes) = &guest_scopes
            && raw_filters
                .iter()
                .any(|raw| !guest_filter_allowed(raw, scopes))
        {
            return vec![closed(
                id,
                "restricted: authority changed during the request",
            )];
        }
        let mut bytes = 0;
        let mut replies = Vec::new();
        for event in found.into_values() {
            // The same rule as `guest_event_readable`, on the kind and room
            // read from the stored JSON.
            if let Some(scopes) = &guest_scopes
                && !guest_readable(event.kind, event.room.as_deref(), scopes)
            {
                continue;
            }
            // The stored JSON, spliced as a live frame is.
            let reply = event_frame(id, &event.json);
            if bytes + reply.len() > MAX_REQ_REPLY_BYTES {
                break;
            }
            bytes += reply.len();
            replies.push(reply);
        }
        replies.push(frame(json!(["EOSE", id])));
        self.subscriptions.insert(id.to_string(), filters);
        replies
    }

    /// NIP-45. The same filters as `REQ`, answered with one number: no
    /// subscription is kept and no event leaves the store. Keepers and the
    /// public door only. A guest's read rule is applied to each event after
    /// its query (a room is an event's single `d` tag, which the tag index
    /// cannot express), so a count of what a guest's filter matches could
    /// reveal events that rule hides.
    fn count(&mut self, parts: &[Value], now: u64) -> Vec<String> {
        let Some(id) = subscription_id(&parts[1]) else {
            return vec![notice("invalid: subscription id")];
        };
        if !self.can_read() {
            if self.guest_scopes(now).is_some() {
                return vec![closed(id, "restricted: COUNT is for keepers only")];
            }
            return vec![closed(id, self.refusal())];
        }
        if parts.len() - 2 > MAX_FILTERS {
            return vec![closed(id, "restricted: too many filters")];
        }
        let mut filters = Vec::new();
        for raw in &parts[2..] {
            if let Some(fault) = filter_fault(raw) {
                return vec![closed(id, fault)];
            }
            let Ok(filter) = serde_json::from_value::<Filter>(raw.clone()) else {
                return vec![closed(id, "invalid: filter")];
            };
            filters.push(filter);
        }
        let count = match self.relay.store.count(self.visibility, &filters, now) {
            Ok(count) => count,
            Err(EventStoreError::Query) => return vec![closed(id, TOO_LARGE)],
            Err(_) => return vec![closed(id, "error: count unavailable")],
        };
        // As for REQ: a keeper removed while the count ran learns nothing.
        if !self.can_read() {
            return vec![closed(id, self.refusal())];
        }
        if count > MAX_EXACT_COUNT {
            return vec![frame(
                json!(["COUNT", id, {"count": MAX_EXACT_COUNT, "approximate": true}]),
            )];
        }
        vec![frame(json!(["COUNT", id, {"count": count}]))]
    }

    /// Open a bounded NIP-77 reconciliation. It deliberately uses the same
    /// filter admission and post-query authority recheck as `REQ`: NIP-77
    /// exposes event IDs and timestamps, so it is a read operation even
    /// though it transfers no event bodies.
    fn neg_open(&mut self, parts: &[Value], now: u64) -> Vec<String> {
        let Some(id) = subscription_id(&parts[1]) else {
            return vec![notice("invalid: negentropy subscription id")];
        };
        if !self.admit_negentropy_round(now) {
            return vec![neg_err(id, "rate-limited: slow down")];
        }
        // A replacement must not keep a previous reconciliation state alive.
        self.negentropy.remove(id);
        if !self.can_read_at(now) {
            return vec![neg_err(id, self.refusal())];
        }
        if self.negentropy.len() >= MAX_NEGENTROPY_SUBSCRIPTIONS {
            return vec![neg_err(id, "restricted: too many negentropy subscriptions")];
        }
        let raw_filter = &parts[2];
        if let Some(fault) = filter_fault(raw_filter) {
            return vec![neg_err(id, fault)];
        }
        let guest_scopes = self.guest_scopes(now);
        if let Some(scopes) = &guest_scopes
            && !guest_filter_allowed(raw_filter, scopes)
        {
            return vec![neg_err(
                id,
                "restricted: filter is outside the circle grant",
            )];
        }
        let Some(initial) = decode_negentropy_message(&parts[3]) else {
            return vec![neg_err(id, "invalid: negentropy message")];
        };
        let Ok(filter) = serde_json::from_value::<Filter>(raw_filter.clone()) else {
            return vec![neg_err(id, "invalid: filter")];
        };
        let events = match self.relay.store.query(self.visibility, &filter, now) {
            Ok(events) if events.len() <= MAX_NEGENTROPY_EVENTS => events,
            Ok(_) => {
                return vec![neg_err(
                    id,
                    "restricted: too many events; narrow the filter",
                )];
            }
            Err(EventStoreError::Query) => return vec![neg_err(id, TOO_LARGE)],
            Err(_) => return vec![neg_err(id, "error: stored events unavailable")],
        };
        if !self.can_read_at(now) {
            return vec![neg_err(id, self.refusal())];
        }
        let guest_scopes = self.guest_scopes(now);
        if let Some(scopes) = &guest_scopes
            && !guest_filter_allowed(raw_filter, scopes)
        {
            return vec![neg_err(
                id,
                "restricted: authority changed during the request",
            )];
        }
        let mut storage = NegentropyStorageVector::with_capacity(events.len());
        for event in events {
            // `query` selected the partition and filter, but a replacement
            // grant could remove one event's guest scope while it ran.
            if let Some(scopes) = &guest_scopes
                && !guest_event_readable(&event, scopes)
            {
                return vec![neg_err(
                    id,
                    "restricted: authority changed during the request",
                )];
            }
            if storage
                .insert(
                    event.created_at.as_secs(),
                    NegentropyId::from_byte_array(event.id.to_bytes()),
                )
                .is_err()
            {
                return vec![neg_err(id, "error: negentropy index unavailable")];
            }
        }
        if storage.seal().is_err() {
            return vec![neg_err(id, "error: negentropy index unavailable")];
        }
        let mut state = match Negentropy::owned(storage, MAX_NEGENTROPY_MESSAGE_BYTES as u64) {
            Ok(state) => state,
            Err(_) => return vec![neg_err(id, "error: negentropy state unavailable")],
        };
        let message = match state.reconcile(&initial) {
            Ok(message) if message.len() <= MAX_NEGENTROPY_MESSAGE_BYTES => message,
            _ => return vec![neg_err(id, "invalid: negentropy message")],
        };
        self.negentropy.insert(
            id.to_owned(),
            NegentropySubscription {
                state,
                raw_filter: raw_filter.clone(),
            },
        );
        vec![frame(json!(["NEG-MSG", id, hex::encode(message)]))]
    }

    /// Continue only a previously admitted reconciliation. A malformed frame,
    /// expired grant, or changed grant drops that state before replying, so a
    /// later frame cannot continue an authority snapshot that no longer holds.
    fn neg_msg(&mut self, parts: &[Value], now: u64) -> Vec<String> {
        let Some(id) = subscription_id(&parts[1]) else {
            return vec![notice("invalid: negentropy subscription id")];
        };
        let Some(message) = decode_negentropy_message(&parts[2]) else {
            self.negentropy.remove(id);
            return vec![neg_err(id, "invalid: negentropy message")];
        };
        if !self.admit_negentropy_round(now) {
            return vec![neg_err(id, "rate-limited: slow down")];
        }
        if !self.can_read_at(now) {
            self.negentropy.remove(id);
            return vec![neg_err(id, self.refusal())];
        }
        let Some(raw_filter) = self
            .negentropy
            .get(id)
            .map(|subscription| subscription.raw_filter.clone())
        else {
            return vec![neg_err(id, "error: subscription not found")];
        };
        let guest_scopes = self.guest_scopes(now);
        if let Some(scopes) = &guest_scopes
            && !guest_filter_allowed(&raw_filter, scopes)
        {
            self.negentropy.remove(id);
            return vec![neg_err(id, "restricted: sheltered authority changed")];
        }
        let reply = match self
            .negentropy
            .get_mut(id)
            .expect("negentropy subscription retained after scope check")
            .state
            .reconcile(&message)
        {
            Ok(reply) if reply.len() <= MAX_NEGENTROPY_MESSAGE_BYTES => reply,
            _ => {
                self.negentropy.remove(id);
                return vec![neg_err(id, "invalid: negentropy message")];
            }
        };
        // There is no blocking work after the previous check, but retain the
        // same fail-closed recheck before writing an ID-bearing reply.
        if !self.can_read_at(now) {
            self.negentropy.remove(id);
            return vec![neg_err(id, self.refusal())];
        }
        vec![frame(json!(["NEG-MSG", id, hex::encode(reply)]))]
    }

    fn neg_close(&mut self, value: &Value) -> Vec<String> {
        if let Some(id) = subscription_id(value) {
            self.negentropy.remove(id);
        }
        vec![]
    }

    /// The live-delivery verdict at `now` if it is known without a database
    /// read: the public door, a keeper (whose key set is cached by its source
    /// generation), or a guest whose cached verdict is still valid. `None`
    /// means a guest's verdict has to be refreshed first.
    fn live_access_cached(&mut self, now: u64) -> Option<LiveAccess> {
        if self.visibility == Visibility::Public {
            return Some(LiveAccess::Open);
        }
        let stamp = self.authority.stamp();
        // A keeper access source that cannot signal gets its keeper check
        // on every event, exactly as keepers do.
        let signalled = self.authority.signals_keepers();
        if !signalled && self.authorised() {
            self.live_cache = None;
            return Some(LiveAccess::Open);
        }
        if let Some(cache) = &self.live_cache
            && cache.stamp == stamp
            && now < cache.valid_until
        {
            return Some(cache.access());
        }
        // A stale keeper set is refreshed by the caller under a permit, not
        // here: this runs on the connection task.
        if signalled && self.try_authorised()? {
            self.live_cache = None;
            return Some(LiveAccess::Open);
        }
        None
    }

    /// The live-delivery verdict at `now`, cached for guests. The stamp is
    /// read before any query, so a change landing mid-refresh is seen again
    /// on the next event rather than lost.
    fn live_access(&mut self, now: u64) -> LiveAccess {
        if let Some(access) = self.live_access_cached(now) {
            return access;
        }
        // A keeper whose key set needs refreshing was not answered by
        // `live_access_cached`: refresh it here, under the permit, and never
        // let it fall through to the guest path, which would cache it as
        // having no scopes.
        match self.authorised_checked() {
            Ok(true) => {
                self.live_cache = None;
                return LiveAccess::Open;
            }
            Ok(false) => {}
            // A keeper set that could not be read is not "not a keeper": say so,
            // and keep nothing, or a cached Denied would outlive the error.
            Err(AuthorityUnavailable) => {
                self.live_cache = None;
                return LiveAccess::Unavailable;
            }
        }
        self.live_cache = None;
        let stamp = self.authority.stamp();
        let scopes = match self.granted_scopes_checked(now) {
            Ok(scopes) => scopes,
            Err(AuthorityUnavailable) => return LiveAccess::Unavailable,
        };
        let valid_until = scopes
            .iter()
            .flatten()
            .map(|scope| scope.expires_at)
            .min()
            .unwrap_or(u64::MAX);
        let cache = LiveAccessCache {
            stamp,
            valid_until,
            scopes,
        };
        let access = cache.access();
        self.live_cache = Some(cache);
        access
    }

    /// Whether a live batch may still reach the wire. It shares the verdict
    /// `on_live` used, with the same invalidation, and costs no query while
    /// that verdict stands.
    pub fn can_read_live(&mut self, now: u64) -> bool {
        self.live_access(now).permits()
    }

    /// [`Self::can_read_live`] without touching storage: `None` when the
    /// verdict needs a refresh, which the caller does under a work permit.
    pub fn try_can_read(&mut self, now: u64) -> Option<bool> {
        self.live_access_cached(now).map(LiveAccess::permits)
    }

    /// Deliver a live event on the connection's own task: `None` when a
    /// guest's verdict needs refreshing first, in which case the caller runs
    /// [`Self::on_live`] under a work permit instead.
    pub fn try_on_live(&mut self, live: &LiveEvent, now: u64) -> Option<Vec<String>> {
        if self.subscriptions.is_empty() {
            return Some(vec![]);
        }
        let access = self.live_access_cached(now)?;
        Some(self.deliver_live(live, access, now))
    }

    pub fn on_live(&mut self, live: &LiveEvent, now: u64) -> Vec<String> {
        // Nothing to deliver and nothing to close: no authority work at all.
        if self.subscriptions.is_empty() {
            return vec![];
        }
        let access = self.live_access(now);
        self.deliver_live(live, access, now)
    }

    fn deliver_live(&mut self, live: &LiveEvent, access: LiveAccess, now: u64) -> Vec<String> {
        if access == LiveAccess::Unavailable {
            tracing::warn!(
                "sheltered authority could not be read; closing this socket's subscriptions"
            );
            let replies = self
                .subscriptions
                .keys()
                .map(|id| {
                    closed(
                        id,
                        "error: sheltered access could not be checked; query again",
                    )
                })
                .collect();
            self.subscriptions.clear();
            return replies;
        }
        if access == LiveAccess::Denied {
            let replies = self
                .subscriptions
                .keys()
                .map(|id| closed(id, self.refusal()))
                .collect();
            self.subscriptions.clear();
            return replies;
        }
        if live.visibility != self.visibility {
            return vec![];
        }
        if access == LiveAccess::Guest {
            // Fail closed: a guest verdict with no scopes to filter by
            // delivers nothing rather than everything the REQ matches.
            let Some(scopes) = self
                .live_cache
                .as_ref()
                .and_then(|cache| cache.scopes.as_ref())
            else {
                return vec![];
            };
            if !guest_event_readable(&live.event, scopes) {
                return vec![];
            }
        }
        if live.event.tags.iter().any(|t| {
            t.as_slice().first().is_some_and(|n| n == "expiration")
                && t.as_slice()
                    .get(1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|t| t <= now)
        }) {
            return vec![];
        }
        self.subscriptions
            .iter()
            .filter(|(_, filters)| {
                filters
                    .iter()
                    .any(|f| f.match_event(&live.event, MatchEventOptions::default()))
            })
            .map(|(id, _)| live.frame_for(id))
            .collect()
    }
}

impl LiveAccessCache {
    fn access(&self) -> LiveAccess {
        if self.scopes.is_some() {
            LiveAccess::Guest
        } else {
            LiveAccess::Denied
        }
    }
}

/// The refusal for a session without sheltered authority: one that has not
/// authenticated is told to, one that has is told it no longer counts.
/// The AUTH refusal for a key that is neither a keeper nor a guest.
const NO_ACCESS: &str = "restricted: this key has no sheltered access";

fn refusal_for(authenticated: &BTreeSet<PublicKey>, access_refused: bool) -> &'static str {
    if !authenticated.is_empty() {
        "restricted: this identity no longer has sheltered access"
    } else if access_refused {
        NO_ACCESS
    } else {
        "auth-required: authenticate for sheltered access"
    }
}

/// NIP-70: the event carries the `["-"]` tag.
pub fn is_protected(event: &Event) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.as_slice().first().map(String::as_str) == Some("-"))
}

/// The event's room: its single `d` tag of exactly two elements.
fn event_room(event: &Event) -> Option<&str> {
    single_d_value(event.tags.iter().map(|tag| tag.as_slice()))
}

fn guest_event_allowed(event: &Event, scopes: &[GuestScope]) -> bool {
    let Some(room) = event_room(event) else {
        return false;
    };
    guest_event_allowed_in(event, room, scopes)
}

fn guest_event_allowed_in(event: &Event, room: &str, scopes: &[GuestScope]) -> bool {
    guest_valid_until(event, room, scopes).is_some()
}

/// The earliest expiry among the scopes that let `event` be written, or
/// `None` if none does. The earliest is the safe bound: a write is only
/// trusted without a second look while every scope that admitted it stands.
fn guest_valid_until(event: &Event, room: &str, scopes: &[GuestScope]) -> Option<u64> {
    scopes
        .iter()
        .filter(|scope| {
            scope.room == room
                && scope.device == event.pubkey
                && scope.write.contains(&event.kind.as_u16())
        })
        .map(|scope| scope.expires_at)
        .min()
}

/// Whether a guest holding `scopes` may read `event`: in a room one of them
/// names (the event's single `d` tag), of a kind that scope lets it read. The
/// rule every REQ, NEG and live delivery applies to a guest.
pub fn guest_event_readable(event: &Event, scopes: &[GuestScope]) -> bool {
    guest_readable(event.kind.as_u16(), event_room(event), scopes)
}

/// A guest may read an event only in a room one of its scopes names, of a
/// kind that scope lets it read. No room, no read.
fn guest_readable(kind: u16, room: Option<&str>, scopes: &[GuestScope]) -> bool {
    let Some(room) = room else {
        return false;
    };
    scopes
        .iter()
        .any(|scope| scope.room == room && scope.read.contains(&kind))
}

fn guest_filter_allowed(value: &Value, scopes: &[GuestScope]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(kinds) = object.get("kinds").and_then(Value::as_array) else {
        return false;
    };
    let Some(rooms) = object.get("#d").and_then(Value::as_array) else {
        return false;
    };
    if kinds.is_empty() || rooms.is_empty() {
        return false;
    }
    rooms.iter().all(|room| {
        room.as_str().is_some_and(|room| {
            kinds.iter().all(|kind| {
                kind.as_u64().is_some_and(|kind| {
                    u16::try_from(kind).is_ok_and(|kind| {
                        scopes
                            .iter()
                            .any(|scope| scope.room == room && scope.read.contains(&kind))
                    })
                })
            })
        })
    })
}

/// Whether a NIP-42 `relay` tag names `expected`. Both are compared as parsed
/// URLs, so host case and a default port do not matter, and a trailing slash
/// on the path is ignored.
pub fn names_relay(given: &str, expected: &Url) -> bool {
    let Ok(mut given) = Url::parse(given) else {
        return false;
    };
    let mut expected = expected.clone();
    for url in [&mut given, &mut expected] {
        let path = url.path().trim_end_matches('/').to_owned();
        url.set_path(&path);
    }
    given == expected
}

/// Why a client filter is refused, or `None` when it is one this relay serves.
/// The reply uses the NIP-01 prefixes: `invalid:` for a malformed value,
/// `unsupported:` for a field it does not serve and `restricted:` for a
/// list over its bound. An empty list is served and matches nothing.
pub fn filter_fault(value: &Value) -> Option<&'static str> {
    let Some(object) = value.as_object() else {
        return Some("invalid: a filter is a JSON object");
    };
    for (key, value) in object {
        let key = key.as_str();
        if ["since", "until", "limit"].contains(&key) {
            if value.as_u64().is_none() {
                return Some("invalid: since, until and limit are whole numbers");
            }
            continue;
        }
        let tag = key.len() == 2 && key.starts_with('#') && key.as_bytes()[1].is_ascii_alphabetic();
        if !tag && !["ids", "authors", "kinds"].contains(&key) {
            return Some("unsupported: filter field");
        }
        let Some(items) = value.as_array() else {
            return Some("invalid: filter values are a list");
        };
        if items.len() > 256 {
            return Some("restricted: more than 256 values in one filter list");
        }
        let hex = ["ids", "authors", "#e", "#p"].contains(&key);
        let valid = items.iter().all(|v| {
            if key == "kinds" {
                return v.as_u64().is_some_and(|k| k <= u16::MAX as u64);
            }
            let Some(s) = v.as_str() else {
                return false;
            };
            if hex {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            } else {
                s.len() <= 4096
            }
        });
        if !valid {
            return Some(if key == "kinds" {
                "invalid: kinds are numbers from 0 to 65535"
            } else if hex {
                "invalid: ids, authors, #e and #p are 64 lowercase hex characters"
            } else {
                "invalid: tag values are strings of at most 4096 bytes"
            });
        }
    }
    None
}

pub fn valid_filter(value: &Value) -> bool {
    filter_fault(value).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteEventStore;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind, Tag};
    use nostr::types::Timestamp;
    use std::sync::RwLock;
    use tempfile::TempDir;
    const NOW: u64 = 1_900_000_000;

    /// A live event for a test, whose events always serialise.
    fn live_event(visibility: Visibility, event: Arc<Event>) -> LiveEvent {
        LiveEvent::try_new(visibility, event).expect("a test event serialises")
    }

    struct Access(RwLock<BTreeSet<PublicKey>>);
    impl KeeperAccess for Access {
        fn owns(&self, key: &PublicKey) -> bool {
            self.0.read().unwrap().contains(key)
        }
    }
    fn setup() -> (TempDir, Arc<EventRelay>, Arc<Access>, Keys) {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let access = Arc::new(Access(RwLock::new([key.public_key()].into())));
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        let relay = Arc::new(EventRelay::new(store, access.clone()));
        (tmp, relay, access, key)
    }
    fn session(relay: &Arc<EventRelay>, visibility: Visibility) -> RelaySession {
        relay.session(
            visibility,
            Url::parse("wss://relay.example/events").unwrap(),
            NOW,
        )
    }
    fn event(key: &Keys, kind: u16, at: u64, text: &str, tags: &[Vec<String>]) -> Event {
        EventBuilder::new(Kind::from(kind), text)
            .custom_created_at(Timestamp::from_secs(at))
            .tags(tags.iter().cloned().map(|v| Tag::parse(v).unwrap()))
            .finalize(key)
            .unwrap()
    }
    fn auth_event(session: &RelaySession, key: &Keys) -> Event {
        event(
            key,
            22242,
            NOW,
            "",
            &[
                vec!["relay".into(), session.relay_url.to_string()],
                vec!["challenge".into(), session.challenge.clone()],
            ],
        )
    }
    fn send(session: &mut RelaySession, value: Value) -> Vec<Value> {
        let replies = session.handle(&value.to_string(), NOW);
        // Live delivery follows the OK, so wait for it before looking.
        session.relay.flush();
        replies
            .iter()
            .map(|r| serde_json::from_str(r).unwrap())
            .collect()
    }
    fn auth(session: &mut RelaySession, key: &Keys) {
        let e = auth_event(session, key);
        assert_eq!(send(session, json!(["AUTH", e]))[0][2], true);
    }

    fn empty_negentropy_initial() -> (Negentropy<'static, NegentropyStorageVector>, String) {
        let mut storage = NegentropyStorageVector::new();
        storage.seal().unwrap();
        let mut client = Negentropy::owned(storage, MAX_NEGENTROPY_MESSAGE_BYTES as u64).unwrap();
        let initial = hex::encode(client.initiate().unwrap());
        (client, initial)
    }

    #[test]
    fn by_default_a_key_refused_for_access_is_challenged_again() {
        let (_tmp, relay, _access, _key) = setup();
        let mut a = session(&relay, Visibility::Sheltered);
        let stranger = Keys::generate();
        let signed = auth_event(&a, &stranger);
        let replies = send(&mut a, json!(["AUTH", signed]));
        assert_eq!(replies[0][2], false);
        assert_eq!(
            replies[0][3],
            "restricted: this key has no sheltered access"
        );
        assert_eq!(replies[1], json!(["AUTH", a.challenge]));
        let later = event(&stranger, 1, NOW, "", &[]);
        assert_eq!(
            send(&mut a, json!(["EVENT", later]))[0][3],
            "auth-required: authenticate for sheltered access"
        );
    }

    #[test]
    fn a_final_access_refusal_prompts_no_retry_and_answers_restricted() {
        let tmp = TempDir::new().unwrap();
        let keeper = Keys::generate();
        let access = Arc::new(Access(RwLock::new([keeper.public_key()].into())));
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        let relay = Arc::new(EventRelay::new(store, access).with_final_access_refusal());
        let stranger = Keys::generate();
        const NO_ACCESS: &str = "restricted: this key has no sheltered access";

        let mut a = session(&relay, Visibility::Sheltered);
        let answered = a.challenge.clone();
        let signed = auth_event(&a, &stranger);
        let replies = send(&mut a, json!(["AUTH", signed]));
        assert_eq!(replies.len(), 1, "no replacement challenge: {replies:?}");
        assert_eq!(replies[0][2], false);
        assert_eq!(replies[0][3], NO_ACCESS);
        assert_eq!(
            a.challenge, answered,
            "the answered challenge stays current"
        );
        let later = event(&stranger, 1, NOW, "", &[]);
        assert_eq!(
            send(&mut a, json!(["EVENT", later])),
            vec![json!(["OK", later.id.to_hex(), false, NO_ACCESS])]
        );
        assert_eq!(
            send(&mut a, json!(["REQ", "q", {"kinds": [1]}])),
            vec![json!(["CLOSED", "q", NO_ACCESS])]
        );
        assert_eq!(
            send(&mut a, json!(["COUNT", "c", {"kinds": [1]}])),
            vec![json!(["CLOSED", "c", NO_ACCESS])]
        );
        // Signing the same challenge again is refused the same way.
        let signed = auth_event(&a, &stranger);
        let again = send(&mut a, json!(["AUTH", signed]));
        assert_eq!(again.len(), 1);
        assert_eq!(again[0][3], NO_ACCESS);

        // A keeper still authenticates on the same connection, answering
        // the challenge the stranger answered, and is served.
        auth(&mut a, &keeper);
        assert_eq!(
            send(&mut a, json!(["REQ", "q", {"kinds": [1]}])),
            vec![json!(["EOSE", "q"])]
        );

        // Any other refusal still comes with a fresh challenge.
        let mut b = session(&relay, Visibility::Sheltered);
        let mut tampered = auth_event(&b, &stranger);
        tampered.content = "tampered".into();
        let replies = send(&mut b, json!(["AUTH", tampered]));
        assert_eq!(replies.len(), 2);
        assert!(replies[0][3].as_str().unwrap().starts_with("invalid:"));
        assert_eq!(replies[1], json!(["AUTH", b.challenge]));
        let later = event(&stranger, 1, NOW, "", &[]);
        assert_eq!(
            send(&mut b, json!(["EVENT", later]))[0][3],
            "auth-required: authenticate for sheltered access"
        );
    }

    #[test]
    fn only_an_auth_let_down_by_its_one_relay_tag_counts_as_a_url_mismatch() {
        let (_tmp, relay, _access, key) = setup();
        let mut a = session(&relay, Visibility::Sheltered);
        let other = || vec!["relay".to_owned(), "wss://other.example/events".to_owned()];
        let challenge = |a: &RelaySession| vec!["challenge".to_owned(), a.challenge.clone()];
        let refused = |a: &mut RelaySession, auth: Value| {
            let replies = send(a, json!(["AUTH", auth]));
            assert_eq!(replies[0][2], false, "{replies:?}");
            assert_eq!(
                replies[0][3],
                "invalid: authentication challenge, relay, time or signature"
            );
        };

        let wrong_relay = event(&key, 22242, NOW, "", &[other(), challenge(&a)]);
        refused(&mut a, json!(wrong_relay));
        assert_eq!(relay.auth_relay_mismatches(), 1);

        // Something else wrong as well, or not one relay tag: not counted.
        let stale = event(
            &key,
            22242,
            NOW,
            "",
            &[other(), vec!["challenge".into(), "not it".into()]],
        );
        refused(&mut a, json!(stale));
        let mut tampered = event(&key, 22242, NOW, "", &[other(), challenge(&a)]);
        tampered.content = "tampered".into();
        refused(&mut a, json!(tampered));
        let expired = event(&key, 22242, NOW - 601, "", &[other(), challenge(&a)]);
        refused(&mut a, json!(expired));
        let wrong_kind = event(&key, 1, NOW, "", &[other(), challenge(&a)]);
        refused(&mut a, json!(wrong_kind));
        let no_relay = event(&key, 22242, NOW, "", &[challenge(&a)]);
        refused(&mut a, json!(no_relay));
        let two_relays = event(
            &key,
            22242,
            NOW,
            "",
            &[
                vec!["relay".into(), a.relay_url.to_string()],
                other(),
                challenge(&a),
            ],
        );
        refused(&mut a, json!(two_relays));
        assert_eq!(send(&mut a, json!(["AUTH", {}]))[0][2], false);
        assert_eq!(relay.auth_relay_mismatches(), 1);

        let accepted = auth_event(&a, &key);
        assert_eq!(send(&mut a, json!(["AUTH", accepted]))[0][2], true);
        assert_eq!(relay.auth_relay_mismatches(), 1);
    }

    #[test]
    fn nip42_binds_the_connection_relay_time_and_signature_and_never_broadcasts_auth() {
        let (_tmp, relay, _access, key) = setup();
        let mut a = session(&relay, Visibility::Public);
        let mut b = session(&relay, Visibility::Public);
        let mut live = relay.subscribe();
        let a_auth = auth_event(&a, &key);
        assert_eq!(send(&mut b, json!(["AUTH", a_auth]))[0][2], false);
        let consumed = a.challenge.clone();
        let wrong_relay = event(
            &key,
            22242,
            NOW,
            "",
            &[
                vec!["relay".into(), "wss://other.example/events".into()],
                vec!["challenge".into(), a.challenge.clone()],
            ],
        );
        let replies = send(&mut a, json!(["AUTH", wrong_relay]));
        assert_eq!(replies[0][2], false);
        assert_eq!(replies[1], json!(["AUTH", a.challenge]));
        assert_ne!(a.challenge, consumed);
        let consumed = a.challenge.clone();
        let duplicate_challenge = event(
            &key,
            22242,
            NOW,
            "",
            &[
                vec!["relay".into(), a.relay_url.to_string()],
                vec!["challenge".into(), a.challenge.clone()],
                vec!["challenge".into(), "duplicate".into()],
            ],
        );
        let replies = send(&mut a, json!(["AUTH", duplicate_challenge]));
        assert_eq!(replies[0][2], false);
        assert_eq!(replies[1], json!(["AUTH", a.challenge]));
        assert_ne!(a.challenge, consumed);
        let mut tampered = auth_event(&a, &key);
        tampered.content = "tampered".into();
        let replies = send(&mut a, json!(["AUTH", tampered]));
        assert_eq!(replies[0][2], false);
        assert_eq!(replies[1], json!(["AUTH", a.challenge]));
        let expired = event(
            &key,
            22242,
            NOW - 601,
            "",
            &auth_event(&a, &key)
                .tags
                .iter()
                .map(|t| t.as_slice().to_vec())
                .collect::<Vec<_>>(),
        );
        let replies = send(&mut a, json!(["AUTH", expired]));
        assert_eq!(replies[0][2], false);
        assert_eq!(replies[1], json!(["AUTH", a.challenge]));
        let consumed = a.challenge.clone();
        let malformed = send(&mut a, json!(["AUTH", {}]));
        assert_eq!(malformed[0][2], false);
        assert_eq!(malformed[1], json!(["AUTH", a.challenge]));
        assert_ne!(a.challenge, consumed);

        let accepted = auth_event(&a, &key);
        let replies = send(&mut a, json!(["AUTH", accepted]));
        assert_eq!(
            replies.len(),
            1,
            "successful AUTH emits no replacement challenge"
        );
        assert_eq!(replies[0][2], true);
        let replay_challenge = a.challenge.clone();
        let replay = send(&mut a, json!(["AUTH", accepted]));
        assert_eq!(
            replay.len(),
            1,
            "a replay does not prompt an authenticated client"
        );
        assert_eq!(replay[0][2], false);
        assert_ne!(a.challenge, replay_challenge);
        assert_eq!(send(&mut a, json!(["EVENT", accepted]))[0][2], false);
        assert!(live.try_recv().is_err());
        assert_eq!(
            send(&mut a, json!(["REQ", "all", {}])),
            vec![json!(["EOSE", "all"])]
        );
    }

    #[test]
    fn nip77_reconciles_event_ids_without_releasing_event_bodies() {
        let (_tmp, relay, _access, key) = setup();
        let mut writer = session(&relay, Visibility::Public);
        auth(&mut writer, &key);
        let stored = event(&key, 1, NOW, "replicate me", &[]);
        assert_eq!(send(&mut writer, json!(["EVENT", stored]))[0][2], true);

        let (mut client, initial) = empty_negentropy_initial();
        let mut reader = session(&relay, Visibility::Public);
        let replies = send(
            &mut reader,
            json!(["NEG-OPEN", "sync", {"kinds":[1]}, initial]),
        );
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0][0], "NEG-MSG");
        let response = decode_negentropy_message(&replies[0][2]).unwrap();
        let mut have = Vec::new();
        let mut need = Vec::new();
        let _ = client
            .reconcile_with_ids(&response, &mut have, &mut need)
            .unwrap();
        assert!(have.is_empty());
        assert_eq!(need.len(), 1);
        assert_eq!(&*need[0], &stored.id.to_bytes());
        assert!(replies[0].to_string().contains("NEG-MSG"));
        assert!(!replies[0].to_string().contains("replicate me"));
    }

    #[test]
    fn nip77_is_read_authorised_and_malformed_rounds_are_scoped() {
        let (_tmp, relay, _access, _key) = setup();
        let (_client, initial) = empty_negentropy_initial();
        let mut sheltered = session(&relay, Visibility::Sheltered);
        let denied = send(
            &mut sheltered,
            json!(["NEG-OPEN", "sync", {"kinds":[1]}, initial]),
        );
        assert_eq!(denied[0][0], "NEG-ERR");
        assert!(denied[0][2].as_str().unwrap().starts_with("auth-required:"));

        let (_client, initial) = empty_negentropy_initial();
        let mut public = session(&relay, Visibility::Public);
        assert_eq!(
            send(
                &mut public,
                json!(["NEG-OPEN", "sync", {"kinds":[1]}, initial]),
            )[0][0],
            "NEG-MSG"
        );
        assert_eq!(
            send(&mut public, json!(["NEG-MSG", "sync", "abc"]))[0][0],
            "NEG-ERR"
        );
        assert_eq!(
            send(&mut public, json!(["NEG-MSG", "sync", "6000"]))[0][2],
            "error: subscription not found"
        );
        assert_eq!(
            send(&mut public, json!(["REQ", "still-open", {"limit":0}])),
            vec![json!(["EOSE", "still-open"])]
        );
    }

    #[test]
    fn refused_filters_say_why_and_empty_lists_match_nothing() {
        let (_tmp, relay, _access, key) = setup();
        let stored = event(&key, 1, NOW, "held", &[]);
        assert_eq!(
            relay.store.put(Visibility::Public, &stored, NOW).unwrap(),
            PutOutcome::Stored
        );
        let mut reader = session(&relay, Visibility::Public);
        for verb in ["REQ", "COUNT"] {
            assert_eq!(
                send(&mut reader, json!([verb, "none"])),
                vec![json!([
                    "CLOSED",
                    "none",
                    "invalid: at least one filter is required"
                ])]
            );
        }
        let hex = "a".repeat(64);
        let values: Vec<String> = (0..256).map(|i| format!("v{i}")).collect();
        let too_many: Vec<String> = (0..257).map(|i| format!("v{i}")).collect();
        for (filter, reason) in [
            (json!({"search": "x"}), "unsupported: filter field"),
            (json!({"#foo": ["x"]}), "unsupported: filter field"),
            (
                json!({"kinds": ["1"]}),
                "invalid: kinds are numbers from 0 to 65535",
            ),
            (
                json!({"authors": ["ab"]}),
                "invalid: ids, authors, #e and #p are 64 lowercase hex characters",
            ),
            (
                json!({"since": -1}),
                "invalid: since, until and limit are whole numbers",
            ),
            (json!({"ids": hex}), "invalid: filter values are a list"),
            (json!([]), "invalid: a filter is a JSON object"),
            (
                json!({"#t": too_many}),
                "restricted: more than 256 values in one filter list",
            ),
            (
                json!({"#t": values, "#d": values}),
                "restricted: filter too large; split it",
            ),
        ] {
            assert_eq!(
                send(&mut reader, json!(["REQ", "s", filter])),
                vec![json!(["CLOSED", "s", reason])],
                "{filter}"
            );
        }
        // An empty list matches nothing, in REQ and COUNT alike.
        assert_eq!(
            send(&mut reader, json!(["REQ", "s", {"authors": []}])),
            vec![json!(["EOSE", "s"])]
        );
        assert_eq!(
            send(&mut reader, json!(["COUNT", "c", {"kinds": [1], "#e": []}])),
            vec![json!(["COUNT", "c", {"count": 0}])]
        );
        assert_eq!(
            send(&mut reader, json!(["COUNT", "c", {"kinds": [1]}])),
            vec![json!(["COUNT", "c", {"count": 1}])]
        );
    }

    #[test]
    fn auth_relay_url_ignores_case_default_port_and_a_trailing_slash() {
        let expected = Url::parse("wss://relay.example/events").unwrap();
        for given in [
            "wss://relay.example/events",
            "wss://RELAY.example/events",
            "wss://relay.example:443/events",
            "wss://relay.example/events/",
        ] {
            assert!(names_relay(given, &expected), "{given}");
        }
        for given in [
            "ws://relay.example/events",
            "wss://relay.example:444/events",
            "wss://relay.example/other",
            "wss://other.example/events",
            "not a url",
        ] {
            assert!(!names_relay(given, &expected), "{given}");
        }
        let root = Url::parse("wss://relay.example").unwrap();
        assert!(names_relay("wss://relay.example/", &root));
        assert!(names_relay("wss://relay.example", &root));
    }

    #[test]
    fn nip77_refuses_an_id_list_longer_than_its_message() {
        let (_tmp, relay, _access, key) = setup();
        let stored = event(&key, 1, NOW, "held", &[]);
        assert_eq!(
            relay.store.put(Visibility::Public, &stored, NOW).unwrap(),
            PutOutcome::Stored
        );
        let mut reader = session(&relay, Visibility::Public);
        // One IdList range claiming 2^34, then 2^62, ids with none following.
        for initial in ["61000002c080808000", "61000002c08080808080808000"] {
            assert_eq!(
                send(
                    &mut reader,
                    json!(["NEG-OPEN", "short", {"kinds":[1]}, initial]),
                ),
                vec![json!(["NEG-ERR", "short", "invalid: negentropy message"])]
            );
        }
        assert_eq!(
            send(&mut reader, json!(["REQ", "after", {"limit":0}])),
            vec![json!(["EOSE", "after"])]
        );
    }

    #[test]
    fn nip77_refuses_a_possibly_truncated_index() {
        let (_tmp, relay, _access, key) = setup();
        for sequence in 0..=MAX_NEGENTROPY_EVENTS {
            let stored = event(&key, 1, NOW + sequence as u64, &sequence.to_string(), &[]);
            assert_eq!(
                relay.store.put(Visibility::Public, &stored, NOW).unwrap(),
                PutOutcome::Stored
            );
        }
        let (_client, initial) = empty_negentropy_initial();
        let mut reader = session(&relay, Visibility::Public);
        assert_eq!(
            send(
                &mut reader,
                json!(["NEG-OPEN", "bounded", {"kinds":[1]}, initial]),
            ),
            vec![json!([
                "NEG-ERR",
                "bounded",
                "restricted: too many events; narrow the filter"
            ])]
        );
    }

    #[test]
    fn nip77_has_a_tighter_reconciliation_budget_than_ordinary_frames() {
        let (_tmp, relay, _access, _key) = setup();
        let mut reader = session(&relay, Visibility::Public);
        for _ in 0..MAX_NEGENTROPY_ROUNDS_PER_MINUTE {
            let (_client, initial) = empty_negentropy_initial();
            assert_eq!(
                send(
                    &mut reader,
                    json!(["NEG-OPEN", "replace", {"kinds":[1]}, initial]),
                )[0][0],
                "NEG-MSG"
            );
        }
        let (_client, initial) = empty_negentropy_initial();
        assert_eq!(
            send(
                &mut reader,
                json!(["NEG-OPEN", "replace", {"kinds":[1]}, initial]),
            ),
            vec![json!(["NEG-ERR", "replace", "rate-limited: slow down"])]
        );
    }

    /// The rule on stored JSON and the rule on a built event agree for every
    /// shape of tags and kind, including the ones a `#d` filter never
    /// returns: no `d` tag, a `D` tag, an empty value, a lone `d`.
    #[test]
    fn the_stored_json_rule_agrees_with_the_built_event_rule() {
        let key = Keys::generate();
        let room = "42".repeat(32);
        let other = "11".repeat(32);
        let scope = |room: &str, read: &[u16]| GuestScope {
            issuer: key.public_key(),
            grant_id: "24".repeat(16),
            room: room.to_owned(),
            device: key.public_key(),
            read: read.iter().copied().collect(),
            write: BTreeSet::new(),
            expires_at: NOW + 600,
        };
        let scope_sets = [
            vec![scope(&room, &[1460, 1462])],
            vec![scope(&other, &[1460]), scope(&room, &[1462])],
            vec![scope(&room, &[])],
            vec![scope("", &[1460])],
        ];
        let tag = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let tag_sets: Vec<Vec<Vec<String>>> = vec![
            vec![],
            vec![tag(&["t", "x"])],
            vec![tag(&["d", &room])],
            vec![tag(&["d", &other])],
            vec![tag(&["d", ""])],
            vec![tag(&["d"])],
            vec![tag(&["D", &room])],
            vec![tag(&["d", &room, "extra"])],
            vec![tag(&["d", &room]), tag(&["d", &room])],
            vec![tag(&["d", &room]), tag(&["d", &other])],
            vec![tag(&["d"]), tag(&["d", &room])],
            vec![tag(&["t", "x"]), tag(&["d", &room]), tag(&["p", "y"])],
            vec![tag(&["dd", &room])],
            vec![tag(&["d", "quote\"room"])],
        ];
        for kind in [1, 1460, 1462, 20461] {
            for tags in &tag_sets {
                let e = event(&key, kind, NOW, "x", tags);
                let from_json =
                    crate::StoredEvent::from_stored(serde_json::to_string(&e).unwrap()).unwrap();
                let from_event = crate::StoredEvent::from_event(&e).unwrap();
                assert_eq!(from_json, from_event, "{kind} {tags:?}");
                assert_eq!(from_json.room.as_deref(), event_room(&e), "{tags:?}");
                assert_eq!(from_json.kind, kind);
                assert_eq!(from_json.id, e.id.to_hex());
                assert_eq!(from_json.created_at, NOW);
                for scopes in &scope_sets {
                    assert_eq!(
                        guest_readable(from_json.kind, from_json.room.as_deref(), scopes),
                        guest_event_readable(&e, scopes),
                        "{kind} {tags:?} {scopes:?}"
                    );
                }
            }
        }
        // A spot check of the rule itself.
        let readable = |kind, tags: &[Vec<String>]| {
            guest_event_readable(&event(&key, kind, NOW, "x", tags), &scope_sets[0])
        };
        assert!(readable(1460, &[tag(&["d", &room])]));
        assert!(!readable(1, &[tag(&["d", &room])]));
        assert!(!readable(1460, &[]));
        assert!(!readable(1460, &[tag(&["d", &room]), tag(&["d", &room])]));
        assert!(!readable(1460, &[tag(&["d", &room, "extra"])]));
        assert!(!readable(1460, &[tag(&["D", &room])]));
    }

    /// A row that does not hold an event fails the whole REQ, as when every
    /// row was built into an event first.
    #[test]
    fn a_corrupt_stored_row_fails_the_req_closed() {
        let (tmp, relay, _access, key) = setup();
        let mut keeper = session(&relay, Visibility::Public);
        auth(&mut keeper, &key);
        let good = event(&key, 1, NOW - 2, "good", &[]);
        let bad = event(&key, 1, NOW - 1, "to be damaged", &[]);
        for e in [&good, &bad] {
            assert_eq!(send(&mut keeper, json!(["EVENT", e]))[0][2], true);
        }
        let conn = rusqlite::Connection::open(tmp.path().join("events.sqlite")).unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let json = serde_json::to_string(&bad).unwrap();
        for damaged in [
            "{}".to_owned(),
            "5".to_owned(),
            "not json".to_owned(),
            json.replace("\"kind\":1,", "\"kind\":70000,"),
            json.replace("\"tags\":[]", "\"tags\":[[]]"),
            json.replace("\"tags\":[]", "\"tags\":[[\"d\",7]]"),
            json.replace("\"sig\":\"", "\"sig\":\"zz"),
            json.replace(&format!("\"id\":\"{}\"", bad.id.to_hex()), "\"id\":\"ab\""),
            // Nothing beyond an event object passes: no extra keys, no
            // array form, no uppercase id.
            format!("{},\"secret\":\"x\"}}", &json[..json.len() - 1]),
            serde_json::to_string(&json!([
                bad.id.to_hex(),
                bad.pubkey.to_hex(),
                bad.created_at.as_secs(),
                1,
                [],
                "to be damaged",
                bad.sig.to_string()
            ]))
            .unwrap(),
            json.replace(&bad.id.to_hex(), &bad.id.to_hex().to_uppercase()),
        ] {
            assert_ne!(damaged, json);
            conn.execute(
                "UPDATE events SET json=?1 WHERE id=?2",
                rusqlite::params![damaged, bad.id.as_bytes()],
            )
            .unwrap();
            assert_eq!(
                send(&mut keeper, json!(["REQ", "s", {"kinds": [1]}])),
                vec![json!(["CLOSED", "s", "error: stored events unavailable"])],
                "{damaged}"
            );
        }
        conn.execute(
            "UPDATE events SET json=?1 WHERE id=?2",
            rusqlite::params![json, bad.id.as_bytes()],
        )
        .unwrap();
        assert_eq!(
            send(&mut keeper, json!(["REQ", "s", {"kinds": [1]}])).len(),
            3
        );
    }

    #[test]
    fn only_frames_that_cannot_open_a_subscription_skip_the_live_channel() {
        assert!(frame_may_subscribe(r#"["REQ","a",{}]"#));
        assert!(frame_may_subscribe(r#"  [ "REQ", "a", {}]"#));
        assert!(frame_may_subscribe(r#"["\u0052EQ","a",{}]"#));
        assert!(frame_may_subscribe("not json"));
        assert!(!frame_may_subscribe(r#"["EVENT",{}]"#));
        assert!(!frame_may_subscribe(r#"["AUTH",{}]"#));
        assert!(!frame_may_subscribe(r#"["CLOSE","a"]"#));
        assert!(!frame_may_subscribe(r#"["COUNT","a",{}]"#));
    }

    #[test]
    fn a_connection_over_its_byte_budget_is_dropped_and_the_others_are_not() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let access = Arc::new(Access(RwLock::new([key.public_key()].into())));
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        // A little over one small event's charge: one fits, a second does not.
        let relay = Arc::new(EventRelay::new(store, access).with_live_queue_bytes(1_200));
        let mut writer = session(&relay, Visibility::Public);
        auth(&mut writer, &key);
        let mut keeping_up = relay.subscribe();
        let mut stalled = relay.subscribe();
        assert_eq!(relay.live.attached(), 2);
        for n in 0..3 {
            let e = event(&key, 1, NOW, &format!("n{n}"), &[]);
            assert_eq!(send(&mut writer, json!(["EVENT", e]))[0][2], true);
            assert_eq!(keeping_up.try_recv().unwrap().event.id, e.id);
        }
        assert_eq!(stalled.try_recv().err(), Some(LiveTryRecvError::Lagged));
        assert_eq!(
            relay.live.attached(),
            1,
            "only the stalled queue was dropped"
        );
        drop(keeping_up);
        assert_eq!(relay.live.attached(), 0);
    }

    #[test]
    fn a_live_queue_takes_only_its_own_partition_and_nothing_with_no_receiver() {
        let (_tmp, relay, _access, key) = setup();
        let mut writer = session(&relay, Visibility::Sheltered);
        auth(&mut writer, &key);
        let mut public_queue = relay.subscribe_partition(Visibility::Public);
        let mut sheltered_queue = relay.subscribe_partition(Visibility::Sheltered);
        let e = event(&key, 1, NOW, "private", &[]);
        assert_eq!(send(&mut writer, json!(["EVENT", e]))[0][2], true);
        assert_eq!(sheltered_queue.try_recv().unwrap().event.id, e.id);
        assert_eq!(public_queue.try_recv().err(), Some(LiveTryRecvError::Empty));
        assert_eq!(public_queue.queued_bytes(), 0, "never charged for it");
        drop((public_queue, sheltered_queue));
        let f = event(&key, 1, NOW, "nobody listening", &[]);
        assert_eq!(send(&mut writer, json!(["EVENT", f]))[0][2], true);
        assert_eq!(relay.live.attached(), 0);
    }

    /// A live frame carries the JSON the store wrote, so it is byte for byte
    /// the frame a REQ sends for the same event and subscription, and the
    /// same message as the `json!` route that built it before.
    #[test]
    fn the_spliced_live_frame_is_byte_identical_to_the_stored_req_frame() {
        // Sheltered: the public door refuses kind 1460.
        let (_tmp, relay, _access, key) = setup();
        let mut writer = session(&relay, Visibility::Sheltered);
        auth(&mut writer, &key);
        let mut reader = session(&relay, Visibility::Sheltered);
        auth(&mut reader, &key);
        let mut live = relay.subscribe();
        let tags = [
            vec!["d".to_owned(), "room \"one\"".to_owned()],
            vec!["t".to_owned(), "\u{1f980}".to_owned()],
        ];
        for (i, content) in [
            "",
            "plain",
            "quo\"te \\ and\nnewline\t\u{0}",
            "caf\u{e9} \u{1f980}",
        ]
        .into_iter()
        .enumerate()
        {
            let e = event(&key, 1460, NOW - 10 + i as u64, content, &tags);
            assert_eq!(send(&mut writer, json!(["EVENT", e]))[0][2], true);
            let announced = live.try_recv().unwrap();
            assert!(live.try_recv().is_err(), "one announcement per write");
            assert_eq!(announced.event.id, e.id);
            assert_eq!(announced.visibility, Visibility::Sheltered);
            let stored = serde_json::to_string(&e).unwrap();
            assert_eq!(
                announced.json(),
                stored,
                "the stored form, not re-serialised"
            );
            for subscription in ["s", "sub \"x\"", "caf\u{e9}", "a\\b"] {
                let spliced = announced.frame_for(subscription);
                let filter = json!({"ids": [e.id.to_hex()]});
                let req = reader.handle(&json!(["REQ", subscription, filter]).to_string(), NOW);
                assert_eq!(req.len(), 2);
                assert_eq!(spliced, req[0], "live and REQ frames are the same bytes");
                assert_eq!(
                    serde_json::from_str::<Value>(&spliced).unwrap(),
                    serde_json::from_str::<Value>(&frame(json!([
                        "EVENT",
                        subscription,
                        &*announced.event
                    ])))
                    .unwrap(),
                );
            }
        }
    }

    #[test]
    fn a_forged_event_is_refused_before_a_permit_and_never_stored_or_fanned_out() {
        let (_tmp, relay, _access, key) = setup();
        let mut keeper = session(&relay, Visibility::Public);
        auth(&mut keeper, &key);
        let mut stranger = session(&relay, Visibility::Public);
        let mut live = relay.subscribe();

        let mut forged = event(&key, 1, NOW, "genuine", &[]);
        forged.content = "forged".into();
        let text = json!(["EVENT", forged]).to_string();
        let prepared = PreparedFrame::parse(text.clone());
        assert!(prepared.has_bad_signature());

        // An authenticated session is refused without the session path.
        assert_eq!(
            keeper.refuse_unverified(&prepared).unwrap(),
            vec![ok(
                &forged.id.to_hex(),
                false,
                "invalid: event shape or signature"
            )],
        );
        // A stranger is not: it goes the ordinary way and is told to authenticate.
        assert!(stranger.refuse_unverified(&prepared).is_none());
        let replies = stranger.handle_prepared(prepared, NOW);
        assert_eq!(
            serde_json::from_str::<Value>(&replies[0]).unwrap()[3],
            "auth-required: authenticate for sheltered access"
        );
        // Even handed to the session, a forged event never reaches the store.
        let replies = keeper.handle_prepared(PreparedFrame::parse(text), NOW);
        assert_eq!(
            serde_json::from_str::<Value>(&replies[0]).unwrap()[3],
            "invalid: event shape or signature"
        );
        relay.flush();
        assert!(live.try_recv().is_err());
        assert_eq!(relay.store.logical_bytes().unwrap(), 0);

        // A good one is prepared once and stored, exactly as the raw frame was.
        let good = event(&key, 1, NOW, "genuine", &[]);
        let prepared = PreparedFrame::parse(json!(["EVENT", good]).to_string());
        assert!(!prepared.has_bad_signature());
        assert!(keeper.refuse_unverified(&prepared).is_none());
        assert_eq!(
            keeper.handle_prepared(prepared, NOW),
            vec![ok(&good.id.to_hex(), true, "")]
        );
        relay.flush();
        assert_eq!(live.try_recv().unwrap().event.id, good.id);
        // Frames that are not EVENTs are not parsed ahead of the session.
        assert!(!PreparedFrame::is_event_frame(r#"["REQ","a",{}]"#));
        assert!(PreparedFrame::is_event_frame(r#"["EVENT",{}]"#));
    }

    /// Replication fills the store only to its reserve; the keeper's own
    /// direct writes still land after replication has hit its cap.
    #[test]
    fn replication_leaves_the_keepers_reserve_for_direct_writes() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let access = Arc::new(Access(RwLock::new([key.public_key()].into())));
        let store =
            Arc::new(SqliteEventStore::open(&tmp.path().join("events.sqlite"), 40_000).unwrap());
        let relay = Arc::new(EventRelay::new(store, access));
        let mut copied = 0;
        let full = loop {
            let wrap = event(&Keys::generate(), 1059, NOW, &"x".repeat(900), &[]);
            match relay
                .admit_replicated(Visibility::Sheltered, &wrap, NOW)
                .unwrap()
            {
                ReplicaAdmission::Stored => copied += 1,
                other => break other,
            }
            assert!(copied < 1000, "replication was never capped");
        };
        assert_eq!(full, ReplicaAdmission::Full);
        assert!(copied > 0);
        let used = relay.store.logical_bytes().unwrap();
        assert!(
            used <= 40_000 - 40_000 / crate::REPLICA_RESERVE_DIVISOR,
            "replication stopped at its reserve ({used} bytes)"
        );

        let mut keeper = session(&relay, Visibility::Sheltered);
        auth(&mut keeper, &key);
        // The keeper's own writes spend the reserve replication left, and
        // only then meet the ordinary ceiling.
        let mut direct = 0;
        let refusal = loop {
            let note = event(
                &key,
                1,
                NOW,
                &format!("keeper {direct} {}", "y".repeat(900)),
                &[],
            );
            let reply = send(&mut keeper, json!(["EVENT", note]));
            if reply[0][2] != true {
                break reply[0][3].as_str().unwrap().to_owned();
            }
            direct += 1;
            assert!(direct < 100);
        };
        assert!(
            direct >= 1,
            "a direct keeper write lands after replication hit its cap"
        );
        assert!(
            refusal.starts_with("restricted: event store full"),
            "{refusal}"
        );
    }

    #[test]
    fn public_writes_need_auth_and_owned_authors_and_never_accept_private_kinds() {
        let (_tmp, relay, _access, key) = setup();
        let mut writer = session(&relay, Visibility::Public);
        let stranger = Keys::generate();
        let note = event(&key, 1, NOW, "public", &[]);
        assert!(
            send(&mut writer, json!(["EVENT", note]))[0][3]
                .as_str()
                .unwrap()
                .starts_with("auth-required:")
        );
        let stranger_auth = auth_event(&writer, &stranger);
        assert_eq!(
            send(&mut writer, json!(["AUTH", stranger_auth]))[0][2],
            false
        );
        auth(&mut writer, &key);
        assert_eq!(
            send(
                &mut writer,
                json!(["EVENT", event(&stranger, 1, NOW, "not keeper", &[])])
            )[0][2],
            false
        );
        for kind in [4, 1059, 30078, 9999] {
            assert_eq!(
                send(
                    &mut writer,
                    json!(["EVENT", event(&key, kind, NOW, "private", &[])])
                )[0][2],
                false
            );
        }
        assert_eq!(send(&mut writer, json!(["EVENT", note]))[0][2], true);
        let mut reader = session(&relay, Visibility::Public);
        let got = send(&mut reader, json!(["REQ", "public", {}]));
        assert_eq!(got[0][2]["id"], note.id.to_hex());
        assert_eq!(got[1], json!(["EOSE", "public"]));
    }

    #[test]
    fn public_bud03_server_list_is_keeper_only_and_replaceable() {
        let (_tmp, relay, _access, key) = setup();
        let stranger = Keys::generate();
        let mut writer = session(&relay, Visibility::Public);
        auth(&mut writer, &key);

        let old = event(&key, 10063, NOW - 1, "old server list", &[]);
        let replacement = event(&key, 10063, NOW, "current server list", &[]);
        assert_eq!(send(&mut writer, json!(["EVENT", old]))[0][2], true);
        assert_eq!(send(&mut writer, json!(["EVENT", replacement]))[0][2], true);
        assert_eq!(
            send(
                &mut writer,
                json!(["EVENT", event(&stranger, 10063, NOW, "forged list", &[])])
            )[0][2],
            false
        );

        let mut reader = session(&relay, Visibility::Public);
        let got = send(&mut reader, json!(["REQ", "bud03", {"kinds": [10063]}]));
        assert_eq!(got[0][2]["id"], replacement.id.to_hex());
        assert_eq!(got[1], json!(["EOSE", "bud03"]));
    }

    #[test]
    fn sheltered_ciphertext_never_crosses_to_the_public_door_even_for_authenticated_readers() {
        let (_tmp, relay, _access, key) = setup();
        let mut private = session(&relay, Visibility::Sheltered);
        let mut public = session(&relay, Visibility::Public);
        assert_eq!(
            send(&mut private, json!(["REQ", "secret", {}]))[0][0],
            "CLOSED"
        );
        auth(&mut private, &key);
        auth(&mut public, &key);
        send(&mut private, json!(["REQ", "private", {}]));
        send(&mut public, json!(["REQ", "public", {}]));
        let outer = Keys::generate();
        let wrap = event(
            &outer,
            1059,
            NOW,
            "ciphertext",
            &[vec!["p".into(), key.public_key().to_hex()]],
        );
        let mut live = relay.subscribe();
        assert_eq!(send(&mut private, json!(["EVENT", wrap]))[0][2], true);
        let live = live.try_recv().unwrap();
        assert!(public.on_live(&live, NOW).is_empty());
        assert_eq!(private.on_live(&live, NOW).len(), 1);
        assert_eq!(
            send(
                &mut public,
                json!(["REQ","exact",{"ids":[wrap.id.to_hex()]}])
            ),
            vec![json!(["EOSE", "exact"])]
        );
        let loaded = send(
            &mut private,
            json!(["REQ","exact",{"ids":[wrap.id.to_hex()]}]),
        );
        assert_eq!(loaded[0][2]["id"], wrap.id.to_hex());
    }

    #[test]
    fn revocation_stops_existing_private_subscriptions_and_authenticated_writes() {
        let (_tmp, relay, access, key) = setup();
        let mut private = session(&relay, Visibility::Sheltered);
        auth(&mut private, &key);
        send(&mut private, json!(["REQ", "private", {}]));
        let e = event(&key, 1, NOW, "late", &[]);
        access.0.write().unwrap().clear();
        let live = live_event(Visibility::Sheltered, Arc::new(e.clone()));
        let closed = private.on_live(&live, NOW);
        assert_eq!(
            serde_json::from_str::<Value>(&closed[0]).unwrap()[0],
            "CLOSED"
        );
        assert!(private.on_live(&live, NOW).is_empty());
        assert_eq!(send(&mut private, json!(["EVENT", e]))[0][2], false);
        assert_eq!(
            send(&mut private, json!(["REQ", "again", {}]))[0][0],
            "CLOSED"
        );
    }

    /// The `Value` route `parse_event` replaced, kept as the oracle.
    fn parse_event_via_value(text: &str) -> Option<(String, Event, bool)> {
        if !PreparedFrame::is_event_frame(text) {
            return None;
        }
        let Value::Array(mut parts) = serde_json::from_str::<Value>(text).ok()? else {
            return None;
        };
        if parts.len() != 2 || parts[0].as_str() != Some("EVENT") {
            return None;
        }
        let value = parts.pop()?;
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| s.len() == 64)
            .unwrap_or("")
            .to_owned();
        let event = serde_json::from_value::<Event>(value).ok()?;
        let signature_ok = event.verify().is_ok();
        Some((id, event, signature_ok))
    }

    /// Parsing an EVENT frame once, typed, accepts and refuses exactly the
    /// frames the `Value` route did, with the same id, event and signature
    /// verdict; refused frames still reach the session, which answers them as
    /// before.
    #[test]
    fn a_typed_event_frame_parse_matches_the_value_route() {
        let key = Keys::generate();
        let e = event(
            &key,
            1,
            NOW,
            "quo\"te \\ caf\u{e9}",
            &[vec!["t".into(), "x".into()]],
        );
        let json = serde_json::to_string(&e).unwrap();
        let id = e.id.to_hex();
        let mut forged = serde_json::to_value(&e).unwrap();
        forged["content"] = json!("changed after signing");
        let array_form = json!([
            id,
            e.pubkey.to_hex(),
            e.created_at.as_secs(),
            1,
            [["t", "x"]],
            e.content,
            e.sig.to_string()
        ]);
        let frames = vec![
            format!("[\"EVENT\",{json}]"),
            format!("  [ \"EVENT\" , {json} ]  "),
            format!("[\"EVENT\",{json},1]"),
            format!("[\"EVENT\"]"),
            format!("[\"EVENT\",{json}"),
            format!("[\"EVENT\",{json}]x"),
            format!("[\"EVENTS\",{json}]"),
            format!("[\"EVENT\",{forged}]"),
            format!("[\"EVENT\",{array_form}]"),
            format!("[\"EVENT\",{}]", json.replace(&id, &id.to_uppercase())),
            format!(
                "[\"EVENT\",{}]",
                json.replacen('{', "{\"extra\":[1,{}],", 1)
            ),
            format!(
                "[\"EVENT\",{}]",
                json.replacen('{', &format!("{{\"id\":\"{id}\","), 1)
            ),
            format!(
                "[\"EVENT\",{}]",
                json.replace("\"kind\":1,", "\"kind\":1.0,")
            ),
            format!(
                "[\"EVENT\",{}]",
                json.replace("\"kind\":1,", "\"kind\":70000,")
            ),
            format!(
                "[\"EVENT\",{}]",
                json.replace("\"tags\":[[", "\"tags\":[[],[")
            ),
            format!("[\"EVENT\",{}]", json.replace(&id, "ab")),
            "[\"EVENT\",{}]".to_owned(),
            // Unknown members the typed parse would only skim, refused by
            // the `Value` route: too deep, a number out of range, a lone
            // surrogate.
            format!(
                "[\"EVENT\",{}]",
                json.replacen(
                    '{',
                    &format!("{{\"x\":{}{},", "[".repeat(130), "]".repeat(130)),
                    1
                )
            ),
            format!("[\"EVENT\",{}]", json.replacen('{', "{\"x\":1e400,", 1)),
            format!(
                "[\"EVENT\",{}]",
                json.replacen('{', &format!("{{\"x\":{},", "9".repeat(400)), 1)
            ),
            format!(
                "[\"EVENT\",{}]",
                json.replacen('{', "{\"x\":\"\\ud800\",", 1)
            ),
            "[\"EVENT\",null]".to_owned(),
            "[\"EVENT\",\"text\"]".to_owned(),
            "[\"\\u0045VENT\",{}]".to_owned(),
            "{\"EVENT\":1}".to_owned(),
            "not json".to_owned(),
        ];
        let mut accepted = 0;
        for frame in &frames {
            // Wherever the typed parse alone accepts, it agrees with the
            // `Value` route.
            if let Some(p) = PreparedFrame::parse_event_typed(frame) {
                assert_eq!(
                    Some((p.id, p.event, p.signature_ok)),
                    parse_event_via_value(frame),
                    "{frame}"
                );
            }
            let typed = PreparedFrame::parse(frame.clone())
                .event
                .map(|p| (p.id, p.event, p.signature_ok));
            assert_eq!(typed, parse_event_via_value(frame), "{frame}");
            accepted += usize::from(typed.is_some());
        }
        assert!(accepted >= 3, "the valid spellings are accepted");
        // The ordinary spellings take the typed parse; the duplicate key
        // falls back to the `Value` route, which accepts it as before.
        for frame in [&frames[0], &frames[1], &frames[7], &frames[8]] {
            assert!(PreparedFrame::parse_event_typed(frame).is_some(), "{frame}");
        }
        assert!(PreparedFrame::parse_event_typed(&frames[11]).is_none());
        assert!(PreparedFrame::parse(frames[11].clone()).event.is_some());
        let good = PreparedFrame::parse(frames[0].clone()).event.unwrap();
        assert!(good.signature_ok);
        assert_eq!(good.id, id);
        let bad = PreparedFrame::parse(frames[7].clone()).event.unwrap();
        assert!(!bad.signature_ok);

        // The frames the typed parse would only skim are refused, and a
        // keeper gets the reply it got before, not a stored event.
        let (_tmp, relay, _access, keeper_key) = setup();
        let mut keeper = session(&relay, Visibility::Sheltered);
        auth(&mut keeper, &keeper_key);
        let own = event(&keeper_key, 1, NOW, "x", &[]);
        let own_json = serde_json::to_string(&own).unwrap();
        for extra in [
            format!("{}{}", "[".repeat(130), "]".repeat(130)),
            "1e400".to_owned(),
            "9".repeat(400),
            "\"\\ud800\"".to_owned(),
        ] {
            let frame = format!(
                "[\"EVENT\",{}]",
                own_json.replacen('{', &format!("{{\"x\":{extra},"), 1)
            );
            let prepared = PreparedFrame::parse(frame.clone());
            assert!(prepared.event.is_none(), "{extra}");
            assert_eq!(
                keeper.handle_prepared(prepared, NOW),
                vec![notice("invalid: expected JSON")],
                "{extra}"
            );
        }
        assert_eq!(
            relay.store.logical_bytes().unwrap(),
            0,
            "nothing was stored"
        );
    }

    #[test]
    fn try_close_answers_close_inline_and_leaves_everything_else_to_the_ordinary_path() {
        let (_tmp, relay, _access, key) = setup();
        let mut writer = session(&relay, Visibility::Public);
        let mut reader = session(&relay, Visibility::Public);
        auth(&mut writer, &key);
        let one = event(&key, 1, NOW - 5, "one", &[]);
        send(&mut writer, json!(["EVENT", one]));
        let live = live_event(Visibility::Public, Arc::new(one));
        let frame = |value: Value| PreparedFrame::parse(value.to_string());
        send(&mut reader, json!(["REQ", "a", {"limit": 0}]));
        send(&mut reader, json!(["REQ", "b", {"limit": 0}]));
        assert_eq!(reader.on_live(&live, NOW).len(), 2);
        // A CLOSE: no reply, and only its own subscription goes.
        assert_eq!(
            reader.try_close(&frame(json!(["CLOSE", "a"]))),
            Some(vec![])
        );
        assert!(reader.has_subscriptions());
        let delivered = reader.on_live(&live, NOW);
        assert_eq!(delivered.len(), 1);
        assert!(delivered[0].starts_with("[\"EVENT\",\"b\","));
        // Unknown ids and non-string ids are a silent no-op, as on the
        // ordinary path.
        assert_eq!(
            reader.try_close(&frame(json!(["CLOSE", "unknown"]))),
            Some(vec![])
        );
        assert_eq!(reader.try_close(&frame(json!(["CLOSE", 7]))), Some(vec![]));
        assert_eq!(
            reader.handle(&json!(["CLOSE", 7]).to_string(), NOW),
            Vec::<String>::new()
        );
        assert!(reader.has_subscriptions());
        assert_eq!(
            reader.try_close(&frame(json!(["CLOSE", "b"]))),
            Some(vec![])
        );
        assert!(!reader.has_subscriptions());
        assert!(reader.on_live(&live, NOW).is_empty());
        // Everything else is left for the ordinary path, which answers it
        // exactly as before.
        for other in [
            json!(["CLOSE"]).to_string(),
            json!(["CLOSE", "a", "extra"]).to_string(),
            json!(["REQ", "a", {}]).to_string(),
            json!(["EVENT", {}]).to_string(),
            "[\"CLOSE\",".to_owned(),
            "[\"\\u0043LOSE\",\"a\"]".to_owned(),
            format!("[\"CLOSE\",\"{}\"]", "a".repeat(MAX_INLINE_CLOSE_BYTES)),
        ] {
            assert_eq!(
                reader.try_close(&PreparedFrame::parse(other.clone())),
                None,
                "{other}"
            );
        }
        assert_eq!(
            send(&mut reader, json!(["CLOSE"])),
            vec![json!([
                "NOTICE",
                "unsupported: use AUTH, EVENT, REQ, COUNT, CLOSE, NEG-OPEN, NEG-MSG or NEG-CLOSE"
            ])]
        );
    }

    #[test]
    fn limit_zero_stays_live_and_replacing_or_closing_a_subscription_removes_its_old_filters() {
        let (_tmp, relay, _access, key) = setup();
        let mut writer = session(&relay, Visibility::Public);
        let mut reader = session(&relay, Visibility::Public);
        auth(&mut writer, &key);
        let one = event(&key, 1, NOW - 5, "one", &[]);
        send(&mut writer, json!(["EVENT", one]));
        assert_eq!(
            send(&mut reader, json!(["REQ","s",{"limit":0,"kinds":[1]}])),
            vec![json!(["EOSE", "s"])]
        );
        let live = live_event(Visibility::Public, Arc::new(one));
        assert_eq!(reader.on_live(&live, NOW).len(), 1);
        send(&mut reader, json!(["REQ","s",{"kinds":[7]}]));
        assert!(reader.on_live(&live, NOW).is_empty());
        send(&mut reader, json!(["REQ", "s", {}]));
        send(&mut reader, json!(["CLOSE", "s"]));
        assert!(reader.on_live(&live, NOW).is_empty());
        send(&mut reader, json!(["REQ", "s", {}]));
        assert_eq!(
            send(&mut reader, json!(["REQ","s",{"search":"unsupported"}]))[0][0],
            "CLOSED"
        );
        assert!(reader.on_live(&live, NOW).is_empty());
    }

    #[test]
    fn fuzzed_frames_and_mutated_signed_events_cannot_store_or_subscribe() {
        let (_tmp, relay, _access, key) = setup();
        let mut reader = session(&relay, Visibility::Public);
        auth(&mut reader, &key);
        let original = event(&key, 1, NOW, "signed content", &[]);
        let encoded = json!(["EVENT", original]).to_string();
        let mut cases = (0..encoded.len())
            .map(|n| encoded[..n].to_string())
            .collect::<Vec<_>>();
        cases.push(format!("{}{}", "[".repeat(200), "]".repeat(200)));
        // A reproducible byte corpus; deliberately not used for cryptography.
        let mut seed = 0x5a17_c0de_u64;
        for n in 0..1024 {
            let bytes = (0..n % 257)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect::<Vec<_>>();
            cases.push(String::from_utf8_lossy(&bytes).into_owned());
        }
        for (field, replacement) in [
            ("id", json!("0".repeat(64))),
            ("pubkey", json!("0".repeat(64))),
            ("sig", json!("0".repeat(128))),
            ("content", json!("changed after signing")),
            ("created_at", json!(NOW + 1)),
            ("kind", json!(7)),
            ("tags", json!([["p", key.public_key().to_hex()]])),
        ] {
            let mut mutated = serde_json::to_value(&original).unwrap();
            mutated[field] = replacement;
            cases.push(json!(["EVENT", mutated]).to_string());
        }
        for (i, text) in cases.iter().enumerate() {
            // Exercise parsing on every case, without hitting the frame budget.
            let at = NOW + i as u64;
            for reply in reader.handle(text, at) {
                let value: Value = serde_json::from_str(&reply).unwrap();
                assert!(!(value[0] == "OK" && value[2] == true), "accepted case {i}");
                assert_ne!(value[0], "EVENT", "leaked an event for case {i}");
            }
            assert!(reader.subscriptions.is_empty(), "case {i}");
        }
        assert_eq!(relay.store.logical_bytes().unwrap(), 0);
    }

    #[test]
    fn unsupported_malformed_and_oversized_frames_fail_without_panics_or_broad_subscriptions() {
        let (_tmp, relay, _access, _key) = setup();
        let mut reader = session(&relay, Visibility::Public);
        for value in [
            json!(null),
            json!({}),
            json!([]),
            json!(["REQ"]),
            json!(["EVENT", {}]),
            json!(["AUTH", {}]),
            json!(["REQ","s",{"ids":[]}]),
            json!(["REQ","s",{"authors":["abc"]}]),
            json!(["REQ","s",{"#p":["not a key"]}]),
            json!(["REQ","s",{"unknown":"ignored?"}]),
        ] {
            assert!(!send(&mut reader, value).is_empty());
        }
        assert!(reader.subscriptions.is_empty());
        for text in ["{".to_string(), "x".repeat(MAX_RELAY_FRAME_BYTES + 1)] {
            assert_eq!(reader.handle(&text, NOW).len(), 1);
        }
        for _ in 0..MAX_FRAMES_PER_MINUTE {
            reader.handle("[]", NOW);
        }
        assert!(reader.handle("[]", NOW)[0].contains("rate-limited"));
    }

    /// An EVENT taken as far as the writer, as the transport takes it.
    fn pending(session: &mut RelaySession, event: &Event) -> PendingWrite {
        let frame = json!(["EVENT", event]).to_string();
        match session.begin_prepared(PreparedFrame::parse(frame), NOW) {
            Handled::Write(write) => *write,
            Handled::Replies(replies) => panic!("refused before the writer: {replies:?}"),
        }
    }

    fn stored_in(relay: &EventRelay, visibility: Visibility) -> usize {
        relay
            .store
            .query(visibility, &Filter::new().limit(128), NOW)
            .unwrap()
            .len()
    }

    fn refused_as_unauthorised(replies: &[String]) -> bool {
        replies.len() == 1
            && replies[0].contains("false")
            && replies[0].contains("no longer authorised to write")
    }

    #[test]
    fn a_keeper_removed_after_its_event_was_prepared_is_not_stored_or_announced() {
        // The test double cannot signal a change, so every write is re-asked.
        let (_tmp, relay, access, key) = setup();
        let mut keeper = session(&relay, Visibility::Sheltered);
        auth(&mut keeper, &key);
        let mut live = relay.subscribe();
        let write = pending(&mut keeper, &event(&key, 1, NOW, "late", &[]));
        access.0.write().unwrap().clear();
        let replies = write.commit_blocking();
        assert!(refused_as_unauthorised(&replies), "{replies:?}");
        relay.flush();
        assert_eq!(stored_in(&relay, Visibility::Sheltered), 0);
        assert!(live.try_recv().is_err());

        // And an unrevoked keeper's write goes through the same path.
        access.0.write().unwrap().insert(key.public_key());
        let fine = event(&key, 1, NOW, "fine", &[]);
        let write = pending(&mut keeper, &fine);
        assert_eq!(
            write.commit_blocking(),
            vec![ok(&fine.id.to_hex(), true, "")]
        );
    }

    /// A keeper source that says when it changes, and how often it is asked.
    struct Counted {
        owner: PublicKey,
        asked: std::sync::atomic::AtomicUsize,
        changes: tokio::sync::watch::Sender<u64>,
    }
    impl KeeperAccess for Counted {
        fn owns(&self, key: &PublicKey) -> bool {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *key == self.owner
        }
        fn subscribe(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
            Some(self.changes.subscribe())
        }
    }

    #[test]
    fn authority_is_asked_again_only_when_a_source_has_moved() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let access = Arc::new(Counted {
            owner: key.public_key(),
            asked: std::sync::atomic::AtomicUsize::new(0),
            changes: tokio::sync::watch::channel(0).0,
        });
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        let relay = Arc::new(EventRelay::new(store, access.clone()));
        let mut keeper = session(&relay, Visibility::Sheltered);
        auth(&mut keeper, &key);

        let asked = || access.asked.load(std::sync::atomic::Ordering::SeqCst);
        let steady = pending(&mut keeper, &event(&key, 1, NOW, "steady", &[]));
        let before = asked();
        assert_eq!(steady.commit_blocking().len(), 1);
        assert_eq!(asked(), before, "nothing moved: a comparison, no read");

        let moved = pending(&mut keeper, &event(&key, 1, NOW, "moved", &[]));
        let before = asked();
        access.changes.send_modify(|generation| *generation += 1);
        assert_eq!(moved.commit_blocking().len(), 1);
        assert!(asked() > before, "a source moved: authority is asked again");
        relay.flush();
        assert_eq!(stored_in(&relay, Visibility::Sheltered), 2);
    }

    #[test]
    fn a_batch_of_replicated_copies_stops_after_the_first_full() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let access = Arc::new(Access(RwLock::new([key.public_key()].into())));
        // Room for several events, but not thirty.
        let store =
            Arc::new(SqliteEventStore::open(&tmp.path().join("events.sqlite"), 20_000).unwrap());
        let relay = Arc::new(EventRelay::new(store, access));
        let body = "x".repeat(1000);
        let events: Vec<Event> = (0..30)
            .map(|n| event(&key, 1, NOW - 100 + n, &format!("{body}{n}"), &[]))
            .collect();
        let outcomes = relay
            .admit_replicated_batch(Visibility::Public, &events, NOW)
            .unwrap();
        assert_eq!(outcomes.last(), Some(&ReplicaAdmission::Full));
        assert!(outcomes.len() > 1, "some were stored first");
        assert!(outcomes.len() < events.len(), "stopped after the Full");
        assert!(
            outcomes[..outcomes.len() - 1]
                .iter()
                .all(|o| *o == ReplicaAdmission::Stored)
        );
    }

    #[test]
    fn an_ephemeral_event_is_answered_and_announced_without_the_writer() {
        let (_tmp, relay, _access, key) = setup();
        let mut keeper = session(&relay, Visibility::Sheltered);
        auth(&mut keeper, &key);
        let mut live = relay.subscribe();
        let blip = event(&key, 20_000, NOW, "blip", &[]);
        assert_eq!(
            send(&mut keeper, json!(["EVENT", blip.clone()]))[0],
            json!(["OK", blip.id.to_hex(), true, ""])
        );
        assert_eq!(live.try_recv().unwrap().event.id, blip.id);
        assert_eq!(
            relay.writer_stats().batches,
            0,
            "no queue place and no commit for what is never stored"
        );
        assert_eq!(stored_in(&relay, Visibility::Sheltered), 0);
    }

    #[test]
    fn an_event_frame_is_an_event_frame_in_any_spacing_and_never_waits_under_a_permit() {
        let (_tmp, relay, _access, key) = setup();
        let mut keeper = session(&relay, Visibility::Sheltered);
        auth(&mut keeper, &key);
        let text = |e: &Event| serde_json::to_string(e).unwrap();
        let spaced = event(&key, 1, NOW, "spaced", &[]);
        let escaped = event(&key, 1, NOW, "escaped", &[]);
        let frames = [
            (
                format!("[ \n\"EVENT\" ,\t{}  ]", text(&spaced)),
                spaced,
                true,
            ),
            // Not recognised by prefix at all; still a pending write.
            (
                format!("[\"EV\\u0045NT\",{}]", text(&escaped)),
                escaped,
                false,
            ),
        ];
        for (frame, e, recognised) in frames {
            assert_eq!(PreparedFrame::is_event_frame(&frame), recognised);
            assert_eq!(!frame_may_subscribe(&frame), recognised);
            match keeper.begin_prepared(PreparedFrame::parse(frame), NOW) {
                Handled::Write(write) => assert_eq!(write.id(), e.id.to_hex()),
                Handled::Replies(replies) => panic!("not a pending write: {replies:?}"),
            }
        }
        assert!(!PreparedFrame::is_event_frame("EVENT"));
        assert!(!PreparedFrame::is_event_frame("[ \"REQ\", \"a\", {}]"));
        assert!(frame_may_subscribe("[ \"REQ\", \"a\", {}]"));
    }

    #[test]
    fn a_wait_that_runs_out_has_its_own_ok_and_a_resend_is_a_duplicate() {
        assert_eq!(
            write_replies(
                "id",
                Err(EventStoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "slow"
                )))
            ),
            vec![ok(
                "id",
                false,
                "error: write still pending; it may be stored, resend to confirm"
            )]
        );
        assert_eq!(
            write_replies("id", Ok(PutOutcome::Duplicate)),
            vec![ok("id", true, "duplicate: already stored")]
        );
        assert_ne!(
            write_replies("id", Err(EventStoreError::Poisoned)),
            write_replies(
                "id",
                Err(EventStoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "slow"
                )))
            )
        );
    }

    // ------------------------------------------------------ guests

    /// Guest scopes held in memory, each with the persona that holds it,
    /// which say when they change.
    struct Guests {
        held: RwLock<Vec<(PublicKey, GuestScope)>>,
        changes: tokio::sync::watch::Sender<u64>,
        issuers: tokio::sync::watch::Sender<u64>,
    }

    impl Guests {
        fn new() -> Self {
            Self {
                held: RwLock::new(Vec::new()),
                changes: tokio::sync::watch::channel(0).0,
                issuers: tokio::sync::watch::channel(0).0,
            }
        }

        fn grant(&self, holder: PublicKey, scope: GuestScope) {
            self.held.write().unwrap().push((holder, scope));
            self.changes.send_modify(|generation| *generation += 1);
        }

        fn withdraw_all(&self) {
            self.held.write().unwrap().clear();
            self.changes.send_modify(|generation| *generation += 1);
        }
    }

    impl GuestAuthority for Guests {
        fn scopes(
            &self,
            identity: &PublicKey,
            now: u64,
        ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
            Ok(self
                .held
                .read()
                .unwrap()
                .iter()
                .filter(|(holder, scope)| holder == identity && now < scope.expires_at)
                .map(|(_, scope)| scope.clone())
                .collect())
        }

        fn device_scopes(
            &self,
            device: &PublicKey,
            now: u64,
        ) -> Result<Vec<GuestScope>, AuthorityUnavailable> {
            Ok(self
                .held
                .read()
                .unwrap()
                .iter()
                .filter(|(_, scope)| scope.device == *device && now < scope.expires_at)
                .map(|(_, scope)| scope.clone())
                .collect())
        }

        fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
            self.changes.subscribe()
        }

        fn subscribe_issuers(&self) -> tokio::sync::watch::Receiver<u64> {
            self.issuers.subscribe()
        }
    }

    struct GuestFixture {
        _tmp: TempDir,
        relay: Arc<EventRelay>,
        guests: Arc<Guests>,
        keeper: Keys,
        guest: Keys,
        device: Keys,
        room: String,
    }

    /// One keeper, and one guest whose device may write kind 1460 and who
    /// may read kinds 1460 and 1462, in one room.
    fn guest_fixture() -> GuestFixture {
        let tmp = TempDir::new().unwrap();
        let keeper = Keys::generate();
        let guest = Keys::generate();
        let device = Keys::generate();
        let room = "42".repeat(32);
        let access = Arc::new(Access(RwLock::new([keeper.public_key()].into())));
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        let guests = Arc::new(Guests::new());
        guests.grant(
            guest.public_key(),
            GuestScope {
                issuer: keeper.public_key(),
                grant_id: "24".repeat(16),
                room: room.clone(),
                device: device.public_key(),
                read: [1460, 1462].into(),
                write: [1460].into(),
                expires_at: NOW + 600,
            },
        );
        let relay = Arc::new(EventRelay::new(store, access).with_guest_authority(guests.clone()));
        GuestFixture {
            _tmp: tmp,
            relay,
            guests,
            keeper,
            guest,
            device,
            room,
        }
    }

    fn in_room(g: &GuestFixture) -> Vec<Vec<String>> {
        vec![vec!["d".into(), g.room.clone()]]
    }

    /// An authenticated guest with one open live REQ over its room.
    fn subscribed_guest(g: &GuestFixture) -> RelaySession {
        let mut guest = session(&g.relay, Visibility::Sheltered);
        auth(&mut guest, &g.guest);
        let opened = send(
            &mut guest,
            json!(["REQ", "live", {"kinds":[1460], "#d":[g.room.clone()]}]),
        );
        assert_eq!(opened, vec![json!(["EOSE", "live"])]);
        guest
    }

    #[test]
    fn a_guest_verdict_without_cached_scopes_delivers_nothing() {
        let g = guest_fixture();
        let live = live_event(
            Visibility::Sheltered,
            Arc::new(event(&g.device, 1460, NOW, "hello", &in_room(&g))),
        );
        let mut guest = subscribed_guest(&g);
        assert_eq!(guest.on_live(&live, NOW).len(), 1);
        guest.invalidate_live_access();
        assert!(guest.live_cache.is_none());
        assert!(
            guest.deliver_live(&live, LiveAccess::Guest, NOW).is_empty(),
            "no scopes to filter by: fail closed, not open"
        );
        guest.live_cache = Some(LiveAccessCache {
            stamp: guest.authority.stamp(),
            valid_until: u64::MAX,
            scopes: None,
        });
        assert!(guest.deliver_live(&live, LiveAccess::Guest, NOW).is_empty());
    }

    #[test]
    fn a_guest_reads_and_writes_only_inside_its_scopes() {
        let g = guest_fixture();
        let mut guest = session(&g.relay, Visibility::Sheltered);
        auth(&mut guest, &g.guest);

        // Its device, its room, a kind it may write: taken.
        let note = event(&g.device, 1460, NOW, "in the room", &in_room(&g));
        assert_eq!(send(&mut guest, json!(["EVENT", note]))[0][2], true);
        // A kind it may only read, another room, another device: refused.
        let outside = [
            event(&g.device, 1462, NOW, "read only", &in_room(&g)),
            event(
                &g.device,
                1460,
                NOW,
                "elsewhere",
                &[vec!["d".into(), "11".repeat(32)]],
            ),
            event(&g.guest, 1460, NOW, "not the device", &in_room(&g)),
        ];
        for e in outside {
            assert_eq!(
                send(&mut guest, json!(["EVENT", e])),
                vec![json!([
                    "OK",
                    e.id.to_hex(),
                    false,
                    "restricted: event is outside the circle grant"
                ])]
            );
        }
        // Reads: only filters its scopes cover, and only what they cover.
        assert_eq!(
            send(&mut guest, json!(["REQ", "wide", {"kinds":[1]}])),
            vec![json!([
                "CLOSED",
                "wide",
                "restricted: filter is outside the circle grant"
            ])]
        );
        let got = send(
            &mut guest,
            json!(["REQ", "room", {"kinds":[1460], "#d":[g.room.clone()]}]),
        );
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0][2]["id"], note.id.to_hex());
        // COUNT is for keepers: a guest's read rule runs per event.
        assert_eq!(
            send(
                &mut guest,
                json!(["COUNT", "c", {"kinds":[1460], "#d":[g.room.clone()]}])
            ),
            vec![json!([
                "CLOSED",
                "c",
                "restricted: COUNT is for keepers only"
            ])]
        );

        // A key with no scopes cannot authenticate on the sheltered door.
        let mut stranger = session(&g.relay, Visibility::Sheltered);
        let e = auth_event(&stranger, &Keys::generate());
        assert_eq!(
            send(&mut stranger, json!(["AUTH", e]))[0][3],
            "restricted: this key has no sheltered access"
        );

        // Withdrawn: the open session reads and writes nothing more.
        g.guests.withdraw_all();
        assert!(!guest.authority_is_current(NOW));
        assert_eq!(
            send(
                &mut guest,
                json!(["REQ", "room", {"kinds":[1460], "#d":[g.room.clone()]}])
            ),
            vec![json!([
                "CLOSED",
                "room",
                "restricted: this identity no longer has sheltered access"
            ])]
        );
        let late = event(&g.device, 1460, NOW, "too late", &in_room(&g));
        assert_eq!(send(&mut guest, json!(["EVENT", late]))[0][2], false);
        // The keeper still reads the one note.
        let mut keeper = session(&g.relay, Visibility::Sheltered);
        auth(&mut keeper, &g.keeper);
        assert_eq!(send(&mut keeper, json!(["REQ", "all", {}])).len(), 2);
    }

    // ------------------------------------------------------ authority events

    /// Kind 9998 carries authority: the sheltered door installs it, and the
    /// public door leaves it to its ordinary rules.
    #[derive(Default)]
    struct Installs {
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl AuthorityEvents for Installs {
        fn is_authority(&self, event: &Event) -> bool {
            event.kind.as_u16() == 9998
        }

        fn install(&self, request: &InstallRequest<'_>) -> Option<Result<(), String>> {
            if request.visibility != Visibility::Sheltered {
                return None;
            }
            if !request.keeper() {
                return Some(Err(request.refusal().to_owned()));
            }
            if request.signature == SignatureCheck::Failed {
                return Some(Err("invalid: authority refused".to_owned()));
            }
            self.seen.lock().unwrap().push(request.event.id.to_hex());
            Some(Ok(()))
        }
    }

    #[test]
    fn authority_events_are_installed_and_never_stored_or_copied() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let access = Arc::new(Access(RwLock::new([key.public_key()].into())));
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        let installs = Arc::new(Installs::default());
        let relay =
            Arc::new(EventRelay::new(store, access).with_authority_events(installs.clone()));
        let mut live = relay.subscribe();
        let authority = event(&key, 9998, NOW, "authority", &[]);

        // Before AUTH: the installer's own refusal, and nothing installed.
        let mut sheltered = session(&relay, Visibility::Sheltered);
        assert_eq!(
            send(&mut sheltered, json!(["EVENT", authority])),
            vec![json!([
                "OK",
                authority.id.to_hex(),
                false,
                "auth-required: authenticate for sheltered access"
            ])]
        );
        auth(&mut sheltered, &key);
        assert_eq!(
            send(&mut sheltered, json!(["EVENT", authority])),
            vec![json!(["OK", authority.id.to_hex(), true, ""])]
        );
        assert_eq!(*installs.seen.lock().unwrap(), vec![authority.id.to_hex()]);
        // On the public door the ordinary rules answer: not a public kind.
        let mut public = session(&relay, Visibility::Public);
        auth(&mut public, &key);
        assert_eq!(
            send(&mut public, json!(["EVENT", authority]))[0][3],
            "restricted: public door accepts keeper-authored public kinds only"
        );
        assert_eq!(installs.seen.lock().unwrap().len(), 1);

        // Never stored, never live, never taken as a sibling's copy.
        assert!(live.try_recv().is_err());
        assert_eq!(stored_in(&relay, Visibility::Sheltered), 0);
        for visibility in [Visibility::Public, Visibility::Sheltered] {
            let prepared = relay
                .prepare_replicated(visibility, std::slice::from_ref(&authority), NOW)
                .unwrap();
            assert!(matches!(
                prepared[0],
                ReplicaPrepared::Settled(ReplicaAdmission::Rejected)
            ));
        }

        // A relay without the hook stores the same event as content.
        let (_tmp, plain, _access, key) = setup();
        let mut keeper = session(&plain, Visibility::Sheltered);
        auth(&mut keeper, &key);
        let content = event(&key, 9998, NOW, "content", &[]);
        assert_eq!(send(&mut keeper, json!(["EVENT", content]))[0][2], true);
        assert_eq!(stored_in(&plain, Visibility::Sheltered), 1);
    }

    // ------------------------------------------------------ announce hook

    #[derive(Default)]
    struct Announced {
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl AnnounceHook for Announced {
        fn announced(&self, event: &Event) {
            self.seen.lock().unwrap().push(event.id.to_hex());
        }
    }

    #[test]
    fn the_announce_hook_sees_each_announced_event_once() {
        let (_tmp, relay, _access, key) = setup();
        let hook = Arc::new(Announced::default());
        assert!(relay.attach_announce_hook(hook.clone()));
        assert!(!relay.attach_announce_hook(hook.clone()), "attached once");
        let seen = || hook.seen.lock().unwrap().clone();
        let mut keeper = session(&relay, Visibility::Sheltered);
        auth(&mut keeper, &key);
        let note = event(&key, 1, NOW, "stored", &[]);
        assert_eq!(send(&mut keeper, json!(["EVENT", note]))[0][2], true);
        assert_eq!(seen(), vec![note.id.to_hex()]);
        // Stored once, so announced once.
        assert_eq!(send(&mut keeper, json!(["EVENT", note]))[0][2], true);
        assert_eq!(seen().len(), 1);
        // A direct ephemeral event is announced by the door itself.
        let ephemeral = event(&key, 20001, NOW, "", &[]);
        assert_eq!(send(&mut keeper, json!(["EVENT", ephemeral]))[0][2], true);
        assert_eq!(seen(), vec![note.id.to_hex(), ephemeral.id.to_hex()]);
        // Refused at the door: never announced.
        let mut stranger = session(&relay, Visibility::Sheltered);
        let refused = event(&Keys::generate(), 1, NOW, "", &[]);
        assert_eq!(send(&mut stranger, json!(["EVENT", refused]))[0][2], false);
        assert_eq!(seen().len(), 2);
    }
}
