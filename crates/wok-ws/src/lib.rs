//! WebSocket transport for Wok's relay session engine ([`wok_store::relay`]).
//!
//! A [`Door`] holds the connection and work budgets one relay's doors share,
//! and hands out unbound axum routers: one for the public partition and one
//! for the sheltered partition. This crate opens no port; the application
//! binds the listener, chooses which router goes on which listener, and
//! supplies the identity its sheltered door admits ([`Admission`]).
//!
//! The public router never mounts the sheltered partition. It serves the
//! NIP-11 relay information document; a sheltered router serves one only
//! when built with [`Door::sheltered_router_with_information`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{
    State, WebSocketUpgrade,
    ws::rejection::WebSocketUpgradeRejection,
    ws::{CloseFrame, Message, WebSocket},
};
use axum::http::{Extensions, HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::FutureExt;
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use url::Url;
use wok_store::relay::{
    EventRelay, Handled, LiveReceiver, LiveRecvError, MAX_RELAY_FRAME_BYTES, PendingWrite,
    PreparedFrame, RelaySession, WriteCancel, WriteTicket, frame_may_subscribe,
};
use wok_store::{MAX_EXPIRE_EVENTS, Visibility};

/// The path both routers serve.
pub const PATH: &str = "/events";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Store and authority work the relay runs on the blocking pool at once,
/// across both partitions (the public door's allowance is a subset of these).
/// Every `spawn_blocking` the door makes for the store, an authority check or
/// an expiry sweep holds one of them; the only other one it makes, an EVENT
/// frame's parse and signature check, is CPU only. Size the runtime's
/// blocking pool with this in mind.
pub const WORK_PERMITS: usize = 2;

/// Connections across both doors, and the public door's share of them.
const CONNECTIONS: usize = 32;
const PUBLIC_CONNECTIONS: usize = 24;
/// The public door's share of [`WORK_PERMITS`].
const PUBLIC_WORK_PERMITS: usize = 1;

/// Per-connection WebSocket read buffer and write threshold, in bytes:
/// measured ~3 MB footprint saving at 20 connections, no delivery loss
/// (tungstenite's default is 128 KiB for each). The replies of one turn are
/// fed into the buffer and flushed once at the end; the buffer is written out
/// whenever it passes the threshold, so a batch holds at most the threshold
/// plus one frame. Events and frames up to the unchanged
/// `MAX_RELAY_FRAME_BYTES` still pass whole.
const WS_READ_BUFFER_BYTES: usize = 16 * 1024;
const WS_WRITE_BUFFER_BYTES: usize = 16 * 1024;

/// Deadlines for connections. The AUTH deadline is for the sheltered door;
/// the heartbeat and idle deadline apply to both doors. The defaults are the
/// NIP-42 and liveness intervals below; tests inject short values without
/// weakening them.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    auth_deadline: Duration,
    heartbeat: Duration,
    idle_deadline: Duration,
}

impl Timings {
    /// How long a sheltered connection may stay unauthenticated, how often a
    /// connection is pinged, and how long one may stay silent.
    pub const fn new(
        auth_deadline: Duration,
        heartbeat: Duration,
        idle_deadline: Duration,
    ) -> Self {
        Self {
            auth_deadline,
            heartbeat,
            idle_deadline,
        }
    }

    /// How long a sheltered connection may stay unauthenticated.
    pub const fn auth_deadline(&self) -> Duration {
        self.auth_deadline
    }

    /// How often an idle connection is pinged.
    pub const fn heartbeat(&self) -> Duration {
        self.heartbeat
    }

    /// How long a connection may send nothing before it is closed.
    pub const fn idle_deadline(&self) -> Duration {
        self.idle_deadline
    }
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            // A remote signer may take a 10-second provider probe followed by
            // up to 60 seconds of explicit approval before it answers AUTH.
            // This sheltered-only grace leaves transport/reply margin;
            // connection budgets remain enforced while AUTH is pending.
            auth_deadline: Duration::from_secs(90),
            heartbeat: Duration::from_secs(30),
            idle_deadline: Duration::from_secs(90),
        }
    }
}

/// Who may open a connection to the sheltered door, decided from the
/// request's extensions before the upgrade: the identity the application's
/// transport attached (an authenticated peer, a client certificate, a
/// connecting address). There is no default; a sheltered router is built
/// only with one. NIP-42 is still required on every connection it admits:
/// admission decides who may connect, not who may read or write.
pub trait Admission: Send + Sync + 'static {
    /// Admit the connection, holding whatever it needs for the connection's
    /// life, or refuse it with the HTTP status to answer.
    fn admit(&self, extensions: &Extensions) -> Result<Admitted, StatusCode>;
}

/// An admitted connection's hold on its admission (a per-peer permit, say),
/// released when the connection ends.
pub struct Admitted(#[allow(dead_code)] Box<dyn Send + Sync>);

impl Admitted {
    /// Hold `guard` for the connection's life.
    pub fn holding(guard: impl Send + Sync + 'static) -> Self {
        Self(Box::new(guard))
    }
}

/// One relay's doors: the routers, and the connection and work budgets they
/// share. Cloning shares the budgets.
#[derive(Clone)]
pub struct Door {
    relay: Arc<EventRelay>,
    connections: Arc<Semaphore>,
    public_connections: Arc<Semaphore>,
    work: Arc<Semaphore>,
    public_work: Arc<Semaphore>,
    stop: Arc<tokio::sync::watch::Sender<bool>>,
    timings: Timings,
}

impl Door {
    pub fn new(relay: Arc<EventRelay>) -> Self {
        Self::with_timings(relay, Timings::default())
    }

    pub fn with_timings(relay: Arc<EventRelay>, timings: Timings) -> Self {
        Self {
            relay,
            connections: Arc::new(Semaphore::new(CONNECTIONS)),
            public_connections: Arc::new(Semaphore::new(PUBLIC_CONNECTIONS)),
            work: Arc::new(Semaphore::new(WORK_PERMITS)),
            public_work: Arc::new(Semaphore::new(PUBLIC_WORK_PERMITS)),
            stop: Arc::new(tokio::sync::watch::channel(false).0),
            timings,
        }
    }

    /// Replace the connection budget: `shared` across both doors, of which
    /// the public door may hold `public`. The defaults are 32 and 24. Call
    /// before any router is built.
    pub fn with_connection_limits(mut self, shared: usize, public: usize) -> Self {
        self.connections = Arc::new(Semaphore::new(shared));
        self.public_connections = Arc::new(Semaphore::new(public));
        self
    }

    /// Replace the work budget: `shared` blocking-pool slots across both
    /// doors, of which public work may hold `public`. The defaults are
    /// [`WORK_PERMITS`] and 1. Call before any router is built.
    pub fn with_work_limits(mut self, shared: usize, public: usize) -> Self {
        self.work = Arc::new(Semaphore::new(shared));
        self.public_work = Arc::new(Semaphore::new(public));
        self
    }

    pub async fn expire(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        // Drain several bounded commits after an offline interval. Rejoin the
        // work queue between batches so a large backlog cannot starve other
        // store work.
        for _ in 0..32 {
            if *self.stop.borrow() || tokio::time::Instant::now() >= deadline {
                return;
            }
            let Ok(Ok(permit)) =
                tokio::time::timeout_at(deadline, Arc::clone(&self.work).acquire_owned()).await
            else {
                return;
            };
            let relay = Arc::clone(&self.relay);
            let result = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                relay.expire(now())
            })
            .await;
            match result {
                Ok(Ok(removed)) if removed == MAX_EXPIRE_EVENTS => {}
                Ok(Ok(_)) => return,
                _ => {
                    tracing::warn!(
                        "event expiration batch did not complete; earlier batches retained"
                    );
                    return;
                }
            }
            tokio::task::yield_now().await;
        }
    }

    /// The relay these doors serve.
    pub fn relay(&self) -> &Arc<EventRelay> {
        &self.relay
    }

    /// The connection deadlines.
    pub fn timings(&self) -> Timings {
        self.timings
    }

    /// The connection budget both doors share. An application's own door to
    /// the same relay (a replication door, say) takes its connections from
    /// here too.
    pub fn connections(&self) -> &Arc<Semaphore> {
        &self.connections
    }

    /// The store and authority work budget both doors share; see
    /// [`WORK_PERMITS`].
    pub fn work(&self) -> &Arc<Semaphore> {
        &self.work
    }

    /// A receiver that turns `true` when [`Self::shutdown`] is called.
    pub fn stopped(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Stop upgraded sockets as well as refusing new upgrades.
    pub fn shutdown(&self) {
        self.connections.close();
        self.stop.send_replace(true);
    }

    /// The public door: anyone reads; writes are what the relay's policy
    /// admits. It also serves the NIP-11 relay information document.
    pub fn public_router(&self, canonical_url: Url) -> Router {
        self.router(Visibility::Public, canonical_url, None, true)
    }

    /// The sheltered door, for connections `admission` lets in. NIP-42 is
    /// still required on each: admission alone is not authorisation. It
    /// serves no relay information document.
    pub fn sheltered_router(&self, canonical_url: Url, admission: Arc<dyn Admission>) -> Router {
        self.router(Visibility::Sheltered, canonical_url, Some(admission), false)
    }

    /// [`Self::sheltered_router`], also serving a NIP-11 relay information
    /// document that says every read and write needs NIP-42. The document is
    /// static, the same for every caller, and carries what the public one
    /// does: supported NIPs and limits, with no key, address, contents or
    /// live state. A request for it is not a connection, so `admission` does
    /// not see it; an upgrade still goes through `admission` and NIP-42
    /// whatever its `Accept` header says.
    pub fn sheltered_router_with_information(
        &self,
        canonical_url: Url,
        admission: Arc<dyn Admission>,
    ) -> Router {
        self.router(Visibility::Sheltered, canonical_url, Some(admission), true)
    }

    fn router(
        &self,
        visibility: Visibility,
        canonical_url: Url,
        admission: Option<Arc<dyn Admission>>,
        information: bool,
    ) -> Router {
        // The public door always serves NIP-11, a sheltered one only when
        // asked to. The CORS headers go on the document's own responses; do
        // not apply a general CORS layer to the sheltered door.
        let methods = match (visibility, information) {
            (Visibility::Public, _) => get(public_get).options(public_preflight),
            (Visibility::Sheltered, true) => {
                get(sheltered_get_with_information).options(public_preflight)
            }
            (Visibility::Sheltered, false) => get(sheltered_get),
        };
        Router::new().route(PATH, methods).with_state(SocketState {
            door: self.clone(),
            visibility,
            canonical_url,
            admission,
        })
    }
}

#[derive(Clone)]
struct SocketState {
    door: Door,
    visibility: Visibility,
    canonical_url: Url,
    /// Set for the sheltered door, and only for it.
    admission: Option<Arc<dyn Admission>>,
}

fn accepts_relay_information(headers: &HeaderMap) -> bool {
    headers.get_all(header::ACCEPT).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(',').any(|range| {
                let mut parts = range.split(';');
                if !parts
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/nostr+json")
                {
                    return false;
                }
                for parameter in parts {
                    let Some((name, value)) = parameter.trim().split_once('=') else {
                        return false;
                    };
                    if name.trim().eq_ignore_ascii_case("q")
                        && !value
                            .trim()
                            .parse::<f32>()
                            .is_ok_and(|q| q > 0.0 && q <= 1.0)
                    {
                        return false;
                    }
                }
                true
            })
        })
    })
}

fn public_information_cors(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Accept"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, HEAD, OPTIONS"),
    );
    response
}

async fn public_preflight() -> Response {
    public_information_cors(StatusCode::NO_CONTENT.into_response())
}

async fn public_get(
    State(state): State<SocketState>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    match ws {
        // A genuine upgrade retains the existing authentication, frame and
        // connection budgets, even if the client also sends an Accept header.
        Ok(ws) => upgrade(state, None, ws),
        Err(rejection) if !accepts_relay_information(&headers) => rejection.into_response(),
        Err(_) => relay_information(false),
    }
}

/// The NIP-11 document, the same bytes for every caller of a door. Static
/// capabilities only: never include an operator's key, private partitions,
/// canonical address, contents or live state. Both doors run the same
/// session, so they share the NIP list and the limits; only whether a read
/// needs NIP-42 differs.
fn relay_information(auth_required: bool) -> Response {
    let mut response = axum::Json(serde_json::json!({
        "supported_nips": wok_store::relay::SUPPORTED_NIPS,
        "limitation": {
            "max_message_length": MAX_RELAY_FRAME_BYTES,
            "max_subscriptions": wok_store::relay::MAX_SUBSCRIPTIONS,
            "max_limit": wok_store::MAX_QUERY_EVENTS,
            "default_limit": wok_store::MAX_QUERY_EVENTS,
            "max_subid_length": wok_store::relay::MAX_SUBSCRIPTION_ID_CHARS,
            "max_event_tags": wok_store::MAX_EVENT_TAGS,
            "restricted_writes": true,
            "auth_required": auth_required
        }
    }))
    .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/nostr+json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    public_information_cors(response)
}

async fn sheltered_get(
    State(state): State<SocketState>,
    extensions: Extensions,
    ws: WebSocketUpgrade,
) -> Response {
    upgrade(state, Some(&extensions), ws)
}

async fn sheltered_get_with_information(
    State(state): State<SocketState>,
    extensions: Extensions,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    match ws {
        // A genuine upgrade goes through admission and NIP-42 as on the
        // plain sheltered door, even if the client also sends an Accept
        // header.
        Ok(ws) => upgrade(state, Some(&extensions), ws),
        Err(rejection) if !accepts_relay_information(&headers) => rejection.into_response(),
        Err(_) => relay_information(true),
    }
}

fn upgrade(state: SocketState, extensions: Option<&Extensions>, ws: WebSocketUpgrade) -> Response {
    let public_permit = if state.visibility == Visibility::Public {
        match Arc::clone(&state.door.public_connections).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    let admitted = if state.visibility == Visibility::Sheltered {
        // Fail closed: a sheltered door with no admission, or a request with
        // no extensions to judge, admits nobody.
        let (Some(admission), Some(extensions)) = (state.admission.as_ref(), extensions) else {
            return StatusCode::FORBIDDEN.into_response();
        };
        match admission.admit(extensions) {
            Ok(admitted) => Some(admitted),
            Err(status) => return status.into_response(),
        }
    } else {
        None
    };
    let Ok(permit) = Arc::clone(&state.door.connections).try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.read_buffer_size(WS_READ_BUFFER_BYTES)
        .write_buffer_size(WS_WRITE_BUFFER_BYTES)
        .max_message_size(MAX_RELAY_FRAME_BYTES)
        .max_frame_size(MAX_RELAY_FRAME_BYTES)
        .on_upgrade(move |socket| serve(socket, state, permit, public_permit, admitted))
        .into_response()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn apply<T: Send + 'static>(
    mut session: RelaySession,
    state: &SocketState,
    f: impl FnOnce(&mut RelaySession) -> T + Send + 'static,
) -> Option<(RelaySession, T)> {
    // Acquire the public allowance first, so queued public work cannot hold
    // the shared permits reserved for private operations and expiry sweeps.
    let permits = timeout(IO_TIMEOUT, async {
        let public = if state.visibility == Visibility::Public {
            Some(
                Arc::clone(&state.door.public_work)
                    .acquire_owned()
                    .await
                    .ok()?,
            )
        } else {
            None
        };
        let shared = Arc::clone(&state.door.work).acquire_owned().await.ok()?;
        Some((public, shared))
    })
    .await
    .ok()??;
    tokio::task::spawn_blocking(move || {
        let _permits = permits;
        let replies = f(&mut session);
        (session, replies)
    })
    .await
    .ok()
}

/// A prepared frame, with the event store write taken out from behind the
/// work permits. The authority checks and the event's own checks run under a
/// permit; an event that passes them is queued for the relay's single writer
/// with no permit held, so waiting for its commit (which is shared with the
/// other connections' events) occupies neither a permit nor a blocking thread.
async fn handle_prepared(
    socket: &mut WebSocket,
    session: RelaySession,
    state: &SocketState,
    prepared: PreparedFrame,
) -> Result<Option<(RelaySession, (Vec<String>, bool))>, Closing> {
    if prepared.is_req_frame() {
        return stream_request(socket, session, state, prepared).await;
    }
    let Some((session, handled)) =
        apply(session, state, move |s| s.begin_prepared(prepared, now())).await
    else {
        return Ok(None);
    };
    let replies = match handled {
        Handled::Replies(replies) => replies,
        Handled::Write(write) => write.commit().await,
    };
    Ok(Some((session, (replies, false))))
}

/// How many bytes of EVENT frames a REQ holds before it starts streaming.
const STREAM_AFTER_BYTES: usize = 16 * 1024;

/// A held page goes out ahead of its EOSE. If the session answered otherwise
/// (a CLOSED: authority changed during the query, or the rows were
/// disordered), the page is dropped, as the buffered path sends no event then.
fn with_held(held: Vec<String>, replies: Vec<String>) -> Vec<String> {
    let ended = replies
        .first()
        .is_some_and(|reply| reply.starts_with("[\"EOSE\""));
    if held.is_empty() || !ended {
        return replies;
    }
    let mut out = held;
    out.extend(replies);
    out
}

/// A REQ whose events go to the socket as the store reads them. The session
/// runs on the blocking pool under a work permit and sends each EVENT frame
/// into an unbounded channel, so it never waits on a slow peer while holding
/// the permit; the page is already bounded by `MAX_REQ_REPLY_BYTES`, so the
/// channel holds no more than the reply vector did. The permit is dropped
/// when the closure returns, before this task has written the rest. This task
/// writes what has arrived and flushes whenever the channel is momentarily
/// empty, so each such batch, rather than the page as a whole, has
/// [`IO_TIMEOUT`] to reach the peer before the connection ends as stalled.
/// The replies that follow the events (EOSE, or CLOSED) are returned for
/// [`deliver`], as for any other frame.
///
/// A sheltered connection's authority is checked, as [`deliver`] checks it,
/// before the query: on a refusal the buffered path answers, and `deliver`
/// strips any event from its replies. The session judges its own authority
/// before the query too, so no event is sent to a reader who fails either.
async fn stream_request(
    socket: &mut WebSocket,
    session: RelaySession,
    state: &SocketState,
    prepared: PreparedFrame,
) -> Result<Option<(RelaySession, (Vec<String>, bool))>, Closing> {
    let sheltered = state.visibility == Visibility::Sheltered;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let work = apply(session, state, move |s| {
        if sheltered && !s.can_read_live(now()) {
            return s.begin_prepared(prepared, now());
        }
        // A small page is held and answered with its EOSE in one batch, as
        // the buffered path answers it, so [`deliver`] still judges it whole;
        // only a page past `STREAM_AFTER_BYTES` goes out as it is read.
        let mut held: Vec<String> = Vec::new();
        let mut held_bytes = 0usize;
        let mut streaming = false;
        let handled = s.begin_prepared_streaming(prepared, now(), &mut |frame| {
            if streaming {
                let _ = tx.send(frame);
                return;
            }
            held_bytes += frame.len();
            held.push(frame);
            if held_bytes >= STREAM_AFTER_BYTES {
                streaming = true;
                for frame in held.drain(..) {
                    let _ = tx.send(frame);
                }
            }
        });
        match handled {
            Handled::Replies(replies) => Handled::Replies(with_held(held, replies)),
            other => other,
        }
    });
    tokio::pin!(work);
    let mut open = true;
    let outcome = loop {
        tokio::select! {
            biased;
            received = rx.recv(), if open => {
                let Some(first) = received else {
                    // The closure has finished and dropped its sender; only
                    // its result is left to wait for.
                    open = false;
                    continue;
                };
                let mut frames = vec![first];
                while let Ok(frame) = rx.try_recv() {
                    frames.push(frame);
                }
                send(socket, frames).await?;
            },
            done = &mut work => break done,
        }
    };
    // Whatever the closure sent before it returned is still queued.
    let mut frames = Vec::new();
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    if !frames.is_empty() {
        send(socket, frames).await?;
    }
    let Some((session, handled)) = outcome else {
        return Ok(None);
    };
    let replies = match handled {
        Handled::Replies(replies) => replies,
        Handled::Write(write) => write.commit().await,
    };
    Ok(Some((session, (replies, false))))
}

/// Most EVENT writes one connection may have in flight at the writer, and the
/// most weight (the writer's own measure, about twice the JSON) they may
/// hold. At either bound the connection stops reading its socket until one
/// lands, so a flood waits in the peer's TCP buffer, not here. One more event
/// than the weight bound may be admitted, so the true ceiling is the bound
/// plus one maximal event.
const MAX_INFLIGHT_WRITES: usize = 64;
const MAX_INFLIGHT_WEIGHT: usize = 2 * 1024 * 1024;
/// How long a closing connection waits for its own writes to land before it
/// answers the rest with the closing reason.
const CLOSE_PENDING_WAIT: Duration = Duration::from_secs(2);

/// Test seam: the most writes any connection has had in flight.
#[cfg(test)]
static PEAK_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One connection's EVENT writes that have been queued for the writer and not
/// yet answered. Each takes its place in the writer's queue on the connection's
/// own task, in the order the frames arrived, so it shares a batch with the
/// connection's other events and everyone else's; what is kept here is only
/// the wait for the answer, with no task of its own. Each yields its replies
/// exactly once, here or (closing) as the closing reason, never both.
///
/// While the writer's queue is full a write waits for its place here, as a
/// future the connection's own select loop polls, rather than inside the arm
/// that read its frame. The connection reads no further frame meanwhile (that
/// is the backpressure, and what keeps the writes in frame order), but its
/// authority, expiry, heartbeat and live-delivery arms keep running, so a
/// revoked or expired guest is not left holding a wait of up to the writer's
/// whole `write_wait`.
struct InFlight {
    tasks: FuturesUnordered<futures_util::future::BoxFuture<'static, (u64, Vec<String>)>>,
    /// Ticket to (event id, weight, how to take it back out of the queue) for
    /// every write not yet answered.
    open: HashMap<u64, (String, usize, WriteCancel)>,
    weight: usize,
    next: u64,
    /// The one write still waiting for a place in the queue. Dropping it
    /// queues nothing.
    reserving: Option<Reserving>,
}

/// A write waiting for a place in the writer's queue.
struct Reserving {
    id: String,
    wait: futures_util::future::BoxFuture<'static, Result<WriteTicket, Vec<String>>>,
}

fn refusal(id: &str, reason: &str) -> String {
    json!(["OK", id, false, reason]).to_string()
}

impl InFlight {
    fn new() -> Self {
        Self {
            tasks: FuturesUnordered::new(),
            open: HashMap::new(),
            weight: 0,
            next: 0,
            reserving: None,
        }
    }

    /// Whether no write has a place in the queue and awaits its answer.
    fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Whether anything is left to wait for: an answer, or a place in the
    /// queue.
    fn waiting(&self) -> bool {
        !self.open.is_empty() || self.reserving.is_some()
    }

    /// Whether another frame may be read. A write waiting for its place in
    /// the queue holds the connection at one reserve at a time.
    fn has_room(&self) -> bool {
        self.reserving.is_none()
            && self.open.len() < MAX_INFLIGHT_WRITES
            && self.weight < MAX_INFLIGHT_WEIGHT
    }

    fn register(&mut self, ticket: WriteTicket) {
        let number = self.next;
        self.next += 1;
        self.weight += ticket.weight();
        self.open.insert(
            number,
            (ticket.id().to_owned(), ticket.weight(), ticket.canceller()),
        );
        #[cfg(test)]
        PEAK_IN_FLIGHT.fetch_max(self.open.len(), std::sync::atomic::Ordering::SeqCst);
        self.tasks
            .push(async move { (number, ticket.wait().await) }.boxed());
    }

    /// Ask for the write's place in the writer's queue. Its `OK` is sent when
    /// the commit lands. Usually the place is free and it is taken at once; if
    /// not, the wait is kept in `reserving` for [`Self::next`] to drive. The
    /// replies are the refusal if no place was found. At most one write may be
    /// waiting for a place, which the caller ensures by reading no frame
    /// while [`Self::has_room`] is false.
    fn begin(&mut self, write: Box<PendingWrite>) -> Vec<String> {
        debug_assert!(self.reserving.is_none());
        let id = write.id().to_owned();
        let mut wait = (*write).reserve().boxed();
        match wait.as_mut().now_or_never() {
            Some(Ok(ticket)) => {
                self.register(ticket);
                Vec::new()
            }
            Some(Err(replies)) => replies,
            None => {
                self.reserving = Some(Reserving { id, wait });
                Vec::new()
            }
        }
    }

    /// The outcome of the waiting reservation: nothing to send once it has a
    /// place, or the refusal if it found none.
    fn reserved(&mut self, result: Result<WriteTicket, Vec<String>>) -> Vec<String> {
        self.reserving = None;
        match result {
            Ok(ticket) => {
                self.register(ticket);
                Vec::new()
            }
            Err(replies) => replies,
        }
    }

    /// [`Self::begin`], then wait for the place if it was not free.
    #[cfg(test)]
    async fn start(&mut self, write: Box<PendingWrite>) -> Vec<String> {
        let replies = self.begin(write);
        let result = match self.reserving.as_mut() {
            Some(reserving) => reserving.wait.as_mut().await,
            None => return replies,
        };
        self.reserved(result)
    }

    /// The replies of the next write to land, or of a write that has found no
    /// place (empty once it has found one), or `None` with nothing in flight
    /// or waiting.
    async fn next(&mut self) -> Option<Vec<String>> {
        tokio::select! {
            Some((ticket, replies)) = self.tasks.next() => {
                if let Some((_, weight, _)) = self.open.remove(&ticket) {
                    self.weight -= weight;
                }
                Some(replies)
            },
            result = async {
                match self.reserving.as_mut() {
                    Some(reserving) => reserving.wait.as_mut().await,
                    None => std::future::pending().await,
                }
            }, if self.reserving.is_some() => Some(self.reserved(result)),
            else => None,
        }
    }

    /// Take back every write that no batch has yet, because this connection's
    /// authority has gone. Each is answered as cancelled, through the usual
    /// wait; one already in a batch commits, and the writer re-checks its
    /// author's authority before it applies it.
    fn cancel_queued(&self) {
        for (_, _, cancel) in self.open.values() {
            cancel.cancel();
        }
    }

    /// Give up on every write still in flight: one closing reply each. A
    /// write no batch has yet is taken back out of the queue, so an abandoned
    /// connection leaves nothing behind in memory; one already in a batch
    /// commits, and a resent event is then a duplicate.
    fn abandon(&mut self) -> Vec<String> {
        self.tasks = FuturesUnordered::new();
        self.weight = 0;
        let mut replies: Vec<String> = self
            .open
            .drain()
            .map(|(_, (id, _, cancel))| {
                cancel.cancel();
                refusal(
                    &id,
                    "error: connection closing; event may not be stored, resend it",
                )
            })
            .collect();
        replies.extend(self.stop_reserving());
        replies
    }

    /// Stop waiting for a place in the queue: nothing was queued, so nothing
    /// is stored, and the closing reply says so.
    fn stop_reserving(&mut self) -> Option<String> {
        self.reserving.take().map(|reserving| {
            refusal(
                &reserving.id,
                "error: connection closing; event not stored, resend it",
            )
        })
    }
}

/// An EVENT frame that passed the cheap checks: its authority checks and
/// `PreparedPut` run in frame order under a permit, then the write is queued
/// and the connection goes on reading. Its `OK` is sent when the commit lands.
async fn begin_write(
    session: RelaySession,
    state: &SocketState,
    prepared: PreparedFrame,
    in_flight: &mut InFlight,
) -> Option<(RelaySession, (Vec<String>, bool))> {
    let (session, handled) =
        apply(session, state, move |s| s.begin_prepared(prepared, now())).await?;
    let replies = match handled {
        Handled::Replies(replies) => replies,
        Handled::Write(write) => in_flight.begin(write),
    };
    Some((session, (replies, false)))
}

/// Wait for every write this connection has in flight, sending each `OK` as
/// it lands.
async fn settle(
    socket: &mut WebSocket,
    state: &SocketState,
    mut session: RelaySession,
    in_flight: &mut InFlight,
) -> Result<RelaySession, Closing> {
    while let Some(replies) = in_flight.next().await {
        session = deliver(socket, state, session, replies).await?;
    }
    Ok(session)
}

/// Send the `OK` of every write that has already landed, without waiting for
/// one that has not.
async fn drain_landed(
    socket: &mut WebSocket,
    state: &SocketState,
    mut session: RelaySession,
    in_flight: &mut InFlight,
) -> Result<RelaySession, Closing> {
    while let Some(Some(replies)) = in_flight.next().now_or_never() {
        session = deliver(socket, state, session, replies).await?;
    }
    Ok(session)
}

/// Put replies on the wire. A sheltered connection's authority is checked
/// again first, after store work and before a private batch is sent; the
/// verdict is cached per session and stamped with the authority generations,
/// so this is a compare unless something moved, and then it is refreshed
/// under a permit.
async fn deliver(
    socket: &mut WebSocket,
    state: &SocketState,
    mut session: RelaySession,
    replies: Vec<String>,
) -> Result<RelaySession, Closing> {
    if replies.is_empty() {
        return Ok(session);
    }
    if state.visibility == Visibility::Sheltered {
        let allowed = match session.try_can_read(now()) {
            Some(allowed) => allowed,
            None => {
                let Some((next, allowed)) = apply(session, state, |s| s.can_read_live(now())).await
                else {
                    return Err(BUSY);
                };
                session = next;
                allowed
            }
        };
        if allowed {
            send(socket, replies).await?;
        } else {
            // AUTH refusals and CLOSED explain the failure but carry no events.
            let safe = replies
                .into_iter()
                .filter(|r| !r.starts_with("[\"EVENT\","))
                .collect();
            send(socket, safe).await?;
        }
    } else {
        send(socket, replies).await?;
    }
    Ok(session)
}

/// Put one turn's replies on the wire. A batch that does not reach the peer
/// ends the connection as [`STALLED`]: whatever is left in the write buffer
/// is dropped with the socket, never written later.
async fn send(socket: &mut WebSocket, replies: Vec<String>) -> Result<(), Closing> {
    send_batch(
        socket,
        replies.into_iter().map(|reply| Message::Text(reply.into())),
        IO_TIMEOUT,
    )
    .await
    .map_err(|_| STALLED)
}

/// Why a batch of replies did not reach the wire.
#[derive(Debug, PartialEq, Eq)]
enum SendFailure {
    /// The peer did not take the batch within the deadline.
    TimedOut,
    /// The socket failed.
    Failed,
}

/// Feed every frame of one turn (a REQ's events and its EOSE or CLOSED, say)
/// and flush once at the end, so a page costs a few writes rather than one
/// per frame. Memory stays bounded under a slow peer: tungstenite writes its
/// buffer out as soon as it passes the write threshold, and when the socket
/// would block, the next `feed` waits in `poll_ready` until the buffer has
/// drained, so at most the threshold plus one frame is held. One deadline
/// covers the whole batch, as it did when each frame was flushed in turn.
/// After a failure the buffer may still hold frames of the batch, so the
/// caller must not write to the sink again (any write flushes them first).
async fn send_batch<S, M>(
    sink: &mut S,
    frames: impl IntoIterator<Item = M>,
    deadline: Duration,
) -> Result<(), SendFailure>
where
    S: futures_util::Sink<M> + Unpin,
{
    use futures_util::SinkExt as _;
    match timeout(deadline, async {
        for frame in frames {
            sink.feed(frame).await?;
        }
        sink.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(SendFailure::Failed),
        Err(_) => Err(SendFailure::TimedOut),
    }
}

/// Why a server-initiated close happens, as a WebSocket close code and a
/// short reason the client can log.
#[derive(Clone, Copy)]
struct Closing {
    code: u16,
    reason: &'static str,
    /// Whether the peer is live enough to wait on: answer its pending frames
    /// and wait for its Close. A deadline close is for a peer that is not, and
    /// must free its connection permits at once, so it only sends the frame.
    settle: bool,
    /// Whether anything may still be written. False after a batch of replies
    /// timed out or failed: tungstenite may still hold up to its write
    /// threshold plus one frame of that batch, and any later write (even a
    /// Close frame) would flush those frames to the peer after the fact. Such
    /// a connection is dropped with no Close frame, which discards them.
    /// A shutdown that interrupts a batch mid-send is still writable: that
    /// batch had just passed its authority check, so its buffered frames are
    /// flushed ahead of the Close frame.
    writable: bool,
}

const NORMAL: Closing = Closing {
    code: 1000,
    reason: "closing",
    settle: true,
    writable: true,
};
const SHUTDOWN: Closing = Closing {
    code: 1001,
    reason: "server shutting down",
    settle: true,
    writable: true,
};
const POLICY: Closing = Closing {
    code: 1008,
    reason: "closing: see the preceding NOTICE or CLOSED frame",
    settle: true,
    writable: true,
};
const DEADLINE: Closing = Closing {
    code: 1008,
    reason: "authentication or liveness deadline",
    settle: false,
    writable: true,
};
const LAGGED: Closing = Closing {
    code: 1013,
    reason: "reader fell behind; reconnect and query again",
    settle: true,
    writable: true,
};
const BUSY: Closing = Closing {
    code: 1013,
    reason: "server busy; reconnect and try again",
    settle: true,
    writable: true,
};

/// A batch of replies did not reach the peer within [`IO_TIMEOUT`], or the
/// socket failed. Nothing more is written; see [`Closing::writable`].
const STALLED: Closing = Closing {
    code: 1011,
    reason: "peer did not take replies in time",
    settle: false,
    writable: false,
};

/// How long a shutdown lets a connection finish the frame it is part way
/// through, so a write it has read is queued and answered before the close.
/// A turn still waiting after this (on a work permit, say, or a slow peer)
/// is interrupted, and a write it had read but not queued is not stored and
/// gets no answer.
const SHUTDOWN_TURN_GRACE: Duration = Duration::from_secs(1);

/// Bound on sending the Close frame to a peer that is not settled with.
const CLOSE_UNSETTLED: Duration = Duration::from_millis(100);
/// Bound on the whole closing handshake.
const CLOSE_GRACE: Duration = Duration::from_secs(3);
/// How long to wait for one more already-sent frame while closing.
const CLOSE_DRAIN_POLL: Duration = Duration::from_millis(20);
/// Frames answered at most while closing.
const CLOSE_DRAIN_FRAMES: usize = 64;

/// The id of an EVENT frame read but never applied, if `text` is one.
fn unapplied_event_id(text: &str) -> Option<String> {
    if !PreparedFrame::is_event_frame(text) {
        return None;
    }
    let value = serde_json::from_str::<Value>(text).ok()?;
    let id = value.get(1)?.get("id")?.as_str()?;
    (id.len() == 64).then(|| id.to_owned())
}

/// End a connection so the client observes it. Dropping a socket that still
/// has unread inbound frames resets it, and a reset can discard the NOTICE
/// and the close before the client reads them; a client with an EVENT in
/// flight then waits on a socket that is already gone. So: answer the EVENT
/// frames that already arrived (they were never applied, so `OK false` is
/// true), send a Close frame with a reason, then read until the client's own
/// Close or EOF, all inside [`CLOSE_GRACE`].
///
/// Writes still in flight each get exactly one answer: their own `OK` if the
/// commit lands within [`CLOSE_PENDING_WAIT`], otherwise the closing reason.
/// A connection closed for a missed deadline is not listening, so its writes
/// are only abandoned.
async fn close_connection(socket: &mut WebSocket, closing: Closing, in_flight: &mut InFlight) {
    if !closing.writable {
        // Dropping the socket discards the stalled batch's buffered frames.
        in_flight.abandon();
        return;
    }
    if !closing.settle {
        in_flight.abandon();
        let frame = CloseFrame {
            code: closing.code,
            reason: closing.reason.into(),
        };
        let _ = timeout(CLOSE_UNSETTLED, socket.send(Message::Close(Some(frame)))).await;
        return;
    }
    // A write still waiting for a place gets none now: it is answered with
    // the rest, below.
    let unqueued = in_flight.stop_reserving();
    let _ = timeout(CLOSE_GRACE, async {
        let deadline = tokio::time::Instant::now() + CLOSE_PENDING_WAIT;
        while !in_flight.is_empty() {
            match tokio::time::timeout_at(deadline, in_flight.next()).await {
                Ok(Some(replies)) => {
                    if send(socket, replies).await.is_err() {
                        return;
                    }
                }
                _ => break,
            }
        }
        let mut rest = in_flight.abandon();
        rest.extend(unqueued);
        if !rest.is_empty() && send(socket, rest).await.is_err() {
            return;
        }
        for _ in 0..CLOSE_DRAIN_FRAMES {
            match timeout(CLOSE_DRAIN_POLL, socket.recv()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Some(id) = unapplied_event_id(&text) {
                        let reply = json!([
                            "OK",
                            id,
                            false,
                            "error: connection closing; event not stored, resend it"
                        ])
                        .to_string();
                        if send(socket, vec![reply]).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(Some(Ok(Message::Close(_))) | None | Some(Err(_))) => return,
                Ok(Some(Ok(_))) => {}
                Err(_) => break,
            }
        }
        let frame = CloseFrame {
            code: closing.code,
            reason: closing.reason.into(),
        };
        if socket.send(Message::Close(Some(frame))).await.is_err() {
            return;
        }
        while let Some(Ok(message)) = socket.recv().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    })
    .await;
}

async fn serve(
    mut socket: WebSocket,
    state: SocketState,
    _permit: OwnedSemaphorePermit,
    _public_permit: Option<OwnedSemaphorePermit>,
    _admitted: Option<Admitted>,
) {
    let mut stopped = state.door.stop.subscribe();
    let between_turns = stopped.clone();
    // Outside `serve_connected`, so a shutdown that drops it still answers
    // what is in flight.
    let mut in_flight = InFlight::new();
    // `serve_connected` takes a shutdown between turns; this interrupts a
    // turn that is still running once the grace has passed.
    let closing = tokio::select! {
        closing = serve_connected(&mut socket, &state, &mut in_flight, between_turns) => closing,
        _ = async {
            let _ = stopped.wait_for(|stopped| *stopped).await;
            tokio::time::sleep(SHUTDOWN_TURN_GRACE).await;
        } => SHUTDOWN,
    };
    close_connection(&mut socket, closing, &mut in_flight).await;
}

async fn serve_connected(
    socket: &mut WebSocket,
    state: &SocketState,
    in_flight: &mut InFlight,
    mut stopped: tokio::sync::watch::Receiver<bool>,
) -> Closing {
    // Attached only while a REQ is open: a connection with no subscription
    // has no use for live events, and must not lag or be woken by them.
    let mut live: Option<LiveReceiver> = None;
    let mut authority_changes = state.door.relay.authority_changes();
    let mut session =
        state
            .door
            .relay
            .session(state.visibility, state.canonical_url.clone(), now());
    if let Err(closing) = send(socket, vec![session.challenge_frame()]).await {
        return closing;
    }
    let auth_deadline = tokio::time::Instant::now() + state.door.timings.auth_deadline;
    let mut last_inbound = tokio::time::Instant::now();
    let mut next_heartbeat = last_inbound + state.door.timings.heartbeat;
    loop {
        let authenticated = session.is_authenticated();
        // The guest's expiry is fixed by the grants it authenticated on (a
        // change to them retires the socket), so this is a field read, never
        // a storage query on the connection task.
        let guest_expiry = session.guest_expiry().map(|expires_at| {
            let wall_now = now();
            tokio::time::Instant::now() + Duration::from_secs(expires_at.saturating_sub(wall_now))
        });
        // Set when this turn found the connection's authority gone.
        let mut authority_lost = false;
        let result = tokio::select! {
            // At the cap the socket is not read: backpressure to the peer.
            incoming=socket.recv(), if in_flight.has_room() =>{
                match incoming {
                    Some(Ok(Message::Text(text)))=>{
                        last_inbound = tokio::time::Instant::now();
                        // Attach before the frame runs, so an event stored while a
                        // REQ's query runs is queued rather than missed.
                        if live.is_none() && frame_may_subscribe(&text) {
                            live = Some(state.door.relay.subscribe_partition(state.visibility));
                        }
                        if !session.admit_frame(now()) {
                            Some((session, (vec!["[\"NOTICE\",\"rate-limited: slow down\"]".into()], true)))
                        } else {
                            // Parse and verify before taking a work permit: a forged
                            // or malformed event costs no permit and no store time,
                            // and verification of different connections' events
                            // runs in parallel.
                            let text = text.as_str().to_owned();
                            let prepared = if PreparedFrame::is_event_frame(&text) {
                                match tokio::task::spawn_blocking(move || PreparedFrame::parse(text)).await {
                                    Ok(prepared) => prepared,
                                    Err(_) => return BUSY,
                                }
                            } else {
                                PreparedFrame::parse(text)
                            };
                            match session.refuse_unverified(&prepared) {
                                Some(replies) => Some((session, (replies, false))),
                                // An EVENT is queued and the next frame read at once.
                                None if prepared.is_event() => {
                                    begin_write(session, state, prepared, in_flight).await
                                }
                                // Anything else runs after this connection's own
                                // writes have landed and been answered, so a REQ
                                // after an EVENT sees it, as when each frame was
                                // finished before the next was read.
                                None => {
                                    let mut session = match settle(socket, state, session, in_flight).await {
                                        Ok(session) => session,
                                        Err(closing) => return closing,
                                    };
                                    // A CLOSE only removes a subscription: it is
                                    // answered here, already admitted above, with
                                    // no work permit and no blocking hop.
                                    match session.try_close(&prepared) {
                                        Some(replies) => Some((session, (replies, false))),
                                        None => match handle_prepared(socket, session, state, prepared).await {
                                            Ok(outcome) => outcome,
                                            Err(closing) => return closing,
                                        },
                                    }
                                }
                            }
                        }
                    },
                    Some(Ok(Message::Binary(_)))=>{
                        let replies = if session.admit_frame(now()) {
                            vec!["[\"NOTICE\",\"invalid: binary frames are not NIP-01\"]".into()]
                        } else { vec!["[\"NOTICE\",\"rate-limited: slow down\"]".into()] };
                        return send(socket, replies).await.err().unwrap_or(POLICY);
                    },
                    Some(Ok(Message::Ping(payload)))=>{
                        last_inbound = tokio::time::Instant::now();
                        if !session.admit_frame(now()) { return send(socket, vec!["[\"NOTICE\",\"rate-limited: slow down\"]".into()]).await.err().unwrap_or(POLICY); }
                        if socket.send(Message::Pong(payload)).await.is_err() { return NORMAL; }
                        continue;
                    },
                    Some(Ok(Message::Pong(_)))=>{
                        last_inbound = tokio::time::Instant::now();
                        if !session.admit_frame(now()) { return send(socket, vec!["[\"NOTICE\",\"rate-limited: slow down\"]".into()]).await.err().unwrap_or(POLICY); }
                        continue;
                    },
                    Some(Ok(Message::Close(_)))=> { let _ = session.admit_frame(now()); return NORMAL; },
                    Some(Err(_))=> { let _ = session.admit_frame(now()); return NORMAL; },
                    None=>return NORMAL,
                }
            },
            received=async {
                match live.as_mut() {
                    Some(live) => live.recv().await,
                    None => std::future::pending().await,
                }
            }=>{
                match received {
                    Ok(_) if !session.has_subscriptions() => {
                        live = None;
                        continue;
                    },
                    // On this task, with no permit: a filter match and a splice,
                    // unless a guest's verdict has to be refreshed first.
                    Ok(event)=>{
                        // The writer answers a batch before it announces it, so
                        // an OK for this connection's own event has landed by now:
                        // send it first, and the connection never sees its own
                        // event live ahead of its OK.
                        if !in_flight.is_empty() {
                            session = match drain_landed(socket, state, session, in_flight).await {
                                Ok(session) => session,
                                Err(closing) => return closing,
                            };
                        }
                        match session.try_on_live(&event, now()) {
                            Some(replies) => Some((session, (replies, false))),
                            None => apply(session, state, move |s| (s.on_live(&event, now()), false)).await,
                        }
                    },
                    Err(LiveRecvError::Lagged)=>{
                        return send(socket,vec!["[\"NOTICE\",\"rate-limited: reader fell behind; reconnect and query again\"]".into()]).await.err().unwrap_or(LAGGED);
                    },
                    Err(LiveRecvError::Closed)=>return NORMAL,
                }
            },
            landed = in_flight.next(), if in_flight.waiting() => {
                Some((session, (landed.unwrap_or_default(), false)))
            },
            _ = authority_changes.changed(), if state.visibility == Visibility::Sheltered => {
                let outcome = apply(session, state, |s| {
                    s.invalidate_live_access();
                    if s.authority_is_current(now()) {
                        (vec![], false)
                    } else {
                        (
                            s.close_subscriptions("restricted: sheltered authority changed"),
                            true,
                        )
                    }
                }).await;
                authority_lost |= matches!(outcome, Some((_, (_, true))));
                outcome
            },
            _ = tokio::time::sleep_until(guest_expiry.unwrap_or_else(tokio::time::Instant::now)), if guest_expiry.is_some() => {
                let outcome = apply(session, state, |s| {
                    (s.close_subscriptions("restricted: circle authority expired"), true)
                }).await;
                authority_lost |= matches!(outcome, Some((_, (_, true))));
                outcome
            },
            // Between turns: the frame read last has been queued or answered.
            _ = async {
                let _ = stopped.wait_for(|stopped| *stopped).await;
            } => return SHUTDOWN,
            _ = tokio::time::sleep_until(auth_deadline), if state.visibility == Visibility::Sheltered && !authenticated => return DEADLINE,
            // A public socket has no AUTH deadline, so it must at least answer
            // pings: one that goes quiet stops holding a public permit.
            _ = tokio::time::sleep_until(last_inbound + state.door.timings.idle_deadline), if state.visibility == Visibility::Public || authenticated => return DEADLINE,
            _ = tokio::time::sleep_until(next_heartbeat), if state.visibility == Visibility::Public => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() { return NORMAL; }
                next_heartbeat = tokio::time::Instant::now() + state.door.timings.heartbeat;
                continue;
            },
            _ = tokio::time::sleep_until(next_heartbeat), if state.visibility == Visibility::Sheltered && authenticated => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() { return NORMAL; }
                next_heartbeat = tokio::time::Instant::now() + state.door.timings.heartbeat;
                let outcome = apply(session, state, |s| {
                    if s.can_read_at(now()) && s.authority_is_current(now()) {
                        (vec![], false)
                    } else {
                        (s.close_subscriptions("restricted: sheltered authority changed"), true)
                    }
                }).await;
                authority_lost |= matches!(outcome, Some((_, (_, true))));
                outcome
            },
        };
        if authority_lost {
            // The connection is closing because its authority went. Writes no
            // batch has yet are not to be stored on it: take them back.
            in_flight.cancel_queued();
        }
        let Some((next, (replies, close_after_reply))) = result else {
            return BUSY;
        };
        session = next;
        if live.is_some() && !session.has_subscriptions() {
            live = None;
        }
        if replies.is_empty() && !close_after_reply {
            continue;
        }
        session = match deliver(socket, state, session, replies).await {
            Ok(session) => session,
            Err(closing) => return closing,
        };
        if close_after_reply {
            return POLICY;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Extension;
    use axum::body::Body;
    use axum::http::Request;
    use futures_util::{SinkExt, StreamExt};
    use negentropy::{Id as NegentropyId, Negentropy, NegentropyStorageVector};
    use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind, Tag};
    use nostr::key::{Keys, PublicKey};
    use nostr::types::Timestamp;
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
    use tower::ServiceExt as _;
    use wok_store::relay::KeeperAccess;
    use wok_store::{EventStore, EventStoreError, PreparedPut, PutResult, SqliteEventStore};
    type Socket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;
    struct Owner(PublicKey);
    impl KeeperAccess for Owner {
        fn owns(&self, key: &PublicKey) -> bool {
            *key == self.0
        }
    }
    fn event(key: &Keys, kind: u16, at: u64, text: &str, tags: Vec<Vec<String>>) -> Event {
        EventBuilder::new(Kind::from(kind), text)
            .custom_created_at(Timestamp::from_secs(at))
            .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
            .finalize(key)
            .unwrap()
    }
    async fn receive(socket: &mut Socket) -> Value {
        loop {
            let message = timeout(Duration::from_secs(5), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let ClientMessage::Text(text) = message {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }
    async fn send_frame(socket: &mut Socket, value: Value) {
        socket
            .send(ClientMessage::Text(value.to_string().into()))
            .await
            .unwrap();
    }
    async fn closes_within(socket: &mut Socket, duration: Duration) -> bool {
        timeout(duration, async {
            loop {
                match socket.next().await {
                    None | Some(Err(_)) | Some(Ok(ClientMessage::Close(_))) => return true,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await
        .unwrap_or(false)
    }
    async fn connect(url: &str, key: Option<&Keys>) -> Socket {
        let (mut socket, _) = connect_async(url).await.unwrap();
        let challenge = receive(&mut socket).await;
        assert_eq!(challenge[0], "AUTH");
        if let Some(key) = key {
            let auth = event(
                key,
                22242,
                now(),
                "",
                vec![
                    vec!["relay".into(), url.into()],
                    vec!["challenge".into(), challenge[1].as_str().unwrap().into()],
                ],
            );
            send_frame(&mut socket, json!(["AUTH", auth])).await;
            assert_eq!(receive(&mut socket).await[2], true);
        }
        socket
    }
    async fn listen(routes: &Door, scope: Visibility) -> (String, tokio::task::JoinHandle<()>) {
        listen_as(routes, scope, TestPeer(1)).await
    }
    async fn listen_as(
        routes: &Door,
        scope: Visibility,
        peer: TestPeer,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
        let app = match scope {
            Visibility::Public => routes.public_router(url.parse().unwrap()),
            Visibility::Sheltered => routes
                .sheltered_router(url.parse().unwrap(), Arc::new(PerPeer::default()))
                .layer(Extension(peer)),
        };
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (url, task)
    }
    fn routes(tmp: &TempDir, key: &Keys) -> Door {
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        Door::new(Arc::new(EventRelay::new(
            store,
            Arc::new(Owner(key.public_key())),
        )))
    }

    fn routes_with_timings(tmp: &TempDir, key: &Keys, timings: Timings) -> Door {
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        Door::with_timings(
            Arc::new(EventRelay::new(store, Arc::new(Owner(key.public_key())))),
            timings,
        )
    }

    /// A server-role WebSocket over an in-memory pipe of `pipe` bytes, with
    /// the production write threshold and a hard cap on the write buffer.
    async fn piped_socket(
        pipe: usize,
        max_buffer: usize,
    ) -> (
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
    ) {
        use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
        let (server_io, client_io) = tokio::io::duplex(pipe);
        // Past the cap tungstenite refuses the frame with an error, so a
        // batch that buffered without bound would fail rather than time out.
        let config = WebSocketConfig::default()
            .write_buffer_size(WS_WRITE_BUFFER_BYTES)
            .max_write_buffer_size(max_buffer);
        let server = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_io,
            Role::Server,
            Some(config),
        )
        .await;
        let client =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_io, Role::Client, None)
                .await;
        (server, client)
    }

    /// A store whose batch commit waits at a gate, to hold a write in flight.
    struct Held {
        inner: SqliteEventStore,
        held: std::sync::Mutex<bool>,
        released: std::sync::Condvar,
        entered: std::sync::atomic::AtomicBool,
        /// Milliseconds each batch takes to "sync", standing in for an fsync.
        sync_ms: std::sync::atomic::AtomicU64,
        /// Every event id, in the order the store was offered them.
        order: std::sync::Mutex<Vec<String>>,
    }
    impl EventStore for Held {
        fn put(&self, v: Visibility, e: &Event, n: u64) -> PutResult {
            self.inner.put(v, e, n)
        }
        fn query(
            &self,
            v: Visibility,
            f: &nostr::filter::Filter,
            n: u64,
        ) -> Result<Vec<Event>, EventStoreError> {
            self.inner.query(v, f, n)
        }
        fn logical_bytes(&self) -> Result<u64, EventStoreError> {
            self.inner.logical_bytes()
        }
        fn put_replicated(&self, v: Visibility, e: &Event, n: u64) -> PutResult {
            self.inner.put_replicated(v, e, n)
        }
        fn expire(&self, now: u64) -> Result<usize, EventStoreError> {
            self.inner.expire(now)
        }
        fn put_prepared_batch(&self, batch: &[PreparedPut]) -> Vec<PutResult> {
            self.entered
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.order
                .lock()
                .unwrap()
                .extend(batch.iter().map(|put| put.event().id.to_hex()));
            let mut held = self.held.lock().unwrap();
            while *held {
                held = self.released.wait(held).unwrap();
            }
            drop(held);
            let sync = self.sync_ms.load(std::sync::atomic::Ordering::SeqCst);
            if sync > 0 {
                std::thread::sleep(Duration::from_millis(sync));
            }
            self.inner.put_prepared_batch(batch)
        }
    }

    fn relay_over(store: Arc<dyn EventStore>, key: &Keys, frames: u32) -> Door {
        Door::new(Arc::new(
            EventRelay::new(store, Arc::new(Owner(key.public_key()))).with_frame_limit(frames),
        ))
    }

    fn held_store(tmp: &TempDir, held: bool) -> Arc<Held> {
        Arc::new(Held {
            inner: SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
            held: std::sync::Mutex::new(held),
            released: std::sync::Condvar::new(),
            entered: std::sync::atomic::AtomicBool::new(false),
            sync_ms: std::sync::atomic::AtomicU64::new(0),
            order: std::sync::Mutex::default(),
        })
    }

    fn release(store: &Held) {
        *store.held.lock().unwrap() = false;
        store.released.notify_all();
    }

    struct ReleaseOnDrop<'a>(&'a Held);

    impl Drop for ReleaseOnDrop<'_> {
        fn drop(&mut self) {
            release(self.0);
        }
    }

    async fn entered(store: &Held) {
        let began = std::time::Instant::now();
        while !store.entered.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "no write reached the store"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Every message until the socket closes or goes quiet.
    async fn until_closed(socket: &mut Socket, quiet: Duration) -> Vec<Value> {
        let mut got = Vec::new();
        while let Ok(Some(Ok(message))) = timeout(quiet, socket.next()).await {
            if let ClientMessage::Text(text) = message {
                got.push(serde_json::from_str(&text).unwrap());
            }
        }
        got
    }

    fn oks(frames: &[Value]) -> Vec<(String, bool, String)> {
        frames
            .iter()
            .filter(|f| f[0] == "OK")
            .map(|f| {
                (
                    f[1].as_str().unwrap().to_owned(),
                    f[2].as_bool().unwrap(),
                    f[3].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    /// An event of exactly `MAX_EVENT_BYTES` of JSON, by padding the text.
    fn largest_event(key: &Keys, at: u64, tag: char) -> Event {
        use wok_store::MAX_EVENT_BYTES;
        let bare = serde_json::to_string(&event(key, 1, at, "", vec![]))
            .unwrap()
            .len();
        let big = event(
            key,
            1,
            at,
            &tag.to_string().repeat(MAX_EVENT_BYTES - bare),
            vec![],
        );
        assert_eq!(serde_json::to_string(&big).unwrap().len(), MAX_EVENT_BYTES);
        big
    }

    /// Eight pipelined events with the frame allowance at six: the sixth is
    /// refused and the connection closes while the first five are still in
    /// flight, and the last two arrive after. Each id is answered at most once.
    async fn closed_with_writes_pending(hold_for: Option<Duration>) -> Vec<Value> {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, true);
        let routes = relay_over(Arc::clone(&store) as Arc<dyn EventStore>, &key, 6);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let events: Vec<Event> = (0..8)
            .map(|n| event(&key, 1, now() - 100 + n, &format!("closing {n}"), vec![]))
            .collect();
        for e in &events {
            send_frame(&mut socket, json!(["EVENT", e])).await;
        }
        entered(&store).await;
        let frames = match hold_for {
            Some(hold) => {
                let releasing = {
                    let store = Arc::clone(&store);
                    tokio::spawn(async move {
                        tokio::time::sleep(hold).await;
                        release(&store);
                    })
                };
                let frames = until_closed(&mut socket, Duration::from_secs(6)).await;
                releasing.await.unwrap();
                frames
            }
            None => {
                let frames = until_closed(&mut socket, Duration::from_secs(6)).await;
                release(&store);
                frames
            }
        };
        let ids: Vec<String> = events.iter().map(|e| e.id.to_hex()).collect();
        let answers = oks(&frames);
        for id in &ids {
            assert!(
                answers.iter().filter(|a| &a.0 == id).count() <= 1,
                "{id} answered twice"
            );
        }
        assert!(
            frames.iter().any(|f| f[0] == "NOTICE"),
            "the rate limit spoke"
        );
        // The first five were in flight; each has an answer.
        for id in &ids[..5] {
            assert_eq!(
                answers.iter().filter(|a| &a.0 == id).count(),
                1,
                "{id} unanswered"
            );
        }
        routes.shutdown();
        task.abort();
        frames
    }

    async fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
        let began = std::time::Instant::now();
        while !ready() {
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// A public-door session authenticated as `key`, as a connection has it.
    fn keeper_session(relay: &Arc<EventRelay>, key: &Keys) -> RelaySession {
        let url = "wss://relay.example/events";
        let mut session = relay.session(Visibility::Public, url.parse().unwrap(), now());
        let challenge = serde_json::from_str::<Value>(&session.challenge_frame()).unwrap()[1]
            .as_str()
            .unwrap()
            .to_owned();
        let auth = event(
            key,
            22242,
            now(),
            "",
            vec![
                vec!["relay".into(), url.into()],
                vec!["challenge".into(), challenge],
            ],
        );
        let replies = session.handle(&json!(["AUTH", auth]).to_string(), now());
        assert!(replies[0].contains("true"), "{replies:?}");
        session
    }

    fn pending_write(session: &mut RelaySession, event: &Event) -> Box<PendingWrite> {
        let prepared = PreparedFrame::parse(json!(["EVENT", event]).to_string());
        match session.begin_prepared(prepared, now()) {
            Handled::Write(write) => write,
            Handled::Replies(replies) => panic!("refused before the writer: {replies:?}"),
        }
    }

    /// The identity a test transport attaches to a sheltered request.
    #[derive(Clone, Copy)]
    struct TestPeer(u8);

    /// Sheltered sockets one test peer may hold at once, as a transport's
    /// per-peer admission caps them.
    const SHELTERED_SOCKETS_PER_PEER: usize = 4;

    /// Admits a request that carries a [`TestPeer`], up to
    /// [`SHELTERED_SOCKETS_PER_PEER`] at once for each peer, and nothing else.
    #[derive(Default)]
    struct PerPeer(std::sync::Mutex<HashMap<u8, Arc<Semaphore>>>);

    impl Admission for PerPeer {
        fn admit(&self, extensions: &Extensions) -> Result<Admitted, StatusCode> {
            let peer = extensions.get::<TestPeer>().ok_or(StatusCode::FORBIDDEN)?;
            let slot = Arc::clone(
                self.0
                    .lock()
                    .expect("test peer map")
                    .entry(peer.0)
                    .or_insert_with(|| Arc::new(Semaphore::new(SHELTERED_SOCKETS_PER_PEER))),
            );
            slot.try_acquire_owned()
                .map(Admitted::holding)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
        }
    }

    /// Admits one connection at a time: the admission holds the only slot.
    struct OneAtATime(Arc<Semaphore>);

    impl Admission for OneAtATime {
        fn admit(&self, _extensions: &Extensions) -> Result<Admitted, StatusCode> {
            Arc::clone(&self.0)
                .try_acquire_owned()
                .map(Admitted::holding)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
        }
    }

    fn refusal_status(
        result: Result<impl Sized, tokio_tungstenite::tungstenite::Error>,
    ) -> StatusCode {
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => response.status(),
            Err(other) => panic!("not an HTTP refusal: {other}"),
            Ok(_) => panic!("the upgrade was admitted"),
        }
    }

    #[tokio::test]
    async fn a_sheltered_door_admits_nobody_its_admission_cannot_place() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
        // No identity attached: the admission has nothing to place.
        let app = routes.sheltered_router(url.parse().unwrap(), Arc::new(PerPeer::default()));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        assert_eq!(
            refusal_status(connect_async(&url).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(routes.connections.available_permits(), 32);
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn an_admitted_connection_holds_its_admission_until_it_ends() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
        let slot = Arc::new(Semaphore::new(1));
        let app = routes.sheltered_router(
            url.parse().unwrap(),
            Arc::new(OneAtATime(Arc::clone(&slot))),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut first = connect(&url, None).await;
        // The refusal carries the admission's own status, and takes no
        // connection from the shared budget.
        assert_eq!(
            refusal_status(connect_async(&url).await),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(routes.connections.available_permits(), 31);
        first.close(None).await.unwrap();
        assert!(closes_within(&mut first, Duration::from_secs(5)).await);
        drop(first);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while slot.available_permits() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the admission was never released"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _second = connect(&url, None).await;
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_batch_is_fed_and_flushed_once_and_arrives_whole_and_in_order() {
        let (mut server, mut client) = piped_socket(64 * 1024, 64 * 1024).await;
        let frames: Vec<String> = (0..500)
            .map(|i| {
                format!(
                    "[\"EVENT\",\"s\",{{\"n\":{i},\"pad\":\"{}\"}}]",
                    "x".repeat(900)
                )
            })
            .chain(std::iter::once("[\"EOSE\",\"s\"]".to_owned()))
            .collect();
        let expected = frames.clone();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            while got.len() < expected.len() {
                match client.next().await {
                    Some(Ok(ClientMessage::Text(text))) => got.push(text.as_str().to_owned()),
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(got, expected);
        });
        let sent = send_batch(
            &mut server,
            frames.into_iter().map(|f| ClientMessage::Text(f.into())),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(sent, Ok(()));
        timeout(Duration::from_secs(5), reader)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_slow_reader_holds_bounded_memory_and_times_out_the_whole_batch() {
        // The peer never reads. The pipe takes 4 KiB; the write buffer may
        // hold the 16 KiB threshold plus one frame, never more.
        let frame_len = 1024;
        let cap = WS_WRITE_BUFFER_BYTES + 2 * frame_len;
        let (mut server, _client) = piped_socket(4 * 1024, cap).await;
        let taken = std::sync::atomic::AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let deadline = Duration::from_millis(300);
        let sent = send_batch(
            &mut server,
            (0..10_000).map(|_| {
                taken.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ClientMessage::Text("x".repeat(frame_len).into())
            }),
            deadline,
        )
        .await;
        // A timeout, not a WriteBufferFull failure: the buffer never passed
        // its cap, because `feed` waited for it to drain.
        assert_eq!(sent, Err(SendFailure::TimedOut));
        assert!(started.elapsed() >= deadline);
        assert!(
            started.elapsed() < deadline * 10,
            "one deadline covers the batch"
        );
        // Only the frames that fit the pipe and the buffer were taken from
        // the batch; the rest were never produced.
        let taken = taken.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            taken <= (4 * 1024 + cap) / frame_len + 2,
            "{taken} frames taken under a stalled peer"
        );
    }

    /// Frames left in the write buffer by a timed-out batch reach the peer
    /// if anything is written afterwards, and never if the socket is dropped,
    /// which is why a stalled connection closes with no further write.
    #[tokio::test]
    async fn a_stalled_batch_leaves_frames_that_only_a_later_write_would_deliver() {
        type Piped = tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>;
        /// A batch the peer never takes: its result and the frames produced.
        async fn stall(server: &mut Piped) -> (Result<(), SendFailure>, usize) {
            let produced = std::sync::atomic::AtomicUsize::new(0);
            let sent = send_batch(
                server,
                (0..10_000).map(|i| {
                    produced.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    ClientMessage::Text(format!("{i:0>1024}").into())
                }),
                Duration::from_millis(200),
            )
            .await;
            (sent, produced.load(std::sync::atomic::Ordering::Relaxed))
        }
        async fn read_all(mut client: Piped) -> usize {
            let mut frames = 0;
            while let Ok(Some(Ok(ClientMessage::Text(_)))) =
                timeout(Duration::from_millis(500), client.next()).await
            {
                frames += 1;
            }
            frames
        }
        // Dropped after the timeout: only what reached the pipe arrives.
        let (mut server, client) = piped_socket(4 * 1024, 64 * 1024).await;
        let (sent, produced) = stall(&mut server).await;
        assert_eq!(sent, Err(SendFailure::TimedOut));
        drop(server);
        let dropped = read_all(client).await;
        assert!(
            dropped + 8 < produced,
            "{dropped} of {produced} frames arrived after a drop"
        );
        // Written to again after the timeout: the stale frames arrive (all
        // but the one whose `feed` was waiting when the deadline fired).
        let (mut server, client) = piped_socket(4 * 1024, 64 * 1024).await;
        let (sent, produced) = stall(&mut server).await;
        assert_eq!(sent, Err(SendFailure::TimedOut));
        let reader = tokio::spawn(read_all(client));
        let _ = timeout(Duration::from_secs(2), server.flush()).await;
        drop(server);
        let later = reader.await.unwrap();
        assert!(
            later + 1 >= produced && later > dropped + 8,
            "{later} of {produced} frames arrived after a later write"
        );
        // A stalled connection is closed with no write at all.
        const { assert!(!STALLED.writable && !STALLED.settle) };
        for closing in [NORMAL, SHUTDOWN, POLICY, DEADLINE, LAGGED, BUSY] {
            assert!(closing.writable);
        }
    }

    #[tokio::test]
    async fn public_information_is_browser_readable_without_keeper_metadata() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let app = routes.public_router("wss://keeper.example/events".parse().unwrap());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(PATH)
                    .header("accept", "application/json, application/nostr+json; q=0.9")
                    .header("origin", "https://client.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/nostr+json");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["access-control-allow-headers"], "Accept");
        assert_eq!(
            response.headers()["access-control-allow-methods"],
            "GET, HEAD, OPTIONS"
        );
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-credentials")
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let document: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            document,
            json!({
                "supported_nips": [1, 9, 11, 40, 42, 45, 70, 77],
                "limitation": {
                    "max_message_length": 263_168,
                    "max_subscriptions": 16,
                    "max_limit": 128,
                    "default_limit": 128,
                    "max_subid_length": 64,
                    "max_event_tags": 512,
                    "restricted_writes": true,
                    "auth_required": false
                }
            })
        );
        let text = std::str::from_utf8(&body).unwrap();
        assert!(!text.contains(&key.public_key().to_hex()));
        assert!(!text.contains("keeper.example"));
        assert!(!text.contains("forgesworn"));
        assert_eq!(routes.connections.available_permits(), 32);
        assert_eq!(routes.public_connections.available_permits(), 24);
        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(PATH)
                    .header("accept", "application/nostr+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn public_information_preflight_does_not_open_sheltered_routes() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let url: Url = "wss://keeper.example/events".parse().unwrap();
        let response = routes
            .public_router(url.clone())
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(PATH)
                    .header("origin", "https://client.example")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "accept")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["access-control-allow-headers"], "Accept");
        for method in ["GET", "OPTIONS"] {
            let response = routes
                .sheltered_router(url.clone(), Arc::new(PerPeer::default()))
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(PATH)
                        .header("accept", "application/nostr+json")
                        .header("origin", "https://client.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(!response.status().is_success());
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-origin")
            );
        }
    }

    #[tokio::test]
    async fn public_information_requires_explicit_acceptable_media_type() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let app = routes(&tmp, &key).public_router("wss://keeper.example/events".parse().unwrap());
        for accept in [
            "",
            "*/*",
            "application/json",
            "application/nostr+json; q=0",
            "application/nostr+json; q=NaN",
            "application/nostr+json; q=1.1",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(PATH)
                        .header("accept", accept)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                !response.status().is_success(),
                "unexpected metadata for {accept}"
            );
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-origin")
            );
        }
    }

    #[tokio::test]
    async fn public_information_accept_header_does_not_replace_websocket_authentication() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (url, task) = listen(&routes, Visibility::Public).await;
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("application/nostr+json"),
        );
        let (mut socket, response) = connect_async(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(receive(&mut socket).await[0], "AUTH");
        let note = event(&key, 1, now(), "authentication still required", vec![]);
        send_frame(&mut socket, json!(["EVENT", note])).await;
        let refused = receive(&mut socket).await;
        assert_eq!(refused[0], "OK");
        assert_eq!(refused[1], note.id.to_hex());
        assert_eq!(refused[2], false);
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn sheltered_information_says_every_read_and_write_needs_auth() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let app = routes.sheltered_router_with_information(
            "wss://keeper.example/events".parse().unwrap(),
            Arc::new(PerPeer::default()),
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(PATH)
                    .header("accept", "application/json, application/nostr+json; q=0.9")
                    .header("origin", "https://client.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/nostr+json");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["access-control-allow-headers"], "Accept");
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-credentials")
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let document: Value = serde_json::from_slice(&body).unwrap();
        // Exactly the public document's keys and limits, with auth required.
        assert_eq!(
            document,
            json!({
                "supported_nips": [1, 9, 11, 40, 42, 45, 70, 77],
                "limitation": {
                    "max_message_length": 263_168,
                    "max_subscriptions": 16,
                    "max_limit": 128,
                    "default_limit": 128,
                    "max_subid_length": 64,
                    "max_event_tags": 512,
                    "restricted_writes": true,
                    "auth_required": true
                }
            })
        );
        let text = std::str::from_utf8(&body).unwrap();
        assert!(!text.contains(&key.public_key().to_hex()));
        assert!(!text.contains("keeper.example"));
        assert!(!text.contains("forgesworn"));
        // Asking for the document opens no connection and takes no budget.
        assert_eq!(routes.connections.available_permits(), 32);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(PATH)
                    .header("accept", "application/nostr+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .is_empty()
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(PATH)
                    .header("origin", "https://client.example")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "accept")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
    }

    #[tokio::test]
    async fn sheltered_information_refuses_other_requests_as_the_plain_door_does() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let url: Url = "wss://keeper.example/events".parse().unwrap();
        let with =
            routes.sheltered_router_with_information(url.clone(), Arc::new(PerPeer::default()));
        let plain = routes.sheltered_router(url, Arc::new(PerPeer::default()));
        for accept in [
            "",
            "*/*",
            "application/json",
            "application/nostr+json; q=0",
            "application/nostr+json; q=NaN",
            "application/nostr+json; q=1.1",
        ] {
            let request = || {
                Request::builder()
                    .uri(PATH)
                    .header("accept", accept)
                    .header("origin", "https://client.example")
                    .body(Body::empty())
                    .unwrap()
            };
            let answered = with.clone().oneshot(request()).await.unwrap();
            let before = plain.clone().oneshot(request()).await.unwrap();
            assert!(
                !answered.status().is_success(),
                "unexpected metadata for {accept}"
            );
            assert_eq!(answered.status(), before.status(), "for {accept}");
            assert!(
                !answered
                    .headers()
                    .contains_key("access-control-allow-origin")
            );
        }
    }

    #[tokio::test]
    async fn an_upgrade_asking_for_information_still_meets_admission_and_auth() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
        let admitted = routes
            .sheltered_router_with_information(url.parse().unwrap(), Arc::new(PerPeer::default()))
            .layer(Extension(TestPeer(1)));
        let task = tokio::spawn(async move {
            axum::serve(listener, admitted).await.unwrap();
        });
        let mut request = url.clone().into_client_request().unwrap();
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("application/nostr+json"),
        );
        let (mut socket, response) = connect_async(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(receive(&mut socket).await[0], "AUTH");
        drop(socket);
        task.abort();

        // No identity attached: admission refuses the upgrade, and the
        // refusal is its status, not the document.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
        let refused = routes
            .sheltered_router_with_information(url.parse().unwrap(), Arc::new(PerPeer::default()));
        let task = tokio::spawn(async move {
            axum::serve(listener, refused).await.unwrap();
        });
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            header::ACCEPT,
            HeaderValue::from_static("application/nostr+json"),
        );
        match connect_async(request).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert!(
                    !response
                        .headers()
                        .contains_key("access-control-allow-origin")
                );
                let body = response.body().as_deref().unwrap_or_default();
                assert!(!String::from_utf8_lossy(body).contains("supported_nips"));
            }
            Err(other) => panic!("not an HTTP refusal: {other}"),
            Ok(_) => panic!("the upgrade was admitted"),
        }
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn public_event_router_serves_nothing_but_its_door() {
        let tmp = TempDir::new().expect("temp dir");
        let key = Keys::generate();
        let response = routes(&tmp, &key)
            .public_router("wss://events.example/events".parse().unwrap())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn background_expiry_drains_multiple_batches_and_preserves_unexpired_events() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        let at = now();
        for n in 0..(MAX_EXPIRE_EVENTS * 2 + 1) {
            let old = event(
                &key,
                1,
                at - 20,
                &format!("old {n}"),
                vec![vec!["expiration".into(), (at - 1).to_string()]],
            );
            store.put(Visibility::Sheltered, &old, at - 20).unwrap();
        }
        let retained = event(&key, 1, at, "still retained", vec![]);
        store.put(Visibility::Sheltered, &retained, at).unwrap();
        let routes = Door::new(Arc::new(EventRelay::new(
            store.clone(),
            Arc::new(Owner(key.public_key())),
        )));
        routes.expire().await;
        assert_eq!(
            store.expire(at).unwrap(),
            0,
            "the route drains more than one batch"
        );
        assert_eq!(
            store
                .query(Visibility::Sheltered, &nostr::filter::Filter::new(), at)
                .unwrap(),
            vec![retained]
        );
        assert_eq!(routes.work.available_permits(), 2);
        routes.shutdown();
    }

    #[tokio::test]
    async fn actual_websockets_keep_private_history_and_live_frames_off_the_public_door() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (public, public_task) = listen(&routes, Visibility::Public).await;
        let (private, private_task) = listen(&routes, Visibility::Sheltered).await;
        let mut anonymous = connect(&private, None).await;
        send_frame(&mut anonymous, json!(["REQ", "no", {}])).await;
        assert_eq!(receive(&mut anonymous).await[0], "CLOSED");
        let mut writer = connect(&private, Some(&key)).await;
        let mut private_reader = connect(&private, Some(&key)).await;
        let mut public_reader = connect(&public, Some(&key)).await;
        for (socket, id) in [
            (&mut private_reader, "inside"),
            (&mut public_reader, "outside"),
        ] {
            send_frame(socket, json!(["REQ",id,{"limit":0}])).await;
            assert_eq!(receive(socket).await, json!(["EOSE", id]));
        }
        let outer = Keys::generate();
        let wrap = event(
            &outer,
            1059,
            now(),
            "opaque ciphertext",
            vec![vec!["p".into(), key.public_key().to_hex()]],
        );
        send_frame(&mut writer, json!(["EVENT", wrap])).await;
        assert_eq!(receive(&mut writer).await[2], true);
        assert_eq!(
            receive(&mut private_reader).await[2]["id"],
            wrap.id.to_hex()
        );
        send_frame(
            &mut public_reader,
            json!(["REQ","exact",{"ids":[wrap.id.to_hex()]}]),
        )
        .await;
        assert_eq!(receive(&mut public_reader).await, json!(["EOSE", "exact"]));
        send_frame(
            &mut private_reader,
            json!(["REQ","saved",{"ids":[wrap.id.to_hex()]}]),
        )
        .await;
        assert_eq!(
            receive(&mut private_reader).await[2]["id"],
            wrap.id.to_hex()
        );
        assert_eq!(receive(&mut private_reader).await, json!(["EOSE", "saved"]));
        routes.shutdown();
        public_task.abort();
        private_task.abort();
    }

    #[tokio::test]
    async fn actual_websocket_nip77_reconciles_ids_but_never_event_bodies() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (url, task) = listen(&routes, Visibility::Public).await;
        let mut writer = connect(&url, Some(&key)).await;
        let stored = event(&key, 1, now(), "not in the index", vec![]);
        send_frame(&mut writer, json!(["EVENT", stored])).await;
        assert_eq!(receive(&mut writer).await[2], true);

        let mut storage = NegentropyStorageVector::new();
        storage.seal().unwrap();
        let mut client = Negentropy::owned(storage, 64 * 1024).unwrap();
        let initial = hex::encode(client.initiate().unwrap());
        let mut reader = connect(&url, None).await;
        send_frame(
            &mut reader,
            json!(["NEG-OPEN", "sync", {"kinds":[1]}, initial]),
        )
        .await;
        let response = receive(&mut reader).await;
        assert_eq!(response[0], "NEG-MSG");
        assert!(!response.to_string().contains("not in the index"));
        let response_bytes = hex::decode(response[2].as_str().unwrap()).unwrap();
        let mut have = Vec::new();
        let mut need = Vec::new();
        let _ = client
            .reconcile_with_ids(&response_bytes, &mut have, &mut need)
            .unwrap();
        assert_eq!(
            need,
            vec![NegentropyId::from_byte_array(stored.id.to_bytes())]
        );

        send_frame(&mut reader, json!(["NEG-MSG", "sync", "abc"])).await;
        assert_eq!(receive(&mut reader).await[0], "NEG-ERR");
        send_frame(&mut reader, json!(["REQ", "still-open", {"limit":0}])).await;
        assert_eq!(receive(&mut reader).await, json!(["EOSE", "still-open"]));
        routes.shutdown();
        task.abort();
    }

    /// Pure writers hold no subscription, so they never attach to the live
    /// channel: a thousand pipelined events (ten sockets, inside each
    /// socket's own frame budget) disconnect nobody, and a reader of all of
    /// them, which the old 128-slot channel would have dropped, keeps up.
    #[tokio::test]
    async fn pipelined_writers_are_never_dropped_for_fanout_and_a_reader_sees_everything() {
        const WRITERS: usize = 10;
        const PER_WRITER: usize = 100;
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (public, task) = listen(&routes, Visibility::Public).await;

        let mut reader = connect(&public, None).await;
        send_frame(&mut reader, json!(["REQ", "all", {"kinds":[1], "limit":0}])).await;
        assert_eq!(receive(&mut reader).await, json!(["EOSE", "all"]));
        let reader_task = tokio::spawn(async move {
            let mut seen = std::collections::BTreeSet::new();
            while seen.len() < WRITERS * PER_WRITER {
                let frame = receive(&mut reader).await;
                assert_eq!(frame[0], "EVENT", "reader was sent {frame}");
                seen.insert(frame[2]["id"].as_str().unwrap().to_owned());
            }
        });

        let mut writers = Vec::new();
        for writer in 0..WRITERS {
            let url = public.clone();
            let key = key.clone();
            writers.push(tokio::spawn(async move {
                let mut socket = connect(&url, Some(&key)).await;
                let batch: Vec<Event> = (0..PER_WRITER)
                    .map(|n| event(&key, 1, now(), &format!("w{writer}-{n}"), vec![]))
                    .collect();
                for e in &batch {
                    send_frame(&mut socket, json!(["EVENT", e])).await;
                }
                for _ in &batch {
                    let reply = receive(&mut socket).await;
                    assert_eq!(reply[0], "OK", "writer was sent {reply}");
                    assert_eq!(reply[2], true, "writer was sent {reply}");
                }
            }));
        }
        for writer in writers {
            writer.await.unwrap();
        }
        reader_task.await.unwrap();
        routes.shutdown();
        task.abort();
    }

    /// The live receiver is attached before a REQ's stored query runs, so an
    /// event stored while the query runs is in the stored batch, the live
    /// queue or both, never neither. (Delivery is at least once, as before.)
    #[tokio::test]
    async fn an_event_stored_around_a_late_req_is_never_lost() {
        const TOTAL: usize = 100;
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let started = Arc::new(tokio::sync::Notify::new());

        let writer_url = public.clone();
        let writer_key = key.clone();
        let writer_started = Arc::clone(&started);
        let writer = tokio::spawn(async move {
            let mut socket = connect(&writer_url, Some(&writer_key)).await;
            let mut ids = Vec::new();
            for n in 0..TOTAL {
                let e = event(&writer_key, 1, now(), &format!("race-{n}"), vec![]);
                ids.push(e.id.to_hex());
                send_frame(&mut socket, json!(["EVENT", e])).await;
                assert_eq!(receive(&mut socket).await[2], true);
                if n == 10 {
                    writer_started.notify_one();
                }
            }
            ids
        });

        let mut reader = connect(&public, None).await;
        started.notified().await;
        send_frame(&mut reader, json!(["REQ", "late", {"kinds":[1]}])).await;
        let mut seen = std::collections::BTreeSet::new();
        let mut eose = false;
        while !(eose && seen.len() == TOTAL) {
            let frame = receive(&mut reader).await;
            match frame[0].as_str().unwrap() {
                "EVENT" => {
                    seen.insert(frame[2]["id"].as_str().unwrap().to_owned());
                }
                "EOSE" => eose = true,
                other => panic!("unexpected {other}: {frame}"),
            }
        }
        let written: std::collections::BTreeSet<String> =
            writer.await.unwrap().into_iter().collect();
        assert_eq!(seen, written);
        routes.shutdown();
        task.abort();
    }

    /// A held page is sent only ahead of an EOSE, never ahead of a CLOSED.
    #[test]
    fn a_held_page_goes_out_only_ahead_of_its_eose() {
        let held = vec!["[\"EVENT\",\"q\",{}]".to_string()];
        let eose = vec!["[\"EOSE\",\"q\"]".to_string()];
        let closed = vec!["[\"CLOSED\",\"q\",\"restricted: authority changed\"]".to_string()];
        assert_eq!(
            with_held(held.clone(), eose.clone()),
            vec![held[0].clone(), eose[0].clone()]
        );
        assert_eq!(with_held(held, closed.clone()), closed);
        assert_eq!(with_held(Vec::new(), eose.clone()), eose);
    }

    /// A sheltered REQ is streamed: its events arrive newest first, then the
    /// EOSE, and a stranger's REQ gets a CLOSED and no event.
    #[tokio::test]
    async fn a_sheltered_req_streams_its_events_then_eose() {
        const TOTAL: u64 = 60;
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (url, task) = listen(&routes, Visibility::Sheltered).await;
        let mut keeper = connect(&url, Some(&key)).await;
        let base = now() - 1000;
        for n in 0..TOTAL {
            let e = event(&key, 1, base + n, &format!("row-{n}"), vec![]);
            send_frame(&mut keeper, json!(["EVENT", e])).await;
            assert_eq!(receive(&mut keeper).await[2], true);
        }
        send_frame(&mut keeper, json!(["REQ", "page", {"kinds": [1]}])).await;
        let mut times = Vec::new();
        loop {
            let frame = receive(&mut keeper).await;
            match frame[0].as_str().unwrap() {
                "EVENT" => times.push(frame[2]["created_at"].as_u64().unwrap()),
                "EOSE" => break,
                other => panic!("unexpected {other}: {frame}"),
            }
        }
        let expected: Vec<u64> = (0..TOTAL).rev().map(|n| base + n).collect();
        assert_eq!(times, expected);

        // A page under the streaming threshold is held and answered whole.
        send_frame(
            &mut keeper,
            json!(["REQ", "small", {"kinds": [1], "limit": 2}]),
        )
        .await;
        let first = receive(&mut keeper).await;
        let second = receive(&mut keeper).await;
        let end = receive(&mut keeper).await;
        assert_eq!(first[2]["created_at"], base + TOTAL - 1);
        assert_eq!(second[2]["created_at"], base + TOTAL - 2);
        assert_eq!(end[0], "EOSE");

        // A key with no access is refused with no event.
        let (mut stranger, _) = connect_async(&url).await.unwrap();
        assert_eq!(receive(&mut stranger).await[0], "AUTH");
        send_frame(&mut stranger, json!(["REQ", "page", {"kinds": [1]}])).await;
        let refused = receive(&mut stranger).await;
        assert_eq!(refused[0], "CLOSED");
        routes.shutdown();
        task.abort();
    }

    /// A server-initiated close is a Close frame with a reason, not silence.
    /// Frames the client had already sent are read and answered first (they
    /// were never applied), so they cannot turn the close into a reset that
    /// hides it.
    #[tokio::test]
    async fn a_rate_limited_socket_gets_a_close_frame_and_unapplied_events_are_answered() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, None).await;
        let stranger = Keys::generate();
        for n in 0..130 {
            let e = event(&stranger, 1, now(), &format!("flood-{n}"), vec![]);
            socket
                .feed(ClientMessage::Text(json!(["EVENT", e]).to_string().into()))
                .await
                .unwrap();
        }
        socket.flush().await.unwrap();
        let mut notices = 0;
        let mut closing_oks = 0;
        let mut close = None;
        timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = socket.next().await {
                match message {
                    ClientMessage::Text(text) => {
                        let frame: Value = serde_json::from_str(&text).unwrap();
                        if frame[0] == "NOTICE" {
                            notices += 1;
                        } else if frame[0] == "OK"
                            && frame[3].as_str().unwrap().contains("connection closing")
                        {
                            closing_oks += 1;
                        }
                    }
                    ClientMessage::Close(frame) => {
                        close = frame;
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("a Close frame within five seconds, not silence");
        assert_eq!(notices, 1);
        assert!(
            closing_oks >= 1,
            "frames already sent are answered, not dropped"
        );
        let close = close.expect("the Close frame carries a code and a reason");
        assert_eq!(u16::from(close.code), 1008);
        assert!(!close.reason.is_empty());
        assert!(closes_within(&mut socket, Duration::from_secs(5)).await);
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_reader_dropped_over_its_byte_budget_sees_a_notice_then_a_close_frame() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        // A budget no event fits in: the first live event drops the reader.
        let routes = Door::new(Arc::new(
            EventRelay::new(store, Arc::new(Owner(key.public_key()))).with_live_queue_bytes(1),
        ));
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut reader = connect(&public, None).await;
        send_frame(&mut reader, json!(["REQ", "all", {"kinds":[1], "limit":0}])).await;
        assert_eq!(receive(&mut reader).await, json!(["EOSE", "all"]));
        let mut writer = connect(&public, Some(&key)).await;
        let e = event(&key, 1, now(), "overflow", vec![]);
        send_frame(&mut writer, json!(["EVENT", e])).await;
        assert_eq!(receive(&mut writer).await[2], true);

        let mut notice = None;
        let mut close = None;
        timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = reader.next().await {
                match message {
                    ClientMessage::Text(text) => notice = Some(text.to_string()),
                    ClientMessage::Close(frame) => {
                        close = frame;
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("a Close frame within five seconds, not silence");
        assert!(notice.unwrap().contains("reader fell behind"));
        let close = close.expect("the Close frame carries a code and a reason");
        assert_eq!(u16::from(close.code), 1013);
        assert!(close.reason.contains("fell behind"));
        assert!(closes_within(&mut reader, Duration::from_secs(5)).await);
        // The writer was never a subscriber and is untouched.
        let again = event(&key, 1, now(), "still fine", vec![]);
        send_frame(&mut writer, json!(["EVENT", again])).await;
        assert_eq!(receive(&mut writer).await[2], true);
        routes.shutdown();
        task.abort();
    }

    /// With every work permit held, a forged event from an authenticated
    /// socket is still refused at once: parsing and verification take no
    /// permit. (A valid event would wait for one.)
    #[tokio::test]
    async fn a_forged_event_is_refused_while_every_work_permit_is_held() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;

        let held_public = Arc::clone(&routes.public_work)
            .acquire_owned()
            .await
            .unwrap();
        let held_shared = Arc::clone(&routes.work)
            .acquire_many_owned(2)
            .await
            .unwrap();
        let mut forged = event(&key, 1, now(), "genuine", vec![]);
        forged.content = "forged".into();
        send_frame(&mut socket, json!(["EVENT", forged])).await;
        let reply = timeout(Duration::from_secs(1), receive(&mut socket))
            .await
            .expect("refused without waiting for a permit");
        assert_eq!(
            reply,
            json!([
                "OK",
                forged.id.to_hex(),
                false,
                "invalid: event shape or signature"
            ])
        );

        drop((held_public, held_shared));
        let good = event(&key, 1, now(), "genuine", vec![]);
        send_frame(&mut socket, json!(["EVENT", good])).await;
        assert_eq!(receive(&mut socket).await[2], true);
        routes.shutdown();
        task.abort();
    }

    /// The write waits on the writer, not on a work permit: with one event in
    /// flight at the store, every permit is free and another connection's
    /// reads are served.
    #[tokio::test]
    async fn an_event_waiting_for_the_writer_holds_no_work_permit() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = Arc::new(Held {
            inner: SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
            held: std::sync::Mutex::new(true),
            released: std::sync::Condvar::new(),
            entered: std::sync::atomic::AtomicBool::new(false),
            sync_ms: std::sync::atomic::AtomicU64::new(0),
            order: std::sync::Mutex::default(),
        });
        let routes = Door::new(Arc::new(EventRelay::new(
            Arc::clone(&store) as Arc<dyn EventStore>,
            Arc::new(Owner(key.public_key())),
        )));
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut writer = connect(&public, Some(&key)).await;
        let mut reader = connect(&public, None).await;
        let note = event(&key, 1, now(), "in flight", vec![]);
        send_frame(&mut writer, json!(["EVENT", note])).await;
        let began = std::time::Instant::now();
        while !store.entered.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "the write never reached the store"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(routes.work.available_permits(), 2);
        assert_eq!(routes.public_work.available_permits(), 1);
        send_frame(&mut reader, json!(["REQ", "any", {"kinds": [1]}])).await;
        assert_eq!(receive(&mut reader).await, json!(["EOSE", "any"]));
        // Not acknowledged until the commit.
        assert!(
            timeout(Duration::from_millis(200), writer.next())
                .await
                .is_err(),
            "no OK before the commit"
        );
        *store.held.lock().unwrap() = false;
        store.released.notify_all();
        let reply = receive(&mut writer).await;
        assert_eq!(reply, json!(["OK", note.id.to_hex(), true, ""]));
        assert!(matches!(
            store
                .query(
                    Visibility::Public,
                    &nostr::filter::Filter::new().id(note.id),
                    now()
                )
                .unwrap()
                .len(),
            1
        ));
        routes.shutdown();
        task.abort();
    }

    /// CLOSE is answered on the connection task: with every work permit
    /// taken, a CLOSE and the frame after it are still served at once, and
    /// the subscription is gone. It still spends the inbound minute budget.
    #[tokio::test]
    async fn close_needs_no_work_permit_and_is_still_rate_admitted() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store: Arc<dyn EventStore> = Arc::new(
            SqliteEventStore::open(&tmp.path().join("events.sqlite"), 10_000_000).unwrap(),
        );
        let routes = relay_over(Arc::clone(&store), &key, 4);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut writer = connect(&public, Some(&key)).await;
        let (mut reader, _) = connect_async(&public).await.unwrap();
        assert_eq!(receive(&mut reader).await[0], "AUTH");
        // Frame 1: a live subscription.
        send_frame(&mut reader, json!(["REQ", "s", {"kinds": [1], "limit": 0}])).await;
        assert_eq!(receive(&mut reader).await, json!(["EOSE", "s"]));
        // Every permit is taken; a frame that needed one would wait.
        let shared = Arc::clone(&routes.work)
            .acquire_many_owned(2)
            .await
            .unwrap();
        let public_permit = Arc::clone(&routes.public_work)
            .acquire_owned()
            .await
            .unwrap();
        // Frames 2 and 3: the CLOSE, then a ping that is answered only once
        // the CLOSE has been handled.
        send_frame(&mut reader, json!(["CLOSE", "s"])).await;
        reader
            .send(ClientMessage::Ping(b"after".to_vec().into()))
            .await
            .unwrap();
        let pong = timeout(Duration::from_secs(2), reader.next())
            .await
            .expect("the CLOSE waited for a work permit")
            .unwrap()
            .unwrap();
        assert!(matches!(pong, ClientMessage::Pong(ref p) if &p[..] == b"after"));
        drop(shared);
        drop(public_permit);
        // The subscription is gone: a new event is not delivered to it.
        let note = event(&key, 1, now(), "after close", vec![]);
        send_frame(&mut writer, json!(["EVENT", note])).await;
        assert_eq!(receive(&mut writer).await[0], "OK");
        assert!(
            timeout(Duration::from_millis(300), reader.next())
                .await
                .is_err(),
            "nothing is delivered to a closed subscription"
        );
        // Frame 4 is the last the budget of 4 admits; frame 5, a CLOSE, is
        // refused like any other frame.
        send_frame(&mut reader, json!(["CLOSE", "s"])).await;
        send_frame(&mut reader, json!(["CLOSE", "s"])).await;
        assert_eq!(
            receive(&mut reader).await,
            json!(["NOTICE", "rate-limited: slow down"])
        );
        assert!(closes_within(&mut reader, Duration::from_secs(5)).await);
        routes.shutdown();
        task.abort();
    }

    /// The 16 KiB socket buffers are far below the largest event and below one
    /// REQ reply; both must still travel whole (the write threshold only delays
    /// small writes, and every reply is flushed as it is sent).
    #[tokio::test]
    async fn a_largest_event_and_a_large_req_reply_round_trip_through_small_socket_buffers() {
        use wok_store::MAX_EVENT_BYTES;
        const {
            assert!(WS_READ_BUFFER_BYTES < MAX_EVENT_BYTES / 8);
            assert!(WS_WRITE_BUFFER_BYTES < MAX_EVENT_BYTES / 8);
        }
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let at = now() - 1_000;
        // Six largest events, about 1.5 MiB: one REQ reply, under the reply cap.
        let events: Vec<Event> = ['a', 'b', 'c', 'd', 'e', 'f']
            .iter()
            .enumerate()
            .map(|(n, c)| largest_event(&key, at + n as u64, *c))
            .collect();
        for e in &events {
            send_frame(&mut socket, json!(["EVENT", e])).await;
            let ok = receive(&mut socket).await;
            assert_eq!(ok[0], "OK");
            assert_eq!(ok[1], e.id.to_hex());
            assert_eq!(ok[2], true, "{ok}");
        }
        send_frame(
            &mut socket,
            json!(["REQ", "big", {"ids": [events[0].id.to_hex()]}]),
        )
        .await;
        let first = receive(&mut socket).await;
        assert_eq!(first[0], "EVENT");
        assert_eq!(first[2]["id"], events[0].id.to_hex());
        assert_eq!(first[2]["content"], events[0].content);
        assert_eq!(receive(&mut socket).await, json!(["EOSE", "big"]));
        send_frame(
            &mut socket,
            json!(["REQ", "all", {"kinds": [1], "limit": 100}]),
        )
        .await;
        let mut got = std::collections::BTreeMap::new();
        loop {
            let frame = receive(&mut socket).await;
            if frame[0] == "EOSE" {
                assert_eq!(frame[1], "all");
                break;
            }
            assert_eq!(frame[0], "EVENT", "{frame}");
            assert_eq!(frame[1], "all");
            got.insert(
                frame[2]["id"].as_str().unwrap().to_owned(),
                frame[2]["content"].as_str().unwrap().to_owned(),
            );
        }
        assert_eq!(got.len(), events.len(), "every large event came back");
        for e in &events {
            assert_eq!(got[&e.id.to_hex()], e.content, "content intact");
        }
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_connection_pipelining_a_burst_gets_every_ok_and_the_writer_batches_it() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        // Hold the first commit until the connection reaches its in-flight cap.
        let store = held_store(&tmp, true);
        let relay = Arc::new(
            EventRelay::new(
                Arc::clone(&store) as Arc<dyn EventStore>,
                Arc::new(Owner(key.public_key())),
            )
            .with_frame_limit(100_000),
        );
        let routes = Door::new(Arc::clone(&relay));
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let events: Vec<Event> = (0..500)
            .map(|n| event(&key, 1, now() - 1_000 + n, &format!("burst {n}"), vec![]))
            .collect();
        let _release_on_drop = ReleaseOnDrop(&store);
        for e in events.iter().take(MAX_INFLIGHT_WRITES) {
            send_frame(&mut socket, json!(["EVENT", e])).await;
        }
        entered(&store).await;
        wait_until("the connection to reach its in-flight cap", || {
            relay.writer_queued().0 + store.order.lock().unwrap().len() == MAX_INFLIGHT_WRITES
        })
        .await;
        release(&store);
        for e in events.iter().skip(MAX_INFLIGHT_WRITES) {
            send_frame(&mut socket, json!(["EVENT", e])).await;
        }
        let mut answered = std::collections::BTreeSet::new();
        for _ in 0..events.len() {
            let reply = receive(&mut socket).await;
            assert_eq!(reply[0], "OK");
            assert_eq!(reply[2], true, "{reply}");
            assert!(
                answered.insert(reply[1].as_str().unwrap().to_owned()),
                "one OK each"
            );
        }
        let expected: std::collections::BTreeSet<String> =
            events.iter().map(|e| e.id.to_hex()).collect();
        assert_eq!(answered, expected);
        relay.flush();
        let stats = relay.writer_stats();
        assert_eq!(stats.events, 500);
        assert!(
            stats.largest_batch > 8,
            "the held connection committed a batch: {stats:?}"
        );
        assert!(PEAK_IN_FLIGHT.load(std::sync::atomic::Ordering::SeqCst) <= MAX_INFLIGHT_WRITES);
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_connection_stops_reading_at_its_cap_and_holds_no_more_than_the_cap() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, true);
        let routes = relay_over(Arc::clone(&store) as Arc<dyn EventStore>, &key, 100_000);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let total = MAX_INFLIGHT_WRITES * 3;
        for n in 0..total {
            let e = event(
                &key,
                1,
                now() - 1_000 + n as u64,
                &format!("cap {n}"),
                vec![],
            );
            send_frame(&mut socket, json!(["EVENT", e])).await;
        }
        entered(&store).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            PEAK_IN_FLIGHT.load(std::sync::atomic::Ordering::SeqCst),
            MAX_INFLIGHT_WRITES,
            "the cap was reached and not passed while the writer was held"
        );
        release(&store);
        let mut answered = std::collections::BTreeSet::new();
        for _ in 0..total {
            let reply = receive(&mut socket).await;
            assert_eq!(reply[2], true);
            assert!(answered.insert(reply[1].as_str().unwrap().to_owned()));
        }
        assert_eq!(answered.len(), total);
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_req_after_pipelined_writes_sees_them_and_follows_their_oks() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, false);
        let routes = relay_over(Arc::clone(&store) as Arc<dyn EventStore>, &key, 100_000);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let ids: Vec<String> = {
            let mut ids = Vec::new();
            for n in 0..30 {
                let e = event(&key, 1, now() - 1_000 + n, &format!("mine {n}"), vec![]);
                ids.push(e.id.to_hex());
                send_frame(&mut socket, json!(["EVENT", e])).await;
            }
            send_frame(
                &mut socket,
                json!(["REQ", "own", {"kinds": [1], "limit": 100}]),
            )
            .await;
            ids
        };
        let mut oks_seen = 0;
        let mut found = std::collections::BTreeSet::new();
        loop {
            let frame = receive(&mut socket).await;
            match frame[0].as_str().unwrap() {
                "OK" => {
                    assert_eq!(frame[2], true);
                    assert_eq!(found.len(), 0, "every OK precedes the REQ's answer");
                    oks_seen += 1;
                }
                "EVENT" => {
                    found.insert(frame[2]["id"].as_str().unwrap().to_owned());
                }
                "EOSE" => break,
                other => panic!("unexpected {other}"),
            }
        }
        assert_eq!(oks_seen, 30);
        assert_eq!(found, ids.into_iter().collect());
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_close_with_writes_landing_answers_each_with_its_own_ok() {
        let frames = closed_with_writes_pending(Some(Duration::from_millis(300))).await;
        let answers = oks(&frames);
        let landed = answers.iter().filter(|a| a.1 && a.2.is_empty()).count();
        assert_eq!(landed, 5, "{answers:?}");
    }

    #[tokio::test]
    async fn a_close_with_writes_still_pending_answers_each_with_the_closing_reason() {
        let frames = closed_with_writes_pending(None).await;
        let answers = oks(&frames);
        let closing = answers
            .iter()
            .filter(|a| {
                !a.1 && a
                    .2
                    .starts_with("error: connection closing; event may not be stored")
            })
            .count();
        assert_eq!(closing, 5, "{answers:?}");
        assert!(
            answers.iter().all(|a| !(a.1 && a.2.is_empty())),
            "no OK for what had not landed"
        );
    }

    #[test]
    fn only_an_event_frame_is_answered_as_unapplied_while_closing() {
        let key = Keys::generate();
        let e = event(&key, 1, now(), "x", vec![]);
        let id = unapplied_event_id(&json!(["EVENT", e]).to_string());
        assert_eq!(id, Some(e.id.to_hex()));
        assert_eq!(unapplied_event_id(r#"["REQ","a",{}]"#), None);
        assert_eq!(unapplied_event_id(r#"["EVENT",{"id":"short"}]"#), None);
        assert_eq!(unapplied_event_id("not json"), None);
    }

    #[tokio::test]
    async fn socket_restart_retains_acknowledged_events_and_author_deletions() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let first = event(&key, 1, now() - 20, "retained", vec![]);
        let second = event(&key, 1, now() - 10, "to delete", vec![]);
        let initial = routes(&tmp, &key);
        let (url, task) = listen(&initial, Visibility::Public).await;
        let mut writer = connect(&url, Some(&key)).await;
        for e in [&first, &second] {
            send_frame(&mut writer, json!(["EVENT", e])).await;
            assert_eq!(receive(&mut writer).await[2], true);
        }
        let deletion = event(
            &key,
            5,
            now(),
            "",
            vec![vec!["e".into(), second.id.to_hex()]],
        );
        send_frame(&mut writer, json!(["EVENT", deletion])).await;
        assert_eq!(receive(&mut writer).await[2], true);
        initial.shutdown();
        task.abort();
        drop(writer);
        drop(initial);
        let restarted = routes(&tmp, &key);
        let (url, task) = listen(&restarted, Visibility::Public).await;
        let mut reader = connect(&url, None).await;
        send_frame(&mut reader, json!(["REQ","saved",{"kinds":[1]}])).await;
        assert_eq!(receive(&mut reader).await[2]["id"], first.id.to_hex());
        assert_eq!(receive(&mut reader).await, json!(["EOSE", "saved"]));
        let mut writer = connect(&url, Some(&key)).await;
        send_frame(&mut writer, json!(["EVENT", second])).await;
        assert_eq!(receive(&mut writer).await[2], false);
        restarted.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_full_public_allocation_leaves_capacity_for_private_keeper_custody() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (public_url, public_task) = listen(&routes, Visibility::Public).await;
        let (private_url, private_task) = listen(&routes, Visibility::Sheltered).await;
        let mut public = Vec::new();
        for _ in 0..24 {
            public.push(connect(&public_url, None).await);
        }
        assert!(
            connect_async(&public_url).await.is_err(),
            "public allocation is full"
        );
        let mut private = connect(&private_url, Some(&key)).await;
        let note = event(&key, 1, now(), "keeper can still commit", vec![]);
        send_frame(&mut private, json!(["EVENT", note])).await;
        assert_eq!(receive(&mut private).await[2], true);
        send_frame(&mut private, json!(["REQ", "saved", {"ids": [note.id]}])).await;
        assert_eq!(receive(&mut private).await[2]["id"], note.id.to_hex());
        assert_eq!(receive(&mut private).await[0], "EOSE");
        routes.shutdown();
        public_task.abort();
        private_task.abort();
    }

    #[tokio::test]
    async fn sheltered_auth_and_liveness_deadlines_are_not_extended_by_control_frames() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes_with_timings(
            &tmp,
            &key,
            Timings::new(
                Duration::from_millis(80),
                Duration::from_millis(25),
                Duration::from_millis(80),
            ),
        );
        let (url, task) = listen(&routes, Visibility::Sheltered).await;

        let (mut unauthenticated, _) = connect_async(&url).await.unwrap();
        assert_eq!(receive(&mut unauthenticated).await[0], "AUTH");
        for _ in 0..3 {
            unauthenticated
                .send(ClientMessage::Ping(Vec::new().into()))
                .await
                .unwrap();
            assert!(matches!(
                unauthenticated.next().await.unwrap().unwrap(),
                ClientMessage::Pong(_)
            ));
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        assert!(
            closes_within(&mut unauthenticated, Duration::from_millis(100)).await,
            "Pings do not extend the successful AUTH deadline"
        );

        let mut healthy = connect(&url, Some(&key)).await;
        let first_ping = timeout(Duration::from_millis(100), healthy.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(first_ping, ClientMessage::Ping(_)));
        healthy
            .send(ClientMessage::Pong(Vec::new().into()))
            .await
            .unwrap();
        let second_ping = timeout(Duration::from_millis(100), healthy.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(second_ping, ClientMessage::Ping(_)));

        let (idle_url, idle_task) = listen_as(&routes, Visibility::Sheltered, TestPeer(2)).await;
        let mut _idle = Vec::new();
        for _ in 0..SHELTERED_SOCKETS_PER_PEER {
            _idle.push(connect_async(&idle_url).await.unwrap().0);
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            connect_async(&idle_url).await.is_ok(),
            "unresponsive sockets release their per-peer permits"
        );
        routes.shutdown();
        task.abort();
        idle_task.abort();
    }

    #[tokio::test]
    async fn a_public_socket_that_stops_answering_pings_is_closed() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes_with_timings(
            &tmp,
            &key,
            Timings::new(
                Duration::from_secs(30),
                Duration::from_millis(25),
                Duration::from_millis(80),
            ),
        );
        let (url, task) = listen(&routes, Visibility::Public).await;
        let (mut quiet, _) = connect_async(&url).await.unwrap();
        // Read nothing, so no Pong is sent back.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            closes_within(&mut quiet, Duration::from_millis(200)).await,
            "a public socket that never answers is dropped"
        );

        let (mut live, _) = connect_async(&url).await.unwrap();
        live.send(ClientMessage::Text(
            serde_json::json!(["REQ", "feed", {"kinds":[1]}])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        // Answer each Ping for well past the idle deadline.
        let until = tokio::time::Instant::now() + Duration::from_millis(250);
        while tokio::time::Instant::now() < until {
            match timeout(Duration::from_millis(100), live.next()).await {
                Ok(Some(Ok(ClientMessage::Ping(payload)))) => {
                    live.send(ClientMessage::Pong(payload)).await.unwrap()
                }
                Ok(Some(Ok(ClientMessage::Text(_)))) => {}
                other => panic!("a responsive public socket stays open: {other:?}"),
            }
        }
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn sheltered_control_frames_share_the_inbound_minute_budget() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (url, task) = listen(&routes, Visibility::Sheltered).await;
        let (mut socket, _) = connect_async(&url).await.unwrap();
        assert_eq!(receive(&mut socket).await[0], "AUTH");
        for _ in 0..120 {
            socket
                .send(ClientMessage::Ping(Vec::new().into()))
                .await
                .unwrap();
            assert!(matches!(
                socket.next().await.unwrap().unwrap(),
                ClientMessage::Pong(_)
            ));
        }
        socket
            .send(ClientMessage::Ping(Vec::new().into()))
            .await
            .unwrap();
        assert_eq!(
            receive(&mut socket).await,
            json!(["NOTICE", "rate-limited: slow down"])
        );
        assert!(
            closes_within(&mut socket, Duration::from_secs(1)).await,
            "the 121st inbound control frame closes the socket"
        );
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn shutdown_closes_upgraded_sockets_and_refuses_new_connections() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (url, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&url, Some(&key)).await;
        routes.shutdown();
        let end = timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap();
        assert!(
            end.is_none()
                || end.is_some_and(|r| r.is_err() || matches!(r, Ok(ClientMessage::Close(_))))
        );
        assert!(connect_async(&url).await.is_err());
        task.abort();
    }

    #[tokio::test]
    async fn pipelined_events_reach_the_store_in_the_order_they_were_sent() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, false);
        store.sync_ms.store(2, std::sync::atomic::Ordering::SeqCst);
        let routes = relay_over(Arc::clone(&store) as Arc<dyn EventStore>, &key, 100_000);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let events: Vec<Event> = (0..300)
            .map(|n| event(&key, 1, now() - 1_000 + n, &format!("ordered {n}"), vec![]))
            .collect();
        for e in &events {
            send_frame(&mut socket, json!(["EVENT", e])).await;
        }
        for _ in &events {
            assert_eq!(receive(&mut socket).await[2], true);
        }
        let offered = store.order.lock().unwrap().clone();
        let sent: Vec<String> = events.iter().map(|e| e.id.to_hex()).collect();
        assert_eq!(offered, sent, "frame order is commit order");
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn abandoned_writes_leave_the_writer_queue_and_a_reconnecting_client_cannot_grow_it() {
        use wok_store::writer::WriterLimits;
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, true);
        let relay = Arc::new(
            EventRelay::new(
                Arc::clone(&store) as Arc<dyn EventStore>,
                Arc::new(Owner(key.public_key())),
            )
            .with_frame_limit(100_000)
            .with_writer_limits(WriterLimits {
                queue_events: 8,
                ..WriterLimits::default()
            }),
        );
        // One write sits in a batch at the gate for the whole test.
        let mut prime_session = keeper_session(&relay, &key);
        let mut prime = InFlight::new();
        let primed = event(&key, 1, now() - 2_000, "primed", vec![]);
        let write = pending_write(&mut prime_session, &primed);
        assert!(prime.start(write).await.is_empty());
        entered(&store).await;

        // Seven places remain. Each connection fills them and goes away; if a
        // gone connection kept its places, the second would wait for ever.
        for cycle in 0..6u64 {
            let mut session = keeper_session(&relay, &key);
            let mut in_flight = InFlight::new();
            for n in 0..7u64 {
                let e = event(
                    &key,
                    1,
                    now() - 1_000 + n,
                    &format!("cycle {cycle} event {n}"),
                    vec![],
                );
                let write = pending_write(&mut session, &e);
                let replies = timeout(Duration::from_secs(5), in_flight.start(write))
                    .await
                    .expect("a place in the queue: the last connection kept none");
                assert!(replies.is_empty(), "{replies:?}");
            }
            assert_eq!(relay.writer_queued().0, 7);
            assert_eq!(in_flight.abandon().len(), 7, "one closing reply each");
            assert_eq!(
                relay.writer_queued(),
                (0, 0),
                "an abandoned connection leaves nothing queued"
            );
        }
        release(&store);
        let landed = timeout(Duration::from_secs(5), prime.next())
            .await
            .unwrap()
            .unwrap();
        assert!(landed[0].contains("true"), "{landed:?}");
        relay.flush();
        assert_eq!(relay.writer_stats().events, 1, "only the primed write ran");
        assert_eq!(
            store
                .query(Visibility::Public, &nostr::filter::Filter::new(), now())
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_write_that_is_still_pending_says_so_and_a_resend_is_a_duplicate() {
        use wok_store::writer::WriterLimits;
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, true);
        let relay = Arc::new(
            EventRelay::new(
                Arc::clone(&store) as Arc<dyn EventStore>,
                Arc::new(Owner(key.public_key())),
            )
            .with_writer_limits(WriterLimits {
                write_wait: Some(Duration::from_millis(300)),
                ..WriterLimits::default()
            }),
        );
        let routes = Door::new(Arc::clone(&relay));
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let note = event(&key, 1, now(), "slow disk", vec![]);
        send_frame(&mut socket, json!(["EVENT", note])).await;
        let reply = timeout(Duration::from_secs(5), receive(&mut socket))
            .await
            .unwrap();
        assert_eq!(
            reply,
            json!([
                "OK",
                note.id.to_hex(),
                false,
                "error: write still pending; it may be stored, resend to confirm"
            ])
        );
        release(&store);
        relay.flush();
        send_frame(&mut socket, json!(["EVENT", note])).await;
        assert_eq!(
            receive(&mut socket).await,
            json!(["OK", note.id.to_hex(), true, "duplicate: already stored"])
        );
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn an_event_frame_in_odd_spelling_waits_for_the_writer_holding_no_work_permit() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, true);
        let routes = relay_over(Arc::clone(&store) as Arc<dyn EventStore>, &key, 100_000);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        let note = event(&key, 1, now(), "odd spelling", vec![]);
        // Not an EVENT frame by prefix, so it takes the unprepared route.
        let frame = format!(
            "[\"EV\\u0045NT\",{}]",
            serde_json::to_string(&note).unwrap()
        );
        assert!(!PreparedFrame::is_event_frame(&frame));
        socket
            .send(ClientMessage::Text(frame.into()))
            .await
            .unwrap();
        entered(&store).await;
        assert_eq!(routes.work.available_permits(), 2);
        assert_eq!(routes.public_work.available_permits(), 1);
        release(&store);
        assert_eq!(
            receive(&mut socket).await,
            json!(["OK", note.id.to_hex(), true, ""])
        );
        routes.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn a_connection_sees_the_ok_for_its_own_event_before_the_event_live() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let store = held_store(&tmp, false);
        let routes = relay_over(Arc::clone(&store) as Arc<dyn EventStore>, &key, 100_000);
        let (public, task) = listen(&routes, Visibility::Public).await;
        let mut socket = connect(&public, Some(&key)).await;
        send_frame(
            &mut socket,
            json!(["REQ", "mine", {"kinds": [1], "limit": 0}]),
        )
        .await;
        assert_eq!(receive(&mut socket).await, json!(["EOSE", "mine"]));
        let events: Vec<Event> = (0..60)
            .map(|n| event(&key, 1, now() - 1_000 + n, &format!("live {n}"), vec![]))
            .collect();
        for e in &events {
            send_frame(&mut socket, json!(["EVENT", e])).await;
        }
        let mut seen = Vec::new();
        while seen.len() < events.len() * 2 {
            let frame = receive(&mut socket).await;
            match frame[0].as_str().unwrap() {
                "OK" => seen.push(("ok", frame[1].as_str().unwrap().to_owned())),
                "EVENT" => seen.push(("event", frame[2]["id"].as_str().unwrap().to_owned())),
                other => panic!("unexpected {other}"),
            }
        }
        for e in &events {
            let id = e.id.to_hex();
            let at = |kind: &str| {
                seen.iter()
                    .position(|(k, i)| *k == kind && *i == id)
                    .unwrap()
            };
            assert!(at("ok") < at("event"), "{id}: its OK comes first");
        }
        routes.shutdown();
        task.abort();
    }

    /// The frames up to the close: the OK for `id`, if one came, and the
    /// close code.
    async fn answer_and_close(socket: &mut Socket, id: &str) -> (Option<Value>, Option<u16>) {
        let mut answer = None;
        let close = loop {
            match timeout(Duration::from_secs(10), socket.next())
                .await
                .unwrap()
            {
                Some(Ok(ClientMessage::Text(text))) => {
                    let frame: Value = serde_json::from_str(&text).unwrap();
                    if frame[0] == "OK" && frame[1] == id {
                        answer = Some(frame);
                    }
                }
                Some(Ok(ClientMessage::Close(frame))) => {
                    break frame.map(|frame| u16::from(frame.code));
                }
                Some(Ok(_)) => {}
                other => panic!("the socket ended without a close frame: {other:?}"),
            }
        };
        (answer, close)
    }

    /// A shutdown that lands while a connection is part way through a frame
    /// lets that turn finish, so a write the door has read is stored and
    /// answered before the close.
    #[tokio::test]
    async fn a_write_read_when_the_shutdown_lands_is_answered_before_the_close() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (url, task) = listen(&routes, Visibility::Sheltered).await;
        let mut socket = connect(&url, Some(&key)).await;
        // Park the next turn: the EVENT is read and checked, then waits for
        // a work permit.
        let held = Arc::clone(&routes.work)
            .acquire_many_owned(WORK_PERMITS as u32)
            .await
            .unwrap();
        let note = event(&key, 1, now(), "read before the shutdown", vec![]);
        send_frame(&mut socket, json!(["EVENT", note])).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        routes.shutdown();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        let (answer, close) = answer_and_close(&mut socket, &note.id.to_hex()).await;
        assert_eq!(
            answer.map(|frame| frame[2].clone()),
            Some(json!(true)),
            "the write the door had read is stored and answered"
        );
        assert_eq!(close, Some(1001));
        task.abort();
    }

    /// A turn still waiting when the shutdown grace runs out does not hold
    /// the shutdown up: the connection closes regardless.
    #[tokio::test]
    async fn a_turn_stuck_past_the_grace_does_not_hold_the_shutdown_up() {
        let tmp = TempDir::new().unwrap();
        let key = Keys::generate();
        let routes = routes(&tmp, &key);
        let (url, task) = listen(&routes, Visibility::Sheltered).await;
        let mut socket = connect(&url, Some(&key)).await;
        let _held = Arc::clone(&routes.work)
            .acquire_many_owned(WORK_PERMITS as u32)
            .await
            .unwrap();
        let note = event(&key, 1, now(), "never gets a permit", vec![]);
        send_frame(&mut socket, json!(["EVENT", note])).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let began = tokio::time::Instant::now();
        routes.shutdown();
        let (answer, close) = answer_and_close(&mut socket, &note.id.to_hex()).await;
        assert_eq!(close, Some(1001));
        assert!(
            began.elapsed() < Duration::from_secs(3),
            "closed {:?} after the shutdown",
            began.elapsed()
        );
        // Never stored: there was no permit to store it with.
        assert_ne!(answer.map(|frame| frame[2].clone()), Some(json!(true)));
        task.abort();
    }
}
