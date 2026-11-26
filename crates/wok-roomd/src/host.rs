//! Loopback-only host for the keeper-controlled room relay: the WebSocket
//! listener clients reach through a TLS proxy, the private Unix socket the
//! supervisor drives it by, and the command line.
use crate::relay::{
    Access, DeviceGrant, Door, LEASE_SECONDS, Live, RoomError, RoomRelay, RoomSpec,
};
use axum::{
    Router,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
};
use nostr::event::Event;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::OsString,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch},
};
use wok_store::{PutOutcome, relay::MAX_RELAY_FRAME_BYTES};

const USAGE: &str = "usage:
  wok-roomd --data <dir> --control <socket> --url <wss://host/events>
            --max-bytes <bytes> --min-free-bytes <bytes>
            [--listen <127.0.0.1:3745>] [--max-rooms <32>] [--local-test]";

/// The command line. Every limit on storage is the operator's to state, so
/// the two byte counts have no default.
#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    /// The private directory that holds the room stores.
    pub data: PathBuf,
    /// The Unix socket the supervisor writes to. Its parent must be private.
    pub control: PathBuf,
    /// The loopback address the WebSocket listener binds.
    pub listen: SocketAddr,
    /// The public `/events` address clients name in their AUTH.
    pub url: String,
    /// The most bytes all rooms together may store.
    pub max_bytes: u64,
    /// The free space intake leaves on the volume.
    pub min_free_bytes: u64,
    /// The most rooms open at once.
    pub max_rooms: usize,
    /// Allow a `ws://` URL, for a test on one machine.
    pub local_test: bool,
}

impl Args {
    /// Read the arguments after the program's name. A flag takes its value
    /// from the next argument or after `=`, and may be given once.
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut values: HashMap<&'static str, OsString> = HashMap::new();
        let mut local_test = false;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let text = arg.to_string_lossy().into_owned();
            let (name, inline) = match text.split_once('=') {
                Some((name, value)) if arg.to_str().is_some() => (name, Some(value)),
                _ => (text.as_str(), None),
            };
            if name == "--local-test" {
                if inline.is_some() || local_test {
                    return Err("--local-test takes no value and is given once".into());
                }
                local_test = true;
                continue;
            }
            let Some(known) = [
                "--data",
                "--control",
                "--listen",
                "--url",
                "--max-bytes",
                "--min-free-bytes",
                "--max-rooms",
            ]
            .into_iter()
            .find(|known| *known == name) else {
                return Err(format!("unexpected argument {name}"));
            };
            let value = match inline {
                Some(value) => OsString::from(value),
                None => args.next().ok_or(format!("{known} needs a value"))?,
            };
            if values.insert(known, value).is_some() {
                return Err(format!("{known} is given more than once"));
            }
        }
        let mut path = |name: &'static str| {
            values
                .remove(name)
                .map(PathBuf::from)
                .ok_or(format!("{name} is required"))
        };
        let data = path("--data")?;
        let control = path("--control")?;
        fn parsed<T: std::str::FromStr>(
            values: &mut HashMap<&'static str, OsString>,
            name: &'static str,
        ) -> Result<Option<T>, String> {
            values
                .remove(name)
                .map(|value| {
                    value
                        .to_str()
                        .and_then(|text| text.parse().ok())
                        .ok_or(format!("{name} has a value that cannot be read"))
                })
                .transpose()
        }
        Ok(Self {
            data,
            control,
            listen: parsed(&mut values, "--listen")?
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 3745))),
            url: parsed(&mut values, "--url")?.ok_or("--url is required")?,
            max_bytes: parsed(&mut values, "--max-bytes")?.ok_or("--max-bytes is required")?,
            min_free_bytes: parsed(&mut values, "--min-free-bytes")?
                .ok_or("--min-free-bytes is required")?,
            max_rooms: parsed(&mut values, "--max-rooms")?.unwrap_or(32),
            local_test,
        })
    }
}

/// Why the process did not start, or stopped.
#[derive(Debug, Error)]
pub enum HostError {
    #[error("{0}")]
    Refused(&'static str),
    #[error("the public URL cannot be read: {0}")]
    Url(#[from] url::ParseError),
    #[error("the room stores cannot be opened: {0}")]
    Stores(#[from] RoomError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("the listener stopped: {0}")]
    Listener(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
struct Host {
    relay: Arc<Mutex<RoomRelay>>,
    url: Arc<str>,
    live: broadcast::Sender<Live>,
    changes: watch::Sender<u64>,
    slots: Arc<Semaphore>,
    asks: Arc<Semaphore>,
    rates: Arc<Mutex<HashMap<IpAddr, (Instant, u32)>>>,
}

impl Host {
    /// 32 connections in all, of which at most 24 may be on the ask door.
    fn new(relay: RoomRelay, url: Arc<str>) -> Self {
        let (live, _) = broadcast::channel(128);
        let (changes, _) = watch::channel(0);
        Self {
            relay: Arc::new(Mutex::new(relay)),
            url,
            live,
            changes,
            slots: Arc::new(Semaphore::new(32)),
            asks: Arc::new(Semaphore::new(24)),
            rates: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn router(&self) -> Router {
        Router::new()
            .route("/events", get(upgrade))
            .with_state(self.clone())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Every use of the relay is blocking work on SQLite, one caller at a time.
async fn work<T: Send + 'static>(
    host: &Host,
    f: impl FnOnce(&mut RoomRelay) -> Result<T, RoomError> + Send + 'static,
) -> Result<T, RoomError> {
    let relay = host.relay.clone();
    tokio::task::spawn_blocking(move || {
        let mut relay = relay.lock().map_err(|_| RoomError::Unavailable)?;
        f(&mut relay)
    })
    .await
    .map_err(|_| RoomError::Unavailable)?
}

async fn send(socket: &mut WebSocket, value: Value) -> bool {
    send_text(socket, value.to_string()).await
}

async fn send_text(socket: &mut WebSocket, text: String) -> bool {
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(text.into())),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}

/// The most live events one connection takes from the queue in one go.
const LIVE_BATCH_EVENTS: usize = 64;
/// The most serialised event bytes it takes in one go, past which it stops;
/// one event larger than this still goes alone.
const LIVE_BATCH_BYTES: usize = 64 * 1024;
/// How long a connection writes event frames, live or history, on one
/// access check before it checks again; any change to the allowlist checks
/// again at once.
const RECHECK: Duration = Duration::from_millis(250);

/// The live event a connection woke for and whatever else has queued behind
/// it, up to the batch bounds, each with its JSON, and whether the queue
/// lagged: dropped events this connection had not read. What was taken
/// before a lag is still sent.
fn live_batch(
    first: Result<Live, broadcast::error::RecvError>,
    live: &mut broadcast::Receiver<Live>,
) -> (Vec<Live>, Vec<String>, bool) {
    let mut batch = Vec::new();
    let mut json = Vec::new();
    let mut bytes = 0;
    let mut next = first.map_err(|_| ());
    loop {
        match next {
            Ok(delivered) => {
                let text = delivered.event.as_json();
                bytes += text.len();
                json.push(text);
                batch.push(delivered);
            }
            Err(()) => return (batch, json, true),
        }
        if batch.len() >= LIVE_BATCH_EVENTS || bytes >= LIVE_BATCH_BYTES {
            return (batch, json, false);
        }
        next = match live.try_recv() {
            Ok(delivered) => Ok(delivered),
            Err(broadcast::error::TryRecvError::Empty) => return (batch, json, false),
            Err(_) => Err(()),
        };
    }
}

/// `["EVENT",<id>,<event>]` from an event already serialised.
fn event_frame(subscription: &str, event: &str) -> String {
    let id = Value::from(subscription).to_string();
    let mut frame = String::with_capacity(event.len() + id.len() + 12);
    frame.push_str("[\"EVENT\",");
    frame.push_str(&id);
    frame.push(',');
    frame.push_str(event);
    frame.push(']');
    frame
}

/// The address a connection is counted against: the peer's, or behind a
/// loopback proxy the last `X-Forwarded-For` entry. An IPv6 source counts as
/// its /64.
fn source(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    let ip = if peer.is_loopback() {
        headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.rsplit(',').next())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(peer)
    } else {
        peer
    };
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or_else(|| {
            let [a, b, c, d, ..] = ip.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }),
        ip => ip,
    }
}

async fn upgrade(
    State(host): State<Host>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let ip = source(&headers, peer.ip());
    {
        let mut rates = host
            .rates
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        rates.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(60));
        // A full table makes room by forgetting its oldest source, so many
        // sources at once cannot shut out a new one for the whole minute.
        if rates.len() >= 2048 && !rates.contains_key(&ip) {
            let oldest = rates
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                rates.remove(&oldest);
            }
        }
        let entry = rates.entry(ip).or_insert((Instant::now(), 0));
        if entry.1 >= 60 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        entry.1 += 1;
    }
    let permit = host
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(ws
        .max_message_size(MAX_RELAY_FRAME_BYTES)
        .max_frame_size(MAX_RELAY_FRAME_BYTES)
        .on_upgrade(move |socket| session(host, socket, permit)))
}

async fn authorised(host: &Host, access: &Access) -> bool {
    let access = access.clone();
    work(
        host,
        move |relay| Ok(relay.still_authorised(&access, now())),
    )
    .await
    .unwrap_or(false)
}

/// Whether a connection's access still holds before its next event frame.
/// It is checked again, under the lock, only when the allowlist has changed
/// or the last check is older than `RECHECK`, so a run of frames does not
/// queue behind every other connection's work once per frame. A change is
/// marked seen before the check, which reads the state the control socket
/// stored before it announced the change; every `sync`, a lease renewal
/// included, is one.
async fn still_holds(
    host: &Host,
    access: &Access,
    changed: &mut watch::Receiver<u64>,
    checked: &mut Instant,
) -> bool {
    if changed.has_changed().unwrap_or(true) || checked.elapsed() >= RECHECK {
        changed.borrow_and_update();
        if !authorised(host, access).await {
            return false;
        }
        *checked = Instant::now();
    }
    true
}

/// One connection: a challenge, one AUTH that picks the room and the door,
/// then EVENT, REQ and CLOSE until the access behind it ends.
async fn session(host: Host, mut socket: WebSocket, _permit: OwnedSemaphorePermit) {
    let mut random = [0; 32];
    if getrandom::fill(&mut random).is_err() {
        return;
    }
    let challenge = hex::encode(random);
    if !send(&mut socket, json!(["AUTH", challenge])).await {
        return;
    }
    let auth = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str::<Value>(&text).ok(),
        _ => None,
    };
    let Some(auth) = auth.filter(|v| v.as_array().is_some_and(|a| a.len() == 2) && v[0] == "AUTH")
    else {
        return;
    };
    let Ok(event) = serde_json::from_value::<Event>(auth[1].clone()) else {
        return;
    };
    let id = event.id.to_hex();
    let url = host.url.clone();
    let access = match work(&host, move |relay| {
        relay.authenticate(&event, &challenge, &url, now())
    })
    .await
    {
        Ok(access) => access,
        Err(error) => {
            let _ = send(&mut socket, json!(["OK", id, false, error.to_string()])).await;
            return;
        }
    };
    let _ask_permit = if access.door() == Door::Ask {
        match host.asks.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                let _ = send(&mut socket, json!(["OK", id, false, "ask door is full"])).await;
                return;
            }
        }
    } else {
        None
    };
    if !send(&mut socket, json!(["OK", id, true, ""])).await {
        return;
    }
    let mut subscriptions: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut live = host.live.subscribe();
    let mut changed = host.changes.subscribe();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut window = Instant::now();
    let mut frames = 0u32;
    'session: loop {
        // In this order. An ended access is noticed before anything else.
        // What is queued live is sent before the next frame is read, so a
        // connection that publishes keeps up with the burst it adds to.
        tokio::select! {
            biased;
            result = changed.changed() => {
                if result.is_err() || !authorised(&host, &access).await {
                    let _ = send(&mut socket, json!(["NOTICE", "access removed"])).await;
                    break;
                }
            },
            // The lease can run out with no frame and no new snapshot.
            _ = tick.tick() => {
                if !authorised(&host, &access).await {
                    let _ = send(&mut socket, json!(["NOTICE", "node access ended"])).await;
                    break;
                }
            }
            received = live.recv() => {
                let (batch, json, lagged) = live_batch(received, &mut live);
                // One trip under the lock matches the whole batch, with the
                // access check `delivers` makes for each event, and returns
                // the subscriptions each event goes to.
                if !batch.is_empty() && !subscriptions.is_empty() {
                    let who = access.clone();
                    let filters = subscriptions.clone();
                    let matched = work(&host, move |relay| {
                        let now = now();
                        Ok(batch
                            .iter()
                            .map(|delivered| {
                                filters
                                    .iter()
                                    .filter(|(_, filters)| {
                                        filters.iter().any(|f| {
                                            relay.delivers(&who, delivered, f.clone(), now)
                                        })
                                    })
                                    .map(|(id, _)| id.clone())
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>())
                    })
                    .await
                    .unwrap_or_default();
                    // The frames go out after the lock is let go.
                    let mut checked = Instant::now();
                    for (text, ids) in json.iter().zip(matched) {
                        for id in ids {
                            if !still_holds(&host, &access, &mut changed, &mut checked).await {
                                let notice = json!(["NOTICE", "access removed"]);
                                let _ = send(&mut socket, notice).await;
                                break 'session;
                            }
                            if !send_text(&mut socket, event_frame(&id, text)).await {
                                return;
                            }
                        }
                    }
                }
                if lagged {
                    let notice = json!(["NOTICE", "live stream interrupted; reconnect"]);
                    let _ = send(&mut socket, notice).await;
                    break;
                }
            },
            incoming = socket.recv() => {
                let Some(Ok(message)) = incoming else {
                    break;
                };
                // 120 frames a minute, whatever they are.
                if window.elapsed() >= Duration::from_secs(60) {
                    window = Instant::now();
                    frames = 0;
                }
                frames += 1;
                if frames > 120 {
                    break;
                }
                let Message::Text(text) = message else {
                    if matches!(message, Message::Close(_)) {
                        break;
                    }
                    continue;
                };
                if !authorised(&host, &access).await {
                    let _ = send(&mut socket, json!(["NOTICE", "access removed"])).await;
                    break;
                }
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    break;
                };
                let Some(array) = value.as_array() else {
                    break;
                };
                match array.first().and_then(Value::as_str) {
                    Some("EVENT") if array.len() == 2 => {
                        let Ok(event) = serde_json::from_value::<Event>(array[1].clone()) else {
                            break;
                        };
                        let id = event.id.to_hex();
                        let access = access.clone();
                        match work(&host, move |relay| relay.publish(&access, &event, now())).await {
                            Ok((outcome, live)) => {
                                if outcome != PutOutcome::Duplicate {
                                    let _ = host.live.send(live);
                                }
                                if !send(&mut socket, json!(["OK", id, true, ""])).await {
                                    break;
                                }
                            }
                            Err(error) => {
                                let refusal = json!(["OK", id, false, error.to_string()]);
                                if !send(&mut socket, refusal).await {
                                    break;
                                }
                            }
                        }
                    }
                    Some("REQ") if (3..=10).contains(&array.len()) => {
                        let Some(id) = array[1]
                            .as_str()
                            .filter(|id| !id.is_empty() && id.len() <= 64)
                            .map(str::to_owned)
                        else {
                            break;
                        };
                        if subscriptions.len() >= 16 && !subscriptions.contains_key(&id) {
                            let refusal = json!(["CLOSED", id, "too many subscriptions"]);
                            let _ = send(&mut socket, refusal).await;
                            continue;
                        }
                        let filters = array[2..].to_vec();
                        let query = filters.clone();
                        let who = access.clone();
                        // One page of history: 128 events or 2 MiB, whichever
                        // comes first, across all of the request's filters,
                        // each serialised once.
                        let history = work(&host, move |relay| {
                            let mut events = Vec::new();
                            let mut ids = HashSet::new();
                            let mut bytes = 0;
                            for filter in query {
                                for event in relay.query(&who, filter, now())? {
                                    if ids.insert(event.id) {
                                        let text = event.as_json();
                                        bytes += text.len();
                                        if bytes > 2 * 1024 * 1024 || events.len() >= 128 {
                                            return Ok(events);
                                        }
                                        events.push(text);
                                    }
                                }
                            }
                            Ok(events)
                        })
                        .await;
                        match history {
                            Ok(events) => {
                                subscriptions.insert(id.clone(), filters);
                                // The query checked access under the lock. The
                                // page goes out as live frames do, checked again
                                // on a change or once the check is old, so live
                                // events queued meanwhile are read in time.
                                let mut checked = Instant::now();
                                for text in &events {
                                    if !still_holds(&host, &access, &mut changed, &mut checked).await {
                                        let notice = json!(["NOTICE", "access removed"]);
                                        let _ = send(&mut socket, notice).await;
                                        break 'session;
                                    }
                                    if !send_text(&mut socket, event_frame(&id, text)).await {
                                        return;
                                    }
                                }
                                if !send(&mut socket, json!(["EOSE", id])).await {
                                    break;
                                }
                            }
                            Err(error) => {
                                let refusal = json!(["CLOSED", id, error.to_string()]);
                                if !send(&mut socket, refusal).await {
                                    break;
                                }
                            }
                        }
                    }
                    Some("CLOSE") if array.len() == 2 => {
                        if let Some(id) = array[1].as_str() {
                            subscriptions.remove(id);
                        }
                    }
                    _ => {
                        if !send(&mut socket, json!(["NOTICE", "unsupported request"])).await {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), socket.send(Message::Close(None))).await;
}

/// One request on the control socket. `v` is the protocol version, 1.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Control {
    Sync {
        v: u8,
        rooms: Vec<RoomSpec>,
        grants: Vec<DeviceGrant>,
    },
    Purge {
        v: u8,
        room: String,
    },
    Publish {
        v: u8,
        room: String,
        events: Vec<Event>,
    },
    Status {
        v: u8,
    },
}

/// One control connection: a JSON request of at most 1 MiB, read to the end
/// of the stream within five seconds, and one JSON reply.
async fn control(mut stream: UnixStream, host: Host) {
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        (&mut stream).take(1024 * 1024 + 1).read_to_end(&mut bytes),
    )
    .await;
    let request = match read {
        Ok(Ok(n)) if n <= 1024 * 1024 => serde_json::from_slice::<Control>(&bytes).ok(),
        _ => None,
    };
    let changed = matches!(request, Some(Control::Sync { .. } | Control::Purge { .. }));
    let result = match request {
        Some(Control::Sync {
            v: 1,
            rooms,
            grants,
        }) => {
            work(&host, move |relay| {
                relay.synchronise(rooms, grants, now())?;
                Ok(json!({"leaseSeconds":LEASE_SECONDS}))
            })
            .await
        }
        Some(Control::Purge { v: 1, room }) => {
            work(&host, move |relay| {
                Ok(json!({"eventsDeleted":relay.purge(&room,now())?}))
            })
            .await
        }
        Some(Control::Status { v: 1 }) => work(&host, |relay| relay.status()).await,
        Some(Control::Publish { v: 1, room, events })
            if !events.is_empty() && events.len() <= 2 =>
        {
            let mut accepted = Vec::new();
            let mut error = None;
            for event in events {
                let room = room.clone();
                match work(&host, move |relay| {
                    relay.publish_closing(&room, &event, now())
                })
                .await
                {
                    Ok((outcome, live)) => {
                        accepted.push(live.event.id.to_hex());
                        if outcome != PutOutcome::Duplicate {
                            let _ = host.live.send(live);
                        }
                    }
                    Err(refused) => {
                        error = Some(refused);
                        break;
                    }
                }
            }
            match error {
                Some(error) => Err(error),
                None => Ok(json!({"accepted":accepted})),
            }
        }
        _ => Err(RoomError::Invalid),
    };
    if changed {
        host.changes
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
    let value = match result {
        Ok(value) => json!({"v":1,"ok":true,"result":value}),
        Err(error) => json!({"v":1,"ok":false,"error":error.to_string()}),
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(value.to_string().as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
}

/// Serve until SIGINT or SIGTERM. Nothing is logged while it runs.
pub async fn run(args: Args) -> Result<(), HostError> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let url = url::Url::parse(&args.url)?;
    if !args.listen.ip().is_loopback()
        || (!args.local_test && url.scheme() != "wss")
        || (args.local_test && !matches!(url.scheme(), "ws" | "wss"))
        || url.path() != "/events"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(HostError::Refused(
            "room relay needs a loopback listener and an explicit /events WebSocket URL",
        ));
    }
    let core = RoomRelay::open(
        &args.data,
        args.max_bytes,
        args.min_free_bytes,
        args.max_rooms,
    )?;
    let parent = args
        .control
        .parent()
        .ok_or(HostError::Refused("control socket needs a private parent"))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(HostError::Refused(
            "control socket parent must be a private directory",
        ));
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&args.control) {
        if !metadata.file_type().is_socket() {
            return Err(HostError::Refused("control path is not a socket"));
        }
        // A socket nothing answers is what a killed process left behind.
        match tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(&args.control)).await
        {
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                std::fs::remove_file(&args.control)?
            }
            _ => return Err(HostError::Refused("control socket is already in use")),
        }
    }
    let control_listener = UnixListener::bind(&args.control)?;
    std::fs::set_permissions(&args.control, std::fs::Permissions::from_mode(0o600))?;
    let host = Host::new(core, args.url.into());
    let local = host.clone();
    let controls = Arc::new(Semaphore::new(8));
    let control_task = tokio::spawn(async move {
        while let Ok((stream, _)) = control_listener.accept().await {
            let Ok(permit) = controls.clone().try_acquire_owned() else {
                continue;
            };
            let host = local.clone();
            tokio::spawn(async move {
                let _permit = permit;
                control(stream, host).await;
            });
        }
    });
    let listener = TcpListener::bind(args.listen).await?;
    let router = host.router();
    let mut server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
            result = &mut server => {
                result??;
                break;
            },
            _ = tick.tick() => {
                let _ = work(&host, |relay| relay.expire(now())).await;
            }
        }
    }
    control_task.abort();
    server.abort();
    let _ = std::fs::remove_file(args.control);
    Ok(())
}

/// The `wok-roomd` command line: 0 once stopped by a signal, 2 for a usage
/// mistake, 1 for anything else that kept it from running.
pub fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args
        .iter()
        .any(|arg| matches!(arg.to_str(), Some("--help" | "-h")))
    {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = match Args::parse(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("wok-roomd: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("wok-roomd: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run(args));
    runtime.shutdown_timeout(Duration::from_secs(2));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wok-roomd: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use nostr::{
        event::{EventBuilder, FinalizeEvent, Kind, Tag},
        key::Keys,
        types::Timestamp,
    };
    use tempfile::TempDir;
    use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
    type Client = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    fn arguments(list: &[&str]) -> Result<Args, String> {
        Args::parse(list.iter().map(OsString::from))
    }

    /// The flags a supervisor passes, each with its value as the next
    /// argument. Their names and meanings are a contract with it.
    #[test]
    fn a_supervisors_argument_list_is_read_as_given() {
        let args = arguments(&[
            "--data",
            "/var/lib/node/rooms",
            "--control",
            "/var/lib/node/relay.sock",
            "--listen",
            "127.0.0.1:4001",
            "--url",
            "wss://node.example/events",
            "--max-bytes",
            "1073741824",
            "--min-free-bytes",
            "268435456",
            "--max-rooms",
            "16",
        ])
        .unwrap();
        assert_eq!(
            args,
            Args {
                data: "/var/lib/node/rooms".into(),
                control: "/var/lib/node/relay.sock".into(),
                listen: "127.0.0.1:4001".parse().unwrap(),
                url: "wss://node.example/events".into(),
                max_bytes: 1_073_741_824,
                min_free_bytes: 268_435_456,
                max_rooms: 16,
                local_test: false,
            }
        );
    }

    #[test]
    fn the_listener_and_room_count_have_defaults_and_the_byte_limits_do_not() {
        let required = [
            "--data=rooms",
            "--control=private/relay.sock",
            "--url=ws://127.0.0.1:3745/events",
            "--max-bytes=1000",
            "--min-free-bytes=0",
        ];
        let args = arguments(&[&required[..], &["--local-test"][..]].concat()).unwrap();
        assert_eq!(args.listen, "127.0.0.1:3745".parse().unwrap());
        assert_eq!(args.max_rooms, 32);
        assert!(args.local_test);
        for missing in 0..required.len() {
            let mut list = required.to_vec();
            list.remove(missing);
            assert!(arguments(&list).is_err(), "without {}", required[missing]);
        }
    }

    #[test]
    fn a_mistyped_repeated_or_valueless_flag_is_refused() {
        let base = [
            "--data",
            "rooms",
            "--control",
            "relay.sock",
            "--url",
            "wss://node.example/events",
            "--max-bytes",
            "1000",
            "--min-free-bytes",
            "0",
        ];
        assert!(arguments(&base).is_ok());
        for extra in [
            &["--max-room", "4"][..],
            &["room-relay"],
            &["--data", "elsewhere"],
            &["--max-rooms"],
            &["--max-rooms", "many"],
            &["--max-bytes", "-1"],
            &["--listen", "localhost"],
            &["--local-test=true"],
            &["--local-test", "--local-test"],
        ] {
            let list = [&base[..], extra].concat();
            assert!(arguments(&list).is_err(), "{extra:?}");
        }
    }

    struct Fixture {
        host: Host,
        address: SocketAddr,
        socket: PathBuf,
        server: tokio::task::JoinHandle<()>,
        control: tokio::task::JoinHandle<()>,
        _temp: TempDir,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
            self.control.abort();
        }
    }
    async fn fixture() -> Fixture {
        fixture_holding(1_000_000).await
    }
    async fn fixture_holding(max_bytes: u64) -> Fixture {
        let temp = TempDir::new().unwrap();
        let relay = RoomRelay::open(temp.path(), max_bytes, 0, 4).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host = Host::new(relay, format!("ws://{address}/events").into());
        let router = host.router();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let socket = temp.path().join("control.sock");
        let local = UnixListener::bind(&socket).unwrap();
        let control_host = host.clone();
        let control = tokio::spawn(async move {
            while let Ok((stream, _)) = local.accept().await {
                control(stream, control_host.clone()).await;
            }
        });
        Fixture {
            host,
            address,
            socket,
            server,
            control,
            _temp: temp,
        }
    }
    async fn command(f: &Fixture, value: Value) -> Value {
        let mut stream = UnixStream::connect(&f.socket).await.unwrap();
        stream
            .write_all(value.to_string().as_bytes())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    fn signed(keys: &Keys, kind: u16, content: &str, tags: Vec<Vec<String>>) -> Event {
        EventBuilder::new(Kind::from(kind), content)
            .custom_created_at(Timestamp::from_secs(now()))
            .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
            .finalize(keys)
            .unwrap()
    }
    async fn receive(client: &mut Client) -> Value {
        let message = tokio::time::timeout(Duration::from_secs(3), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }
    async fn login(f: &Fixture, room: &str, keys: &Keys, mode: &str) -> (Client, bool) {
        let (mut client, _) = connect_async(format!("ws://{}/events", f.address))
            .await
            .unwrap();
        let challenge = receive(&mut client).await;
        let event = signed(
            keys,
            22242,
            "",
            vec![
                vec!["challenge".into(), challenge[1].as_str().unwrap().into()],
                vec!["relay".into(), f.host.url.to_string()],
                vec!["room".into(), room.into()],
                vec!["mode".into(), mode.into()],
            ],
        );
        client
            .send(ClientMessage::Text(
                json!(["AUTH", event]).to_string().into(),
            ))
            .await
            .unwrap();
        let response = receive(&mut client).await;
        (client, response[2] == true)
    }
    #[tokio::test]
    async fn websocket_history_and_revocation_follow_the_local_control_snapshot() {
        let f = fixture().await;
        let room = "01".repeat(32);
        let inviter = Keys::generate();
        let device = Keys::generate();
        let rooms = json!([{"room":room,"inviter":inviter.public_key().to_hex(),"ends":null}]);
        let grants = json!([{"room":room,"device":device.public_key().to_hex(),"expires":now()+3600,"read":true,"write":true}]);
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":grants})).await["ok"],
            true
        );
        let (mut client, allowed) = login(&f, &room, &device, "room").await;
        assert!(allowed);
        let (_, allowed) = login(&f, &room, &Keys::generate(), "room").await;
        assert!(!allowed);
        let event = signed(
            &Keys::generate(),
            1464,
            "sealed fixture",
            vec![vec!["expiration".into(), (now() + 600).to_string()]],
        );
        client
            .send(ClientMessage::Text(
                json!(["EVENT", event]).to_string().into(),
            ))
            .await
            .unwrap();
        assert_eq!(receive(&mut client).await[2], true);
        client
            .send(ClientMessage::Text(
                json!(["REQ", "history", {}]).to_string().into(),
            ))
            .await
            .unwrap();
        assert_eq!(receive(&mut client).await[2]["id"], event.id.to_hex());
        assert_eq!(receive(&mut client).await[0], "EOSE");
        let closing = vec![
            signed(
                &inviter,
                1462,
                "sealed close",
                vec![vec!["expiration".into(), (now() + 600).to_string()]],
            ),
            signed(
                &inviter,
                1461,
                r#"{"v":1,"ended":true}"#,
                vec![vec!["expiration".into(), (now() + 600).to_string()]],
            ),
        ];
        assert_eq!(
            command(
                &f,
                json!({"op":"publish","v":1,"room":room,"events":closing})
            )
            .await["ok"],
            true
        );
        for event in &closing {
            assert_eq!(receive(&mut client).await[2]["id"], event.id.to_hex());
        }
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":[]})).await["ok"],
            true
        );
        assert_eq!(receive(&mut client).await[0], "NOTICE");
        assert_eq!(
            command(&f, json!({"op":"purge","v":1,"room":room})).await["result"]["eventsDeleted"],
            3
        );
        let (_, allowed) = login(&f, &room, &device, "room").await;
        assert!(!allowed);
        let status = command(&f, json!({"op":"status","v":1})).await;
        assert_eq!(status["result"]["usedBytes"], 0);
    }

    /// A live event published after a `sync` that removes a device's grant
    /// has returned never reaches that device's open connection: it is told
    /// and closed. (The change notice usually closes it before the event
    /// arrives; `delivers` refusing the event is tested in `relay`.)
    #[tokio::test]
    async fn an_event_after_a_removing_sync_never_reaches_the_removed_device() {
        let f = fixture().await;
        let room = "03".repeat(32);
        let inviter = Keys::generate();
        let removed = Keys::generate();
        let kept = Keys::generate();
        let grant = |keys: &Keys| json!({"room":room,"device":keys.public_key().to_hex(),"expires":now()+3600,"read":true,"write":true});
        let rooms = json!([{"room":room,"inviter":inviter.public_key().to_hex(),"ends":null}]);
        let both = json!([grant(&removed), grant(&kept)]);
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":both})).await["ok"],
            true
        );
        let mut clients = Vec::new();
        for keys in [&removed, &kept] {
            let (mut client, allowed) = login(&f, &room, keys, "room").await;
            assert!(allowed);
            client
                .send(ClientMessage::Text(
                    json!(["REQ", "live", {}]).to_string().into(),
                ))
                .await
                .unwrap();
            assert_eq!(receive(&mut client).await[0], "EOSE");
            clients.push(client);
        }
        let mut kept_client = clients.pop().unwrap();
        let mut removed_client = clients.pop().unwrap();
        let only_kept = json!([grant(&kept)]);
        assert_eq!(
            command(
                &f,
                json!({"op":"sync","v":1,"rooms":rooms,"grants":only_kept})
            )
            .await["ok"],
            true
        );
        let late: Vec<Event> = (0..3)
            .map(|i| {
                signed(
                    &kept,
                    1464,
                    &format!("late {i}"),
                    vec![vec!["expiration".into(), (now() + 600).to_string()]],
                )
            })
            .collect();
        for event in &late {
            kept_client
                .send(ClientMessage::Text(
                    json!(["EVENT", event]).to_string().into(),
                ))
                .await
                .unwrap();
        }
        let mut seen = 0;
        while seen < late.len() * 2 {
            let message = receive(&mut kept_client).await;
            assert!(message[0] == "OK" || message[0] == "EVENT", "{message}");
            seen += 1;
        }
        let first = receive(&mut removed_client).await;
        assert_eq!(first[0], "NOTICE", "{first}");
        while let Ok(Some(Ok(message))) =
            tokio::time::timeout(Duration::from_secs(3), removed_client.next()).await
        {
            assert!(!message.is_text(), "{message:?}");
        }
    }

    /// Every frame a connection reads until it has `events` live events
    /// and `oks` OKs, or the first frame that is neither.
    async fn read_burst(
        client: &mut futures_util::stream::SplitStream<Client>,
        events: usize,
        oks: usize,
    ) -> Result<Vec<String>, String> {
        let mut ids = Vec::new();
        let mut answered = 0;
        while ids.len() < events || answered < oks {
            let message = match tokio::time::timeout(Duration::from_secs(5), client.next()).await {
                Ok(Some(Ok(message))) => message,
                other => {
                    return Err(format!(
                        "after {} events, {answered} OKs: {other:?}",
                        ids.len()
                    ));
                }
            };
            let value: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            match value[0].as_str() {
                Some("EVENT") if value[1] == "live" => {
                    ids.push(value[2]["id"].as_str().unwrap().to_owned());
                }
                Some("OK") if value[2] == true => answered += 1,
                _ => {
                    return Err(format!(
                        "after {} events, {answered} OKs: {value}",
                        ids.len()
                    ));
                }
            }
        }
        Ok(ids)
    }

    /// More events than the live channel holds, sent at once by several
    /// devices that also read, reach every subscriber that reads promptly
    /// whole and in one order, on a connection that stays open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_from_several_devices_reaches_every_prompt_reader_whole() {
        const READERS: usize = 8;
        const PUBLISHERS: usize = 4;
        // 110 events and the REQ: under 120 frames a minute.
        const EACH: usize = 110;
        const TOTAL: usize = PUBLISHERS * EACH;
        let f = fixture_holding(16_000_000).await;
        let room = "02".repeat(32);
        let inviter = Keys::generate();
        let devices: Vec<Keys> = (0..READERS + PUBLISHERS)
            .map(|_| Keys::generate())
            .collect();
        let rooms = json!([{"room":room,"inviter":inviter.public_key().to_hex(),"ends":null}]);
        let grants: Vec<Value> = devices
            .iter()
            .map(|d| json!({"room":room,"device":d.public_key().to_hex(),"expires":now()+3600,"read":true,"write":true}))
            .collect();
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":grants})).await["ok"],
            true
        );
        let mut clients = Vec::new();
        for (n, keys) in devices.iter().enumerate() {
            let (mut client, allowed) = login(&f, &room, keys, "room").await;
            assert!(allowed);
            client
                .send(ClientMessage::Text(
                    json!(["REQ", "live", {}]).to_string().into(),
                ))
                .await
                .unwrap();
            assert_eq!(receive(&mut client).await[0], "EOSE");
            // Signed before the burst, so signing does not pace it.
            let events: Vec<Event> = if n < READERS {
                Vec::new()
            } else {
                (0..EACH)
                    .map(|i| {
                        signed(
                            keys,
                            1464,
                            &format!("burst {i}"),
                            vec![vec!["expiration".into(), (now() + 600).to_string()]],
                        )
                    })
                    .collect()
            };
            clients.push((client, events));
        }
        // A fresh lease, so the node's 15 seconds cover only the burst.
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":grants})).await["ok"],
            true
        );
        let mut sent = HashSet::new();
        for (_, events) in &clients {
            sent.extend(events.iter().map(|e| e.id.to_hex()));
        }
        let tasks: Vec<_> = clients
            .into_iter()
            .map(|(client, events)| {
                tokio::spawn(async move {
                    let (mut sink, mut stream) = client.split();
                    let oks = events.len();
                    let writer = tokio::spawn(async move {
                        for event in &events {
                            sink.send(ClientMessage::Text(
                                json!(["EVENT", event]).to_string().into(),
                            ))
                            .await
                            .unwrap();
                        }
                        sink
                    });
                    let read = read_burst(&mut stream, TOTAL, oks).await;
                    let _ = writer.await;
                    read
                })
            })
            .collect();
        let mut outcomes = Vec::new();
        for (n, task) in tasks.into_iter().enumerate() {
            let role = if n < READERS { "reader" } else { "publisher" };
            outcomes.push((role, task.await.unwrap()));
        }
        let failures: Vec<_> = outcomes
            .iter()
            .filter_map(|(role, outcome)| outcome.as_ref().err().map(|e| format!("{role}: {e}")))
            .collect();
        assert!(failures.is_empty(), "{failures:#?}");
        let mut first: Option<&Vec<String>> = None;
        for (_, outcome) in &outcomes {
            let ids = outcome.as_ref().unwrap();
            assert_eq!(ids.iter().cloned().collect::<HashSet<_>>(), sent);
            match first {
                Some(order) => assert_eq!(ids, order),
                None => first = Some(ids),
            }
        }
    }

    /// Before an event frame, access is checked again under the lock when
    /// the allowlist has changed or the last check is older than `RECHECK`,
    /// and otherwise trusted: the window a removal can take to bite.
    #[tokio::test]
    async fn access_is_checked_again_before_a_frame_on_a_change_or_once_old() {
        let f = fixture().await;
        let room = "05".repeat(32);
        let inviter = Keys::generate();
        let device = Keys::generate();
        let rooms = json!([{"room":room,"inviter":inviter.public_key().to_hex(),"ends":null}]);
        let grants = json!([{"room":room,"device":device.public_key().to_hex(),"expires":now()+3600,"read":true,"write":true}]);
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":grants})).await["ok"],
            true
        );
        let challenge = "ab".repeat(32);
        let url = f.host.url.to_string();
        let event = signed(
            &device,
            22242,
            "",
            vec![
                vec!["challenge".into(), challenge.clone()],
                vec!["relay".into(), url.clone()],
                vec!["room".into(), room.clone()],
                vec!["mode".into(), "room".into()],
            ],
        );
        let access = work(&f.host, move |relay| {
            relay.authenticate(&event, &challenge, &url, now())
        })
        .await
        .unwrap();
        let mut changed = f.host.changes.subscribe();
        let mut checked = Instant::now();
        assert!(still_holds(&f.host, &access, &mut changed, &mut checked).await);
        // A renewal that keeps the grant is a change too: checked once and
        // marked seen, so the frames after it do not each check again.
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":grants})).await["ok"],
            true
        );
        assert!(still_holds(&f.host, &access, &mut changed, &mut checked).await);
        assert!(!changed.has_changed().unwrap());
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":[]})).await["ok"],
            true
        );
        // The removal is a change: checked again at once.
        assert!(!still_holds(&f.host, &access, &mut changed, &mut checked).await);
        // With the change seen, a fresh check is trusted, an old one is not.
        let mut fresh = Instant::now();
        assert!(still_holds(&f.host, &access, &mut changed, &mut fresh).await);
        let mut old = Instant::now() - RECHECK;
        assert!(!still_holds(&f.host, &access, &mut changed, &mut old).await);
    }

    /// A device that follows a burst live and asks for a full page of
    /// history partway through it gets the page, its EOSE and every event of
    /// the burst, on a connection that stays open, while other devices
    /// publish more than the live channel holds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_history_page_read_during_a_burst_still_gets_the_whole_burst() {
        const PUBLISHERS: usize = 4;
        const EACH: usize = 110;
        const TOTAL: usize = PUBLISHERS * EACH;
        // A full page: 128 stored events, from two devices at 64 each.
        const SEEDERS: usize = 2;
        const SEEDED: usize = 64;
        // Live events the reader has before it asks for the page.
        const BEFORE: usize = 32;
        let f = fixture_holding(16_000_000).await;
        let room = "04".repeat(32);
        let inviter = Keys::generate();
        let devices: Vec<Keys> = (0..SEEDERS + PUBLISHERS + 1)
            .map(|_| Keys::generate())
            .collect();
        let rooms = json!([{"room":room,"inviter":inviter.public_key().to_hex(),"ends":null}]);
        let grants: Vec<Value> = devices
            .iter()
            .map(|d| json!({"room":room,"device":d.public_key().to_hex(),"expires":now()+3600,"read":true,"write":true}))
            .collect();
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":grants})).await["ok"],
            true
        );
        let event = |keys: &Keys, i: usize| {
            signed(
                keys,
                1464,
                &format!("event {i}"),
                vec![vec!["expiration".into(), (now() + 600).to_string()]],
            )
        };
        let authors = |keys: &[Keys]| -> Vec<String> {
            keys.iter().map(|d| d.public_key().to_hex()).collect()
        };
        let mut seeded = HashSet::new();
        for keys in &devices[..SEEDERS] {
            let (mut client, allowed) = login(&f, &room, keys, "room").await;
            assert!(allowed);
            for i in 0..SEEDED {
                let event = event(keys, i);
                seeded.insert(event.id.to_hex());
                client
                    .send(ClientMessage::Text(
                        json!(["EVENT", event]).to_string().into(),
                    ))
                    .await
                    .unwrap();
                assert_eq!(receive(&mut client).await[2], true);
            }
        }
        // The burst's subscription: its authors, whom no history matches.
        // The page's: the seeders, whom nothing live matches.
        let burst = json!({"authors": authors(&devices[SEEDERS..SEEDERS + PUBLISHERS])});
        let history = json!({"authors": authors(&devices[..SEEDERS])});
        let mut publishers = Vec::new();
        let mut sent = HashSet::new();
        for keys in &devices[SEEDERS..=SEEDERS + PUBLISHERS] {
            let (mut client, allowed) = login(&f, &room, keys, "room").await;
            assert!(allowed);
            client
                .send(ClientMessage::Text(
                    json!(["REQ", "live", burst]).to_string().into(),
                ))
                .await
                .unwrap();
            assert_eq!(receive(&mut client).await[0], "EOSE");
            publishers.push((client, Vec::new()));
        }
        let (reader, _) = publishers.pop().unwrap();
        for ((_, events), keys) in publishers.iter_mut().zip(&devices[SEEDERS..]) {
            *events = (0..EACH).map(|i| event(keys, i)).collect();
            sent.extend(events.iter().map(|e| e.id.to_hex()));
        }
        // A fresh lease, so the node's 15 seconds cover only the burst.
        assert_eq!(
            command(&f, json!({"op":"sync","v":1,"rooms":rooms,"grants":grants})).await["ok"],
            true
        );
        let tasks: Vec<_> = publishers
            .into_iter()
            .map(|(client, events)| {
                tokio::spawn(async move {
                    let (mut sink, mut stream) = client.split();
                    let oks = events.len();
                    let writer = tokio::spawn(async move {
                        for event in &events {
                            sink.send(ClientMessage::Text(
                                json!(["EVENT", event]).to_string().into(),
                            ))
                            .await
                            .unwrap();
                        }
                        sink
                    });
                    let read = read_burst(&mut stream, TOTAL, oks).await;
                    let _ = writer.await;
                    read
                })
            })
            .collect();
        let (mut sink, mut stream) = reader.split();
        let mut page = HashSet::new();
        let mut live = HashSet::new();
        let mut asked = false;
        let mut ended = false;
        let outcome = loop {
            if ended && live.len() == TOTAL {
                break Ok(());
            }
            if !asked && live.len() >= BEFORE {
                sink.send(ClientMessage::Text(
                    json!(["REQ", "page", history]).to_string().into(),
                ))
                .await
                .unwrap();
                asked = true;
            }
            let message = match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
                Ok(Some(Ok(message))) => message,
                other => {
                    break Err(format!(
                        "page {}, live {}: {other:?}",
                        page.len(),
                        live.len()
                    ));
                }
            };
            let value: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
            let id = value[2]["id"].as_str().map(str::to_owned);
            match (value[0].as_str(), value[1].as_str(), id) {
                (Some("EVENT"), Some("live"), Some(id)) => {
                    live.insert(id);
                }
                (Some("EVENT"), Some("page"), Some(id)) if asked && !ended => {
                    page.insert(id);
                }
                (Some("EOSE"), Some("page"), _) if asked && !ended => ended = true,
                _ => {
                    break Err(format!("page {}, live {}: {value}", page.len(), live.len()));
                }
            }
        };
        let mut failures = Vec::new();
        if let Err(error) = outcome {
            failures.push(format!("history reader: {error}"));
        }
        for task in tasks {
            if let Err(error) = task.await.unwrap() {
                failures.push(format!("publisher: {error}"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
        assert_eq!(live, sent);
        assert_eq!(page, seeded);
    }
}
