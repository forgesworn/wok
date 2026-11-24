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
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(value.to_string().into())),
    )
    .await
    .is_ok_and(|r| r.is_ok())
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
    loop {
        tokio::select! {
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
                        // comes first, across all of the request's filters.
                        let history = work(&host, move |relay| {
                            let mut events = Vec::new();
                            let mut ids = HashSet::new();
                            let mut bytes = 0;
                            for filter in query {
                                for event in relay.query(&who, filter, now())? {
                                    if ids.insert(event.id) {
                                        bytes += event.as_json().len();
                                        if bytes > 2 * 1024 * 1024 || events.len() >= 128 {
                                            return Ok(events);
                                        }
                                        events.push(event);
                                    }
                                }
                            }
                            Ok(events)
                        })
                        .await;
                        match history {
                            Ok(events) => {
                                subscriptions.insert(id.clone(), filters);
                                for event in events {
                                    if !authorised(&host, &access).await
                                        || !send(&mut socket, json!(["EVENT", id, event])).await
                                    {
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
            },
            received = live.recv() => {
                let delivered = match received {
                    Ok(delivered) => delivered,
                    Err(_) => {
                        let notice = json!(["NOTICE", "live stream interrupted; reconnect"]);
                        let _ = send(&mut socket, notice).await;
                        break;
                    }
                };
                let who = access.clone();
                let filters = subscriptions.clone();
                let candidate = delivered.clone();
                let recipients = work(&host, move |relay| {
                    Ok(filters
                        .into_iter()
                        .filter_map(|(id, filters)| {
                            filters
                                .into_iter()
                                .any(|f| relay.delivers(&who, &candidate, f, now()))
                                .then_some(id)
                        })
                        .collect::<Vec<_>>())
                })
                .await
                .unwrap_or_default();
                for id in recipients {
                    if !authorised(&host, &access).await
                        || !send(&mut socket, json!(["EVENT", id, delivered.event])).await
                    {
                        return;
                    }
                }
            },
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
        let temp = TempDir::new().unwrap();
        let relay = RoomRelay::open(temp.path(), 1_000_000, 0, 4).unwrap();
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
}
