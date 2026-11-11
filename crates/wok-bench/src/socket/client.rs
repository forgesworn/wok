//! The client half of a socket cell: connections that authenticate with a
//! real NIP-42 AUTH, then keep a window of signed EVENT frames in flight.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::try_join_all;
use futures_util::{SinkExt, StreamExt};
use nostr::event::Event;
use nostr::key::Keys;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::{Error as WsError, Message, Utf8Bytes};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};
use wok_store::relay::ok;

use crate::engine::writes::Lane;
use crate::engine::{STALL, auth_event, event_text, wall_seconds};

pub(crate) type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How long connecting, the challenge and the AUTH answer may each take.
const SETUP_WAIT: Duration = Duration::from_secs(30);
/// How long the server has to end a connection after the client's Close.
const CLOSE_WAIT: Duration = Duration::from_secs(60);

/// One signed event, serialised before any clock starts.
pub(crate) struct Frame {
    pub(crate) id: String,
    /// The `["EVENT", ...]` text, cheap to clone into a message.
    pub(crate) text: Utf8Bytes,
    /// The reply an accepted write must get: `["OK","<id>",true,""]`.
    pub(crate) ok: String,
}

impl Frame {
    pub(crate) fn new(event: &Event) -> Result<(Self, String), String> {
        let text = event_text(event)?;
        let id = event.id.to_hex();
        let frame = Self {
            ok: ok(&id, true, ""),
            id,
            text: Utf8Bytes::from(text.clone()),
        };
        Ok((frame, text))
    }
}

/// The next text frame, skipping the Ping and Pong frames a connection may
/// carry; any other kind of frame, an end or an error is an error here.
async fn next_text(label: &str, socket: &mut Socket, wait: Duration) -> Result<String, String> {
    loop {
        match timeout(wait, socket.next()).await {
            Err(_) => return Err(format!("{label}: no frame within {wait:?}")),
            Ok(None) => return Err(format!("{label}: the connection closed unexpectedly")),
            Ok(Some(Err(e))) => return Err(format!("{label}: the connection failed: {e}")),
            Ok(Some(Ok(Message::Text(text)))) => return Ok(text.as_str().to_owned()),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Close(frame)))) => {
                return Err(format!(
                    "{label}: the server closed the connection: {frame:?}"
                ));
            }
            Ok(Some(Ok(other))) => {
                return Err(format!("{label}: an unexpected frame: {other:?}"));
            }
        }
    }
}

/// Connect, and nothing more: no frame is read. `nodelay` is the client's
/// TCP_NODELAY.
pub(crate) async fn connect_plain(label: &str, url: &str, nodelay: bool) -> Result<Socket, String> {
    let connected = timeout(SETUP_WAIT, connect_async_with_config(url, None, nodelay))
        .await
        .map_err(|_| format!("{label}: connecting took more than {SETUP_WAIT:?}"))?;
    let (socket, _) = connected.map_err(|e| format!("{label}: connect to {url}: {e}"))?;
    Ok(socket)
}

/// Connect and read the AUTH challenge. `nodelay` is the client's TCP_NODELAY.
async fn connect(label: &str, url: &str, nodelay: bool) -> Result<(Socket, String), String> {
    let mut socket = connect_plain(label, url, nodelay).await?;
    let first = next_text(label, &mut socket, SETUP_WAIT).await?;
    let value: Value = serde_json::from_str(&first)
        .map_err(|e| format!("{label}: the first frame is not JSON ({e}): {first}"))?;
    match (value[0].as_str(), value[1].as_str()) {
        (Some("AUTH"), Some(challenge)) => Ok((socket, challenge.to_owned())),
        _ => Err(format!("{label}: expected an AUTH challenge, got {first}")),
    }
}

/// Connect, then answer the challenge with a real AUTH stamped with wall
/// time, which the door must accept with `OK true`.
pub(crate) async fn connect_authenticated(
    label: String,
    url: &str,
    keys: &Keys,
    nodelay: bool,
) -> Result<Socket, String> {
    let (mut socket, challenge) = connect(&label, url, nodelay).await?;
    let event =
        auth_event(keys, url, &challenge, wall_seconds()).map_err(|e| format!("{label}: {e}"))?;
    let id = event.id.to_hex();
    let text = serde_json::to_string(&json!(["AUTH", event]))
        .map_err(|e| format!("{label}: serialise the AUTH frame: {e}"))?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| format!("{label}: send the AUTH frame: {e}"))?;
    let reply = next_text(&label, &mut socket, SETUP_WAIT).await?;
    if reply != ok(&id, true, "") {
        return Err(format!("{label}: AUTH was not accepted: {reply}"));
    }
    Ok(socket)
}

/// Every connection of a cell, connected and authenticated before any clock
/// starts. Connection `lane` authenticates as `keys[lane % keys.len()]`.
pub(crate) async fn connect_all(
    label: &str,
    url: &str,
    keys: &[Keys],
    connections: usize,
    nodelay: bool,
) -> Result<Vec<Socket>, String> {
    try_join_all((0..connections).map(|lane| {
        connect_authenticated(
            format!("{label}, connection {lane}"),
            url,
            &keys[lane % keys.len()],
            nodelay,
        )
    }))
    .await
}

/// Send one frame, remember when, and expect its OK.
async fn send_frame<'a>(
    label: &str,
    socket: &mut Socket,
    frame: &'a Frame,
    pending: &mut HashMap<&'a str, Instant>,
) -> Result<(), String> {
    pending.insert(frame.ok.as_str(), Instant::now());
    socket
        .send(Message::Text(frame.text.clone()))
        .await
        .map_err(|e| format!("{label}: send write {}: {e}", frame.id))
}

/// Name what an unexpected reply was: the checks that fail a run.
fn unexpected(label: &str, text: &str) -> String {
    let shown: String = text.chars().take(200).collect();
    let what = if text.starts_with("[\"OK\"") {
        if text.contains(",false,") {
            "OK false: the write was refused"
        } else {
            "an OK for an id that is not in flight"
        }
    } else if text.starts_with("[\"NOTICE\"") {
        "a NOTICE"
    } else if text.starts_with("[\"CLOSED\"") {
        "a CLOSED"
    } else {
        "an unexpected frame"
    };
    format!("{label}: {what}: {shown}")
}

/// The client's end of a connection: send a Close frame and require the
/// connection to end. A Close in reply, the stream ending or a reset all count
/// as the end; a frame of text does not.
pub(crate) async fn close_cleanly(label: &str, socket: &mut Socket) -> Result<(), String> {
    match socket.close(None).await {
        Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {}
        Err(e) => return Err(format!("{label}: send the Close frame: {e}")),
    }
    let ended = timeout(CLOSE_WAIT, async {
        loop {
            match socket.next().await {
                None | Some(Err(_) | Ok(Message::Close(_))) => return Ok(()),
                Some(Ok(Message::Text(text))) => {
                    return Err(unexpected(label, text.as_str()));
                }
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    match ended {
        Ok(result) => result,
        Err(_) => Err(format!(
            "{label}: the connection did not end within {CLOSE_WAIT:?} of the Close frame"
        )),
    }
}

/// One connection's closed loop: wait for the start, keep `window` of its
/// frames in flight, send the next as each OK returns, and match every OK to a
/// frame sent. Anything else (an `OK false`, a NOTICE, a CLOSED, an unknown id,
/// a close, an error or a stall) fails the run. The time of the last OK is
/// stamped before the connection is closed, so closing is outside the time.
pub(crate) async fn write_lane(
    label: String,
    mut socket: Socket,
    frames: Arc<Vec<Frame>>,
    indices: Vec<usize>,
    window: usize,
    start: Arc<Barrier>,
) -> Result<Lane, String> {
    let mut lane = Lane {
        latencies: Vec::with_capacity(indices.len()),
        ..Lane::default()
    };
    let total = indices.len();
    let mut pending: HashMap<&str, Instant> = HashMap::with_capacity(window);
    let mut next = 0;
    start.wait().await;
    while next < total && pending.len() < window {
        send_frame(&label, &mut socket, &frames[indices[next]], &mut pending).await?;
        next += 1;
    }
    let mut received = 0;
    while received < total {
        let text = match timeout(STALL, socket.next()).await {
            Err(_) => {
                return Err(format!(
                    "{label}: no reply within {STALL:?} with {} writes in flight",
                    pending.len()
                ));
            }
            Ok(None) => {
                return Err(format!(
                    "{label}: the connection closed with {} writes in flight",
                    pending.len()
                ));
            }
            Ok(Some(Err(e))) => return Err(format!("{label}: the connection failed: {e}")),
            Ok(Some(Ok(Message::Text(text)))) => text,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Close(frame)))) => {
                return Err(format!(
                    "{label}: the server closed the connection with {} writes in flight: {frame:?}",
                    pending.len()
                ));
            }
            Ok(Some(Ok(other))) => {
                return Err(format!("{label}: an unexpected frame: {other:?}"));
            }
        };
        let at = Instant::now();
        let Some(sent) = pending.remove(text.as_str()) else {
            return Err(unexpected(&label, text.as_str()));
        };
        lane.latencies.push((at - sent).as_nanos() as u64);
        received += 1;
        if next < total {
            send_frame(&label, &mut socket, &frames[indices[next]], &mut pending).await?;
            next += 1;
        }
    }
    lane.finished = Some(Instant::now());
    close_cleanly(&label, &mut socket).await?;
    Ok(lane)
}

/// Open a connection, authenticate it as `keys` when given, send one frame and
/// return the single reply, then close cleanly. For the refusal checks, which
/// are outside the timed cells.
pub(crate) async fn exchange(
    label: &str,
    url: &str,
    keys: Option<&Keys>,
    text: &str,
    nodelay: bool,
) -> Result<String, String> {
    let mut socket = match keys {
        Some(keys) => connect_authenticated(label.to_owned(), url, keys, nodelay).await?,
        None => connect(label, url, nodelay).await?.0,
    };
    socket
        .send(Message::Text(text.to_owned().into()))
        .await
        .map_err(|e| format!("{label}: send the frame: {e}"))?;
    let reply = next_text(label, &mut socket, SETUP_WAIT).await?;
    close_cleanly(label, &mut socket).await?;
    Ok(reply)
}
