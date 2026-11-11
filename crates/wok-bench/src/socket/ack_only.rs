//! The `door-path` scenario's acknowledge-only socket stand-in.
//!
//! This is a benchmark stand-in, not a relay, and must never be used as one.
//! It bounds the cost of the client and the socket: the same client lane
//! drives it over the same loopback WebSocket, and it answers each
//! `["EVENT", ...]` text frame with `["OK","<id>",true,""]` and does nothing
//! else. It sends no AUTH challenge and asks for none, does not parse the
//! event, checks no signature, runs no session engine and stores nothing, so
//! an `OK true` from it means only that the frame arrived. It lives in
//! `wok-bench` only, binds `127.0.0.1:0` and refuses any other address.

use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use axum::serve::ListenerExt;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use wok_store::relay::{MAX_RELAY_FRAME_BYTES, ok};

use crate::config::Variant;

/// The door's WebSocket buffer sizes (`WS_READ_BUFFER_BYTES` and
/// `WS_WRITE_BUFFER_BYTES` in `wok-ws`, which are private), so that the
/// stand-in's socket is configured as the door's is.
pub(crate) const READ_BUFFER_BYTES: usize = 16 * 1024;
pub(crate) const WRITE_BUFFER_BYTES: usize = 16 * 1024;
/// How every EVENT frame the bench sends begins: `event_text` serialises the
/// event with its id first. The id is the 64 characters after this.
pub(crate) const EVENT_PREFIX: &str = "[\"EVENT\",{\"id\":\"";
/// How long the server task has to end once it is told to stop.
const STOP_WAIT: Duration = Duration::from_secs(30);
/// How long the runtime has to finish its blocking work when it is dropped.
const RUNTIME_WAIT: Duration = Duration::from_secs(10);

/// The id of an EVENT frame, sliced at a fixed offset with no parse: the 64
/// characters after [`EVENT_PREFIX`], which a closing quote must follow.
pub(crate) fn event_id(text: &str) -> Option<&str> {
    let rest = text.strip_prefix(EVENT_PREFIX)?;
    let id = rest.get(..64)?;
    rest[64..].starts_with('"').then_some(id)
}

/// Answer every EVENT frame with `OK true`. Anything that is not an EVENT
/// frame of the expected shape ends the connection, which fails the client's
/// lane, so a mismatch cannot pass as an acknowledgement.
async fn acknowledge(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.recv().await {
        match message {
            Message::Text(text) => {
                let Some(id) = event_id(text.as_str()) else {
                    return;
                };
                if socket
                    .send(Message::Text(ok(id, true, "").into()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            // A Close is answered by the next read, which then ends the
            // loop; pings are answered by the library.
            Message::Close(_) | Message::Ping(_) | Message::Pong(_) => {}
            Message::Binary(_) => return,
        }
    }
}

async fn upgrade(ws: WebSocketUpgrade) -> Response {
    ws.read_buffer_size(READ_BUFFER_BYTES)
        .write_buffer_size(WRITE_BUFFER_BYTES)
        .max_message_size(MAX_RELAY_FRAME_BYTES)
        .max_frame_size(MAX_RELAY_FRAME_BYTES)
        .on_upgrade(acknowledge)
}

/// A running stand-in. Dropping it stops its runtime.
pub(crate) struct AckOnly {
    /// `ws://127.0.0.1:<port>/events`.
    pub(crate) url: String,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
    runtime: Option<Runtime>,
}

impl AckOnly {
    /// Serve the stand-in on `127.0.0.1:0`, on its own runtime sized and with
    /// the listener's TCP_NODELAY set as `variant` gives them, as
    /// `Server::start` serves a door.
    pub(crate) fn start(variant: &Variant) -> Result<Self, String> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(variant.workers)
            .max_blocking_threads(variant.blocking)
            .enable_io()
            .enable_time()
            .build()
            .map_err(|e| format!("start the stand-in's runtime: {e}"))?;
        let listener = runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .map_err(|e| format!("bind 127.0.0.1:0: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("read the listener's address: {e}"))?;
        if !addr.ip().is_loopback() {
            return Err(format!("the listener is on {addr}, not on loopback"));
        }
        let url = format!("ws://{addr}{}", wok_ws::PATH);
        let router = Router::new().route(wok_ws::PATH, get(upgrade));
        let nodelay = variant.nodelay;
        let listener = listener.tap_io(move |stream| {
            let _ = stream.set_nodelay(nodelay);
        });
        let (stop, stopped) = oneshot::channel::<()>();
        let task = runtime.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            url,
            stop: Some(stop),
            task: Some(task),
            runtime: Some(runtime),
        })
    }

    /// Stop serving and require the server task to end.
    pub(crate) fn stop(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let task = self.task.take().ok_or("the stand-in was already stopped")?;
        let runtime = self.runtime.as_ref().ok_or("the stand-in has no runtime")?;
        match runtime.block_on(async { tokio::time::timeout(STOP_WAIT, task).await }) {
            Err(_) => Err(format!(
                "the stand-in's task did not end within {STOP_WAIT:?} of being stopped"
            )),
            Ok(Err(e)) => Err(format!("the stand-in's task panicked: {e}")),
            Ok(Ok(Err(e))) => Err(format!("the stand-in's task ended with an error: {e}")),
            Ok(Ok(Ok(()))) => Ok(()),
        }
    }
}

impl Drop for AckOnly {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(RUNTIME_WAIT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_id_is_sliced_only_from_a_frame_of_the_expected_shape() {
        let id = "ab".repeat(32);
        let frame = format!("{EVENT_PREFIX}{id}\",\"pubkey\":\"00\"}}]");
        assert_eq!(event_id(&frame), Some(id.as_str()));
        assert_eq!(event_id(&format!("{EVENT_PREFIX}{}\"", &id[..63])), None);
        assert_eq!(event_id(&format!("[\"REQ\",{{\"id\":\"{id}\"}}]")), None);
        assert_eq!(event_id("[\"EVENT\"]"), None);
    }
}
