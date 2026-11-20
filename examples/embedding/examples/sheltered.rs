use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::{Extensions, StatusCode};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use nostr::event::{EventBuilder, FinalizeEvent, Kind, Tag};
use nostr::key::{Keys, PublicKey};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use wok_store::SqliteEventStore;
use wok_store::relay::{EventRelay, KeeperAccess};
use wok_ws::{Admission, Admitted, Door, PATH};

struct OnlyKeeper(PublicKey);

impl KeeperAccess for OnlyKeeper {
    fn owns(&self, key: &PublicKey) -> bool {
        key == &self.0
    }
}

struct Loopback;

impl Admission for Loopback {
    fn admit(&self, extensions: &Extensions) -> Result<Admitted, StatusCode> {
        match extensions.get::<ConnectInfo<SocketAddr>>() {
            Some(ConnectInfo(peer)) if peer.ip().is_loopback() => Ok(Admitted::holding(())),
            _ => Err(StatusCode::FORBIDDEN),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("events.sqlite");
    let store =
        tokio::task::spawn_blocking(move || SqliteEventStore::open(&path, 64 * 1024 * 1024))
            .await??;
    let keys = Keys::generate();
    let relay = Arc::new(EventRelay::new(
        Arc::new(store),
        Arc::new(OnlyKeeper(keys.public_key())),
    ));
    let door = Door::new(Arc::clone(&relay)).with_history_limits(2, 0);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("ws://{}{PATH}", listener.local_addr()?);
    let app = Router::new()
        .route("/", get(|| async { "host application" }))
        .merge(door.sheltered_router(url.parse()?, Arc::new(Loopback)));

    let (stop, stopped) = tokio::sync::oneshot::channel();
    let closing = door.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = stopped.await;
            closing.shutdown();
        })
        .await
    });
    let sweeper = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let mut stopped = door.stopped();
        loop {
            tokio::select! {
                _ = stopped.wait_for(|stopped| *stopped) => break,
                _ = tick.tick() => {},
            }
            door.expire().await;
        }
    });

    let checked = tokio::time::timeout(Duration::from_secs(10), check_relay(&url, &keys)).await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    sweeper.await?;
    tokio::task::spawn_blocking(move || relay.flush()).await?;
    checked??;
    println!("Authenticated and published through the host's Axum router.");
    Ok(())
}

async fn check_relay(url: &str, keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await?;
    let challenge = socket.next().await.ok_or("no AUTH challenge")??;
    let challenge: Value = serde_json::from_str(challenge.to_text()?)?;
    assert_eq!(challenge[0], "AUTH");
    let challenge = challenge[1].as_str().ok_or("invalid AUTH challenge")?;
    let auth = EventBuilder::new(Kind::from(22242), "")
        .tags([
            Tag::parse(["relay", url])?,
            Tag::parse(["challenge", challenge])?,
        ])
        .finalize(keys)?;
    let note = EventBuilder::new(Kind::from(1), "embedded relay").finalize(keys)?;
    for (command, event) in [("AUTH", auth), ("EVENT", note)] {
        socket
            .send(Message::Text(json!([command, event]).to_string().into()))
            .await?;
        let reply = socket.next().await.ok_or("no relay reply")??;
        let reply: Value = serde_json::from_str(reply.to_text()?)?;
        assert_eq!(reply[0], "OK", "{reply}");
        assert_eq!(reply[1], event.id.to_hex());
        assert_eq!(reply[2], true, "{reply}");
    }
    socket.close(None).await?;
    Ok(())
}
