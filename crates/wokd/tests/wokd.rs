//! `wokd` end to end: a configuration parsed as the binary parses it, served
//! through the same entry point, and driven by a stock client and by raw
//! sockets.

use std::path::Path;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind, Tag};
use nostr::filter::Filter;
use nostr::key::Keys;
use nostr::nips::nip19::ToBech32;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use wok_ws::PATH;
use wokd::{Config, RemoveError, RunError, Target, serve};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Running {
    url: String,
    config: Config,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), RunError>>,
}

impl Running {
    async fn stop(self) {
        let _ = self.stop.send(());
        timeout(Duration::from_secs(10), self.task)
            .await
            .expect("the server drains on shutdown")
            .expect("the server task")
            .expect("the server stops cleanly");
    }
}

async fn start(dir: &Path, members: &[&Keys]) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
    let members = members
        .iter()
        .map(|keys| format!("\"{}\"", keys.public_key().to_bech32().unwrap()))
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!(
        "url = \"{url}\"\ndata_dir = '{}'\nmax_store_bytes = 67108864\n\
         min_free_bytes = 0\nmembers = [{members}]\n",
        dir.display()
    );
    let config = Config::from_toml(&text).expect("a valid configuration");
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(serve(config.clone(), listener, async move {
        let _ = stopped.await;
    }));
    Running {
        url,
        config,
        stop,
        task,
    }
}

fn note(keys: &Keys, text: &str) -> Event {
    EventBuilder::new(Kind::TextNote, text)
        .finalize(keys)
        .unwrap()
}

async fn receive(socket: &mut Socket) -> Value {
    loop {
        let message = timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("a reply within five seconds")
            .expect("the socket is open")
            .expect("a frame");
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

/// The next frame that is not an AUTH challenge, and how many challenges
/// came before it.
async fn reply_past_challenges(socket: &mut Socket) -> (Value, usize) {
    let mut challenges = 0;
    loop {
        let frame = receive(socket).await;
        if frame[0] == "AUTH" {
            challenges += 1;
            continue;
        }
        return (frame, challenges);
    }
}

/// The next text frame within `wait`, if any.
async fn next_within(socket: &mut Socket, wait: Duration) -> Option<Value> {
    timeout(wait, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).ok(),
                Some(Ok(_)) => continue,
                _ => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn send(socket: &mut Socket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}

/// Connect and read the AUTH challenge.
async fn connect(url: &str) -> (Socket, String) {
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let challenge = receive(&mut socket).await;
    assert_eq!(challenge[0], "AUTH");
    (socket, challenge[1].as_str().unwrap().to_owned())
}

/// Send AUTH as `keys`; the OK frame.
async fn auth(socket: &mut Socket, url: &str, challenge: &str, keys: &Keys) -> Value {
    let event = EventBuilder::new(Kind::from(22242), "")
        .tags([
            Tag::parse(["relay", url]).unwrap(),
            Tag::parse(["challenge", challenge]).unwrap(),
        ])
        .finalize(keys)
        .unwrap();
    send(socket, json!(["AUTH", event])).await;
    receive(socket).await
}

async fn member(url: &str, keys: &Keys) -> Socket {
    let (mut socket, challenge) = connect(url).await;
    let ok = auth(&mut socket, url, &challenge, keys).await;
    assert_eq!(ok[2], true, "a member authenticates: {ok}");
    socket
}

async fn publish(socket: &mut Socket, event: &Event) -> Value {
    send(socket, json!(["EVENT", event])).await;
    receive(socket).await
}

/// The events a REQ returns before EOSE (or the CLOSED frame instead).
async fn query(socket: &mut Socket, filter: Value) -> Result<Vec<Value>, Value> {
    send(socket, json!(["REQ", "q", filter])).await;
    let mut events = Vec::new();
    loop {
        let frame = receive(socket).await;
        match frame[0].as_str() {
            Some("EVENT") => events.push(frame[2].clone()),
            Some("EOSE") => return Ok(events),
            _ => return Err(frame),
        }
    }
}

#[tokio::test]
async fn a_member_publishes_and_reads_back_with_a_stock_client() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let client = nostr_sdk::client::Client::builder()
        .authenticator(nostr_sdk::authenticator::SignerAuthenticator::new(
            alice.clone(),
        ))
        .build();
    client.add_relay(server.url.as_str()).await.unwrap();
    client.connect().await;
    let event = note(&alice, "for the group");
    let mut sent = false;
    for _ in 0..8 {
        if let Ok(Ok(output)) = timeout(Duration::from_secs(3), client.send_event(&event)).await
            && !output.success.is_empty()
        {
            sent = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(
        sent,
        "a stock client authenticates as a member and publishes"
    );
    let events = client
        .fetch_events(Filter::new().id(event.id))
        .timeout(Duration::from_secs(5))
        .await
        .expect("a member's fetch is answered");
    assert!(events.iter().any(|e| e.id == event.id));
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn before_auth_a_read_is_refused_with_the_nip42_prefix() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let (mut socket, _) = connect(&server.url).await;
    let closed = query(&mut socket, json!({"kinds": [1]})).await.unwrap_err();
    assert_eq!(closed[0], "CLOSED");
    assert!(
        closed[2].as_str().unwrap().starts_with("auth-required:"),
        "{closed}"
    );
    drop(socket);
    server.stop().await;
}

#[tokio::test]
async fn an_authenticated_non_member_gets_nothing_on_the_wire() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let mut alice_socket = member(&server.url, &alice).await;
    let stored = note(&alice, "members only");
    assert_eq!(publish(&mut alice_socket, &stored).await[2], true);

    let (mut bob_socket, challenge) = connect(&server.url).await;
    let refused = auth(&mut bob_socket, &server.url, &challenge, &bob).await;
    eprintln!("non-member AUTH: {refused}");
    assert_eq!(refused[2], false);
    assert!(
        refused[3].as_str().unwrap().starts_with("restricted:"),
        "{refused}"
    );

    // What a stock client sees next: each EVENT after the refused AUTH is
    // refused, after a fresh challenge that invites it to try again.
    for round in 0..3 {
        send(&mut bob_socket, json!(["EVENT", note(&bob, "let me in")])).await;
        let (reply, challenges) = reply_past_challenges(&mut bob_socket).await;
        eprintln!("non-member EVENT, round {round}: {challenges} new challenge(s), then {reply}");
        assert_eq!(reply[0], "OK");
        assert_eq!(reply[2], false);
    }
    send(&mut bob_socket, json!(["REQ", "q", {"kinds": [1]}])).await;
    let (read, challenges) = reply_past_challenges(&mut bob_socket).await;
    eprintln!("non-member REQ: {challenges} new challenge(s), then {read}");
    assert_eq!(
        read[0], "CLOSED",
        "a non-member's REQ is closed, not answered"
    );
    send(&mut bob_socket, json!(["COUNT", "c", {"kinds": [1]}])).await;
    let (counted, challenges) = reply_past_challenges(&mut bob_socket).await;
    eprintln!("non-member COUNT: {challenges} new challenge(s), then {counted}");
    assert_eq!(counted[0], "CLOSED");
    send(
        &mut bob_socket,
        json!(["NEG-OPEN", "n", {"kinds": [1]}, "61"]),
    )
    .await;
    let (reconciled, challenges) = reply_past_challenges(&mut bob_socket).await;
    eprintln!("non-member NEG-OPEN: {challenges} new challenge(s), then {reconciled}");
    assert_eq!(reconciled[0], "NEG-ERR");

    // Live: a member's new event never reaches the non-member.
    let later = note(&alice, "still members only");
    assert_eq!(publish(&mut alice_socket, &later).await[2], true);
    let leaked = next_within(&mut bob_socket, Duration::from_millis(500)).await;
    assert!(
        !leaked.as_ref().is_some_and(|frame| frame[0] == "EVENT"),
        "no event reaches a non-member: {leaked:?}"
    );
    drop(bob_socket);
    drop(alice_socket);
    server.stop().await;
}

#[tokio::test]
async fn a_member_may_store_an_event_signed_by_any_key() {
    // Pinned, not endorsed: the sheltered door keeps events under any outer
    // key (gift wraps need it), and NIP-09 deletion is its author's alone, so
    // nobody can delete such an event over the protocol.
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let carol = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let mut socket = member(&server.url, &alice).await;
    let foreign = note(&carol, "signed outside the group");
    let ok = publish(&mut socket, &foreign).await;
    assert_eq!(ok[2], true, "{ok}");
    let found = query(&mut socket, json!({"ids": [foreign.id.to_hex()]}))
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    drop(socket);
    server.stop().await;
}

#[tokio::test]
async fn a_restart_keeps_the_events_and_drops_a_removed_member() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let server = start(tmp.path(), &[&alice, &bob]).await;
    let mut socket = member(&server.url, &bob).await;
    let kept = note(&bob, "before the restart");
    assert_eq!(publish(&mut socket, &kept).await[2], true);
    drop(socket);
    server.stop().await;

    // Bob is taken out of the list.
    let server = start(tmp.path(), &[&alice]).await;
    let mut socket = member(&server.url, &alice).await;
    let found = query(&mut socket, json!({"ids": [kept.id.to_hex()]}))
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "an acknowledged event survives the restart");
    let (mut bob_socket, challenge) = connect(&server.url).await;
    let refused = auth(&mut bob_socket, &server.url, &challenge, &bob).await;
    assert_eq!(refused[2], false, "a removed member is refused: {refused}");
    drop(bob_socket);
    drop(socket);
    server.stop().await;
}

#[test]
fn shutdown_answers_and_closes_an_open_socket_before_run_returns() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("ws://127.0.0.1:{port}{PATH}");
    let text = format!(
        "listen = \"127.0.0.1:{port}\"\nurl = \"{url}\"\ndata_dir = '{}'\n\
         max_store_bytes = 67108864\nmin_free_bytes = 0\nmembers = [\"{}\"]\n",
        tmp.path().display(),
        alice.public_key().to_bech32().unwrap()
    );
    let config = Config::from_toml(&text).unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    // The server gets a runtime of its own, dropped as soon as `run`
    // returns, as in `main`.
    let server = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(wokd::run(config, async move {
                let _ = stopped.await;
            }))
    });
    let client = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    client.block_on(async {
        let mut tries = 0;
        let (mut socket, challenge) = loop {
            match tokio_tungstenite::connect_async(&url).await {
                Ok((mut socket, _)) => {
                    let challenge = receive(&mut socket).await;
                    break (socket, challenge[1].as_str().unwrap().to_owned());
                }
                Err(_) if tries < 100 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("the server never listened: {error}"),
            }
        };
        assert_eq!(auth(&mut socket, &url, &challenge, &alice).await[2], true);
        let event = note(&alice, "in flight at shutdown");
        send(&mut socket, json!(["EVENT", event])).await;
        stop.send(()).unwrap();
        let mut answered = None;
        let close = loop {
            match timeout(Duration::from_secs(10), socket.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    let frame: Value = serde_json::from_str(&text).unwrap();
                    if frame[0] == "OK" && frame[1] == event.id.to_hex() {
                        answered = Some(frame);
                    }
                }
                Ok(Some(Ok(Message::Close(frame)))) => {
                    break frame.map(|frame| u16::from(frame.code));
                }
                Ok(Some(Ok(_))) => {}
                other => panic!("the socket ended without a close frame: {other:?}"),
            }
        };
        eprintln!("in-flight write at shutdown answered: {answered:?}");
        // Either the write was read before the shutdown, and is stored and
        // answered with its own OK, or it was still unread, and the close
        // answers it as not stored. Never unanswered.
        let frame = answered.expect("the in-flight write is answered");
        assert!(
            frame[2] == true
                || frame[3]
                    .as_str()
                    .is_some_and(|reason| reason.starts_with("error: connection closing")),
            "{frame}"
        );
        assert_eq!(close, Some(1001), "a going-away close, not a reset");
    });
    server
        .join()
        .unwrap()
        .expect("run returns cleanly after a shutdown");
}

#[tokio::test]
async fn a_removal_is_refused_while_the_relay_serves_the_data_directory() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let mut socket = member(&server.url, &alice).await;
    let event = note(&alice, "stored");
    assert_eq!(publish(&mut socket, &event).await[2], true);
    let config = server.config.clone();
    let refused = wokd::remove(&config, &Target::Ids(vec![event.id]));
    assert!(matches!(refused, Err(RemoveError::Running)), "{refused:?}");
    drop(socket);
    server.stop().await;
    // Stopped, the same removal runs.
    let done = wokd::remove(&config, &Target::Ids(vec![event.id])).unwrap();
    assert_eq!(done.removed, vec![event.id]);
}

#[tokio::test]
async fn an_operator_removes_a_foreign_signed_event_and_it_cannot_come_back() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let carol = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let mut socket = member(&server.url, &alice).await;
    let reported = note(&carol, "reported by a member");
    let own = note(&alice, "the member's own");
    assert_eq!(publish(&mut socket, &reported).await[2], true);
    assert_eq!(publish(&mut socket, &own).await[2], true);
    drop(socket);
    let config = server.config.clone();
    server.stop().await;

    let unknown = note(&alice, "never stored").id;
    let done = wokd::remove(&config, &Target::Ids(vec![reported.id, unknown])).unwrap();
    assert_eq!(done.removed, vec![reported.id]);
    assert_eq!(
        done.not_found,
        vec![unknown],
        "an id that was not stored is reported"
    );
    assert!(done.erased);

    let server = start(tmp.path(), &[&alice]).await;
    let mut socket = member(&server.url, &alice).await;
    let left = query(&mut socket, json!({"kinds": [1]})).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["id"], own.id.to_hex());
    let again = publish(&mut socket, &reported).await;
    eprintln!("re-published after removal: {again}");
    assert_eq!(again[2], false, "a removed event is not stored again");
    drop(socket);
    server.stop().await;
}

#[tokio::test]
async fn an_operator_removes_everything_a_key_signed() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let carol = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let mut socket = member(&server.url, &alice).await;
    for i in 0..3 {
        let event = note(&carol, &format!("from carol {i}"));
        assert_eq!(publish(&mut socket, &event).await[2], true);
    }
    let own = note(&alice, "kept");
    assert_eq!(publish(&mut socket, &own).await[2], true);
    drop(socket);
    let config = server.config.clone();
    server.stop().await;
    let done = wokd::remove(&config, &Target::Author(carol.public_key())).unwrap();
    assert_eq!(done.removed.len(), 3);
    assert!(done.not_found.is_empty());

    let server = start(tmp.path(), &[&alice]).await;
    let mut socket = member(&server.url, &alice).await;
    let left = query(&mut socket, json!({"kinds": [1]})).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["id"], own.id.to_hex());
    drop(socket);
    server.stop().await;
}

#[test]
fn a_removal_with_no_store_says_so_and_creates_nothing() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let dir = tmp.path().join("absent");
    let text = format!(
        "url = \"ws://127.0.0.1:7447/events\"\ndata_dir = '{}'\nmax_store_bytes = 67108864\n\
         min_free_bytes = 0\nmembers = [\"{}\"]\n",
        dir.display(),
        alice.public_key().to_bech32().unwrap()
    );
    let config = Config::from_toml(&text).unwrap();
    let missing = wokd::remove(&config, &Target::Author(alice.public_key()));
    assert!(matches!(missing, Err(RemoveError::NoStore)), "{missing:?}");
    assert!(!dir.exists());
}
