//! `wokd` end to end: a configuration parsed as the binary parses it, served
//! through the same entry point, and driven by a stock client and by raw
//! sockets.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind, Tag};
use nostr::filter::Filter;
use nostr::key::Keys;
use nostr::nips::nip19::ToBech32;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use wok_ws::PATH;
use wokd::{Config, RemoveError, RunError, Target, serve};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Running {
    url: String,
    config: Config,
    reload: mpsc::Sender<Config>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), RunError>>,
}

impl Running {
    /// Hand the relay its configuration again, with `members` as the group,
    /// as the binary does on SIGHUP.
    async fn reload(&self, members: &[&Keys]) {
        let text = config_text(&self.config.data_dir, members, &self.url, "");
        let next = Config::from_toml(&text).expect("a valid configuration");
        self.reload
            .send(next)
            .await
            .expect("the relay takes reloads");
    }

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
    start_at(dir, members, listener, url).await
}

/// [`start`] on `listener`, with `url` as the address clients name.
async fn start_at(dir: &Path, members: &[&Keys], listener: TcpListener, url: String) -> Running {
    start_at_with(dir, members, listener, url, "").await
}

/// [`start`], with `extra` appended to the configuration.
async fn start_with(dir: &Path, members: &[&Keys], extra: &str) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
    start_at_with(dir, members, listener, url, extra).await
}

async fn start_at_with(
    dir: &Path,
    members: &[&Keys],
    listener: TcpListener,
    url: String,
    extra: &str,
) -> Running {
    let text = config_text(dir, members, &url, extra);
    let config = Config::from_toml(&text).expect("a valid configuration");
    let (stop, stopped) = oneshot::channel();
    let (reload, reloads) = mpsc::channel(1);
    let task = tokio::spawn(serve(config.clone(), listener, reloads, async move {
        let _ = stopped.await;
    }));
    Running {
        url,
        config,
        reload,
        stop,
        task,
    }
}

/// A configuration file's text: `members` as the group, `url` as the
/// address clients name, the store in `dir`, and `extra` appended.
fn config_text(dir: &Path, members: &[&Keys], url: &str, extra: &str) -> String {
    let members = members
        .iter()
        .map(|keys| format!("\"{}\"", keys.public_key().to_bech32().unwrap()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "url = \"{url}\"\ndata_dir = '{}'\nmax_store_bytes = 67108864\n\
         min_free_bytes = 0\nmembers = [{members}]\n{extra}",
        dir.display()
    )
}

/// Read until the relay closes the socket: the text frames before the close,
/// and the close code.
async fn until_closed(socket: &mut Socket) -> (Vec<Value>, Option<u16>) {
    let mut frames = Vec::new();
    loop {
        match timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("the relay closes the socket within five seconds")
        {
            Some(Ok(Message::Text(text))) => frames.push(serde_json::from_str(&text).unwrap()),
            Some(Ok(Message::Close(frame))) => {
                return (frames, frame.map(|frame| u16::from(frame.code)));
            }
            Some(Ok(_)) => {}
            other => panic!("the socket ended without a close frame: {other:?}"),
        }
    }
}

/// A plain HTTP GET to the relay's address, as a browser's `fetch` sends
/// it: the status code, the header block in lower case, and the body.
async fn http_get(url: &str, accept: &str) -> (u16, String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let address = url
        .trim_start_matches("ws://")
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    let mut stream = tokio::net::TcpStream::connect(&address).await.unwrap();
    let request = format!(
        "GET {PATH} HTTP/1.1\r\nHost: {address}\r\nAccept: {accept}\r\n\
         Origin: https://client.example\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("the relay answers")
        .unwrap();
    let text = String::from_utf8(response).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP response");
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_ascii_lowercase(), body.to_owned())
}

/// A WebSocket proxy in front of `upstream`, counting the AUTH frames its
/// clients send: its address, and the count.
async fn counting_proxy(upstream: String) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}{PATH}", listener.local_addr().unwrap());
    let auths = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&auths);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let upstream = upstream.clone();
            let counted = Arc::clone(&counted);
            tokio::spawn(async move {
                let Ok(client) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                let Ok((relay, _)) = tokio_tungstenite::connect_async(upstream.as_str()).await
                else {
                    return;
                };
                let (mut to_client, mut from_client) = client.split();
                let (mut to_relay, mut from_relay) = relay.split();
                let up = async {
                    while let Some(Ok(message)) = from_client.next().await {
                        if let Message::Text(text) = &message
                            && text.as_str().starts_with("[\"AUTH\"")
                        {
                            counted.fetch_add(1, Ordering::SeqCst);
                        }
                        if to_relay.send(message).await.is_err() {
                            break;
                        }
                    }
                };
                let down = async {
                    while let Some(Ok(message)) = from_relay.next().await {
                        if to_client.send(message).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::select! {
                    () = up => {}
                    () = down => {}
                }
            });
        }
    });
    (url, auths)
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
async fn a_stock_client_with_a_refused_key_signs_once_and_its_publish_fails() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("ws://{}{PATH}", listener.local_addr().unwrap());
    let (url, auths) = counting_proxy(upstream).await;
    let server = start_at(tmp.path(), &[&alice], listener, url.clone()).await;
    let client = nostr_sdk::client::Client::builder()
        .authenticator(nostr_sdk::authenticator::SignerAuthenticator::new(
            bob.clone(),
        ))
        .build();
    client.add_relay(url.as_str()).await.unwrap();
    client.connect().await;
    // The relay challenges on connect and the client answers it unasked.
    timeout(Duration::from_secs(5), async {
        while auths.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the client answers the first challenge");

    let event = note(&bob, "let me in");
    let output = timeout(Duration::from_secs(5), client.send_event(&event))
        .await
        .expect("a refused key's publish ends within five seconds");
    eprintln!("refused key's publish: {output:?}");
    let failure = match output {
        Ok(output) => {
            assert!(output.success.is_empty(), "nothing was stored");
            output.failed.into_values().collect::<Vec<_>>().join("; ")
        }
        Err(error) => error.to_string(),
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    let signed = auths.load(Ordering::SeqCst);
    eprintln!("AUTH frames the client sent: {signed}");
    assert!(failure.contains("restricted:"), "{failure}");
    assert_eq!(signed, 1, "a refused key is not prompted to sign again");
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test]
async fn an_auth_naming_another_url_is_final_and_the_same_challenge_still_works() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let (mut socket, challenge) = connect(&server.url).await;
    let refused = auth(
        &mut socket,
        "wss://elsewhere.example/events",
        &challenge,
        &alice,
    )
    .await;
    assert_eq!(refused[2], false, "{refused}");
    assert_eq!(
        refused[3],
        "invalid: authentication challenge, relay, time or signature"
    );
    // Had a replacement challenge been sent, it would come before this OK.
    let accepted = auth(&mut socket, &server.url, &challenge, &alice).await;
    assert_eq!(accepted[0], "OK", "no replacement challenge: {accepted}");
    assert_eq!(accepted[2], true, "{accepted}");
    drop(socket);
    server.stop().await;
}

#[tokio::test]
async fn a_stock_client_naming_another_url_signs_once() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("ws://{}{PATH}", listener.local_addr().unwrap());
    let (url, auths) = counting_proxy(upstream).await;
    // `url` is not the address the client connects to, so every AUTH it
    // signs names another relay.
    let server = start_at(
        tmp.path(),
        &[&alice],
        listener,
        "wss://relay.example/events".to_owned(),
    )
    .await;
    let client = nostr_sdk::client::Client::builder()
        .authenticator(nostr_sdk::authenticator::SignerAuthenticator::new(
            alice.clone(),
        ))
        .build();
    client.add_relay(url.as_str()).await.unwrap();
    client.connect().await;
    timeout(Duration::from_secs(5), async {
        while auths.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the client answers the first challenge");
    // Without the final refusal, a stock client signed 120 within a fifth
    // of a second, until the frame allowance closed the connection.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let signed = auths.load(Ordering::SeqCst);
    eprintln!("AUTH frames the client sent: {signed}");
    assert_eq!(
        signed, 1,
        "a client naming another URL is not prompted again"
    );
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
    // refused as restricted, with no fresh challenge to sign.
    for round in 0..3 {
        send(&mut bob_socket, json!(["EVENT", note(&bob, "let me in")])).await;
        let (reply, challenges) = reply_past_challenges(&mut bob_socket).await;
        eprintln!("non-member EVENT, round {round}: {challenges} new challenge(s), then {reply}");
        assert_eq!(challenges, 0, "no challenge invites the key to try again");
        assert_eq!(reply[0], "OK");
        assert_eq!(reply[2], false);
        assert_eq!(reply[3], "restricted: this key has no sheltered access");
    }
    send(&mut bob_socket, json!(["REQ", "q", {"kinds": [1]}])).await;
    let (read, challenges) = reply_past_challenges(&mut bob_socket).await;
    eprintln!("non-member REQ: {challenges} new challenge(s), then {read}");
    assert_eq!(challenges, 0);
    assert_eq!(
        read[0], "CLOSED",
        "a non-member's REQ is closed, not answered"
    );
    assert_eq!(read[2], "restricted: this key has no sheltered access");
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
async fn after_a_refused_key_a_member_authenticates_on_the_same_socket() {
    let tmp = TempDir::new().unwrap();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let server = start(tmp.path(), &[&alice]).await;
    let (mut socket, challenge) = connect(&server.url).await;
    let refused = auth(&mut socket, &server.url, &challenge, &bob).await;
    assert_eq!(refused[2], false, "{refused}");
    // The refusal sent no new challenge: the first one is still current.
    let accepted = auth(&mut socket, &server.url, &challenge, &alice).await;
    assert_eq!(accepted[2], true, "{accepted}");
    let stored = note(&alice, "after all");
    assert_eq!(publish(&mut socket, &stored).await[2], true);
    drop(socket);
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

#[tokio::test]
async fn a_reload_closes_a_removed_members_connection_and_admits_an_added_one() {
    let tmp = TempDir::new().unwrap();
    let (alice, bob, carol) = (Keys::generate(), Keys::generate(), Keys::generate());
    let server = start(tmp.path(), &[&alice, &carol]).await;
    let mut alice_socket = member(&server.url, &alice).await;
    assert!(
        query(&mut alice_socket, json!({"kinds": [1]}))
            .await
            .unwrap()
            .is_empty()
    );
    let mut carol_socket = member(&server.url, &carol).await;
    assert!(
        query(&mut carol_socket, json!({"kinds": [1]}))
            .await
            .unwrap()
            .is_empty()
    );

    // Alice out, Bob in, in one reload, with no restart.
    server.reload(&[&bob, &carol]).await;
    let (frames, code) = until_closed(&mut alice_socket).await;
    assert_eq!(
        frames,
        vec![json!([
            "CLOSED",
            "q",
            "restricted: sheltered authority changed"
        ])],
        "the removed member's subscription is closed, then its connection"
    );
    assert_eq!(code, Some(1008));

    let mut bob_socket = member(&server.url, &bob).await;
    let after = note(&bob, "after the reload");
    assert_eq!(publish(&mut bob_socket, &after).await[2], true);
    // The member who stayed keeps its subscription through the change.
    let live = receive(&mut carol_socket).await;
    assert_eq!(live[0], "EVENT", "{live}");
    assert_eq!(live[1], "q");
    assert_eq!(live[2]["id"], after.id.to_hex());

    let (mut again, challenge) = connect(&server.url).await;
    let refused = auth(&mut again, &server.url, &challenge, &alice).await;
    assert_eq!(refused[2], false, "a removed key is refused: {refused}");
    assert!(
        refused[3].as_str().unwrap().starts_with("restricted:"),
        "{refused}"
    );
    drop((again, bob_socket, carol_socket));
    server.stop().await;
}

#[tokio::test]
async fn a_reload_spares_a_socket_still_authenticating_and_drops_an_idle_removed_member() {
    let tmp = TempDir::new().unwrap();
    let (alice, bob) = (Keys::generate(), Keys::generate());
    let server = start(tmp.path(), &[&alice]).await;
    // Authenticated, with nothing open.
    let mut alice_socket = member(&server.url, &alice).await;
    // Connected before the reload, not yet authenticated.
    let (mut waiting, challenge) = connect(&server.url).await;

    server.reload(&[&bob]).await;
    let (frames, code) = until_closed(&mut alice_socket).await;
    assert!(frames.is_empty(), "nothing was open to close: {frames:?}");
    assert_eq!(code, Some(1008), "the connection goes all the same");

    // The waiting socket was left alone, and the challenge it was sent
    // before the reload lets the added key in.
    let ok = auth(&mut waiting, &server.url, &challenge, &bob).await;
    assert_eq!(ok[2], true, "{ok}");
    let stored = note(&bob, "on a socket opened before the reload");
    assert_eq!(publish(&mut waiting, &stored).await[2], true);
    drop(waiting);
    server.stop().await;
}

/// The built `wokd` binary serving the configuration at `path`, its log read
/// line by line. Killed if a test fails before stopping it.
#[cfg(unix)]
struct Daemon {
    child: std::process::Child,
    lines: std::sync::mpsc::Receiver<String>,
    log: Vec<String>,
    reader: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl Daemon {
    fn start(path: &Path) -> Self {
        use std::io::BufRead as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new(env!("CARGO_BIN_EXE_wokd"))
            .arg("--config")
            .arg(path)
            .env("NO_COLOR", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let (line, lines) = std::sync::mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            for text in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                let _ = line.send(text);
            }
        });
        Self {
            child,
            lines,
            log: Vec::new(),
            reader: Some(reader),
        }
    }

    /// Send it `name`, such as `-HUP`.
    fn signal(&self, name: &str) {
        let sent = std::process::Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success(), "kill {name}");
    }

    /// Read its log until a line contains `needle`, within ten seconds.
    fn wait_for(&mut self, needle: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let text = self
                .lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no log line with {needle:?} in: {:#?}", self.log));
            let found = text.contains(needle);
            self.log.push(text);
            if found {
                return;
            }
        }
    }

    /// Stop it with SIGTERM, which it must still be running to take, and
    /// return its whole log once it has exited cleanly.
    fn stop(mut self) -> String {
        assert!(self.child.try_wait().unwrap().is_none(), "still running");
        self.signal("-TERM");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "wokd stops on SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "{status}");
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
        self.log.extend(self.lines.try_iter());
        self.log.join("\n")
    }
}

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port nothing listens on, for a configuration's `listen`.
#[cfg(unix)]
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Authenticate as `keys` once the binary at `url` listens.
#[cfg(unix)]
async fn member_once_listening(url: &str, keys: &Keys) -> Socket {
    for _ in 0..250 {
        if let Ok((mut socket, _)) = tokio_tungstenite::connect_async(url).await {
            let challenge = receive(&mut socket).await;
            let challenge = challenge[1].as_str().unwrap().to_owned();
            assert_eq!(auth(&mut socket, url, &challenge, keys).await[2], true);
            return socket;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("wokd never listened on {url}");
}

/// The binary itself: SIGHUP reloads the file, a bad file changes nothing,
/// SIGHUP does not stop it, and no key reaches its log.
#[cfg(unix)]
#[test]
fn sighup_reloads_the_members_and_a_bad_file_changes_nothing() {
    let tmp = TempDir::new().unwrap();
    let data = tmp.path().join("data");
    let path = tmp.path().join("wokd.toml");
    let (alice, bob) = (Keys::generate(), Keys::generate());
    let port = free_port();
    let url = format!("ws://127.0.0.1:{port}{PATH}");
    let write = |text: String| {
        std::fs::write(&path, format!("listen = \"127.0.0.1:{port}\"\n{text}")).unwrap();
    };
    write(config_text(&data, &[&alice], &url, ""));
    let mut daemon = Daemon::start(&path);

    let client = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let secret = alice.secret_key().to_bech32().unwrap();
    client.block_on(async {
        let mut alice_socket = member_once_listening(&url, &alice).await;
        assert!(
            query(&mut alice_socket, json!({"kinds": [1]}))
                .await
                .unwrap()
                .is_empty()
        );

        // A secret key pasted by mistake: refused, members unchanged.
        write(
            config_text(&data, &[&bob], &url, "")
                .replace(&bob.public_key().to_bech32().unwrap(), &secret),
        );
        daemon.signal("-HUP");
        daemon.wait_for("reload refused");
        send(&mut alice_socket, json!(["COUNT", "c", {"kinds": [1]}])).await;
        let counted = receive(&mut alice_socket).await;
        assert_eq!(counted[0], "COUNT", "still a member: {counted}");

        // Alice out, Bob in, and one setting only a restart applies.
        write(config_text(
            &data,
            &[&bob],
            &url,
            "relay_information = false",
        ));
        daemon.signal("-HUP");
        let (frames, code) = until_closed(&mut alice_socket).await;
        assert_eq!(frames.len(), 1, "{frames:?}");
        assert_eq!(frames[0][0], "CLOSED");
        assert_eq!(code, Some(1008));
        let mut bob_socket = member(&url, &bob).await;
        let stored = note(&bob, "after SIGHUP");
        assert_eq!(publish(&mut bob_socket, &stored).await[2], true);
    });
    daemon.wait_for("membership changed");
    daemon.wait_for("relay_information");

    // SIGHUP did not stop it; SIGTERM does, cleanly.
    let log = daemon.stop();
    for key in [
        secret,
        alice.public_key().to_bech32().unwrap(),
        bob.public_key().to_bech32().unwrap(),
        alice.public_key().to_hex(),
        bob.public_key().to_hex(),
    ] {
        assert!(!log.contains(&key), "a key in the log:\n{log}");
    }
}

/// The binary itself: an AUTH naming another relay URL is refused as any bad
/// AUTH is, and the log says so at once, in a count, repeating nothing the
/// client sent.
#[cfg(unix)]
#[test]
fn an_auth_naming_another_url_is_logged_at_once_without_what_it_named() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("wokd.toml");
    let alice = Keys::generate();
    let port = free_port();
    let url = format!("ws://127.0.0.1:{port}{PATH}");
    std::fs::write(
        &path,
        format!(
            "listen = \"127.0.0.1:{port}\"\n{}",
            config_text(&tmp.path().join("data"), &[&alice], &url, "")
        ),
    )
    .unwrap();
    let mut daemon = Daemon::start(&path);
    let client = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    client.block_on(async {
        // Naming `url` raises nothing.
        let _member = member_once_listening(&url, &alice).await;
        let (mut stray, challenge) = connect(&url).await;
        let refused = auth(
            &mut stray,
            "wss://elsewhere.example/events",
            &challenge,
            &alice,
        )
        .await;
        assert_eq!(refused[2], false, "{refused}");
        assert_eq!(
            refused[3],
            "invalid: authentication challenge, relay, time or signature"
        );
    });
    daemon.wait_for("AUTH named a relay URL other than `url`");
    let log = daemon.stop();
    assert!(log.contains("attempts=1"), "{log}");
    for sent in [
        "elsewhere.example".to_owned(),
        alice.public_key().to_bech32().unwrap(),
        alice.public_key().to_hex(),
    ] {
        assert!(!log.contains(&sent), "{sent} in the log:\n{log}");
    }
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
    let (_reload, reloads) = mpsc::channel(1);
    // The server gets a runtime of its own, dropped as soon as `run`
    // returns, as in `main`.
    let server = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(wokd::run(config, reloads, async move {
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

#[tokio::test]
async fn the_relay_information_document_says_login_is_required_and_names_nobody() {
    let dir = TempDir::new().unwrap();
    let alice = Keys::generate();
    let running = start(dir.path(), &[&alice]).await;
    let (status, head, body) = http_get(&running.url, "application/nostr+json").await;
    assert_eq!(status, 200, "{head}");
    assert!(
        head.contains("content-type: application/nostr+json"),
        "{head}"
    );
    assert!(head.contains("access-control-allow-origin: *"), "{head}");
    let document: Value = serde_json::from_str(&body).unwrap();
    let mut keys = document.as_object().unwrap().keys().collect::<Vec<_>>();
    keys.sort();
    assert_eq!(keys, ["limitation", "supported_nips"]);
    assert_eq!(document["limitation"]["auth_required"], true);
    assert_eq!(document["limitation"]["restricted_writes"], true);
    assert!(!body.contains(&alice.public_key().to_hex()));
    assert!(!body.contains(&alice.public_key().to_bech32().unwrap()));
    assert!(!body.contains("127.0.0.1"));
    // Without the NIP-11 media type there is no document.
    let (status, head, body) = http_get(&running.url, "application/json").await;
    assert!(!(200..300).contains(&status), "{head}");
    assert!(!body.contains("supported_nips"));
    // And a socket still has to log in as a member.
    let mut socket = member(&running.url, &alice).await;
    let event = note(&alice, "after the document");
    assert_eq!(publish(&mut socket, &event).await[2], true);
    drop(socket);
    running.stop().await;
}

#[tokio::test]
async fn with_relay_information_off_the_relay_serves_no_document() {
    let dir = TempDir::new().unwrap();
    let alice = Keys::generate();
    let running = start_with(dir.path(), &[&alice], "relay_information = false\n").await;
    assert!(!running.config.relay_information);
    let (status, head, body) = http_get(&running.url, "application/nostr+json").await;
    assert!(!(200..300).contains(&status), "{head}");
    assert!(!head.contains("access-control-allow-origin"), "{head}");
    assert!(!body.contains("supported_nips"));
    running.stop().await;
}
