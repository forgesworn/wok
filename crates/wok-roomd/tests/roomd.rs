//! The built `wok-roomd` binary, started the way a supervisor starts it: its
//! command line, the control socket it binds, one connection through each
//! refusal and one through AUTH, and what it leaves behind when it stops.
#![cfg(unix)]

use futures_util::{SinkExt, StreamExt};
use nostr::{
    event::{Event, EventBuilder, FinalizeEvent, Kind, Tag},
    key::Keys,
    types::Timestamp,
};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running `wok-roomd`. Killed if a test fails before stopping it.
struct Daemon {
    child: Child,
}

impl Daemon {
    fn signal(&self, name: &str) {
        let sent = Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success(), "kill {name}");
    }

    fn wait(mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "wok-roomd did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Its exit code and everything it wrote to standard error.
    fn refusal(mut self) -> (Option<i32>, String) {
        use std::io::Read as _;
        let mut said = String::new();
        let mut stderr = self.child.stderr.take().unwrap();
        stderr.read_to_string(&mut said).unwrap();
        (self.wait().code(), said)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One node's private directory, made by its supervisor before anything
/// runs: the room stores and the control socket sit in it side by side.
struct Node {
    temp: TempDir,
    port: u16,
}

impl Node {
    fn new() -> Self {
        let node = Self {
            temp: TempDir::new().unwrap(),
            port: free_port(),
        };
        std::fs::create_dir(node.private()).unwrap();
        std::fs::set_permissions(node.private(), std::fs::Permissions::from_mode(0o700)).unwrap();
        node
    }

    fn private(&self) -> PathBuf {
        self.temp.path().join("private")
    }

    fn socket(&self) -> PathBuf {
        self.private().join("relay.sock")
    }

    fn url(&self) -> String {
        format!("ws://127.0.0.1:{}/events", self.port)
    }

    fn arguments(&self) -> Vec<String> {
        [
            "--data",
            self.private().join("rooms").to_str().unwrap(),
            "--control",
            self.socket().to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{}", self.port),
            "--url",
            &self.url(),
            "--max-bytes",
            "1048576",
            "--min-free-bytes",
            "0",
            "--max-rooms",
            "4",
            "--local-test",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn spawn(&self, arguments: &[String]) -> Daemon {
        let child = Command::new(env!("CARGO_BIN_EXE_wok-roomd"))
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Daemon { child }
    }

    /// Start it and wait until its control socket answers.
    async fn start(&self) -> Daemon {
        let daemon = self.spawn(&self.arguments());
        let deadline = Instant::now() + Duration::from_secs(10);
        while command(&self.socket(), json!({"v":1,"op":"status"}))
            .await
            .is_none()
        {
            assert!(Instant::now() < deadline, "wok-roomd did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        daemon
    }
}

/// One request on the control socket, written and half-closed as the
/// supervisor does, and its reply. `None` if nothing is listening.
async fn command(socket: &Path, value: Value) -> Option<Value> {
    let mut stream = UnixStream::connect(socket).await.ok()?;
    stream.write_all(value.to_string().as_bytes()).await.ok()?;
    stream.shutdown().await.ok()?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn signed(keys: &Keys, kind: u16, tags: Vec<Vec<String>>) -> Event {
    EventBuilder::new(Kind::from(kind), "")
        .custom_created_at(Timestamp::from_secs(now()))
        .tags(tags.into_iter().map(|tag| Tag::parse(tag).unwrap()))
        .finalize(keys)
        .unwrap()
}

/// Connect, answer the challenge for `room` by the room door, and return the
/// relay's `OK` frame.
async fn login(node: &Node, room: &str, keys: &Keys) -> Value {
    let (mut client, _) = connect_async(node.url()).await.unwrap();
    let mut frame = async || -> Value {
        let message = tokio::time::timeout(Duration::from_secs(5), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    };
    let challenge = frame().await;
    assert_eq!(challenge[0], "AUTH");
    let event = signed(
        keys,
        22242,
        vec![
            vec!["challenge".into(), challenge[1].as_str().unwrap().into()],
            vec!["relay".into(), node.url()],
            vec!["room".into(), room.into()],
            vec!["mode".into(), "room".into()],
        ],
    );
    client
        .send(Message::Text(json!(["AUTH", event]).to_string().into()))
        .await
        .unwrap();
    client.next().await.map_or(Value::Null, |message| {
        serde_json::from_str(message.unwrap().to_text().unwrap()).unwrap()
    })
}

fn snapshot(room: &str, inviter: &Keys, device: &Keys) -> Value {
    json!({
        "v": 1,
        "op": "sync",
        "rooms": [{"room": room, "inviter": inviter.public_key().to_hex(), "ends": null}],
        "grants": [{
            "room": room,
            "device": device.public_key().to_hex(),
            "expires": now() + 3600,
            "read": true,
            "write": true,
        }],
    })
}

#[tokio::test]
async fn a_started_relay_serves_only_what_its_control_socket_was_told() {
    let node = Node::new();
    let daemon = node.start().await;
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&node.socket()), 0o600);
    assert_eq!(mode(&node.private().join("rooms")), 0o700);

    // Nothing has been synchronised: no lease, so nobody gets in.
    let status = command(&node.socket(), json!({"v":1,"op":"status"}))
        .await
        .unwrap();
    assert_eq!(
        status,
        json!({"v":1,"ok":true,"result":{"rooms":0,"devices":0,"usedBytes":0,"leaseActive":false}})
    );
    let room = "0a".repeat(32);
    let (inviter, device) = (Keys::generate(), Keys::generate());
    let refused = login(&node, &room, &device).await;
    assert_eq!(
        (&refused[2], &refused[3]),
        (&json!(false), &json!("node reconnecting"))
    );

    let synchronised = command(&node.socket(), snapshot(&room, &inviter, &device))
        .await
        .unwrap();
    assert_eq!(
        synchronised,
        json!({"v":1,"ok":true,"result":{"leaseSeconds":15}})
    );
    assert_eq!(login(&node, &room, &device).await[2], true);
    let stranger = login(&node, &room, &Keys::generate()).await;
    assert_eq!(
        (&stranger[2], &stranger[3]),
        (&json!(false), &json!("access removed"))
    );

    // A request of another version, or one it does not know, changes nothing.
    for unknown in [
        json!({"v":2,"op":"status"}),
        json!({"v":1,"op":"open"}),
        json!({"v":1,"op":"status","verbose":true}),
    ] {
        assert_eq!(
            command(&node.socket(), unknown).await.unwrap(),
            json!({"v":1,"ok":false,"error":"invalid request"})
        );
    }

    daemon.signal("-TERM");
    assert!(daemon.wait().success(), "SIGTERM is a clean stop");
    assert!(!node.socket().exists(), "it removed its socket");
}

#[tokio::test]
async fn a_second_process_is_refused_and_a_killed_ones_socket_is_replaced() {
    let node = Node::new();
    let first = node.start().await;
    let second = node.spawn(&node.arguments()).wait();
    assert_eq!(second.code(), Some(1), "the data directory is locked");
    assert!(
        command(&node.socket(), json!({"v":1,"op":"status"}))
            .await
            .is_some(),
        "the first is undisturbed"
    );

    let room = "0b".repeat(32);
    let (inviter, device) = (Keys::generate(), Keys::generate());
    command(&node.socket(), snapshot(&room, &inviter, &device))
        .await
        .unwrap();
    assert_eq!(login(&node, &room, &device).await[2], true);

    // Killed outright, it leaves its socket file behind. The next start
    // finds that nothing answers there and takes the path over.
    first.signal("-KILL");
    first.wait();
    assert!(node.socket().exists());
    let restarted = node.start().await;

    // The allowlist was never on disk: until the supervisor sends it again,
    // a device that was admitted a moment ago is refused.
    let refused = login(&node, &room, &device).await;
    assert_eq!(
        (&refused[2], &refused[3]),
        (&json!(false), &json!("node reconnecting"))
    );
    command(&node.socket(), snapshot(&room, &inviter, &device))
        .await
        .unwrap();
    assert_eq!(login(&node, &room, &device).await[2], true);
    restarted.signal("-TERM");
    assert!(restarted.wait().success());
}

#[test]
fn the_command_line_refuses_what_it_cannot_run_safely() {
    let node = Node::new();
    let run = |arguments: Vec<String>| node.spawn(&arguments).refusal();
    let with = |flag: &str, value: &str| {
        let mut arguments = node.arguments();
        let at = arguments.iter().position(|a| a == flag).unwrap();
        arguments[at + 1] = value.into();
        arguments
    };

    let (code, said) = run(vec![]);
    assert_eq!(code, Some(2));
    assert!(said.contains("--data is required") && said.contains("usage:"));
    let (code, said) = run(vec!["room-relay".into()]);
    assert_eq!(code, Some(2));
    assert!(said.contains("unexpected argument room-relay"));

    // A listener beyond loopback, a plain `ws://` URL without the test
    // switch, and a path other than `/events`.
    let address = "room relay needs a loopback listener and an explicit /events WebSocket URL";
    let mut plain = node.arguments();
    plain.retain(|a| a != "--local-test");
    for arguments in [
        with("--listen", "0.0.0.0:3745"),
        plain,
        with("--url", "wss://node.example/"),
        with("--url", "wss://user@node.example/events"),
    ] {
        let (code, said) = run(arguments);
        assert_eq!(code, Some(1));
        assert!(said.contains(address), "{said}");
    }

    // A control socket whose parent others can enter.
    let open = node.temp.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (code, said) = run(with("--control", open.join("relay.sock").to_str().unwrap()));
    assert_eq!(code, Some(1));
    assert!(said.contains("control socket parent must be a private directory"));

    // A control path that is an ordinary file is not removed to make way.
    std::fs::write(node.socket(), "not a socket").unwrap();
    let (code, said) = run(node.arguments());
    assert_eq!(code, Some(1));
    assert!(said.contains("control path is not a socket"));
    assert_eq!(std::fs::read(node.socket()).unwrap(), b"not a socket");
}
