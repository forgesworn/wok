use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use nostr::key::Keys;
use serde_json::json;
use tempfile::{Builder, TempDir};
use tokio::time::{sleep, timeout};
use wok_ws::PATH;

use super::{Socket, auth, config_text, publish, query, receive, room_grant, room_note};

// Docker assigns the host port on each run. The client dials that port but
// names the fixed canonical URL in AUTH and in signed room grants.
const CANONICAL_URL: &str = "ws://wok-smoke.test/events";

struct Deployment {
    dir: TempDir,
    volume: String,
    containers: Vec<String>,
}

impl Deployment {
    fn new(keeper: &Keys) -> Self {
        let dir = Builder::new().prefix("wok-smoke-").tempdir().unwrap();
        let volume = dir.path().file_name().unwrap().to_str().unwrap().to_owned();
        let text = config_text(
            Path::new("/data"),
            &[keeper],
            CANONICAL_URL,
            "listen = \"0.0.0.0:7447\"\n",
        );
        std::fs::write(dir.path().join("wokd.toml"), text).unwrap();
        docker(&["volume", "create", &volume]);
        Self {
            dir,
            volume,
            containers: Vec::new(),
        }
    }

    fn start(&mut self, image: &str) -> String {
        let name = format!("{}-{}", self.volume, self.containers.len());
        self.containers.push(name.clone());
        let config = format!(
            "type=bind,source={},target=/etc/wokd/wokd.toml,readonly",
            self.dir.path().join("wokd.toml").display()
        );
        let volume = format!("type=volume,source={},target=/data", self.volume);
        docker(&[
            "run",
            "--detach",
            "--name",
            &name,
            "--publish",
            "127.0.0.1::7447",
            "--mount",
            &config,
            "--mount",
            &volume,
            image,
        ]);
        let address = docker(&["port", &name, "7447/tcp"]);
        assert!(address.starts_with("127.0.0.1:"), "{address}");
        format!("ws://{address}{PATH}")
    }

    fn stop(&self) {
        let name = self.containers.last().unwrap();
        docker(&["stop", "--timeout", "10", name]);
        assert_eq!(
            docker(&["inspect", "--format", "{{.State.ExitCode}}", name]),
            "0"
        );
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        for name in &self.containers {
            if std::thread::panicking() {
                let logs = command(&["logs", name]);
                eprintln!(
                    "{name}:\n{}{}",
                    String::from_utf8_lossy(&logs.stdout),
                    String::from_utf8_lossy(&logs.stderr)
                );
            }
            cleanup(&["rm", "--force", name]);
        }
        cleanup(&["volume", "rm", &self.volume]);
    }
}

fn command(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("run Docker")
}

fn docker(args: &[&str]) -> String {
    let output = command(args);
    assert!(
        output.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn cleanup(args: &[&str]) {
    let output = command(args);
    if !output.status.success() {
        eprintln!(
            "docker {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

async fn connect(url: &str) -> (Socket, String) {
    let mut socket = timeout(Duration::from_secs(20), async {
        loop {
            if let Ok((socket, _)) = tokio_tungstenite::connect_async(url).await {
                break socket;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the packaged relay becomes ready");
    let frame = receive(&mut socket).await;
    assert_eq!(frame[0], "AUTH", "{frame}");
    (socket, frame[1].as_str().unwrap().to_owned())
}

async fn member(url: &str, keys: &Keys) -> Socket {
    let (mut socket, challenge) = connect(url).await;
    let reply = auth(&mut socket, CANONICAL_URL, &challenge, keys).await;
    assert_eq!(reply[0], "OK", "{reply}");
    assert_eq!(reply[2], true, "{reply}");
    socket
}

#[tokio::test]
#[ignore = "requires Docker and a locally built WOK_TEST_IMAGE"]
async fn packaged_relay_preserves_member_events() {
    let image = std::env::var("WOK_TEST_IMAGE").expect("set WOK_TEST_IMAGE to the local image tag");
    assert_eq!(
        docker(&["image", "inspect", "--format", "{{.Config.User}}", &image]),
        "wok"
    );
    let keeper = Keys::generate();
    let guest = Keys::generate();
    let device = Keys::generate();
    let room = "11".repeat(32);
    let event = room_note(&keeper, &room, "packaged relay persistence");
    let now = event.created_at.as_secs();
    let active = room_grant(
        &keeper,
        CANONICAL_URL,
        &room,
        &guest,
        &device,
        now,
        "active",
        now + 3600,
    );
    let revoked = room_grant(
        &keeper,
        CANONICAL_URL,
        &room,
        &guest,
        &device,
        now + 1,
        "revoked",
        now + 3600,
    );
    let filter = json!({"ids": [event.id], "kinds": [1460], "#d": [room]});
    let stored = serde_json::to_value(&event).unwrap();

    let mut deploy = Deployment::new(&keeper);
    let url = deploy.start(&image);
    let mut socket = member(&url, &keeper).await;
    let reply = publish(&mut socket, &event).await;
    assert_eq!(reply[0], "OK", "{reply}");
    assert_eq!(reply[1], event.id.to_hex(), "{reply}");
    assert_eq!(reply[2], true, "{reply}");
    assert_eq!(
        query(&mut socket, filter.clone()).await.unwrap(),
        std::slice::from_ref(&stored)
    );
    assert_eq!(publish(&mut socket, &active).await[2], true);
    let mut guest_socket = member(&url, &guest).await;
    assert_eq!(
        query(&mut guest_socket, filter.clone()).await.unwrap(),
        std::slice::from_ref(&stored)
    );
    drop(guest_socket);
    assert_eq!(publish(&mut socket, &revoked).await[2], true);
    drop(socket);
    deploy.stop();

    let url = deploy.start(&image);
    let mut socket = member(&url, &keeper).await;
    // The new container has the same data volume and no writes from this client.
    assert_eq!(query(&mut socket, filter.clone()).await.unwrap(), [stored]);
    let reply = publish(&mut socket, &active).await;
    assert_eq!(
        reply[2], false,
        "the older grant cannot be replayed: {reply}"
    );
    let (mut guest_socket, challenge) = connect(&url).await;
    let reply = auth(&mut guest_socket, CANONICAL_URL, &challenge, &guest).await;
    assert_eq!(
        reply[2], false,
        "the revoked guest cannot authenticate: {reply}"
    );
    let denied = query(&mut guest_socket, filter).await.unwrap_err();
    assert_eq!(denied[0], "CLOSED", "{denied}");
    drop(guest_socket);
    drop(socket);
    deploy.stop();
}
