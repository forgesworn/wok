use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use nostr::key::Keys;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tempfile::{Builder, TempDir};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::{Connector, connect_async_tls_with_config};
use wok_ws::PATH;

use super::{Socket, auth, config_text, free_port, note, publish, query, receive};

struct Stack {
    dir: TempDir,
    project: String,
    image: String,
    port: u16,
}

impl Stack {
    fn new(image: String) -> Self {
        let dir = Builder::new().prefix("wok-tls-").tempdir().unwrap();
        let project = dir
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        Self {
            dir,
            project,
            image,
            port: free_port(),
        }
    }

    fn prepare(&self, keeper: &Keys, url: &str) -> Connector {
        let dir = self.dir.path();
        std::fs::write(
            dir.join("compose.yaml"),
            include_str!("../../../../deploy/compose.yaml"),
        )
        .unwrap();
        std::fs::write(
            dir.join("nginx.conf"),
            include_str!("../../../../deploy/nginx.conf"),
        )
        .unwrap();
        let config = config_text(
            Path::new("/data"),
            &[keeper],
            url,
            "listen = \"0.0.0.0:7447\"\nsockets_per_address = 32\n",
        );
        std::fs::write(dir.join("wokd.toml"), config).unwrap();
        let ca = certificates(dir);
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let client =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        Connector::Rustls(Arc::new(client))
    }

    fn compose(&self, args: &[&str]) -> std::io::Result<Output> {
        Command::new("docker")
            .current_dir(self.dir.path())
            .env("WOK_IMAGE", &self.image)
            .env("WOK_HTTPS_BIND", "127.0.0.1")
            .env("WOK_HTTPS_PORT", self.port.to_string())
            .args([
                "compose",
                "--file",
                "compose.yaml",
                "--project-name",
                &self.project,
            ])
            .args(args)
            .output()
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Ok(logs) = self.compose(&["logs", "--no-color"])
        {
            eprintln!(
                "{}{}",
                String::from_utf8_lossy(&logs.stdout),
                String::from_utf8_lossy(&logs.stderr)
            );
        }
        match self.compose(&["down", "--volumes"]) {
            Ok(output) if output.status.success() => (),
            other => eprintln!("could not clean up the Compose test: {other:?}"),
        }
    }
}

fn checked(output: Output, step: &str) -> Output {
    assert!(
        output.status.success(),
        "{step}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn certificates(dir: &Path) -> CertificateDer<'static> {
    std::fs::create_dir(dir.join("tls")).unwrap();
    std::fs::write(dir.join("leaf.ext"), "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n").unwrap();
    for args in [
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Wok smoke test CA",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]
        .as_slice(),
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
            "tls/privkey.pem",
            "-out",
            "leaf.csr",
        ],
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            "1",
            "-days",
            "1",
            "-extfile",
            "leaf.ext",
            "-out",
            "tls/fullchain.pem",
        ],
    ] {
        let output = Command::new("openssl")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        checked(output, "generate a test certificate");
    }
    CertificateDer::from_pem_file(dir.join("ca.pem")).unwrap()
}

async fn open(url: &str, connector: &Connector) -> Result<Socket, Error> {
    connect_async_tls_with_config(url, None, false, Some(connector.clone()))
        .await
        .map(|(socket, _)| socket)
}

async fn authenticate(socket: &mut Socket, url: &str, keys: &Keys) -> Value {
    let challenge = receive(socket).await;
    assert_eq!(challenge[0], "AUTH", "{challenge}");
    auth(socket, url, challenge[1].as_str().unwrap(), keys).await
}

#[tokio::test]
#[ignore = "requires OpenSSL, Docker Compose and a locally available WOK_TEST_IMAGE"]
async fn packaged_relay_behind_tls() {
    let image = std::env::var("WOK_TEST_IMAGE").expect("set WOK_TEST_IMAGE to an available image");
    let stack = Stack::new(image);
    let url = format!("wss://127.0.0.1:{}{PATH}", stack.port);
    let keeper = Keys::generate();
    let connector = stack.prepare(&keeper, &url);
    checked(
        stack.compose(&["config", "--quiet"]).unwrap(),
        "validate Compose",
    );
    checked(stack.compose(&["up", "--detach"]).unwrap(), "start Compose");

    let mut socket = timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(socket) = open(&url, &connector).await {
                break socket;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the TLS relay becomes ready with a trusted certificate");
    assert_eq!(authenticate(&mut socket, &url, &keeper).await[2], true);
    let event = note(&keeper, "through the deployed TLS proxy");
    assert_eq!(publish(&mut socket, &event).await[2], true);
    let filter = json!({"ids": [event.id]});
    assert_eq!(
        query(&mut socket, filter.clone()).await.unwrap(),
        [serde_json::to_value(&event).unwrap()]
    );
    let relay = checked(
        stack.compose(&["ps", "--quiet", "wokd"]).unwrap(),
        "identify the relay",
    );
    let relay = str::from_utf8(&relay.stdout).unwrap().trim();
    assert!(!relay.is_empty(), "wokd is running");
    let inspect = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{json .HostConfig.PortBindings}}",
            relay,
        ])
        .output()
        .unwrap();
    let bindings: Value =
        serde_json::from_slice(&checked(inspect, "inspect relay port bindings").stdout).unwrap();
    assert!(
        bindings.is_null()
            || bindings
                .as_object()
                .is_some_and(|bindings| bindings.is_empty()),
        "the relay publishes no ports: {bindings}"
    );

    let mut outsider = open(&url, &connector).await.unwrap();
    assert_eq!(
        authenticate(&mut outsider, &url, &Keys::generate()).await[2],
        false
    );
    assert_eq!(query(&mut outsider, filter).await.unwrap_err()[0], "CLOSED");

    // Keeper and refused socket plus two more hold all four proxy slots.
    let _third = open(&url, &connector).await.unwrap();
    let _fourth = open(&url, &connector).await.unwrap();
    let blocked = open(&url, &connector).await.unwrap_err();
    assert!(
        matches!(&blocked, Error::Http(reply) if reply.status().as_u16() == 429),
        "{blocked}"
    );
}
