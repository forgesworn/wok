//! The server half of a socket cell: a `wok_ws::Door` over an `EventRelay` on
//! a fresh store, served by `axum::serve` on `127.0.0.1:0` on its own runtime.

use std::sync::Arc;
use std::time::Duration;

use axum::http::{Extensions, StatusCode};
use axum::serve::ListenerExt;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;
use url::Url;
use wok_store::relay::{EventRelay, GuestAuthority};
use wok_store::{EventStore, SqliteEventStore, Visibility};
use wok_ws::{Admission, Admitted, Door};

use crate::config::{Config, Variant};
use crate::engine::{Clock, Keepers, relay_with_guests};
use crate::support::fresh_store;

/// How long the server task has to end once the door is shut down.
const STOP_WAIT: Duration = Duration::from_secs(30);
/// How long the runtime has to finish its blocking work when it is dropped.
const RUNTIME_WAIT: Duration = Duration::from_secs(10);

/// Admits every connection to the sheltered door.
///
/// This exists only for the loopback benchmark, where the only peer is the
/// benchmark's own client on 127.0.0.1. NIP-42 is still required on every
/// connection it admits, so a client must still authenticate as a keeper
/// before it can write. It must never be used by an application: it decides
/// nothing about who may connect.
struct AdmitAll;

impl Admission for AdmitAll {
    fn admit(&self, _extensions: &Extensions) -> Result<Admitted, StatusCode> {
        Ok(Admitted::holding(()))
    }
}

/// A running door. Dropping it stops the runtime first, then releases the
/// relay and the store, and last the directory their files live in.
pub(crate) struct Server {
    /// `ws://127.0.0.1:<port>/events`, the URL every AUTH names.
    pub(crate) url: String,
    pub(crate) relay: Arc<EventRelay>,
    pub(crate) store: Arc<SqliteEventStore>,
    door: Door,
    task: Option<JoinHandle<std::io::Result<()>>>,
    runtime: Option<Runtime>,
    /// Last, so that nothing is still open in the directory when it goes.
    _dir: TempDir,
}

impl Server {
    /// A fresh store, relay and door for one cell. The relay keeps its own
    /// clock (the wall clock), as a door's relay runs. The connection limits
    /// are raised to `connections` on both doors and the work limits are the
    /// variant's; nothing else is changed from the production door.
    pub(crate) fn start(
        cfg: &Config,
        keepers: &Arc<Keepers>,
        visibility: Visibility,
        variant: &Variant,
        store_events: usize,
        connections: usize,
    ) -> Result<Self, String> {
        let store = fresh_store(cfg, store_events)?;
        Self::start_on(keepers, visibility, variant, store, connections, None)
    }

    /// [`Self::start`] on a store the caller opened, `(dir, store)` with the
    /// store's files in `dir`, and with `guests` installed as the relay's
    /// guest authority when given.
    pub(crate) fn start_on(
        keepers: &Arc<Keepers>,
        visibility: Visibility,
        variant: &Variant,
        (dir, store): (TempDir, Arc<SqliteEventStore>),
        connections: usize,
        guests: Option<Arc<dyn GuestAuthority>>,
    ) -> Result<Self, String> {
        let relay = relay_with_guests(
            Arc::clone(&store) as Arc<dyn EventStore>,
            keepers,
            None,
            Clock::Wall,
            guests,
        );
        let connections = connections.max(1);
        let door = Door::new(Arc::clone(&relay))
            .with_connection_limits(connections, connections)
            .with_work_limits(variant.shared, variant.public);
        let runtime = Builder::new_multi_thread()
            .worker_threads(variant.workers)
            .max_blocking_threads(variant.blocking)
            .enable_io()
            .enable_time()
            .build()
            .map_err(|e| format!("start the server runtime: {e}"))?;
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
        let canonical = Url::parse(&url).map_err(|e| format!("the door's URL {url}: {e}"))?;
        let router = match visibility {
            Visibility::Public => door.public_router(canonical),
            Visibility::Sheltered => door.sheltered_router(canonical, Arc::new(AdmitAll)),
        };
        // Whatever the variant says, so that both settings give one listener type.
        let nodelay = variant.nodelay;
        let listener = listener.tap_io(move |stream| {
            let _ = stream.set_nodelay(nodelay);
        });
        let mut stopped = door.stopped();
        let task = runtime.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.wait_for(|stopped| *stopped).await.is_ok();
                })
                .await
        });
        Ok(Self {
            url,
            relay,
            store,
            door,
            task: Some(task),
            runtime: Some(runtime),
            _dir: dir,
        })
    }

    /// Shut the door down and require the server task to end.
    pub(crate) fn stop(&mut self) -> Result<(), String> {
        self.door.shutdown();
        let task = self.task.take().ok_or("the server was already stopped")?;
        let runtime = self.runtime.as_ref().ok_or("the server has no runtime")?;
        match runtime.block_on(async { tokio::time::timeout(STOP_WAIT, task).await }) {
            Err(_) => Err(format!(
                "the server task did not end within {STOP_WAIT:?} of the door's shutdown"
            )),
            Ok(Err(e)) => Err(format!("the server task panicked: {e}")),
            Ok(Ok(Err(e))) => Err(format!("the server task ended with an error: {e}")),
            Ok(Ok(Ok(()))) => Ok(()),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(RUNTIME_WAIT);
        }
    }
}
