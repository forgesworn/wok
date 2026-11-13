//! `wokd --config <file>`: run a members-only Nostr relay. On SIGHUP it reads
//! the file again and applies its members.
//! `wokd remove --config <file> ...`: an operator's removal, with the relay
//! stopped. See the crate documentation for both.

use std::process::ExitCode;

use nostr::event::EventId;
use nostr::key::PublicKey;
use nostr::nips::nip19::FromBech32;
use wokd::{Config, Target};

const USAGE: &str = "usage:
  wokd --config <file>
  wokd remove --config <file> --id <event id> [--id <event id> ...]
  wokd remove --config <file> --author <npub>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("remove") => remove(&args[1..]),
        _ => serve(&args),
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn read_config(path: &str) -> Result<Config, ExitCode> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        eprintln!("wokd: could not read {path}: {error}");
        ExitCode::from(2)
    })?;
    Config::from_toml(&text).map_err(|error| {
        eprintln!("wokd: {path}: {error}");
        ExitCode::from(2)
    })
}

fn serve(args: &[String]) -> ExitCode {
    let [flag, path] = args else {
        return usage();
    };
    if flag != "--config" {
        return usage();
    }
    let config = match read_config(path) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let arenas_limited = limit_malloc_arenas();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();
    if !arenas_limited {
        tracing::warn!("could not limit the allocator's arenas; memory use may be higher");
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("wokd: could not start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let served = runtime.block_on(async {
        let (reload, reloads) = tokio::sync::mpsc::channel(1);
        // Before the listener binds, so a relay that accepts connections
        // also takes SIGHUP as a reload rather than dying of it.
        #[cfg(unix)]
        reload_on_hangup(path.clone(), reload);
        #[cfg(not(unix))]
        drop(reload);
        wokd::run(config, reloads, shutdown_signal()).await
    });
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// glibc's malloc arenas, at most. Otherwise glibc gives a thread that meets
/// contention an arena of its own, up to eight per core, and each arena holds
/// on to memory freed into it.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const MALLOC_ARENAS: libc::c_int = 2;

/// Cap glibc's malloc arenas at [`MALLOC_ARENAS`], before the runtime starts
/// any thread. An operator's own `MALLOC_ARENA_MAX` is left as it is. False
/// only when glibc refused the setting.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn limit_malloc_arenas() -> bool {
    if std::env::var_os("MALLOC_ARENA_MAX").is_some() {
        return true;
    }
    // SAFETY: `mallopt` only sets an allocator parameter, and glibc takes its
    // own locks to do so.
    unsafe { libc::mallopt(libc::M_ARENA_MAX, MALLOC_ARENAS) == 1 }
}

/// Elsewhere there is no glibc arena setting to make.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn limit_malloc_arenas() -> bool {
    true
}

/// On each SIGHUP, read `path` again and hand the relay what it says. A file
/// that cannot be read, or is not a valid configuration, changes nothing.
#[cfg(unix)]
fn reload_on_hangup(path: String, reload: tokio::sync::mpsc::Sender<Config>) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hangups = match signal(SignalKind::hangup()) {
        Ok(hangups) => hangups,
        Err(error) => {
            tracing::warn!("no reload on SIGHUP ({error}): membership changes take a restart");
            return;
        }
    };
    tokio::spawn(async move {
        while hangups.recv().await.is_some() {
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(error) => {
                    tracing::error!(
                        "reload refused, nothing changed: could not read {path}: {error}"
                    );
                    continue;
                }
            };
            match Config::from_toml(&text) {
                Ok(next) => {
                    if reload.send(next).await.is_err() {
                        return;
                    }
                }
                // No message repeats a value from the file.
                Err(error) => tracing::error!("reload refused, nothing changed: {path}: {error}"),
            }
        }
    });
}

/// `remove`: exit 0 when everything asked for was removed, 3 when some ids
/// were not stored, 2 for a usage or configuration mistake, 1 otherwise.
fn remove(args: &[String]) -> ExitCode {
    let mut path = None;
    let mut ids = Vec::new();
    let mut author = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => path = args.next().cloned(),
            "--id" => match args
                .next()
                .filter(|value| value.len() == 64)
                .and_then(|value| EventId::from_hex(value).ok())
            {
                Some(id) => ids.push(id),
                None => {
                    eprintln!("wokd remove: --id takes an event id, 64 hex characters");
                    return ExitCode::from(2);
                }
            },
            "--author" => match args.next() {
                Some(value) if value.starts_with("nsec1") => {
                    eprintln!(
                        "wokd remove: --author takes a public key (npub), not a secret key; \
                         treat that secret key as exposed"
                    );
                    return ExitCode::from(2);
                }
                Some(value) => match PublicKey::from_bech32(value) {
                    Ok(key) => author = Some(key),
                    Err(_) => {
                        eprintln!("wokd remove: --author takes an npub public key");
                        return ExitCode::from(2);
                    }
                },
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    let target = match (ids.is_empty(), author) {
        (false, None) => Target::Ids(ids),
        (true, Some(author)) => Target::Author(author),
        _ => return usage(),
    };
    let Some(path) = path else {
        return usage();
    };
    let config = match read_config(&path) {
        Ok(config) => config,
        Err(code) => return code,
    };
    match wokd::remove(&config, &target) {
        Ok(done) => {
            println!("removed {} event(s)", done.removed.len());
            for id in &done.removed {
                println!("  {}", id.to_hex());
            }
            if !done.removed.is_empty() && !done.erased {
                println!(
                    "the write-ahead log could not be truncated: the removed bytes leave it \
                     when the relay next truncates it"
                );
            }
            if done.not_found.is_empty() {
                ExitCode::SUCCESS
            } else {
                println!("not stored, so nothing removed or barred:");
                for id in &done.not_found {
                    println!("  {}", id.to_hex());
                }
                ExitCode::from(3)
            }
        }
        Err(error) => {
            eprintln!("wokd remove: {error}");
            ExitCode::FAILURE
        }
    }
}

/// SIGINT, or SIGTERM where there is one.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = interrupt => {},
        _ = terminate => {},
    }
}
