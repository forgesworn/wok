//! `wok-roomd --data <dir> --control <socket> --url <wss://host/events> ...`:
//! run a keeper-controlled room relay. See the crate's README.
use std::process::ExitCode;

#[cfg(unix)]
fn main() -> ExitCode {
    wok_roomd::host::main()
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("wok-roomd needs a Unix-like system: its control channel is a Unix socket");
    ExitCode::from(2)
}
