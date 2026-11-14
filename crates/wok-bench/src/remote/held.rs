//! Held-socket writes on an open-loop schedule: `write --rate`.
//!
//! Each writer socket opens and authenticates once. Event `i` is due at
//! `t0 + i / rate` (every event at `t0` for a burst) and goes out on socket
//! `i mod connections`. `intended_to_ok` runs from the due time to the OK, so
//! a stall shows in every write queued behind it; `send_to_ok` runs from the
//! flush that carried the frame.
//!
//! Every socket stays inside wokd's production frame limit: AUTH, at most 115
//! requests and a Pong for each 30-second Ping, which is at most 120 frames
//! however the minute windows fall, as long as the run ends within 150 s of
//! the AUTH. Close is not counted. The schedule spans at most 55 s and the
//! drain at most 60 s more. Writers and readers together take at most 32
//! sockets.
//!
//! Readers, when asked for, send one REQ at a time on their own open-loop
//! schedule, each waiting for its EOSE, with one subscription id the relay
//! replaces each time.

use std::collections::HashMap;

use tokio::sync::watch;
use tokio::time::timeout_at;
use tokio_tungstenite::tungstenite::Error as WsError;

use super::wal_index::{Sampler, nanos, report};
use super::*;

/// Requests one socket may send: with its AUTH and at most four Pongs, this
/// is wokd's production allowance of 120 frames.
const REQUESTS_PER_SOCKET: usize = 115;
const MAX_SOCKETS: usize = 32;
const MAX_SPAN: Duration = Duration::from_secs(55);
const DRAIN_WAIT: Duration = Duration::from_secs(60);
/// From fixing the schedule's start to its first due time, so that every
/// lane is waiting when it comes.
const LEAD: Duration = Duration::from_millis(250);
const READ_FILTERS: usize = 128;
const READ_SETS: &str = "since_until,authors_kinds";
const CLOSE_WAIT: Duration = Duration::from_secs(60);
const SUBSCRIPTION: &str = "read";
const METHOD: &str = "held sockets, one AUTH each; event i is due at t0 + i/rate (every event at t0 for a burst) on socket i mod connections; intended_to_ok runs from the due time to the OK, send_to_ok from the flush that carried the frame, send_lag from the due time to that flush; drain_ms runs from the last due time to the last OK";

#[derive(Debug, Clone, Copy, PartialEq)]
enum Schedule {
    Rate(f64),
    Burst,
}

impl Schedule {
    fn parse(value: &str) -> Result<Self, String> {
        if value == "burst" {
            return Ok(Self::Burst);
        }
        positive("rate", value).map(Self::Rate).map_err(|_| {
            format!("--rate `{value}` must be a positive number of writes a second, or `burst`")
        })
    }

    /// When event `i` is due, from the schedule's start.
    fn offset(self, i: usize) -> Duration {
        match self {
            Self::Burst => Duration::ZERO,
            Self::Rate(rate) => {
                Duration::try_from_secs_f64(i as f64 / rate).unwrap_or(Duration::MAX)
            }
        }
    }

    /// From the first due time to the last.
    fn span(self, events: usize) -> Duration {
        self.offset(events.saturating_sub(1))
    }

    fn name(self) -> &'static str {
        match self {
            Self::Rate(_) => "rate",
            Self::Burst => "burst",
        }
    }

    fn rate(self) -> Option<f64> {
        match self {
            Self::Rate(rate) => Some(rate),
            Self::Burst => None,
        }
    }
}

fn positive(name: &str, value: &str) -> Result<f64, String> {
    value
        .replace('_', "")
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v > 0.0)
        .ok_or_else(|| format!("--{name} `{value}` must be a positive rate a second"))
}

/// A relay frame cut to 200 characters for an error message.
fn shown(text: &str) -> String {
    text.chars().take(200).collect()
}

struct Reading {
    sets: Vec<&'static str>,
    filters: Arc<Vec<Value>>,
    rate: f64,
}

#[derive(Default)]
struct Written {
    intended_to_ok: Vec<u64>,
    sent_to_ok: Vec<u64>,
    send_lag: Vec<u64>,
    pings: usize,
    last_ok: Option<Instant>,
    trace: Vec<Value>,
}

#[derive(Default)]
struct Reads {
    requests: usize,
    events: usize,
    live_events: usize,
    live_closed: usize,
    intended_to_eose: Vec<u64>,
    sent_to_eose: Vec<u64>,
    stopped: &'static str,
}

/// Refuses a run that would leave wokd's production limits or run too long.
fn check_plan(
    schedule: Schedule,
    events: usize,
    writers: usize,
    readers: usize,
    read_rate: Option<f64>,
    has_input: bool,
    has_read_set: bool,
) -> Result<(), String> {
    if writers == 0 || writers.saturating_add(readers) > MAX_SOCKETS {
        return Err(format!(
            "a held run needs at least one writer and at most {MAX_SOCKETS} sockets in all"
        ));
    }
    if events < writers {
        return Err("--events must be at least --connections".into());
    }
    if events.div_ceil(writers) > REQUESTS_PER_SOCKET {
        return Err(format!(
            "{events} events on {writers} sockets is more than {REQUESTS_PER_SOCKET} a socket, the most wokd's production frame limit allows; use at most {} events or more sockets",
            writers * REQUESTS_PER_SOCKET
        ));
    }
    let span = schedule.span(events);
    if span > MAX_SPAN {
        return Err(format!(
            "{events} events on this schedule span {:.1} s, more than the {} s a run may take",
            span.as_secs_f64(),
            MAX_SPAN.as_secs()
        ));
    }
    if readers == 0 {
        if read_rate.is_some() || has_input || has_read_set {
            return Err("--read-rate, --input and --read-set need --readers".into());
        }
        return Ok(());
    }
    let Some(read_rate) = read_rate else {
        return Err("--readers needs --read-rate, the REQs a second across all readers".into());
    };
    if !has_input {
        return Err("--readers needs --input, the corpus the relay was seeded with".into());
    }
    if matches!(schedule, Schedule::Rate(_)) {
        let planned = ((span.as_secs_f64() * read_rate).floor() as usize).saturating_add(1);
        if planned.div_ceil(readers) > REQUESTS_PER_SOCKET {
            return Err(format!(
                "{planned} reads on {readers} readers is more than {REQUESTS_PER_SOCKET} a socket, the most wokd's production frame limit allows; lower --read-rate or add readers"
            ));
        }
    }
    Ok(())
}

/// The read filters: `READ_FILTERS` from each named set, taken in turn.
fn read_filters(corpus: &Corpus, names: &str) -> Result<(Vec<&'static str>, Vec<Value>), String> {
    let sets = query_sets(corpus, READ_FILTERS, corpus.digest ^ 2)?;
    let mut chosen: Vec<&(&'static str, Vec<Value>)> = Vec::new();
    for name in names.split(',').map(str::trim) {
        let set = sets
            .iter()
            .find(|(known, _)| *known == name)
            .ok_or_else(|| {
                format!(
                    "--read-set `{name}` is not one of {}",
                    sets.iter()
                        .map(|(known, _)| *known)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        if chosen.iter().any(|(known, _)| *known == name) {
            return Err(format!("--read-set names `{name}` twice"));
        }
        chosen.push(set);
    }
    let filters: Vec<Value> = (0..READ_FILTERS)
        .flat_map(|k| chosen.iter().map(move |set| set.1[k].clone()))
        .collect();
    Ok((chosen.iter().map(|(name, _)| *name).collect(), filters))
}

pub(super) async fn write(mut opts: Opts, rate: &str) -> Result<Value, String> {
    let schedule = Schedule::parse(rate)?;
    let url = opts.required("url")?;
    let events = opts.number("events", 500usize)?;
    let writers = opts.number("connections", 8usize)?;
    let readers = opts.number("readers", 0usize)?;
    let read_rate = opts
        .optional("read-rate")
        .map(|value| positive("read-rate", &value))
        .transpose()?;
    let input = opts.optional("input").map(PathBuf::from);
    let wal_index = opts.optional("wal-index").map(PathBuf::from);
    let read_set = opts.optional("read-set");
    let trace = match opts.text("trace", "off")?.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err("--trace must be `on` or `off`".into()),
    };
    let keys = member_keys(&mut opts)?;
    let signing = match &keys {
        Some(keys) => keys.clone(),
        None => {
            let cfg = corpus_config(&mut opts)?;
            author_keys(&cfg)?[0].clone()
        }
    };
    opts.finish()?;
    check_plan(
        schedule,
        events,
        writers,
        readers,
        read_rate,
        input.is_some(),
        read_set.is_some(),
    )?;
    let reading = match (&input, read_rate) {
        (Some(input), Some(rate)) => {
            let corpus = read_corpus(input)?;
            let (sets, filters) = read_filters(&corpus, read_set.as_deref().unwrap_or(READ_SETS))?;
            Some(Reading {
                sets,
                filters: Arc::new(filters),
                rate,
            })
        }
        _ => None,
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("read the wall clock: {e}"))?
        .as_nanos();
    let signed = fresh_events(&signing, events, &format!("held write {nonce:x}"))?;
    let mut lanes: Vec<Vec<(Frame, Duration)>> = (0..writers).map(|_| Vec::new()).collect();
    for (i, event) in signed.iter().enumerate() {
        lanes[i % writers].push((Frame::new(event)?.0, schedule.offset(i)));
    }
    let (url, member) = (url.as_str(), keys.as_ref());
    let opened = try_join_all((0..writers + readers).map(move |n| async move {
        let label = if n < writers {
            format!("held writer {n}")
        } else {
            format!("held reader {}", n - writers)
        };
        open(url, member, &label).await
    }))
    .await?;
    let (mut sockets, mut setups): (Vec<Socket>, Vec<u64>) = opened.into_iter().unzip();
    let reader_sockets = sockets.split_off(writers);
    let ceiling = StoreOptions::server().wal_ceiling_pages;
    let sampler = wal_index.as_deref().map(Sampler::start).transpose()?;
    let t0 = Instant::now() + LEAD;
    let started_unix_us = (SystemTime::now() + LEAD)
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("read the wall clock: {e}"))?
        .as_micros() as u64;
    let span = schedule.span(events);
    let deadline = t0 + span + DRAIN_WAIT;
    let (done, watching) = watch::channel(false);
    let writing: Vec<_> = lanes
        .into_iter()
        .zip(sockets)
        .enumerate()
        .map(|(lane, (frames, socket))| {
            tokio::spawn(write_lane(lane, socket, frames, (t0, deadline), trace))
        })
        .collect();
    let reading_tasks: Vec<_> = match &reading {
        Some(plan) => reader_sockets
            .into_iter()
            .enumerate()
            .map(|(reader, socket)| {
                tokio::spawn(read_lane(
                    (reader, readers),
                    socket,
                    Arc::clone(&plan.filters),
                    plan.rate,
                    (t0, deadline),
                    watching.clone(),
                ))
            })
            .collect(),
        None => Vec::new(),
    };
    let written = try_join_all(writing.into_iter().map(|task| async move {
        task.await
            .unwrap_or_else(|e| Err(format!("a writer task failed: {e}")))
    }))
    .await;
    done.send_modify(|finished| *finished = true);
    let read = try_join_all(reading_tasks.into_iter().map(|task| async move {
        task.await
            .unwrap_or_else(|e| Err(format!("a reader task failed: {e}")))
    }))
    .await;
    let found = sampler.map(Sampler::finish).transpose()?;
    let (written, read) = (written?, read?);
    let mut merged = Written::default();
    for mut lane in written {
        merged.intended_to_ok.append(&mut lane.intended_to_ok);
        merged.sent_to_ok.append(&mut lane.sent_to_ok);
        merged.send_lag.append(&mut lane.send_lag);
        merged.pings += lane.pings;
        merged.last_ok = merged.last_ok.max(lane.last_ok);
        merged.trace.append(&mut lane.trace);
    }
    let finished = merged.last_ok.unwrap_or(t0);
    let wall = finished.saturating_duration_since(t0);
    let drain = finished.saturating_duration_since(t0 + span);
    let ok_true = merged.intended_to_ok.len();
    let mut result = json!({
        "mode": "held",
        "schedule": schedule.name(),
        "rate_per_s": schedule.rate(),
        "events": events,
        "connections": writers,
        "readers": readers,
        "ok_true": ok_true,
        "planned_span_ms": ms(span),
        "wall_ms": ms(wall),
        "drain_ms": ms(drain),
    });
    result["events_per_s"] = json!(per_second(ok_true, wall));
    result["intended_to_ok"] = summarise(&mut merged.intended_to_ok);
    result["send_to_ok"] = summarise(&mut merged.sent_to_ok);
    result["send_lag"] = summarise(&mut merged.send_lag);
    result["connection_setup"] = summarise(&mut setups);
    result["pings"] = json!(merged.pings);
    result["method"] = json!(METHOD);
    result["reads"] = reading
        .as_ref()
        .map_or(Value::Null, |plan| reads_json(plan, read));
    result["wal"] = found.map_or(Value::Null, |found| {
        report(&found, t0, ceiling, events, trace)
    });
    if trace {
        result["trace"] = json!({
            "started_unix_us": started_unix_us,
            "columns": ["lane", "intended_offset_us", "intended_to_ok_us", "sent_to_ok_us"],
            "writes": merged.trace,
        });
    }
    Ok(result)
}

/// One writer socket: sends each frame at its due time, those already due in
/// one flush, and reads OKs until every write has one.
async fn write_lane(
    lane: usize,
    mut socket: Socket,
    frames: Vec<(Frame, Duration)>,
    (t0, deadline): (Instant, Instant),
    trace: bool,
) -> Result<Written, String> {
    let label = format!("held writer {lane}");
    let due: Vec<Instant> = frames.iter().map(|(_, offset)| t0 + *offset).collect();
    let position: HashMap<&str, usize> = frames
        .iter()
        .enumerate()
        .map(|(i, (frame, _))| (frame.id.as_str(), i))
        .collect();
    let mut sent: Vec<Option<Instant>> = vec![None; frames.len()];
    let mut acked = vec![false; frames.len()];
    let (mut next, mut outstanding) = (0, frames.len());
    let mut written = Written::default();
    while outstanding > 0 {
        let now = Instant::now();
        if next < frames.len() && due[next] <= now {
            let first = next;
            while next < frames.len() && due[next] <= now {
                socket
                    .feed(Message::Text(frames[next].0.text.clone()))
                    .await
                    .map_err(|e| format!("{label}: send EVENT: {e}"))?;
                next += 1;
            }
            socket
                .flush()
                .await
                .map_err(|e| format!("{label}: flush: {e}"))?;
            let flushed = Instant::now();
            sent[first..next].fill(Some(flushed));
            continue;
        }
        let wake = if next < frames.len() {
            due[next].min(deadline)
        } else {
            deadline
        };
        let frame = match timeout_at(tokio::time::Instant::from_std(wake), socket.next()).await {
            Ok(frame) => frame,
            Err(_) if wake >= deadline => {
                return Err(format!(
                    "{label}: {outstanding} writes had no OK within {DRAIN_WAIT:?} of the last due time"
                ));
            }
            Err(_) => continue,
        };
        let at = Instant::now();
        let text = match frame {
            None => {
                return Err(format!(
                    "{label}: the connection closed with {outstanding} writes outstanding"
                ));
            }
            Some(Err(e)) => return Err(format!("{label}: socket error: {e}")),
            Some(Ok(Message::Close(close))) => {
                return Err(format!("{label}: relay closed: {close:?}"));
            }
            Some(Ok(Message::Ping(_))) => {
                written.pings += 1;
                continue;
            }
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(_)) => continue,
        };
        let reply: Value = serde_json::from_str(text.as_str())
            .map_err(|e| format!("{label}: non-JSON relay frame: {e}"))?;
        match reply[0].as_str() {
            Some("AUTH") => continue,
            Some("OK") => {}
            _ => {
                return Err(format!(
                    "{label}: unexpected reply: {}",
                    shown(text.as_str())
                ));
            }
        }
        let (index, flushed) = reply[1]
            .as_str()
            .and_then(|id| position.get(id).copied())
            .filter(|&i| !acked[i])
            .and_then(|i| sent[i].map(|flushed| (i, flushed)))
            .ok_or_else(|| {
                format!(
                    "{label}: an OK for no write in flight: {}",
                    shown(text.as_str())
                )
            })?;
        if reply[2].as_bool() != Some(true)
            || reply[3]
                .as_str()
                .is_some_and(|message| message.starts_with("duplicate:"))
        {
            return Err(format!("{label}: write refused: {}", shown(text.as_str())));
        }
        acked[index] = true;
        outstanding -= 1;
        let intended = at.saturating_duration_since(due[index]);
        let after_flush = at.saturating_duration_since(flushed);
        written.intended_to_ok.push(nanos(intended));
        written.sent_to_ok.push(nanos(after_flush));
        written
            .send_lag
            .push(nanos(flushed.saturating_duration_since(due[index])));
        written.last_ok = Some(at);
        if trace {
            written.trace.push(json!([
                lane,
                nanos(due[index].saturating_duration_since(t0)) / 1000,
                nanos(intended) / 1000,
                nanos(after_flush) / 1000
            ]));
        }
    }
    close_cleanly(&label, &mut socket).await?;
    Ok(written)
}

/// One reader socket: this reader's share of the read schedule, each REQ
/// awaited to its EOSE, until the writes are done, the deadline passes or the
/// socket's request budget is spent.
async fn read_lane(
    (reader, readers): (usize, usize),
    mut socket: Socket,
    filters: Arc<Vec<Value>>,
    rate: f64,
    (t0, deadline): (Instant, Instant),
    done: watch::Receiver<bool>,
) -> Result<Reads, String> {
    let label = format!("held reader {reader}");
    let mut read = Reads::default();
    let mut j = reader;
    loop {
        let Some(due) = Duration::try_from_secs_f64(j as f64 / rate)
            .ok()
            .and_then(|offset| t0.checked_add(offset))
            .filter(|at| *at < deadline)
        else {
            read.stopped = "deadline";
            break;
        };
        while let Ok(frame) = timeout_at(tokio::time::Instant::from_std(due), socket.next()).await {
            idle_frame(&label, frame, &mut read)?;
        }
        let finished = *done.borrow();
        if finished {
            read.stopped = "writes done";
            break;
        }
        if read.requests == REQUESTS_PER_SOCKET {
            read.stopped = "budget";
            break;
        }
        send_text(
            &mut socket,
            json!(["REQ", SUBSCRIPTION, &filters[j % filters.len()]]).to_string(),
            &label,
        )
        .await?;
        let sent = Instant::now();
        loop {
            let reply = next_json(&label, &mut socket).await?;
            match (reply[0].as_str(), reply[1].as_str()) {
                (Some("EOSE"), Some(SUBSCRIPTION)) => break,
                (Some("EVENT"), Some(SUBSCRIPTION)) => read.events += 1,
                (Some("AUTH"), _) => {}
                _ => {
                    return Err(format!(
                        "{label}: unexpected reply: {}",
                        shown(&reply.to_string())
                    ));
                }
            }
        }
        let at = Instant::now();
        read.intended_to_eose
            .push(nanos(at.saturating_duration_since(due)));
        read.sent_to_eose
            .push(nanos(at.saturating_duration_since(sent)));
        read.requests += 1;
        j += readers;
    }
    close_reader(&label, &mut socket).await?;
    Ok(read)
}

/// A frame that came while a reader waited for its next due time: a live
/// event or a CLOSED for its subscription, a fresh challenge, or a control
/// frame.
fn idle_frame(
    label: &str,
    frame: Option<Result<Message, WsError>>,
    read: &mut Reads,
) -> Result<(), String> {
    let text = match frame {
        None => return Err(format!("{label}: the connection closed")),
        Some(Err(e)) => return Err(format!("{label}: socket error: {e}")),
        Some(Ok(Message::Close(close))) => {
            return Err(format!("{label}: relay closed: {close:?}"));
        }
        Some(Ok(Message::Text(text))) => text,
        Some(Ok(_)) => return Ok(()),
    };
    let reply: Value = serde_json::from_str(text.as_str())
        .map_err(|e| format!("{label}: non-JSON relay frame: {e}"))?;
    match (reply[0].as_str(), reply[1].as_str()) {
        (Some("EVENT"), Some(SUBSCRIPTION)) => read.live_events += 1,
        (Some("CLOSED"), Some(SUBSCRIPTION)) => read.live_closed += 1,
        (Some("AUTH"), _) => {}
        _ => {
            return Err(format!(
                "{label}: unexpected frame between requests: {}",
                shown(text.as_str())
            ));
        }
    }
    Ok(())
}

/// Sends a Close and waits for the connection to end, allowing what the live
/// subscription may still deliver meanwhile.
async fn close_reader(label: &str, socket: &mut Socket) -> Result<(), String> {
    match socket.close(None).await {
        Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {}
        Err(e) => return Err(format!("{label}: send the Close frame: {e}")),
    }
    let ended = timeout(CLOSE_WAIT, async {
        loop {
            match socket.next().await {
                None | Some(Err(_) | Ok(Message::Close(_))) => return Ok(()),
                Some(Ok(Message::Text(text))) => {
                    let reply: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                    if !matches!(
                        (reply[0].as_str(), reply[1].as_str()),
                        (Some("EVENT" | "EOSE" | "CLOSED"), Some(SUBSCRIPTION))
                    ) {
                        return Err(format!(
                            "{label}: unexpected frame after Close: {}",
                            shown(text.as_str())
                        ));
                    }
                }
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    ended.unwrap_or_else(|_| {
        Err(format!(
            "{label}: the connection did not end within {CLOSE_WAIT:?} of the Close frame"
        ))
    })
}

fn reads_json(plan: &Reading, reads: Vec<Reads>) -> Value {
    let mut merged = Reads::default();
    let mut stopped = Vec::with_capacity(reads.len());
    for mut lane in reads {
        merged.requests += lane.requests;
        merged.events += lane.events;
        merged.live_events += lane.live_events;
        merged.live_closed += lane.live_closed;
        merged.intended_to_eose.append(&mut lane.intended_to_eose);
        merged.sent_to_eose.append(&mut lane.sent_to_eose);
        stopped.push(lane.stopped);
    }
    json!({
        "rate_per_s": plan.rate,
        "sets": plan.sets,
        "requests": merged.requests,
        "events": merged.events,
        "live_events": merged.live_events,
        "live_closed": merged.live_closed,
        "intended_to_eose": summarise(&mut merged.intended_to_eose),
        "sent_to_eose": summarise(&mut merged.sent_to_eose),
        "stopped": stopped,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::config::Variant;
    use crate::engine::Keepers;
    use crate::socket::server::Server;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn schedules_parse_and_span() {
        assert_eq!(Schedule::parse("burst"), Ok(Schedule::Burst));
        assert_eq!(Schedule::parse("48"), Ok(Schedule::Rate(48.0)));
        assert_eq!(Schedule::parse("1_000"), Ok(Schedule::Rate(1000.0)));
        for bad in ["0", "-1", "inf", "NaN", "x", ""] {
            assert!(Schedule::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            Schedule::Rate(48.0).span(1_440),
            Duration::from_secs_f64(1_439.0 / 48.0)
        );
        assert_eq!(Schedule::Burst.span(2_990), Duration::ZERO);
    }

    #[test]
    fn plans_stay_inside_the_production_limits() {
        let rate = Schedule::Rate(48.0);
        assert!(check_plan(Schedule::Burst, 2_990, 26, 0, None, false, false).is_ok());
        assert!(check_plan(Schedule::Burst, 2_991, 26, 0, None, false, false).is_err());
        assert!(check_plan(rate, 2_689, 26, 0, None, false, false).is_err());
        assert!(check_plan(rate, 1_440, 30, 3, Some(8.0), true, false).is_err());
        assert!(check_plan(rate, 1_440, 26, 4, None, true, false).is_err());
        assert!(check_plan(rate, 1_440, 26, 4, Some(8.0), false, false).is_err());
        assert!(check_plan(rate, 1_440, 26, 0, Some(8.0), false, false).is_err());
        assert!(check_plan(rate, 1_440, 26, 1, Some(8.0), true, false).is_err());
        assert!(check_plan(rate, 1_440, 26, 4, Some(8.0), true, false).is_ok());
    }

    #[test]
    fn held_writes_and_reads_run_against_a_door() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("corpus.jsonl").display().to_string();
        let data = dir.path().display().to_string();
        let shm = dir.path().join("events.sqlite-shm").display().to_string();
        run(&strings(&[
            "export",
            "--out",
            input.as_str(),
            "--events",
            "200",
            "--authors",
            "4",
        ]))
        .unwrap();
        run(&strings(&[
            "seed",
            "--input",
            input.as_str(),
            "--data-dir",
            data.as_str(),
        ]))
        .unwrap();
        let store = SqliteEventStore::open_with_options(
            &dir.path().join("events.sqlite"),
            4u64 << 30,
            0,
            StoreOptions::server(),
        )
        .unwrap();
        let keepers = Arc::new(Keepers::new([
            author_keys(&Config::default()).unwrap()[0].public_key()
        ]));
        let variant = Variant {
            workers: 2,
            blocking: 8,
            shared: 2,
            public: 1,
            nodelay: true,
        };
        let mut server = Server::start_on(
            &keepers,
            Visibility::Sheltered,
            &variant,
            (dir, Arc::new(store)),
            32,
            None,
        )
        .unwrap();
        let url = server.url.clone();
        let mut args = strings(&[
            "write",
            "--url",
            url.as_str(),
            "--events",
            "100",
            "--connections",
            "4",
            "--rate",
            "100",
            "--readers",
            "1",
            "--read-rate",
            "25",
            "--input",
            input.as_str(),
        ]);
        if cfg!(unix) {
            args.extend(strings(&["--wal-index", shm.as_str()]));
        }
        let steady = run(&args).unwrap();
        assert_eq!(steady["ok_true"], json!(100));
        assert_eq!(steady["intended_to_ok"]["count"], json!(100));
        let requests = steady["reads"]["requests"].as_u64().unwrap();
        assert!(requests >= 1);
        assert_eq!(
            steady["reads"]["intended_to_eose"]["count"],
            json!(requests)
        );
        if cfg!(unix) {
            let wal = &steady["wal"];
            assert!(wal["commits"].as_u64().unwrap() > 0);
            assert!(wal["frames_appended"].as_u64().unwrap() > 0);
            assert!(wal["peak_frames"].as_u64().unwrap() > 0);
        }
        let burst = run(&strings(&[
            "write",
            "--url",
            url.as_str(),
            "--events",
            "100",
            "--connections",
            "4",
            "--rate",
            "burst",
        ]))
        .unwrap();
        assert_eq!(burst["ok_true"], json!(100));
        assert_eq!(burst["schedule"], json!("burst"));
        server.stop().unwrap();
    }
}
