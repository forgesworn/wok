# Changelog

## 0.8.0 - 2026-11-25

Performance, and a smaller container image. The store schema (version 5),
the file format and the wire protocol are unchanged from 0.7.0, and a
volume written by the 0.7.0 image opens under this one.

- Breaking for the container image: it has no shell, so nothing can be
  `docker exec`ed in a running container. An operator's removal, which
  needs the relay stopped as before, now runs as a container of its own
  against the same volume and configuration; `wokd`'s README gives the
  command. Nothing else an operator does changes.
- `wok-store`: a batch of ordinary events keeps its savepoint journals in
  memory. SQLite's default moves a journal to a temporary file once one
  event has changed sixteen pages and keeps it there for the rest of the
  transaction, so every later event cost two writes for each page it
  touched, in the system's temporary directory rather than the store's own.
  Storing 18,000 events on Linux took 679,989 `pwrite` calls and 2,637
  temporary files before, and 315,939 calls and no file after. On macOS
  (medians of six rounds) 32 submitters stored 18,964 events a second where
  they stored 10,114, and one event a commit 9,072 where it was 4,693. A
  batch keeps SQLite's default if it carries a deletion, an event with more
  than 64 tags, or one that replaces a stored version with more than 64 tag
  rows; so do expiry sweeps, an operator's removal and a purge. The journal
  held in memory is therefore one ordinary event's: 66 KiB for a short note
  and 1.4 MiB at the most measured. Android builds already kept every
  journal in memory. No change to the schema or the file format.
- `wok-store`: the store's connections choose each query plan from the
  statement alone (SQLite's query planner stability guarantee). SQLite
  otherwise looks at some bound values as it plans and compiles a cached
  statement again when one has changed, which was every run: about a third
  of a history query's time. A one-row lookup takes 1.6 µs where it took
  9.7, and a page of 20 to 50 events 17 to 32 per cent less (macOS, medians
  of three rounds). The plans are the ones SQLite chose before: a test
  compares them for every query shape and for every statement the store's
  connections keep prepared. Removal and migration statements, which are
  compiled for one use, are not in it.
- `wokd`: a guest's scope lookup keeps one compiled statement, with the
  same plan stability: 1.8 µs a lookup where it was 5.0.
- `wokd` caps its runtime's blocking pool at 8 threads
  (`BLOCKING_THREADS`), where tokio allows 512. Signature checks run there,
  and a burst of writes from 24 connections used to leave 81 to 121 threads
  and 8.8 to 10.4 MB of heap; it now leaves 13 threads and 6.8 to 7.4 MB,
  with no loss of throughput.
- `wokd`, `wok-roomd` and `wok-bench` are built with whole-program
  optimisation in one codegen unit and without a symbol table
  (`[profile.release]`), for size: `wokd`'s speed is level. A panic still
  names its file and line; a backtrace shows addresses. An application that
  links the libraries keeps its own profile.
- The container image builds its SQLite without the extensions `wokd` never
  uses (full-text search, R-tree, JSON, dbstat, soundex, loadable
  extensions, deprecated interfaces, shared cache) and without memory
  statistics. With the profile above, `wokd` in the arm64 image is 5.13 MB
  where it was 8.47 MB.
- `wok-ws`: a connection takes every `OK` that has landed as one batch and
  puts them on the socket in one write. The writer answers a whole commit
  at once, and each of its `OK`s used to be flushed on its own. Nothing
  waits to make a batch, and the order of the `OK`s is as it was: usually
  the order sent, never promised. With one connection pipelining 24,000
  events on Linux, client and relay in one process made 25,555 `sendto`
  calls where they made 48,032; 24,000 of each are the client's own frames,
  so the relay's writes fell from about 24,000 to about 1,550.
- The container image is built on a distroless base
  (`gcr.io/distroless/cc-debian13`): glibc, libgcc and `wokd`, with no shell
  and no package manager. Compressed, the arm64 image is 13.1 MB where it
  was 33.4 MB. The `wok` user, its uid 10001 and `/data` with its mode are as
  they were, and a volume written by the 0.7.0 image opens under this one.
  Nothing can be `docker exec`ed in it: an operator's removal runs as its
  own container, as `wokd`'s README shows. CI now also stores an event with
  500 tags and a deletion of 40 events in the image, the writes that need a
  temporary file, and runs a removal there.
- `wokd` hands the allocator's free memory back to the kernel every 30
  seconds on Linux with glibc. After two bursts of writes from 24
  connections its heap stood at 6.5 to 6.6 MB, and at 4.1 to 4.3 MB once a
  trim had run; the relay before these changes settled at 7.2 to 7.4 MB. A
  trim takes 0.2 to 0.3 ms as a rule and runs off the worker threads.
- `wokd` links secp256k1's small precomputed tables (`lowmemory`): 1.1 MB
  less binary (with the trim above, 4.08 MB in the arm64 image where it was
  5.13 MB) and about 1 MB less resident memory once a signature has been
  checked. A signature check takes 23.9 µs where it took 19.7 (Linux arm64,
  parse included); the relay's frame budget admits 64 events a second over
  time, so that is a quarter of a millisecond in each second at worst.
  Cargo unifies features across one build, so a build that includes `wokd`
  gives the small tables to every package in it; `wok-bench` and `wok-roomd`
  built on their own keep the full ones, and the benchmark image now builds
  the two separately.
- `wok-store`: an addressable event asked for by its author, kind and `d`
  tag is found from the tag index. A filter that names `authors` was always
  answered from the author's events, each one's tags probed, so the lookup
  cost a probe for every event of that kind the author had. With about 78
  of them (100,000 events from 64 authors, release build) it took 137 to
  177 µs at the median on arm64 macOS and 130 to 148 µs on Linux, and it
  takes 3.2 to 3.7 µs and 2.8 to 2.9 µs now. Before a query that names
  `authors` and a tag, the store counts the rows the driving tag's values
  hold between them, in one statement and to no more than 17; at 16 or
  fewer the tag index drives, and the author and kind are checked on each
  event its rows lead to. Both shapes select the same events, so the count
  only chooses what the answer costs. A tag with more than 16 values is not
  counted. The count takes 1.1 to 1.5 µs for one value and 5.9 µs for
  sixteen (arm64 macOS, as are the figures that follow). A query that names
  an author and a common tag pays it and gains nothing: 1.5 µs beside a
  statement that took 10.7 µs. An author with a single event of the kind is
  the case that loses: 1.7 µs before, 2.7 µs when the value has one row and
  4.8 µs when it has sixteen. Sixteen `d` values asked of an author with
  400 events of the kind took 657 µs and take 25 µs; asked of an author
  with only those sixteen they took 23.5 µs and take 24.6 µs. A `COUNT` is
  answered as before.
- `wok-ws`: a subscriber's live events go out several to a write. The
  writer announces a whole commit at once, so a connection's queue holds its
  events together, and each used to be matched and flushed on its own. A
  connection now takes what is queued behind the event it was woken for, up
  to 64 events or 16 KiB of frames (the socket's write buffer), and writes
  them together in the order they were queued. Its own events still come
  back after their `OK`s: those are taken after the last event of the batch
  and sent first. With one connection pipelining 24,000 events to eight
  subscribers on Linux, client and relay in one process made 37,812 `sendto`
  calls where they made 217,807: the 192,000 live frames went out in about
  12,300 writes, where each had its own. With 16 connections writing to 32
  subscribers the door acknowledged 23,850 writes a second where it
  acknowledged 17,660 (medians of 52 cells each, in a Docker VM on a busy
  host). One writer showed no difference.
- `wok-bench`: `--socket-subscribers N` attaches connections that hold an
  open `REQ` and read every event of a socket cell live. A subscriber that
  lags or misses an event fails the run. The default is none, so earlier
  figures still compare.

## 0.7.0 - 2026-11-24

- `wok-roomd`, a second program: a keeper-controlled room relay, moved here
  from the Bothy node where it was built. Each room has a database of its
  own, a supervisor on the same machine pushes the allowlist over a private
  Unix socket and renews it every 15 seconds, an ask door takes sealed
  requests for a room's inviter from keys not yet admitted, and purging a
  room deletes its database and leaves a 30-day tombstone. The control
  protocol and the flags are unchanged from the Bothy build. So is the
  layout of the data directory: the names of the room stores, which a test
  now pins, and the store schema. Checked after the release on one machine:
  a directory written by a Bothy build, with a purged room's tombstone in
  it, was opened and read by 0.7.0. The command is now `wok-roomd`, with no
  `room-relay` word before the flags. It is not in the container image.
- `wok-roomd` runs on Unix-like systems only. On Windows the crate is empty
  and the binary exits with a message.
- `url` moves to 2.5.9 for RUSTSEC-2026-0592, in the lockfile only.
- No change to the libraries, `wokd` or the store schema (version 5).

## 0.6.4 - 2026-11-20

- The embedded phone profile waits 30 seconds without a commit before
  truncating the WAL, so intermittent writes can share a checkpoint.
  It also checkpoints at the 500-page threshold and when the store closes.

## 0.6.3 - 2026-11-20

- The embedded phone store profile budgets 1.75 MiB for SQLite page
  caches, with 1 MiB for the writer and 256 KiB each for the two readers
  and the checkpointer.
- WebSocket EVENT intake uses the transport's bytes directly. A verified
  event can have its authority and store preparation checked on the same
  worker when the work permit is immediately available.

- WebSocket doors reserve capacity before reading a history page. Up to
  four replies across both doors may be in progress, with up to two from
  the public door. Waiting for capacity leaves SQLite readers free, and
  embedded hosts can set the limits with `Door::with_history_limits`.

- SQLite serves multi-filter REQs by merging the ordered keys from each
  filter, then reading only the bodies reached by the relay's reply budget.
  The keys and bodies come from one read snapshot. Buffered replies are
  held until the reader's authority has been checked again.
- `wok-bench relay query --set overlap` measures a two-filter REQ that
  returns the same page as `authors_kinds`. Use `--read-set overlap` to
  measure it alongside held-socket writes.

## 0.6.2 - 2026-11-19

- The container image workflow also publishes each `v*` release tag as
  `ghcr.io/forgesworn/wok:<version>`, beside the commit tag, and refuses a
  tag that does not match the workspace version. `main` still publishes
  `latest`.
- `wokd`'s README names the published image and says that a containerised
  `wokd` needs `listen = "0.0.0.0:7447"`: on the default loopback address
  inside a container, the published port reached nothing.
- No change to the libraries, `wokd` or the store schema (version 5).

## 0.6.1 - 2026-11-15

- `wok-ws`: a REQ's query, and the authority check before it, now take one
  of `READ_PERMITS` (2) instead of one of the `WORK_PERMITS` (2) that EVENT
  intake, AUTH, COUNT, negentropy, authority refreshes and expiry sweeps
  share, so REQs no longer wait for a work permit behind EVENT intake, nor
  EVENT intake behind REQs. A public REQ still takes the public door's
  allowance first, so the public door still runs one step at a time, REQs
  included. Up to 4 store and authority steps can now run on the blocking
  pool at once, where it was 2: an application that sizes its blocking pool
  from `WORK_PERMITS` should add `READ_PERMITS`. COUNT and negentropy, and
  any store read an application makes under a work permit, share the
  store's two read connections with REQs, so one of them can wait for a
  connection, holding its work permit, while two REQs read.
- `wok-bench relay write --rate` holds its writer sockets open, each
  authenticated once, and sends on an open-loop schedule: `--rate N` writes
  a second, or `burst` for every event due at once. It reports latency from
  each event's due time and from the flush that carried it to its OK, so a
  stall shows in every write queued behind it. Every socket stays inside
  wokd's production frame limit, and writers and readers together take at
  most 32 sockets. `--readers` adds REQs at `--read-rate`, drawn from the
  seeded corpus (`--input`), while it writes. The default write workload, a
  fresh connection per event, is unchanged.
- `--wal-index` names a Wok store's `-shm` file, which the run reads
  read-only and without a lock to report commits, log growth, restarts and
  checkpoint runs beside the write latencies. It cannot tell a PASSIVE
  checkpoint from a blocking FULL one. It changes nothing in the libraries
  or `wokd`.

## 0.6.0 - 2026-11-13

- `wok-store`: schema version 5. It is version 4 with one more index,
  `events_kind` on `(visibility, kind, created_at, id)`, so a filter that
  names one kind reads that kind newest first instead of walking the whole
  partition in time order. A filter with several kinds keeps the time walk.
  A NIP-45 count that names ids now always counts them from the id index, as
  the query path already did.
- A version 4 store, Bothy's included, is upgraded at its first open with
  this build: the index is built, reading every event once and growing the
  file by a few per cent, and the store is marked version 5 only once the
  index is there, so an open stopped part way leaves it at 4 for the next
  open to finish. `wokd`'s first start on a version 4 store takes longer for
  this, in proportion to the events held. A version 5 store is refused
  (`NewerSchema`) by every earlier build, current Bothy builds included.
  Going back is `export_stored` with this build, which reads either version,
  and an import with the older one.
- `wok-store`: `EventStore::query_stored_each` hands a query's rows to a
  callback as they are read, newest first and then by id, until it answers
  `false`. Its default is built on `query_stored`, so other implementations
  compile unchanged; `SqliteEventStore` steps its statement row by row.
- `wok-store`: `RelaySession::begin_prepared_streaming` answers a `REQ` with
  one filter by handing each EVENT frame to a sink as its row is read, and
  every other frame as `begin_prepared` does. The reader's authority is
  judged before the query and again after it. Frames already handed over
  cannot be withdrawn; a loss of authority during the query turns the EOSE
  into a CLOSED. `PreparedFrame::is_req_frame` says which frames it may
  stream.
- `wok-ws`: a one-filter REQ whose events pass 16 KiB is streamed, each event
  sent as the store reads it, and the work permit is released before the
  rest is written. A smaller page is still answered whole with its EOSE. A
  member removed while a streamed page is being read may receive part of it
  before the CLOSED, where a buffered page is withheld entirely. Each batch
  written, rather than the whole page, has the I/O timeout to reach the peer
  before the connection ends as stalled.
- `wok-store`: the checkpoint thread starts a PASSIVE checkpoint at most
  every 250 ms instead of every 50 ms, so the main file's sync holds up a
  busy writer's commits less often. Durability is unchanged. A deletion's
  follow-up pass can wait that long behind one already running.
- `wok-store`: `StoredEvent::from_stored` reads a row in the layout the
  store writes without serde, and leaves every other row to the serde
  check as before; differential tests hold it to that check.
- `wokd` runs on 2 runtime worker threads, set by a new `workers` setting,
  instead of tokio's one per core. A change takes a restart, and a reload
  names it as one.
- `wokd` gives its store a 256 KiB writer page cache instead of the server
  profile's 1 MiB. `StoreOptions::server()` itself is unchanged.
- `wokd` caps glibc's malloc arenas at 2 at start-up on Linux, unless
  `MALLOC_ARENA_MAX` is set in its environment. It adds a `libc` dependency
  on that target only.
- `wok-bench` gains a `relay` command: it exports a common corpus, seeds Wok
  and drives query, write and fan-out workloads against remote Nostr relays
  over WebSocket.

## 0.5.6 - 2026-11-12

- `wok-store`: `EventRelay::auth_relay_mismatches` counts the AUTH events
  refused only because their one `relay` tag named another relay URL than
  the session's, with the kind, signature, time and challenge all good. The
  refusal a client gets is unchanged. The count is taken before any access
  check, so anyone who can open a socket can raise it.
- `wokd` logs a warning when that count rises: at once, then at most once a
  minute, with the number of attempts and nothing a client sent. A `url` that
  is not the address clients connect to used to show only as every client
  failing AUTH.
- `wok-store`: `EventRelay::with_final_url_refusal` makes an AUTH refused only
  because its one `relay` tag named another relay send no replacement
  challenge, and keeps the challenge it answered current, so a client that
  names the right URL can still authenticate on that connection. The reply
  and the `auth-required:` answer to later frames are unchanged. Without it, a
  stock client that signs every challenge it is sent (nostr-sdk 0.45 does)
  signed again at once with the same URL until the frame allowance closed the
  connection, then reconnected and started over. Off by default.
- `wokd` turns it on. A nostr-sdk client against a mismatched `url` now signs
  once per connection, and a publish on that connection fails at the
  client's own timeout instead of at once.

## 0.5.5 - 2026-11-12

- `wokd` reloads its members on SIGHUP, without a restart. A removed key's
  open subscriptions are closed with `CLOSED` and then its connection, and
  it is refused from then on; an added key can authenticate. A file that
  cannot be read or does not pass the checks changes nothing. Every other
  setting still takes a restart, and a reload that changes one says so in
  the log. SIGHUP no longer stops `wokd`: stop it with SIGTERM or Ctrl-C. On
  Windows there is no SIGHUP, and a change of members takes a restart.
- `wokd` library: `run` and `serve` take a channel of reloaded
  configurations, `reload` applies one, and `Members::replace` swaps the
  group and announces the change to open connections.

## 0.5.4 - 2026-11-11

- `wok-ws`: `Door::sheltered_router_with_information` is the sheltered door
  serving a NIP-11 relay information document. It is the public door's
  document, with the same NIP list and limits, except that `auth_required` is
  `true`: the same static bytes for every caller, with no key, address,
  contents or live state. A request for it is not a connection, so admission
  does not see it; an upgrade still goes through admission and NIP-42,
  whatever its `Accept` header says. `sheltered_router` and the public
  document are unchanged.
- `wokd` serves that document by default. `relay_information = false` turns it
  off.

## 0.5.3 - 2026-11-11

- `wok-store`: when a commit leaves the WAL at `wal_ceiling_pages` and
  another checkpoint holds SQLite's checkpoint lock, the writer now waits for
  the lock, within the same `CEILING_WAIT` as its wait for readers, and then
  runs its blocking checkpoint. SQLite refuses a checkpoint at once while
  another runs, and the writer used to let the next commit through after such
  a refusal, so the log could pass the ceiling for as long as its attempts
  kept meeting another checkpoint. Writes can now stall in this case where
  they used to pass. The ceiling is still not a hard limit: if a reader or
  another checkpoint holds on for longer than `CEILING_WAIT`, commits go
  through for a second before the writer tries again. `CheckpointStats`
  counts each blocking checkpoint once, and `blocking_time` now includes the
  wait for the lock.

## 0.5.2 - 2026-11-11

- `wok-store`: `SqliteEventStore::checkpoint_stats` reports what the store's
  checkpointing has done since it was opened: the passive, truncating and
  blocking checkpoints it has run, the time the writer has spent in the
  blocking ones and the longest of them, and the most WAL pages a commit has
  left. Reading it changes nothing, and the store behaves as before.
- `wok-bench` reports those counts as `checkpoints` wherever it reports
  `writer`, and `door-path` marks an arm run `stalled` when its longest wait
  for an OK passed 200 ms. No rule uses the marker.

## 0.5.1 - 2026-11-11

- `wok-bench` gains a diagnostic `door-path` scenario, run only when named
  and not part of a default `all` run. It sets the sheltered door beside the
  engine driven directly, with and without the door's blocking-pool hops,
  and beside a bench-only stand-in that only acknowledges frames, to see
  whether those hops account for the door's cost. The libraries are
  unchanged; the bench binary binds `127.0.0.1` on an ephemeral port for it.
- `wok-bench` gains a diagnostic `guest-path` scenario, run only when named
  and not part of a default `all` run. It sets keeper writes through the
  sheltered door beside guest writes, whose publishes ask a guest authority
  for scopes, on an empty and a seeded store, and counts and times every
  authority call. The libraries are unchanged; the bench binary binds
  `127.0.0.1` on an ephemeral port for it, and its guest authorities (one in
  memory, one a model over a small SQLite file) live in `wok-bench` only and
  are not for applications.
- `wok-store`: `EventRelay::with_final_access_refusal` makes an AUTH refused
  because its key has no access final for that key. The refusal sends no
  replacement challenge, and until an AUTH succeeds every frame that needs
  authority is answered `restricted: this key has no sheltered access`
  instead of `auth-required:`. A stock NIP-42 client signs every challenge it
  is sent, so a refused key otherwise signs again as fast as the frame
  allowance lets it: nostr-sdk 0.45 sent 119 AUTH frames in two seconds. The
  challenge it answered stays current, so a key with access can still
  authenticate on the connection. An AUTH refused for anything else still
  gets a fresh challenge. Off by default, so the default replies are
  unchanged.
- `wokd` turns it on. A non-member's client signs once, and its publish
  fails at once with `restricted:` instead of `authentication failed`.

## 0.5.0 - 2026-11-11

- Add `wokd`, a members-only Nostr relay built on `wok-store` and `wok-ws`.
  `wokd --config <file>` serves one group, whose `npub` keys its operator
  lists. Every read, write, count and reconciliation needs NIP-42 as a
  listed key; there is no open mode, no public door and no NIP-11 document
  yet. It listens on `127.0.0.1:7447` unless configured otherwise, sends
  nothing anywhere, creates its data directory owner-only on Unix, and on
  SIGINT or SIGTERM answers what each socket has read and closes it.
- `wokd remove --config <file> --id <event id>` (or `--author <npub>`) is an
  operator's removal with the relay stopped, through `wok-store`'s removal.
  The relay holds a lock on its data directory, so a removal is refused
  while it runs.
- `wokd`'s configuration is strict: an unknown field, an empty member list, a
  hex key or an `nsec` stops it, and no error repeats a value.
  `crates/wokd/README.md` says what an operator runs and what they may owe.
  `wokd` is source only: it is not published to crates.io, and no binaries
  are built.
- `wok-ws`: a shutdown is taken between frames, so a write a connection has
  read when the shutdown lands is queued and answered before the close. Until
  now the frame being worked on was dropped: not stored and never answered.
  A turn still running a second after the shutdown (waiting on a work permit,
  say, or a slow peer) is interrupted as before, so a shutdown stays bounded.
- `wok-store`: an operator's removal. `SqliteEventStore::remove` takes events
  out of a partition by id, whoever signed them, and `remove_author` every
  event one key signed, in transactions of at most `MAX_EXPIRE_EVENTS`. Each
  removed event is barred from being stored again; a replaceable head that
  points at it goes too, so its coordinate text is not left behind; deletion
  events are removable like any other; and the write-ahead log is truncated
  afterwards (`Removal::erased` says whether it was). It is for acting on a
  report with nothing else serving the store, and `StoreOptions::offline`
  opens one with no background checkpoint or warm-up. NIP-09 deletion is
  unchanged.
- `wok-bench` gains a `socket` scenario: acknowledged writes through
  `wok-ws`'s two doors over real WebSocket connections, beside the same
  events driven straight at the session engine in the same run. Each cell
  starts its own store, relay, door and server runtime; clients authenticate
  with NIP-42 and every event is signed and verified. Server worker and
  blocking threads, the doors' work permits and `TCP_NODELAY` can be varied
  per run, and each door's refusals are checked before anything is measured.
- The scenario leaves the libraries unchanged. The unpublished bench binary
  binds `127.0.0.1` on an ephemeral port for this scenario, refuses any other
  address, and a default `all` run now does so. Its sheltered door uses an
  admit-everything `Admission` that lives in `wok-bench` only and is not for
  applications.

## 0.4.0 - 2026-11-11

- Add `wok-ws`, the relay's WebSocket doors, moved from Bothy's node
  repository. A `Door` holds one relay's connection and work budgets and
  hands out unbound axum routers: a public one, which also serves the NIP-11
  relay information document, and a sheltered one. It opens no port.
- The sheltered router is built only with an `Admission`, which decides from
  the request's extensions whether a connection may open and holds what it
  returns (a per-peer permit, say) for the connection's life. There is no
  default, and a request it cannot place is refused. NIP-42 is still required
  on every connection it admits.
- The deadlines (`Timings`), the budgets (32 connections, 24 of them public;
  `WORK_PERMITS` of 2, 1 of them public, adjustable with
  `with_connection_limits` and `with_work_limits`), the buffer sizes, the
  close codes and reasons, the HTTP statuses and the NIP-11 document are as
  Bothy had them, including a close reason that still says "circle authority
  expired".
- New dependencies, in `wok-ws` only: `axum` 0.8 with `ws`, and
  `futures-util` 0.3. `wok-store` gains none.
- `wok-bench` gains an `engine` scenario: the relay session engine driven
  frame by frame with no network, beside the bare writer and the raw store in
  the same run. It gives acknowledged writes by session count and in-flight
  window, REQ and COUNT through a session against the same filters on the
  store, and what a subscribed session holds in Rust allocations. Every event
  is signed and the engine checks each signature. A default run now includes
  it, and the whole process runs under a counting allocator, which each
  result's header records.
- `wok-store` is unchanged since 0.3.0, and so is schema 4.

## 0.3.0 - 2026-11-11

- Add the relay session engine as `wok_store::relay`, moved from Bothy's node
  repository: NIP-01 sessions with NIP-42 authentication, NIP-45 counts and
  NIP-77 reconciliation over the store, on a public door and a sheltered one.
  Replies are word for word what Bothy sent, including two refusals that still
  say "circle grant".
- The engine holds no policy. `KeeperAccess` says who the keepers are,
  `GuestAuthority` gives guests room- and kind-scoped access to the sheltered
  partition, `AuthorityEvents` names the events a door installs instead of
  storing, and `AnnounceHook` sees each event announced live.
- Breaking: `single_d_value`, `event_frame` and the hidden
  `PreparedPut::verified`, public in 0.1.0 and 0.2.0 only for Bothy's copy of
  the engine, are crate-private again, so a caller outside the crate can no
  longer skip the signature check. Bothy no longer uses them. `LiveFanout`
  stays public, since `wok-bench` drives it directly.
- New dependencies: `negentropy` 0.5, `url` 2.5, `hex` 0.4, and `nostr`'s
  `os-rng` feature, from which each NIP-42 challenge is drawn.
- A filter that names several ids is answered from the id index, one seek for
  each id. SQLite used to walk the partition in time order for it, so the
  query took longer as the partition grew; a filter with one id was not
  affected. Answers and their order are unchanged.
- New unpublished workspace crate `wok-bench`: a store-level baseline
  benchmark of ingest, queries and live fan-out. Its figures hold later
  changes to "no slower" on one machine; they are not a comparison with any
  other relay.
- No schema change.

## 0.2.0 - 2026-11-10

- Move to `rusqlite` 0.41.1 and its bundled SQLite 3.54 for RUSTSEC-2026-0459
  (#1). The advisory is no longer ignored in `cargo audit`.
- `EventStoreError::Sqlite` carries `rusqlite::Error`, so this release is
  breaking: a consumer that also links `rusqlite` must move to 0.41 in the
  same change, since a build links only one bundled SQLite.
- The minimum supported Rust version is now 1.89, as `rusqlite` 0.41 requires.
- `rusqlite` 0.41 replaces a progress handler only through `&mut Connection`,
  which an open transaction does not give. Each connection now carries one
  handler from when it opens, and the store arms and disarms its query and
  expiry deadlines through it. A reader's deadline is disarmed when its query
  returns, where it used to stay set until the next query.
- Update locked tokio to 1.54.1 and faster-hex to 0.10.1 for
  RUSTSEC-2026-0386 and RUSTSEC-2026-0306.
- No schema change: schema 4 remains, and existing stores open as before.

## 0.1.0 - 2026-11-10

- First release: the event store, its group-commit writer and live fan-out,
  moved from Bothy's node repository at `9d75c2c` as the `wok-store` crate.
  Behaviour and the on-disk format (schema 4) are unchanged.
- Thread names are now `wok-event-writer`, `wok-wal-checkpoint` and
  `wok-warm`.
- `single_d_value`, `event_frame`, `LiveFanout` (with its methods) and the
  hidden `PreparedPut::verified` are public, for Bothy's relay engine until it
  moves into Wok.
- The writer counts a batch in `stats()` before it answers the batch's
  callers. In Bothy a caller could hold its answer while `stats()` still
  lacked its batch, which made one writer test fail on slow machines (#2).
- The truncate-race test's competing connection pauses between TRUNCATE
  checkpoints. Back to back, they could hold the write lock for the writer's
  whole busy timeout on a slow CI runner (#2).
- Known: the bundled SQLite 3.53.2 is affected by RUSTSEC-2026-0459 (#1),
  ignored in `cargo audit` until the joint move to `rusqlite` 0.41.
