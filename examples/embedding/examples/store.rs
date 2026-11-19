use nostr::event::{EventBuilder, FinalizeEvent, Kind};
use nostr::filter::Filter;
use nostr::key::Keys;
use wok_store::{EventStore, PutOutcome, SqliteEventStore, Visibility};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("events.sqlite");
    let max_bytes = 64 * 1024 * 1024;
    let event = EventBuilder::new(Kind::from(1), "embedded storage").finalize(&Keys::generate())?;
    let now = event.created_at.as_secs();

    let store = SqliteEventStore::open(&path, max_bytes)?;
    assert_eq!(
        store.put(Visibility::Sheltered, &event, now)?,
        PutOutcome::Stored
    );
    drop(store);

    let store = SqliteEventStore::open(&path, max_bytes)?;
    let filter = Filter::new().id(event.id);
    assert!(store.query(Visibility::Public, &filter, now)?.is_empty());
    assert_eq!(store.query(Visibility::Sheltered, &filter, now)?, [event]);
    println!("Read the stored event from the sheltered partition after reopening.");
    Ok(())
}
