//! Experimental in-memory transport with room-capability admission.
//! NOT end-to-end encrypted. Never expose to untrusted networks.
pub mod auth;
use std::{collections::{HashMap, VecDeque}, sync::{Arc, Mutex, Weak}, time::{Duration, Instant}};
use rand::{rngs::OsRng,RngCore};
use serde::Serialize;
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore};

pub const MAX_FRAME_BYTES: usize = 16 * 1024;
/// Protocol v2 signed-message wire envelope: version byte + 96-bit IV + >=128-bit GCM tag.
pub const MIN_ENVELOPE_BYTES: usize = 1 + 12 + 16;
/// MLS transport framing: [version=3, kind=1..=4, opaque TLS serialized bytes].
/// The server does not decrypt or authenticate MLS content.
pub const MLS_FRAME_VERSION: u8 = 3;
pub const MLS_MIN_FRAME_BYTES: usize = 3;
pub const MLS_KIND_APPLICATION: u8 = 1;
pub const MLS_KIND_COMMIT: u8 = 2;
pub const MLS_KIND_WELCOME: u8 = 3;
pub const MLS_KIND_KEY_PACKAGE: u8 = 4;
pub const ROOM_CAPACITY: usize = 32;
pub const MAX_ACTIVE_ROOMS: usize = 256;
pub const MAX_PARTICIPANTS_PER_ROOM: usize = 16;
/// Aggregate room-wide quota, in addition to each socket's 20 frames/second.
pub const MAX_ROOM_FRAMES_PER_SECOND: u32 = 64;
// Volatile, ciphertext-only replay window. NOT durable offline synchronization.
const MAX_REPLAY_FRAMES: usize = 64;
// Worst-case memory: 256 active rooms × 128 KiB = 32 MiB ciphertext plus overhead.
const MAX_REPLAY_BYTES: usize = 128 * 1024;
const REPLAY_TTL: Duration = Duration::from_secs(30*60);

pub struct Room {
    sender: broadcast::Sender<Vec<u8>>,
    participants: Arc<Semaphore>,
    ingress: Mutex<RoomIngressQuota>,
}

struct RoomIngressQuota {
    started: Instant,
    frames: u32,
    protocol: Option<u8>,
    generation: String,
    next_sequence: u64,
    replay: VecDeque<ReplayFrame>,
    replay_bytes: usize,
}

impl RoomIngressQuota {
    fn new() -> Self {
        let mut nonce=[0u8;16];
        OsRng.fill_bytes(&mut nonce);
        Self { started:Instant::now(),frames:0,protocol:None,
            generation:hex::encode(nonce),next_sequence:1,
            replay:VecDeque::new(),replay_bytes:0 }
    }

    fn permit(&mut self, now: Instant) -> bool {
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.frames = 0;
        }
        if self.frames >= MAX_ROOM_FRAMES_PER_SECOND { return false; }
        self.frames += 1;
        true
    }
}

/// Never place plaintext, member tokens, invite secrets or MLS private state
/// in the relay replay window. Clients authenticate their own MLS frames.
#[derive(Clone,Serialize)]
pub struct ReplayFrame {
    pub sequence: u64,
    pub wire_hex: String,
    #[serde(skip)]
    recorded: Instant,
}

#[derive(Serialize)]
pub struct ReplaySnapshot {
    pub generation: String,
    pub first_sequence: u64,
    pub latest_sequence: u64,
    pub frames: Vec<ReplayFrame>,
}

impl Room {
    /// Identify gaps or server restarts; never silently skip a missing
    /// encrypted Commit. Without an authenticated client cursor, return
    /// only metadata (a new member MUST join via Welcome).
    pub fn replay_since(&self,cursor:Option<(&str,u64)>)->Result<ReplaySnapshot,&'static str>{
        let mut state=self.ingress.lock().map_err(|_|"replay lock poisoned")?;
        while state.replay.front().is_some_and(|e|e.recorded.elapsed()>=REPLAY_TTL) {
            if let Some(removed)=state.replay.pop_front() {
                state.replay_bytes=state.replay_bytes.saturating_sub(removed.wire_hex.len()/2);
            }
        }
        let latest=state.next_sequence-1;
        let first=state.replay.front().map_or(latest.saturating_add(1),|x|x.sequence);
        let frames=match cursor {
            None=>Vec::new(),
            Some((generation,sequence))=>{
                if generation!=state.generation{return Err("replay generation mismatch");}
                if sequence>latest{return Err("replay cursor from the future");}
                if sequence.saturating_add(1)<first{return Err("replay gap: rejoin required");}
                state.replay.iter().filter(|x|x.sequence>sequence).cloned().collect()
            }
        };
        Ok(ReplaySnapshot{
            generation:state.generation.clone(),
            first_sequence:first,latest_sequence:latest,frames
        })
    }

    /// Reserve one live connection slot; releasing the permit frees it automatically.
    pub fn try_enter(&self) -> Result<OwnedSemaphorePermit, &'static str> {
        self.participants.clone().try_acquire_owned().map_err(|_| "room full")
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.sender.subscribe()
    }

    pub fn publish(&self, payload: Vec<u8>) -> Result<(), &'static str> {
        if !valid_envelope(&payload) {
            return Err("invalid frame size");
        }
        // Aggregate rate limiting is essential: sixteen legitimate-looking peers
        // can otherwise publish 16×20 frames/s and overwhelm each subscriber.
        {
            let mut ingress = self.ingress.lock().map_err(|_| "room quota lock poisoned")?;
            // Lock protocol on first authenticated room publication. Never mix
            // legacy PSK v2 traffic with MLS v3 membership/epoch messages.
            // A new empty room may choose a fresh protocol; active rooms cannot.
            let version = payload[0];
            if ingress.protocol.is_some_and(|chosen| chosen != version) {
                return Err("room protocol version mismatch");
            }
            if !ingress.permit(Instant::now()) { return Err("room publish quota exceeded"); }
            ingress.protocol = Some(version);
            if version==MLS_FRAME_VERSION {
                let sequence=ingress.next_sequence;
                ingress.next_sequence=ingress.next_sequence.checked_add(1)
                    .ok_or("replay sequence exhausted")?;
                while ingress.replay.front().is_some_and(|entry|entry.recorded.elapsed()>=REPLAY_TTL) {
                    if let Some(old)=ingress.replay.pop_front() {
                        ingress.replay_bytes=ingress.replay_bytes.saturating_sub(old.wire_hex.len()/2);
                    }
                }
                ingress.replay_bytes=ingress.replay_bytes.saturating_add(payload.len());
                ingress.replay.push_back(ReplayFrame{
                    sequence,wire_hex:hex::encode(&payload),recorded:Instant::now()
                });
                while ingress.replay.len()>MAX_REPLAY_FRAMES ||
                    ingress.replay_bytes>MAX_REPLAY_BYTES {
                    if let Some(old)=ingress.replay.pop_front() {
                        ingress.replay_bytes=ingress.replay_bytes.saturating_sub(old.wire_hex.len()/2);
                    }
                }
            }
        }
        // The live broadcast remains unchanged; an offline client must
        // explicitly authenticate and reconcile a replay cursor before send.
        let _ = self.sender.send(payload);
        Ok(())
    }
}

/// Checks wire format only. It cannot authenticate ciphertext; that is done by the client.
pub fn valid_envelope(bytes: &[u8]) -> bool {
    if bytes.len() > MAX_FRAME_BYTES { return false; }
    match bytes.first() {
        Some(2) => bytes.len() >= MIN_ENVELOPE_BYTES,
        Some(&MLS_FRAME_VERSION) => bytes.len() >= MLS_MIN_FRAME_BYTES &&
            matches!(bytes[1], MLS_KIND_APPLICATION | MLS_KIND_COMMIT | MLS_KIND_WELCOME | MLS_KIND_KEY_PACKAGE),
        _ => false,
    }
}

#[derive(Default)]
pub struct Rooms {
    rooms: Mutex<HashMap<String, Weak<Room>>>,
}

impl Rooms {
    pub fn join(&self, room_id: &str) -> Result<Arc<Room>, &'static str> {
        if room_id.len() != 32 || !room_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err("room id must be 32 lowercase hexadecimal characters");
        }
        let mut rooms = self.rooms.lock().map_err(|_| "room lock poisoned")?;
        // Remove names for inactive rooms, without storing message history.
        rooms.retain(|_, room| room.strong_count() > 0);
        if let Some(existing) = rooms.get(room_id).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        if rooms.len() >= MAX_ACTIVE_ROOMS {
            return Err("too many active rooms");
        }
        let (sender, _) = broadcast::channel(ROOM_CAPACITY);
        let room = Arc::new(Room { sender, participants: Arc::new(Semaphore::new(MAX_PARTICIPANTS_PER_ROOM)), ingress: Mutex::new(RoomIngressQuota::new()) });
        rooms.insert(room_id.to_owned(), Arc::downgrade(&room));
        Ok(room)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn message_reaches_subscribers() {
        let rooms = Rooms::default();
        let room = rooms.join(ID).unwrap();
        let mut receiver = room.subscribe();
        let frame = vec![2u8; MIN_ENVELOPE_BYTES];
        room.publish(frame.clone()).unwrap();
        assert_eq!(receiver.recv().await.unwrap(), frame);
    }

    #[test]
    fn encrypted_replay_detects_gaps_restarts_and_future_cursors() {
        let rooms=Rooms::default();
        let room=rooms.join(ID).unwrap();
        let empty=room.replay_since(None).unwrap();
        assert_eq!(empty.latest_sequence,0);
        assert!(empty.frames.is_empty(),"no cursor may reveal historical frames");
        for i in 0..(MAX_REPLAY_FRAMES+3) {
            if i==MAX_REPLAY_FRAMES {
                // Advance only the test quota clock; the production limit
                // remains 64 incoming frames per second per room.
                room.ingress.lock().unwrap().started=
                    Instant::now()-Duration::from_secs(1);
            }
            room.publish(vec![3,MLS_KIND_APPLICATION,i as u8]).unwrap();
        }
        let snapshot=room.replay_since(None).unwrap();
        assert_eq!(snapshot.latest_sequence,(MAX_REPLAY_FRAMES+3) as u64);
        assert_eq!(snapshot.first_sequence,4);
        assert!(room.replay_since(Some((&snapshot.generation,0))).is_err(),
            "history truncation must fail closed, not skip a missed Commit");
        assert!(room.replay_since(Some(("00000000000000000000000000000000",snapshot.latest_sequence))).is_err());
        assert!(room.replay_since(Some((&snapshot.generation,snapshot.latest_sequence+1))).is_err());
        let replay=room.replay_since(Some((&snapshot.generation,3))).unwrap();
        assert_eq!(replay.frames.len(),MAX_REPLAY_FRAMES);
        assert!(replay.frames.iter().all(|frame|frame.wire_hex.starts_with("0301")));
        assert!(room.replay_since(Some((&snapshot.generation,snapshot.latest_sequence))).unwrap().frames.is_empty());
        drop(room);
        let recreated=rooms.join(ID).unwrap();
        assert!(recreated.replay_since(Some((&snapshot.generation,snapshot.latest_sequence))).is_err());
    }

    #[test]
    fn rejects_invalid_identifiers_and_frame_sizes() {
        let rooms = Rooms::default();
        assert!(rooms.join("../outside").is_err());
        assert!(rooms.join("ABCDEF0123456789ABCDEF0123456789").is_err());
        let room = rooms.join(ID).unwrap();
        assert!(room.publish(vec![]).is_err());
        assert!(room.publish(vec![2; MAX_FRAME_BYTES + 1]).is_err());
        assert!(room.publish(b"plaintext should not relay".to_vec()).is_err());
        assert!(room.publish(vec![0; MIN_ENVELOPE_BYTES]).is_err());
        assert!(room.publish(vec![2; MIN_ENVELOPE_BYTES - 1]).is_err());
        assert!(room.publish(vec![1; MIN_ENVELOPE_BYTES]).is_err());
        assert!(room.publish(vec![2; MIN_ENVELOPE_BYTES]).is_ok());
        let mls_room = rooms.join("ffffffffffffffffffffffffffffffff").unwrap();
        assert!(mls_room.publish(vec![3, MLS_KIND_APPLICATION, 42]).is_ok());
        assert!(mls_room.publish(vec![3, MLS_KIND_COMMIT, 42]).is_ok());
        assert!(mls_room.publish(vec![3, MLS_KIND_WELCOME, 42]).is_ok());
        assert!(mls_room.publish(vec![3, MLS_KIND_KEY_PACKAGE, 42]).is_ok());
        assert!(room.publish(vec![3, MLS_KIND_APPLICATION, 42]).is_err());
        assert!(mls_room.publish(vec![2; MIN_ENVELOPE_BYTES]).is_err());
        assert!(room.publish(vec![3, 0, 42]).is_err());
        assert!(room.publish(vec![3, 5, 42]).is_err());
        assert!(room.publish(vec![3, 1]).is_err());
        assert!(room.publish(vec![3, 1, 42].into_iter().chain(vec![0u8; MAX_FRAME_BYTES].into_iter()).collect()).is_err());
    }

    #[test]
    fn room_protocol_lock_is_independent_and_released_with_empty_room() {
        let rooms = Rooms::default();
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let group = rooms.join(id).unwrap();
        assert!(group.publish(vec![3, MLS_KIND_COMMIT, 1]).is_ok());
        assert_eq!(
            group.publish(vec![2; MIN_ENVELOPE_BYTES]).unwrap_err(),
            "room protocol version mismatch"
        );
        assert!(group.publish(vec![3, MLS_KIND_WELCOME, 1]).is_ok());
        drop(group);
        let replacement = rooms.join(id).unwrap();
        // In-memory room state is ephemeral; no protocol lock persists after
        // every participant has departed.
        assert!(replacement.publish(vec![2; MIN_ENVELOPE_BYTES]).is_ok());
        assert_eq!(
            replacement.publish(vec![3, MLS_KIND_COMMIT, 1]).unwrap_err(),
            "room protocol version mismatch"
        );
    }

    #[test]
    fn room_quota_blocks_collective_floods_and_recovers_after_window() {
        let room = Rooms::default().join(ID).unwrap();
        let packet = vec![2u8; MIN_ENVELOPE_BYTES];
        for _ in 0..MAX_ROOM_FRAMES_PER_SECOND {
            assert!(room.publish(packet.clone()).is_ok());
        }
        assert_eq!(room.publish(packet).unwrap_err(), "room publish quota exceeded");
        let mut ingress = room.ingress.lock().unwrap();
        let previous = ingress.started;
        assert!(!ingress.permit(previous + Duration::from_millis(999)));
        assert!(ingress.permit(previous + Duration::from_secs(1)));
    }

    #[test]
    fn enforces_room_limit_and_reclaims_inactive_rooms() {
        let rooms = Rooms::default();
        let mut active = Vec::new();
        for i in 0..MAX_ACTIVE_ROOMS {
            active.push(rooms.join(&format!("{i:032x}")).unwrap());
        }
        assert!(rooms.join(&format!("{:032x}", MAX_ACTIVE_ROOMS)).is_err());
        active.pop();
        assert!(rooms.join(&format!("{:032x}", MAX_ACTIVE_ROOMS)).is_ok());
    }

    #[test]
    fn room_has_sixteen_slots_and_releases_on_disconnect() {
        let room = Rooms::default().join(ID).unwrap();
        let mut participants = Vec::new();
        for _ in 0..MAX_PARTICIPANTS_PER_ROOM {
            participants.push(room.try_enter().unwrap());
        }
        assert!(room.try_enter().is_err());
        participants.pop();
        assert!(room.try_enter().is_ok());
    }

    #[test]
    fn independent_rooms_have_independent_limits() {
        let rooms = Rooms::default();
        let first = rooms.join(ID).unwrap();
        let another = rooms.join("ffffffffffffffffffffffffffffffff").unwrap();
        let _permits: Vec<_> = (0..MAX_PARTICIPANTS_PER_ROOM)
            .map(|_| first.try_enter().unwrap())
            .collect();
        assert!(first.try_enter().is_err());
        assert!(another.try_enter().is_ok());
    }

    #[test]
    fn releases_room_on_last_disconnect() {
        let rooms = Rooms::default();
        let first = rooms.join(ID).unwrap();
        let weak = Arc::downgrade(&first);
        let second = rooms.join(ID).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        drop(first);
        drop(second);
        assert!(weak.upgrade().is_none());
        assert!(rooms.join(ID).is_ok());
    }
}
