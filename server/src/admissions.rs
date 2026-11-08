//! Ephemeral per-device bearer admission for the local MLS test transport.
//! Cryptographic group membership is still decided by OpenMLS at endpoints.
//! This layer revokes relay access for evicted participants.
use std::{collections::HashMap, sync::Mutex};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

pub const MAX_DEVICE_TOKENS_PER_ROOM: usize = 16;
pub const MAX_TOKEN_ROOMS: usize = 256;

struct MemberToken {
    digest: [u8;32],
    leaf: u32,
    killed: watch::Sender<bool>,
}

#[derive(Default)]
pub struct MembershipAdmissions {
    rooms: Mutex<HashMap<String, Vec<MemberToken>>>,
}

fn digest_token(token: &str) -> Option<[u8;32]> {
    if token.len()!=64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes=hex::decode(token).ok()?;
    Some(Sha256::digest(bytes).into())
}

impl MembershipAdmissions {
    pub fn mint(&self, room: &str, leaf: u32) -> Result<String,&'static str> {
        if !pictochat_relay::auth::valid_room_id(room) || leaf==0 { return Err("invalid member admission"); }
        let mut all=self.rooms.lock().map_err(|_|"admission lock poisoned")?;
        if !all.contains_key(room) && all.len()>=MAX_TOKEN_ROOMS {return Err("too many token rooms");}
        let entries=all.entry(room.to_owned()).or_default();
        if entries.len()>=MAX_DEVICE_TOKENS_PER_ROOM {return Err("too many member tokens");}
        if entries.iter().any(|item| item.leaf==leaf) {return Err("member token already exists");}
        let mut secret=[0u8;32];OsRng.fill_bytes(&mut secret);
        let digest=Sha256::digest(secret).into();
        let (killed,_)=watch::channel(false);
        entries.push(MemberToken{digest,leaf,killed});
        let result=hex::encode(secret);
        secret.fill(0);
        Ok(result)
    }

    pub fn verify(&self, room: &str, token: &str) -> Option<watch::Receiver<bool>> {
        let digest=digest_token(token)?;
        let all=self.rooms.lock().ok()?;
        let candidate=all.get(room)?.iter().find(|entry| entry.digest==digest)?;
        let receiver=candidate.killed.subscribe();
        if *receiver.borrow() {return None;}
        Some(receiver)
    }

    pub fn revoke(&self, room: &str, leaf: u32) -> bool {
        let Ok(mut all)=self.rooms.lock() else {return false;};
        let Some(tokens)=all.get_mut(room) else {return false;};
        let Some(index)=tokens.iter().position(|member|member.leaf==leaf) else {return false;};
        let token=tokens.swap_remove(index);
        token.killed.send_replace(true);
        if tokens.is_empty(){all.remove(room);}
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn minted_token_is_room_scoped_and_revocation_closes_existing_watchers() {
        let registry=MembershipAdmissions::default();
        let room="0123456789abcdef0123456789abcdef";
        let other="ffffffffffffffffffffffffffffffff";
        let invite=registry.mint(room,1).unwrap();
        assert_eq!(invite.len(),64);
        assert!(registry.verify(room,&invite).is_some());
        assert!(registry.verify(other,&invite).is_none());
        assert!(registry.verify(room,&"00".repeat(32)).is_none());
        assert!(registry.mint(room,1).is_err());
        let mut subscriber=registry.verify(room,&invite).unwrap();
        assert!(!*subscriber.borrow());
        assert!(registry.revoke(room,1));
        subscriber.changed().await.unwrap();
        assert!(*subscriber.borrow_and_update());
        assert!(registry.verify(room,&invite).is_none());
        assert!(!registry.revoke(room,1));
        assert!(registry.mint(room,1).is_ok());
    }

    #[test]
    fn tokens_are_unique_and_owner_leaf_cannot_be_minted() {
        let registry=MembershipAdmissions::default();
        let id="0123456789abcdef0123456789abcdef";
        assert!(registry.mint(id,0).is_err());
        let a=registry.mint(id,1).unwrap();
        let b=registry.mint(id,2).unwrap();
        assert_ne!(a,b);
        assert!(registry.verify(id,&a).is_some());
        assert!(registry.verify(id,&b).is_some());
    }
}
