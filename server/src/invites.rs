//! Volatile invitation handoff. The broker never decrypts an MLS Welcome
//! or owns an MLS group key. URLs contain the random joining secret only
//! in the fragment; clients POST it in a same-origin request body.
//! This is a local experimental transport, not an authenticated identity directory.
use std::{collections::HashMap, sync::Mutex, time::{Duration,Instant}};
use rand::{rngs::OsRng,RngCore};
use sha2::{Digest,Sha256};

const MAX_ROOMS: usize=256;
const MAX_PENDING: usize=12;
const MAX_REQUEST_BYTES: usize=12000;
const MAX_WELCOME_BYTES: usize=32000;
const REQUEST_LIFETIME: Duration=Duration::from_secs(120);

struct Request {
    id: String,
    key_package: String,
    created: Instant,
    result: Option<String>,
    delivered: bool,
    previous_leaf: Option<u32>,
}

struct Invitation {
    digest: [u8;32],
    requests: Vec<Request>,
}

#[derive(Default)]
pub struct InviteBroker { rooms: Mutex<HashMap<String,Invitation>> }

impl InviteBroker {
    pub fn register(&self,room:&str,secret:&str)->Result<(),&'static str>{
        if !pictochat_relay::auth::valid_room_id(room) || !valid_hex(secret,64){
            return Err("invalid invitation registration");
        }
        let digest: [u8;32]=Sha256::digest(hex::decode(secret).map_err(|_|"invalid secret")?).into();
        let mut rooms=self.rooms.lock().map_err(|_|"lock poisoned")?;
        if !rooms.contains_key(room) && rooms.len()>=MAX_ROOMS {return Err("invitation capacity");}
        rooms.insert(room.into(),Invitation{digest,requests:Vec::new()});
        Ok(())
    }

    pub fn request(&self,room:&str,secret:&str,key_package:&str,previous_leaf:Option<u32>)->Result<String,&'static str>{
        if !valid_hex(secret,64) || key_package.is_empty() ||
           key_package.len()>MAX_REQUEST_BYTES || !key_package.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'+' || b==b'/' || b==b'='){
            return Err("invalid join request");
        }
        let digest: [u8;32]=Sha256::digest(hex::decode(secret).map_err(|_|"bad secret")?).into();
        let mut rooms=self.rooms.lock().map_err(|_|"lock poisoned")?;
        let invite=rooms.get_mut(room).ok_or("invitation missing")?;
        if invite.digest!=digest {return Err("invalid invitation");}
        invite.requests.retain(|r|r.created.elapsed()<REQUEST_LIFETIME);
        if invite.requests.len()>=MAX_PENDING {return Err("pending join capacity");}
        if let Some(leaf)=previous_leaf {
            if leaf==0 || invite.requests.iter().any(|r|
               r.previous_leaf==Some(leaf)) {
                return Err("duplicate or invalid rejoin leaf");
            }
        }
        let mut bytes=[0u8;16];OsRng.fill_bytes(&mut bytes);
        let id=hex::encode(bytes);
        invite.requests.push(Request{id:id.clone(),key_package:key_package.into(),created:Instant::now(),result:None,delivered:false,previous_leaf});
        Ok(id)
    }

    pub fn pending(&self,room:&str)->Vec<(String,String,Option<u32>)>{
        let Ok(mut rooms)=self.rooms.lock() else {return Vec::new()};
        let Some(invite)=rooms.get_mut(room) else {return Vec::new()};
        invite.requests.retain(|r|r.created.elapsed()<REQUEST_LIFETIME);
        invite.requests.iter().filter(|r|!r.delivered && r.result.is_none()).map(|r|(r.id.clone(),r.key_package.clone(),r.previous_leaf)).collect()
    }

    pub fn complete(&self,room:&str,id:&str,result:&str)->Result<(),&'static str>{
        if !valid_hex(id,32)||result.is_empty()||result.len()>MAX_WELCOME_BYTES{return Err("invalid completion");}
        let mut rooms=self.rooms.lock().map_err(|_|"lock poisoned")?;
        let invite=rooms.get_mut(room).ok_or("unknown invitation")?;
        let r=invite.requests.iter_mut().find(|r|r.id==id && r.created.elapsed()<REQUEST_LIFETIME)
            .ok_or("unknown request")?;
        if r.delivered || r.result.is_some(){return Err("already completed");}
        r.result=Some(result.into());
        Ok(())
    }

    pub fn result(&self,room:&str,id:&str,secret:&str)->Result<Option<String>,&'static str>{
        if !valid_hex(id,32)||!valid_hex(secret,64){return Err("bad credentials");}
        let digest:[u8;32]=Sha256::digest(hex::decode(secret).map_err(|_|"bad secret")?).into();
        let mut rooms=self.rooms.lock().map_err(|_|"lock poisoned")?;
        let invite=rooms.get_mut(room).ok_or("not found")?;
        if invite.digest!=digest{return Err("bad invitation");}
        let r=invite.requests.iter_mut().find(|r|r.id==id && r.created.elapsed()<REQUEST_LIFETIME)
            .ok_or("expired request")?;
        let delivered=r.result.take();
        if delivered.is_some(){r.delivered=true;}
        Ok(delivered)
    }
}
fn valid_hex(s:&str,len:usize)->bool{s.len()==len && s.bytes().all(|b|b.is_ascii_hexdigit())}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn authenticated_join_is_bounded_expires_and_delivers_once(){
        let b=InviteBroker::default();
        let room="0123456789abcdef0123456789abcdef";
        let secret="ab".repeat(32);
        b.register(room,&secret).unwrap();
        assert!(b.request(room,&"cd".repeat(32),"AQID",None).is_err());
        let id=b.request(room,&secret,"AQID",None).unwrap();
        assert_eq!(b.pending(room).len(),1);
        assert!(b.result(room,&id,&"cd".repeat(32)).is_err());
        b.complete(room,&id,r#"{"welcome":"AQID"}"#).unwrap();
        assert!(b.complete(room,&id,"duplicate").is_err());
        assert_eq!(b.result(room,&id,&secret).unwrap(),Some(r#"{"welcome":"AQID"}"#.into()));
        assert_eq!(b.result(room,&id,&secret).unwrap(),None);
        assert_eq!(b.pending(room).len(),0,"a consumed Welcome must never reappear as a pending join");
        assert!(b.complete(room,&id,"replay").is_err());
        let resume=b.request(room,&secret,"BAUG",Some(2)).unwrap();
        assert!(b.request(room,&secret,"BwgJ",Some(2)).is_err(),
            "same old bearer cannot start concurrent group rejoin requests");
        assert!(b.pending(room).iter().any(|r|r.0==resume && r.2==Some(2)));
    }
}
