//! **Internal-only** checkpoint provider for MLS recovery research.
//! This does not encrypt its snapshots. Never expose them to a server,
//! localStorage, logs, diagnostic dumps, or an untrusted JS caller.
//! The calling browser storage layer must provide transactional AEAD at rest,
//! anti-rollback and an authenticated catch-up BEFORE reenabling the session.
use openmls_rust_crypto::{MemoryStorage,RustCrypto};
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize,Serialize};

const MAX_CHECKPOINT_BYTES: usize=2*1024*1024;
const MAX_ENTRIES: usize=4096;

#[derive(Default,Debug)]
pub struct CheckpointProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for CheckpointProvider {
    type CryptoProvider=RustCrypto;
    type RandProvider=RustCrypto;
    type StorageProvider=MemoryStorage;
    fn crypto(&self)->&Self::CryptoProvider {&self.crypto}
    fn rand(&self)->&Self::RandProvider {&self.crypto}
    fn storage(&self)->&Self::StorageProvider {&self.storage}
}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub version: u32,
    pub label: Vec<u8>,
    pub signer: serde_json::Value,
    pub group_id: Vec<u8>,
    pub owner_key: Option<Vec<u8>>,
    pub storage: Vec<(Vec<u8>,Vec<u8>)>,
}

impl CheckpointProvider {
    pub(crate) fn keys(&self)->Result<Vec<(Vec<u8>,Vec<u8>)>,&'static str>{
        let values=self.storage.values.read().map_err(|_|"checkpoint storage poisoned")?;
        if values.len()>MAX_ENTRIES{return Err("checkpoint entries exceeded");}
        Ok(values.iter().map(|(k,v)|(k.clone(),v.clone())).collect())
    }

    pub(crate) fn from_keys(keys:Vec<(Vec<u8>,Vec<u8>)>)->Result<Self,&'static str>{
        if keys.len()>MAX_ENTRIES{return Err("checkpoint entries exceeded");}
        let provider=Self::default();
        {
            let mut store=provider.storage.values.write()
                .map_err(|_|"checkpoint storage poisoned")?;
            for (key,value) in keys {
                if key.is_empty()||key.len()>4096||value.len()>MAX_CHECKPOINT_BYTES ||
                   store.contains_key(&key) {
                    return Err("duplicate or invalid storage checkpoint entry");
                }
                store.insert(key,value);
            }
        }
        Ok(provider)
    }
}

impl Checkpoint {
    pub(crate) fn encode(&self)->Result<Vec<u8>,&'static str>{
        let bytes=serde_json::to_vec(self).map_err(|_|"checkpoint serialization failed")?;
        if bytes.len()>MAX_CHECKPOINT_BYTES{return Err("checkpoint too large");}
        Ok(bytes)
    }
    pub(crate) fn decode(bytes:&[u8])->Result<Self,&'static str>{
        if bytes.is_empty()||bytes.len()>MAX_CHECKPOINT_BYTES{
            return Err("checkpoint malformed or oversized");
        }
        let state:Self=serde_json::from_slice(bytes)
            .map_err(|_|"checkpoint parsing failed")?;
        if state.version!=1||state.label.is_empty()||state.label.len()>64 ||
            state.group_id.is_empty()||state.group_id.len()>128 ||
            state.storage.len()>MAX_ENTRIES ||
            state.owner_key.as_ref().is_some_and(|key|key.len()!=32){
            return Err("invalid checkpoint metadata");
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_untrusted_raw_checkpoint_payloads(){
        assert!(Checkpoint::decode(&[]).is_err());
        assert!(Checkpoint::decode(b"{}").is_err());
        assert!(Checkpoint::decode(&vec![0u8;MAX_CHECKPOINT_BYTES+1]).is_err());
        assert!(CheckpointProvider::from_keys(vec![(b"a".to_vec(),b"x".to_vec()),
            (b"a".to_vec(),b"y".to_vec())]).is_err());
    }
}
