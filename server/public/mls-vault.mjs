// PictoRust P0 research: encrypted local checkpoint vault, NOT active MLS
// session recovery. Never release a restored MLS group for sending until
// authenticated catch-up proves that its epoch and delivery cursor are current.
// This protects stolen disk snapshots, not scripts running in this origin,
// device compromise, or full IndexedDB rollback.
const DB_NAME="pictorust-mls-checkpoint-v1";
const DB_VERSION=1, MAX_BYTES=2*1024*1024;
const encode=new TextEncoder();
const hex32=/^[0-9a-f]{32}$/, hex64=/^[0-9a-f]{64}$/;
function requireSecure(){
  if(!globalThis.isSecureContext||!crypto?.subtle||!navigator.locks)
    throw Error("Secure context, WebCrypto and Web Locks required");
}
function checkInfo({room,owner,epoch,sequence}){
  if(!hex32.test(room)||!hex64.test(owner)||
    !Number.isSafeInteger(epoch)||epoch<0||
    !Number.isSafeInteger(sequence)||sequence<0)
    throw Error("Invalid MLS checkpoint binding");
}
function req(request){
  return new Promise((resolve,reject)=>{
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error||Error("IndexedDB request failed"));
  });
}
function finished(tx){
  return new Promise((resolve,reject)=>{
    tx.oncomplete=()=>resolve();
    tx.onerror=()=>reject(tx.error||Error("IndexedDB transaction failed"));
    tx.onabort=()=>reject(tx.error||Error("IndexedDB transaction aborted"));
  });
}
function openDb(){
  requireSecure();
  return new Promise((resolve,reject)=>{
    const r=indexedDB.open(DB_NAME,DB_VERSION);
    r.onupgradeneeded=()=>{
      const db=r.result;
      if(!db.objectStoreNames.contains("keys"))
        db.createObjectStore("keys");
      if(!db.objectStoreNames.contains("checkpoints"))
        db.createObjectStore("checkpoints");
    };
    r.onsuccess=()=>resolve(r.result);
    r.onerror=()=>reject(r.error||Error("IndexedDB open failed"));
    r.onblocked=()=>reject(Error("Another tab blocks checkpoint storage"));
  });
}
async function deviceKey(db){
  const tx=db.transaction("keys","readonly");
  const saved=await req(tx.objectStore("keys").get("device"));
  if(saved)return saved;
  // Key generation stays on the endpoint. A non-extractable CryptoKey is
  // serialized by IndexedDB's structured clone; never convert it to raw bytes.
  const key=await crypto.subtle.generateKey({name:"AES-GCM",length:256},
    false,["encrypt","decrypt"]);
  const put=db.transaction("keys","readwrite");
  const existing=await req(put.objectStore("keys").get("device"));
  if(existing){await finished(put);return existing;}
  put.objectStore("keys").put(key,"device");
  await finished(put);
  return key;
}
const recordId=(room,owner)=>room+":"+owner;
const aad=meta=>encode.encode(JSON.stringify({
  product:"PictoRust MLS checkpoint",version:1,
  origin:location.origin,room:meta.room,owner:meta.owner,
  epoch:meta.epoch,sequence:meta.sequence
}));
function validateRecord(record,expected){
  if(!record||record.version!==1||record.room!==expected.room||
    record.owner!==expected.owner||record.origin!==location.origin||
    !(record.iv instanceof Uint8Array)||
    !(record.ciphertext instanceof ArrayBuffer)||
    record.iv.length!==12||record.ciphertext.byteLength>MAX_BYTES+16)
    throw Error("Invalid sealed checkpoint metadata");
  checkInfo(record);
}
export async function saveSealedCheckpoint({room,owner,epoch,sequence,plaintext}){
  requireSecure();checkInfo({room,owner,epoch,sequence});
  if(!(plaintext instanceof Uint8Array)||plaintext.length===0||
    plaintext.length>MAX_BYTES)throw Error("MLS checkpoint has invalid length");
  return navigator.locks.request("pictorust-vault:"+room,async()=>{
    const db=await openDb();
    try{
      const key=await deviceKey(db);
      const previous=await req(db.transaction("checkpoints","readonly")
        .objectStore("checkpoints").get(recordId(room,owner)));
      if(previous){
        validateRecord(previous,{room,owner});
        if(epoch<previous.epoch||sequence<previous.sequence)
          throw Error("Local MLS checkpoint rollback denied");
      }
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const meta={room,owner,epoch,sequence};
      const ciphertext=await crypto.subtle.encrypt(
        {name:"AES-GCM",iv,additionalData:aad(meta)},key,plaintext);
      const tx=db.transaction("checkpoints","readwrite");
      tx.objectStore("checkpoints").put({
        version:1,origin:location.origin,...meta,iv,ciphertext
      },recordId(room,owner));
      await finished(tx);
    }finally{db.close();}
  });
}
export async function readSealedCheckpoint({room,owner}){
  requireSecure();
  if(!hex32.test(room)||!hex64.test(owner))
    throw Error("Invalid MLS checkpoint identity");
  return navigator.locks.request("pictorust-vault:"+room,async()=>{
    const db=await openDb();
    try{
      const record=await req(db.transaction("checkpoints","readonly")
        .objectStore("checkpoints").get(recordId(room,owner)));
      if(!record)return null;
      validateRecord(record,{room,owner});
      const key=await deviceKey(db);
      let bytes;
      try{
        bytes=await crypto.subtle.decrypt(
          {name:"AES-GCM",iv:record.iv,additionalData:aad(record)},
          key,record.ciphertext);
      }catch{
        throw Error("Stored MLS checkpoint authentication failed");
      }
      if(bytes.byteLength===0||bytes.byteLength>MAX_BYTES)
        throw Error("Restored MLS checkpoint size rejected");
      return {plaintext:new Uint8Array(bytes),epoch:record.epoch,
        sequence:record.sequence,synchronized:false};
    }finally{db.close();}
  });
}
export async function deleteSealedCheckpoint({room,owner}){
  requireSecure();
  if(!hex32.test(room)||!hex64.test(owner))
    throw Error("Invalid MLS checkpoint identity");
  return navigator.locks.request("pictorust-vault:"+room,async()=>{
    const db=await openDb();
    try{
      const tx=db.transaction("checkpoints","readwrite");
      tx.objectStore("checkpoints").delete(recordId(room,owner));
      await finished(tx);
    }finally{db.close();}
  });
}
