// Browser reboot + encrypted local MLS snapshot proof. This is NOT online
// recovery: restored MLS state is deliberately unsynchronized and cannot send.
import assert from "node:assert/strict";
import {chromium} from "playwright";
const base=process.env.PICTORUST_E2E_ORIGIN||"http://127.0.0.1:8787";
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
try{
  const page=await browser.newPage({ignoreHTTPSErrors:true});
  await page.goto(base,{waitUntil:"domcontentloaded"});
  const metadata=await page.evaluate(async()=>{
    const wasm=await import("/mls/pkg/pictorust_mls_web.js");
    await wasm.default();
    const client=new wasm.BrowserMlsClient("Sealed owner");
    client.start_group();
    const owner=client.members()[0].signatureKeyHex;
    const room=Array.from(crypto.getRandomValues(new Uint8Array(16)),
      byte=>byte.toString(16).padStart(2,"0")).join("");
    const second=new wasm.BrowserMlsClient("Sealed guest");
    const [commit,welcome,tree]=client.add_member(second.key_package());
    if(!commit.length)throw Error("owner commit missing");
    second.accept_welcome(welcome,tree);
    second.pin_owner(Uint8Array.from(owner.match(/../g).map(x=>parseInt(x,16))));
    const device=client.own_signature_key_hex();
    const otherDevice=second.own_signature_key_hex();
    if(device===otherDevice)throw Error("device identities collide");
    const checkpoint=client.checkpoint_plaintext();
    const guestCheckpoint=second.checkpoint_plaintext();
    const vault=await import("/mls/vault.mjs");
    const record={room,owner,device,epoch:Number(client.epoch()),sequence:5};
    await vault.saveSealedCheckpoint({...record,plaintext:checkpoint});
    await vault.saveSealedCheckpoint({...record,device:otherDevice,
      plaintext:guestCheckpoint,sequence:5});
    const sealed=await vault.readSealedCheckpoint({room,owner,device});
    const guest=await vault.readSealedCheckpoint({room,owner,device:otherDevice});
    if(sealed.synchronized!==false||guest.synchronized!==false)
      throw Error("vault cannot mark checkpoint verified");
    let rollbackDenied=false;
    try{await vault.saveSealedCheckpoint({...record,sequence:4,plaintext:checkpoint});}
    catch{rollbackDenied=true;}
    if(!rollbackDenied)throw Error("outdated local cursor was accepted");
    client.dispose();second.dispose();
    return {...record,otherDevice};
  });
  await page.reload({waitUntil:"domcontentloaded"});
  const after=await page.evaluate(async({room,owner,device,otherDevice})=>{
    const vault=await import("/mls/vault.mjs");
    const sealed=await vault.readSealedCheckpoint({room,owner,device});
    if(!sealed)return {present:false};
    const wasm=await import("/mls/pkg/pictorust_mls_web.js");
    await wasm.default();
    const otherSealed=await vault.readSealedCheckpoint({room,owner,device:otherDevice});
    const otherRestored=wasm.BrowserMlsClient.restore_checkpoint_untrusted(otherSealed.plaintext);
    const segregated=otherRestored.own_signature_key_hex()===otherDevice &&
      otherRestored.own_signature_key_hex()!==device;
    otherRestored.dispose();
    const restored=wasm.BrowserMlsClient.restore_checkpoint_untrusted(sealed.plaintext);
    const sameSigner=restored.members()[0].signatureKeyHex===owner;
    const epoch=Number(restored.epoch());
    const unsynchronized=!restored.synchronized();
    let blocked=false;
    try{restored.send(new TextEncoder().encode("must never send without catchup"));}
    catch{blocked=true;}
    restored.dispose();
    // Corrupt stored ciphertext; AES-GCM must reject it on the next read.
    const db=await new Promise((resolve,reject)=>{
      const req=indexedDB.open("pictorust-mls-checkpoint-v1");
      req.onsuccess=()=>resolve(req.result);
      req.onerror=()=>reject(req.error);
    });
    await new Promise((resolve,reject)=>{
      const tx=db.transaction("checkpoints","readwrite");
      const store=tx.objectStore("checkpoints");
      const key=room+":"+owner+":"+device;
      const get=store.get(key);
      get.onsuccess=()=>{
        const record=get.result;
        const bytes=new Uint8Array(record.ciphertext);
        bytes[0]^=1;
        record.ciphertext=bytes.buffer;
        store.put(record,key);
      };
      tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);
    });
    db.close();
    let tamperDenied=false;
    try{await vault.readSealedCheckpoint({room,owner,device});}
    catch{tamperDenied=true;}
    await vault.deleteSealedCheckpoint({room,owner,device});
    const deleted=await vault.readSealedCheckpoint({room,owner,device});
    return {present:true,sameSigner,segregated,epoch,unsynchronized,blocked,
      tamperDenied,deleted:deleted===null};
  },metadata);
  assert.equal(after.present,true);
  assert.equal(after.sameSigner,true);
  assert.equal(after.segregated,true,"different MLS devices must never overwrite one another");
  assert.equal(after.epoch,metadata.epoch);
  assert.equal(after.unsynchronized,true);
  assert.equal(after.blocked,true);
  assert.equal(after.tamperDenied,true);
  assert.equal(after.deleted,true);
  console.log("Browser MLS checkpoint: sealed IndexedDB survives refresh, rejects tampering and stale sends");
}finally{await browser.close();}
