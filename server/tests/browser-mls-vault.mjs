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
    const checkpoint=client.checkpoint_plaintext();
    const vault=await import("/mls/vault.mjs");
    const record={room,owner,epoch:Number(client.epoch()),sequence:5};
    await vault.saveSealedCheckpoint({...record,plaintext:checkpoint});
    const sealed=await vault.readSealedCheckpoint({room,owner});
    if(sealed.synchronized!==false)throw Error("vault cannot mark checkpoint verified");
    let rollbackDenied=false;
    try{await vault.saveSealedCheckpoint({...record,sequence:4,plaintext:checkpoint});}
    catch{rollbackDenied=true;}
    if(!rollbackDenied)throw Error("outdated local cursor was accepted");
    client.dispose();
    return record;
  });
  await page.reload({waitUntil:"domcontentloaded"});
  const after=await page.evaluate(async({room,owner})=>{
    const vault=await import("/mls/vault.mjs");
    const sealed=await vault.readSealedCheckpoint({room,owner});
    if(!sealed)return {present:false};
    const wasm=await import("/mls/pkg/pictorust_mls_web.js");
    await wasm.default();
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
      const key=room+":"+owner;
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
    try{await vault.readSealedCheckpoint({room,owner});}
    catch{tamperDenied=true;}
    await vault.deleteSealedCheckpoint({room,owner});
    const deleted=await vault.readSealedCheckpoint({room,owner});
    return {present:true,sameSigner,epoch,unsynchronized,blocked,
      tamperDenied,deleted:deleted===null};
  },metadata);
  assert.equal(after.present,true);
  assert.equal(after.sameSigner,true);
  assert.equal(after.epoch,metadata.epoch);
  assert.equal(after.unsynchronized,true);
  assert.equal(after.blocked,true);
  assert.equal(after.tamperDenied,true);
  assert.equal(after.deleted,true);
  console.log("Browser MLS checkpoint: sealed IndexedDB survives refresh, rejects tampering and stale sends");
}finally{await browser.close();}
