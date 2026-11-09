// Integration test for opaque MLS replay sequencing, NOT an MLS crypto test.
// Actual MLS authentication is exercised by browser-original-mls.mjs.
import assert from "node:assert/strict";
import {chromium} from "playwright";

const origin=process.env.PICTORUST_E2E_ORIGIN||"http://127.0.0.1:8787";
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
try{
  const page=await browser.newPage({ignoreHTTPSErrors:true});
  await page.goto(origin,{waitUntil:"domcontentloaded"});
  const result=await page.evaluate(async()=>{
    const created=await fetch("/new-room",{method:"POST"});
    if(!created.ok)throw Error("create room "+created.status);
    const {roomId,token}=await created.json();
    const replay=async (bearer,payload)=>{
      const response=await fetch("/mls/replay/"+roomId,{
        method:"POST",cache:"no-store",
        headers:{"Content-Type":"application/json","Authorization":"Bearer "+bearer},
        body:JSON.stringify(payload)
      });
      return {status:response.status,data:response.ok?await response.json():null};
    };
    const proto=location.protocol==="https:"?"wss://":"ws://";
    const socket=new WebSocket(proto+location.host+"/ws/"+roomId,
      ["picto.v1","auth."+token]);
    await new Promise((resolve,reject)=>{
      socket.onopen=resolve;socket.onerror=()=>reject(Error("socket denied"));
    });
    try{
      const initial=await replay(token,{});
      const missingToken=await fetch("/mls/replay/"+roomId,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:"{}"
      });
      // Test only transport framing; these are NOT valid MLS ciphertexts.
      const received=new Promise(resolve=>socket.onmessage=resolve);
      socket.send(new Uint8Array([3,1,42]));
      await received;
      const latest=await replay(token,{});
      const after=await replay(token,{
        generation:initial.data.generation,
        after_sequence:initial.data.latest_sequence
      });
      const wrongGeneration=await replay(token,{
        generation:"00000000000000000000000000000000",
        after_sequence:0
      });
      const future=await replay(token,{
        generation:latest.data.generation,
        after_sequence:9999
      });
      return {initial,latest,after,wrongGeneration,future,unauth:missingToken.status,
        cacheControl:created.headers.get("cache-control")};
    }finally{socket.close();}
  });
  assert.equal(result.initial.status,200);
  assert.equal(result.initial.data.latest_sequence,0);
  assert.deepEqual(result.initial.data.frames,[]);
  assert.equal(result.latest.status,200);
  assert.equal(result.latest.data.latest_sequence,1);
  assert.equal(result.after.status,200);
  assert.equal(result.after.data.frames.length,1);
  assert.equal(result.after.data.frames[0].sequence,1);
  assert.equal(result.after.data.frames[0].wire_hex,"03012a");
  assert.equal(result.unauth,403);
  assert.equal(result.wrongGeneration.status,409);
  assert.equal(result.future.status,409);
  console.log("Bounded encrypted replay cursor API: strict bearer, generation, sequence and gap checks passed");
}finally{await browser.close();}
