// Regression: real OpenMLS is the invisible backend of the unchanged
// ORIGINAL Nintendo DS UI. Do not add or replace HTML controls for this test.
import assert from "node:assert/strict";
import {chromium} from "playwright";
import {mkdir} from "node:fs/promises";
const origin=process.env.PICTORUST_E2E_ORIGIN||"http://127.0.0.1:8787";
await mkdir("screenshots/mls", {recursive:true});
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
try{
 const ctx=await browser.newContext({ignoreHTTPSErrors:true,permissions:["clipboard-read","clipboard-write"],
   viewport:{width:1200,height:1000}});
 const alice=await ctx.newPage(), bob=await ctx.newPage();
 await bob.addInitScript(()=>{
   const Native=window.WebSocket;
   window.__pictorustTestSockets=[];
   window.__pictorustTestProtocols=[];
   window.WebSocket=class extends Native {
     constructor(url,protocols){
       super(url,protocols);
       window.__pictorustTestSockets.push(this);
       window.__pictorustTestProtocols.push([...protocols]);
     }
   };
 });
 const failures=[];
 for(const p of [alice,bob])p.on("pageerror",e=>failures.push(e.message));
 await alice.goto(origin,{waitUntil:"networkidle"});
 await alice.waitForFunction(()=>document.querySelectorAll("#touch-keys button[data-original-hitbox]").length===50);
 await alice.locator("#nickname").fill("Alice");
 await alice.locator("#new-room").click();
 await alice.waitForFunction(()=>document.querySelector("#token").value.length===64);
 await alice.locator("#connect").click();
 await alice.waitForFunction(()=>document.querySelector("#status").textContent.includes("MLS verschlüsselt"));
 await alice.locator("#security-panel summary").click();
 await alice.locator("#copy-invite").click();
 const invite=await alice.evaluate(()=>navigator.clipboard.readText());
 assert.match(invite,/#pictorust=mls1&room=/);
 assert.ok(!invite.includes("auth."),"never expose owner auth token");
 const ownerRoom=await alice.locator("#room").inputValue();
 // Delay the first owner poll so the guest receives several HTTP 202
 // responses before an authenticated Welcome exists.
 let slowedFirstPoll=false;
 await alice.route("**/mls/join/pending/**",async route=>{
   if(!slowedFirstPoll){
     slowedFirstPoll=true;
     await new Promise(resolve=>setTimeout(resolve,1750));
   }
   await route.continue();
 });
 await bob.goto(invite,{waitUntil:"domcontentloaded"});
 await bob.waitForFunction(()=>document.querySelector("#status").textContent.includes("Gruppenbeitritt erfolgreich"),null,{timeout:30000});
 assert.equal(await bob.locator("#room").inputValue(),ownerRoom);
 assert.equal(await bob.locator("#lobby").isHidden(),true);
 assert.equal(await alice.locator("#lobby").isHidden(),true);
 assert.equal(await bob.evaluate(()=>location.hash),"","invitation secret removed from address bar");

 for(const p of [alice,bob]){
   const geometry=await p.evaluate(()=>{
     const stage=document.querySelector("#picto").getBoundingClientRect();
     return {
       ratio:stage.width/stage.height,
       keys:document.querySelectorAll("#touch-keys button[data-original-hitbox]").length,
       rooms:Array.from(document.querySelectorAll("[data-room-letter]")).map(x=>x.dataset.roomLetter).join(""),
       hasOriginalScreens:!!document.querySelector("#picto > .top-screen")&&
          !!document.querySelector("#picto > .bottom-screen"),
       hasFakeStage:!!document.querySelector("#ds-stage")
     };
   });
   assert.ok(Math.abs(geometry.ratio-256/384)<0.01);
   assert.equal(geometry.keys,50);assert.equal(geometry.rooms,"ABCDE");
   assert.equal(geometry.hasOriginalScreens,true);assert.equal(geometry.hasFakeStage,false);
 }
 await alice.locator("#text").fill("OpenMLS Original ÄÖÜ ğışç 😊");
 await alice.locator("#send").click();
 await bob.locator("#messages").getByText("OpenMLS Original ÄÖÜ ğışç 😊").waitFor({timeout:12000});
 // Use the same original touch keyboard and original drawing canvas.
 // Independently prove the MLS reverse direction before testing drawn payloads.
 await bob.locator("#text").fill("MLS Rückkanal Bob nach Alice");
 await bob.locator("#send").click();
 await alice.locator("#messages").getByText("MLS Rückkanal Bob nach Alice").waitFor({timeout:12000});
 await bob.locator("#keyboard-mode").click();
 await bob.locator('#international-keys button[data-char="ğ"]').click();
 await bob.locator("#text").fill("Antwort ");
 await bob.locator('#international-keys button[data-char="ğ"]').click();
 await bob.locator("#pen-tool").click();
 const rect=await bob.locator("#drawing").boundingBox();
 assert.ok(rect);
 await bob.mouse.move(rect.x+20,rect.y+10);
 await bob.mouse.down();
 await bob.mouse.move(rect.x+100,rect.y+55,{steps:10});
 await bob.mouse.up();
 const draftText=await bob.locator("#text").inputValue();
 assert.equal(draftText,"Antwort ğ","original multilingual touch key must input into the real drawing draft");
 await bob.locator("#send").click();
 try{
   await alice.locator("#messages .entry img").first().waitFor({timeout:12000});
 }catch(e){
   console.error("MLS drawing diagnostic",JSON.stringify({
     bobStatus:await bob.locator("#status").textContent(),
     aliceStatus:await alice.locator("#status").textContent(),
     aliceMessages:await alice.locator("#messages").textContent(),
     bobText:await bob.locator("#text").inputValue()
   }));
   throw e;
 }
 assert.ok((await alice.locator("#messages").textContent()).includes("Antwort ğ"));
 const nickname=await alice.locator("#messages .entry").last().locator(".who").textContent();
 assert.equal(nickname,"Gast"); // Bob intentionally kept the default nickname
 // Print must keep original raster exporter, not new HTML cards.
 await alice.evaluate(()=>{window.print=()=>{};});
 await alice.locator("#pdf").click();
 await alice.waitForFunction(()=>document.querySelectorAll("#pixel-print .pixel-page").length>=1);
 await alice.locator("#picto").screenshot({path:"screenshots/mls/mls-original-ui-authenticated.png",
   animations:"disabled"});
 // Simulate a genuine lost transport while the owner remains online.
 // Rejoin MUST rotate the guest's MLS identity, remove its old leaf,
 // revoke its old WebSocket bearer and verify the owner again.
 const oldBearer=await bob.evaluate(()=>window.__pictorustTestProtocols[0][1]);
 assert.match(oldBearer,/^auth\.[0-9a-f]{64}$/);
 await bob.evaluate(()=>window.__pictorustTestSockets[0].close(4001,"transport-interruption"));
 await bob.waitForFunction(()=>document.querySelector("#status").textContent.includes("MLS wiederverbunden"),
   null,{timeout:45000});
 const newBearer=await bob.evaluate(()=>window.__pictorustTestProtocols.at(-1)[1]);
 assert.match(newBearer,/^auth\.[0-9a-f]{64}$/);
 assert.notEqual(newBearer,oldBearer,"a rejoin must receive a fresh relay bearer");
 const revokedRejected=await bob.evaluate(({room,oldBearer})=>new Promise(resolve=>{
   const url=(location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws/"+room;
   const socket=new WebSocket(url,["picto.v1",oldBearer]);
   const timeout=setTimeout(()=>{socket.close();resolve(false);},5000);
   socket.onerror=()=>{clearTimeout(timeout);resolve(true);};
   socket.onopen=()=>{clearTimeout(timeout);socket.close();resolve(false);};
 }),{room:ownerRoom,oldBearer});
 assert.equal(revokedRejected,true,"old member token must be revoked during rejoin");
 await alice.locator("#text").fill("Wiederherstellung mit neuer MLS-Epoche");
 await alice.locator("#send").click();
 await bob.locator("#messages").getByText("Wiederherstellung mit neuer MLS-Epoche")
   .waitFor({timeout:12000});
 await bob.locator("#text").fill("Antwort nach sicherer Wiederverbindung");
 await bob.locator("#send").click();
 await alice.locator("#messages").getByText("Antwort nach sicherer Wiederverbindung")
   .waitFor({timeout:12000});
 // A storage failure must halt the real original chat BEFORE transmission:
 // its ratchet advanced, so plaintext must never be sent with unsafe state.
 await alice.evaluate(()=>{
   window.indexedDB.open=()=>{throw Error("simulated encrypted vault outage");};
 });
 await alice.locator("#text").fill("MUST NOT REACH BOB");
 await alice.locator("#send").click();
 await alice.waitForFunction(()=>document.querySelector("#status").textContent.includes("Checkpoint"),
   null,{timeout:12000});
 assert.equal(await alice.locator("#text").inputValue(),"MUST NOT REACH BOB",
   "unsafe MLS send must keep the original text draft for the user");
 assert.equal((await bob.locator("#messages").textContent()).includes("MUST NOT REACH BOB"),false,
   "a failed durable checkpoint MUST NOT transmit MLS ciphertext");
 assert.deepEqual(failures,[]);
 console.log("OpenMLS behind unchanged original DS UI: invitation, text, drawings, PDF and authenticated fresh-key recovery passed");
}finally{await browser.close();}
