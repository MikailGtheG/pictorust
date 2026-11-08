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
 assert.deepEqual(failures,[]);
 console.log("OpenMLS behind unchanged original DS UI: invitation, text, drawings and PDF passed");
}finally{await browser.close();}
