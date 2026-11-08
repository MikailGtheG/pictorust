// Actual three-browser OpenMLS over WASM + real Rust relay.
// This is a local integration test, not an independent cryptographic audit.
import assert from "node:assert/strict";
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
const dir=process.env.PICTORUST_MLS_SCREENSHOTS||"screenshots/mls";
await mkdir(dir,{recursive:true});
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
const failures=[];
let alice=null,bob=null,charlie=null;
try {
  const context=await browser.newContext({viewport:{width:1050,height:960}});
  alice=await context.newPage();
  bob=await context.newPage();
  for(const p of [alice,bob])p.on("pageerror",err=>failures.push(err.message));
  await Promise.all([alice.goto("http://127.0.0.1:8787/mls"),bob.goto("http://127.0.0.1:8787/mls")]);
  await Promise.all([alice.locator("#own-package").inputValue().then(v=>assert.ok(v.length>100)),
    bob.locator("#own-package").inputValue().then(v=>assert.ok(v.length>100))]);
  await alice.locator("#name").fill("Alice");
  await alice.locator("#name").dispatchEvent("change");
  await bob.locator("#name").fill("Bob");
  await bob.locator("#name").dispatchEvent("change");
  await alice.locator("#mine").waitFor();
  await alice.locator("#new-room").click();
  await alice.waitForFunction(()=>document.getElementById("room").value.length===32);
  const id=await alice.locator("#room").inputValue();
  const token=await alice.locator("#token").inputValue();
  await bob.locator("#room").fill(id);
  await alice.locator("#start").click();
  await alice.waitForFunction(()=>document.querySelector("#status").textContent.includes("MLS-Epoche"));
  const ownerSigner=await alice.locator("#own-signer").inputValue();
  assert.match(ownerSigner,/^[0-9a-f]{64}$/);
  const key=await bob.locator("#own-package").inputValue();
  const fingerprint=await bob.locator("#mine").inputValue();
  await alice.locator("#invite-package").fill(key);
  await alice.locator("#verified-fingerprint").fill(fingerprint);
  await alice.locator("#admit").click();
  await alice.waitForFunction(()=>document.querySelector("#issued-welcome").value.includes("welcome"));
  const invite=await alice.locator("#issued-welcome").inputValue();
  await bob.locator("#welcome").fill(invite);
  await bob.locator("#trusted-owner").fill(ownerSigner);
  await bob.locator("#join").click();
  await bob.waitForFunction(()=>document.querySelector("#status").textContent.includes("2 Mitglied"));
  const bobToken=await bob.locator("#token").inputValue();
  assert.match(bobToken,/^[0-9a-f]{64}$/);
  assert.notEqual(bobToken,token,"owner bearer must not be shared with Bob");
  // Add a third independent browser and confirm existing Bob consumes the
  // authenticated owner's Add Commit before Charlie processes Welcome.
  charlie=await context.newPage();
  charlie.on("pageerror",err=>failures.push(err.message));
  await charlie.goto("http://127.0.0.1:8787/mls");
  await charlie.waitForFunction(()=>document.getElementById("own-package").value.length>100);
  await charlie.locator("#name").fill("Charlie");
  await charlie.locator("#name").dispatchEvent("change");
  await charlie.locator("#room").fill(id);
  await charlie.waitForFunction(()=>document.getElementById("mine").value.length===64);
  await alice.locator("#invite-package").fill(await charlie.locator("#own-package").inputValue());
  await alice.locator("#verified-fingerprint").fill(await charlie.locator("#mine").inputValue());
  await alice.locator("#issued-welcome").evaluate(el => { el.value=""; });
  await alice.locator("#admit").click();
  await alice.waitForFunction(()=>document.getElementById("issued-welcome").value.includes("welcome"));
  await bob.waitForFunction(()=>document.querySelectorAll("#members p").length===3);
  await charlie.locator("#welcome").fill(await alice.locator("#issued-welcome").inputValue());
  await charlie.locator("#trusted-owner").fill(ownerSigner);
  await charlie.locator("#join").click();
  await charlie.waitForFunction(()=>document.querySelectorAll("#members p").length===3);
  const charlieToken=await charlie.locator("#token").inputValue();
  assert.notEqual(charlieToken,token);
  assert.notEqual(charlieToken,bobToken);
  const unauthorizedRevoke=await charlie.evaluate(async(room)=>{
    const r=await fetch(`/mls/revoke/${room}/1`,{
      method:"POST",headers:{Authorization:"Bearer "+document.querySelector("#token").value}
    });
    return r.status;
  },id);
  assert.equal(unauthorizedRevoke,403,"member cannot revoke other relay tokens");
  await alice.locator("#message").fill("MLS: Hallo ÄÖÜ ğışç 😊");
  await alice.locator("#send").click();
  await bob.locator("#feed").getByText("MLS: Hallo ÄÖÜ ğışç 😊").waitFor({timeout:15000});
  await charlie.locator("#feed").getByText("MLS: Hallo ÄÖÜ ğışç 😊").waitFor({timeout:15000});
  // Original DS UI is no longer a placeholder: the actual MLS messages
  // must appear within the sprite-backed top screen.
  const stage=await alice.locator("#ds-stage").evaluate(element=>{
    const bg=getComputedStyle(element).backgroundImage;
    const feed=document.querySelector("#feed").getBoundingClientRect();
    const outer=element.getBoundingClientRect();
    return {background:bg,width:outer.width,height:outer.height,feedInside:feed.top>=outer.top && feed.bottom<=outer.bottom};
  });
  assert.match(stage.background,/\/original\/images\/background\.png/);
  assert.ok(Math.abs(stage.width/stage.height-256/384)<0.01);
  assert.equal(stage.feedInside,true);

  // The lower DS screen must send real encrypted drawings, not just text.
  await alice.locator("#mls-pen-tool").click();
  const drawing=alice.locator("#mls-drawing");
  const rect=await drawing.boundingBox();
  assert.ok(rect);
  await alice.mouse.move(rect.x+20,rect.y+20);
  await alice.mouse.down();
  await alice.mouse.move(rect.x+80,rect.y+55,{steps:8});
  await alice.mouse.up();
  await alice.locator("#mls-text-tool").click();
  await alice.locator("#message").fill("MLS Zeichnung");
  await alice.locator("#send").click();
  await bob.locator("#feed .entry").filter({hasText:"MLS Zeichnung"}).locator("img").waitFor({timeout:15000});
  const drawingPixel=await bob.locator("#feed .entry").filter({hasText:"MLS Zeichnung"}).locator("img").evaluate(img=>img.naturalWidth);
  assert.equal(drawingPixel,512);

  // Reuse original sprite PDF renderer; the MLS history remains in memory.
  await alice.evaluate(()=>{window.print=()=>{};});
  await alice.locator("#mls-pdf").click();
  await alice.waitForFunction(()=>document.querySelectorAll("#pixel-print .pixel-page").length>=1);
  const pdfImages=await alice.locator("#pixel-print .pixel-page").count();
  assert.ok(pdfImages>=1);
  await alice.emulateMedia({media:"print"});
  await alice.pdf({path:`${dir}/mls-original-pixel-chat.pdf`,
    printBackground:true,preferCSSPageSize:true,scale:1});
  await alice.emulateMedia({media:"screen"});
  await alice.locator("#ds-stage").screenshot({path:`${dir}/mls-original-ds-stage.png`,animations:"disabled"});
  // Never leak even synthetic admission capabilities in published screenshots.
  for(const page of [alice,bob,charlie]){
    await page.addStyleTag({content:"#token,#issued-welcome,#welcome,#own-package,#invite-package{filter:blur(14px)}"});
  }
  await alice.screenshot({path:`${dir}/mls-alice-group.png`,fullPage:true});
  await bob.screenshot({path:`${dir}/mls-bob-group.png`,fullPage:true});
  await charlie.screenshot({path:`${dir}/mls-charlie-group.png`,fullPage:true});
  const bobSigner=await bob.locator("#own-signer").inputValue();
  assert.match(bobSigner,/^[0-9a-f]{64}$/);
  const removeOption=alice.locator("#remove-leaf option").filter({hasText:bobSigner.slice(0,20)});
  await alice.locator("#remove-leaf").selectOption(await removeOption.getAttribute("value"));
  await alice.locator("#remove").click();
  await bob.waitForFunction(()=>document.querySelector("#status").textContent.includes("Verbindung verloren")
    || document.querySelector("#status").textContent.includes("entfernt"));
  await charlie.waitForFunction(()=>document.querySelectorAll("#members p").length===2);
  await alice.locator("#message").fill("Neue Epoche nur für Alice und Charlie");
  await alice.locator("#send").click();
  await charlie.locator("#feed").getByText("Neue Epoche nur für Alice und Charlie").waitFor({timeout:15000});
  assert.equal(await bob.locator("#feed").getByText("Neue Epoche nur für Alice und Charlie").count(),0);
  assert.equal(await bob.locator("#send").isDisabled(),true);
  // Revoked token must not be able to establish a new WebSocket, even while
  // the rest of the group and the original owner capability remain active.
  const revokedSocketRejected=await bob.evaluate(({room,token})=>new Promise(resolve=>{
    const ws=new WebSocket(`ws://${location.host}/ws/${room}`,
      ["picto.v1","auth."+token]);
    const timer=setTimeout(()=>{ws.close();resolve(false);},4000);
    ws.onerror=()=>{clearTimeout(timer);resolve(true);};
    ws.onopen=()=>{clearTimeout(timer);ws.close();resolve(false);};
  }),{room:id,token:bobToken});
  assert.equal(revokedSocketRejected,true,"removed member must lose relay admission");

  await alice.screenshot({path:`${dir}/mls-after-removal.png`,fullPage:true});
  assert.deepEqual(failures,[]);
  console.log("Real browser MLS group integration passed: three browsers, DS sprite chat and encrypted drawings/PDF, distinct bearer admissions, owner policy, revocation and surviving epoch.");
}finally{await browser.close();}
