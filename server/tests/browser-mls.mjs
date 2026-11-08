// Actual two-browser OpenMLS over WASM + real Rust relay.
// This is a local integration test, not an independent cryptographic audit.
import assert from "node:assert/strict";
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";
const dir=process.env.PICTORUST_MLS_SCREENSHOTS||"screenshots/mls";
await mkdir(dir,{recursive:true});
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
const failures=[];
let alice=null,bob=null;
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
  await bob.locator("#token").fill(token);
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
  await alice.locator("#message").fill("MLS: Hallo ÄÖÜ ğışç 😊");
  await alice.locator("#send").click();
  await bob.locator("#feed").getByText("MLS: Hallo ÄÖÜ ğışç 😊").waitFor({timeout:15000});
  // Never leak even synthetic admission capabilities in published screenshots.
  for(const page of [alice,bob]){
    await page.addStyleTag({content:"#token,#issued-welcome,#welcome,#own-package,#invite-package{filter:blur(14px)}"});
  }
  await alice.screenshot({path:`${dir}/mls-alice-group.png`,fullPage:true});
  await bob.screenshot({path:`${dir}/mls-bob-group.png`,fullPage:true});
  const options=await alice.locator("#remove-leaf option").count();
  assert.ok(options>1);
  await alice.locator("#remove-leaf").selectOption({index:1});
  await alice.locator("#remove").click();
  await bob.waitForFunction(()=>document.querySelector("#status").textContent.includes("Verbindung verloren")
    || document.querySelector("#status").textContent.includes("entfernt"));
  await alice.locator("#message").fill("Neue Epoche nur für Alice");
  await alice.locator("#send").click();
  assert.equal(await bob.locator("#feed").getByText("Neue Epoche nur für Alice").count(),0);
  assert.equal(await bob.locator("#send").isDisabled(),true);
  await alice.screenshot({path:`${dir}/mls-after-removal.png`,fullPage:true});
  assert.deepEqual(failures,[]);
  console.log("Real browser MLS group integration passed: signed KeyPackage, welcome, encrypted messages, revocation.");
}finally{await browser.close();}
