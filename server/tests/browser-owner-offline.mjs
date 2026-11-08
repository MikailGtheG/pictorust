// P0 regression: after the owner disconnects, already authenticated guests
// can still exchange application ciphertext. This is not owner succession.
import assert from "node:assert/strict";
import {chromium} from "playwright";
const origin=process.env.PICTORUST_E2E_ORIGIN||"http://127.0.0.1:8787";
const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
try {
  const context=await browser.newContext({
    ignoreHTTPSErrors:true,
    permissions:["clipboard-read","clipboard-write"],
    viewport:{width:1200,height:1000}
  });
  const alice=await context.newPage();
  const bob=await context.newPage();
  const charlie=await context.newPage();
  const errors=[];
  for(const page of [alice,bob,charlie])
    page.on("pageerror",error=>errors.push(error.message));
  await alice.goto(origin,{waitUntil:"networkidle"});
  await alice.locator("#nickname").fill("Alice");
  await alice.locator("#new-room").click();
  await alice.waitForFunction(()=>document.querySelector("#token").value.length===64);
  await alice.locator("#connect").click();
  await alice.waitForFunction(()=>document.querySelector("#status").textContent.includes("MLS verschlüsselt"));
  await alice.locator("#security-panel summary").click();
  await alice.locator("#copy-invite").click();
  const invite=await alice.evaluate(()=>navigator.clipboard.readText());
  assert.match(invite,/#pictorust=mls1/);
  await bob.goto(invite,{waitUntil:"domcontentloaded"});
  await bob.waitForFunction(()=>document.querySelector("#status").textContent.includes("Gruppenbeitritt erfolgreich"),null,{timeout:30000});
  await charlie.goto(invite,{waitUntil:"domcontentloaded"});
  await charlie.waitForFunction(()=>document.querySelector("#status").textContent.includes("Gruppenbeitritt erfolgreich"),null,{timeout:30000});
  // The later member's commit needs to be delivered and verified by Bob.
  await alice.locator("#text").fill("Alle Mitglieder bereit");
  await alice.locator("#send").click();
  await bob.locator("#messages").getByText("Alle Mitglieder bereit").waitFor({timeout:12000});
  await charlie.locator("#messages").getByText("Alle Mitglieder bereit").waitFor({timeout:12000});

  await alice.locator("#disconnect").click();
  await alice.waitForFunction(()=>document.querySelector("#send").disabled);
  // The server must not terminate valid non-owner WebSockets.
  await bob.locator("#text").fill("Bob schreibt trotz Owner-Offline");
  await bob.locator("#send").click();
  await charlie.locator("#messages").getByText("Bob schreibt trotz Owner-Offline").waitFor({timeout:12000});
  await charlie.locator("#text").fill("Charlie bestätigt die MLS-Gruppe");
  await charlie.locator("#send").click();
  await bob.locator("#messages").getByText("Charlie bestätigt die MLS-Gruppe").waitFor({timeout:12000});
  assert.deepEqual(errors,[]);
  console.log("Owner-offline: two authenticated guests exchanged MLS messages; no owner succession attempted");
} finally {await browser.close();}
