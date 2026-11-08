// Security contract tests: they do not replace a cryptographic audit.
// Run with: node scripts/security/p0-contract.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const src=p=>readFileSync(new URL("../../"+p,import.meta.url),"utf8");
const relay=src("server/src/main.rs");
const broker=src("server/src/invites.rs");
const web=src("server/public/mls-session.mjs");
const mls=src("mls-lab/src/client.rs");
const original=src("server/public/index.html");

test("server fails closed for missing or duplicated Origin on public origins",()=>{
  assert.match(relay,/\(None,None\) => public\.is_none\(\)/);
  assert.match(relay,/\(Some\(value\),None\)/);
  assert.match(relay,/public_endpoints_require_a_single_matching_origin/);
  assert.match(relay,/DefaultBodyLimit::max\(48 \* 1024\)/);
});
test("the browser never leaks its member bearer into a URL",()=>{
  assert.doesNotMatch(web,/location\.(href|search|hash).*memberToken/);
  assert.match(web,/history\.replaceState\(null,"",location\.pathname\+location\.search\)/);
  assert.match(web,/location\.protocol==="https:"\?"wss:\/\/"\:"ws:\/\//);
});
test("rejoining rotates the member, rejects replay and revokes an old bearer",()=>{
  assert.match(web,/previous_token:previousToken/);
  assert.match(web,/client\.remove_member\(oldLeaf\)/);
  assert.match(web,/\/mls\/revoke\//);
  assert.match(broker,/delivered=true/);
  assert.match(broker,/previous_leaf==Some\(leaf\)/);
});
test("offline or corrupt MLS states must not silently resume without an authenticated Welcome",()=>{
  assert.match(mls,/group epoch may be stale; rejoin required/);
  assert.match(mls,/pub fn mark_transport_interrupted/);
  assert.match(web,/client\?\.mark_transport_interrupted\(\)/);
  assert.match(web,/client\.accept_welcome\(/);
  assert.match(web,/client\.pin_owner\(/);
});
test("public relay rejects legacy frames and original DS HTML stays the page",()=>{
  assert.match(relay,/frame_allowed_for_mode\(&data, require_mls_v3\)/);
  assert.match(relay,/include_str!\("\.\.\/public\/index\.html"\)/);
  assert.match(original,/id="picto"/);
  assert.match(original,/id="touch-keys"/);
});
