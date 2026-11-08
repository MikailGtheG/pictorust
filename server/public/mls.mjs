import init, { BrowserMlsClient } from "/mls/pkg/pictorust_mls_web.js";

const $ = id => document.getElementById(id);
const te = new TextEncoder();
const td = new TextDecoder("utf-8", {fatal:true});
let client = null, socket = null, isOwner = false, roomId = "";
let receiveChain = Promise.resolve();
const sentFrames = new Set();
const MAX_WIRE = 16384;
const message = text => { $("status").textContent = text; };
const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2,"0")).join("");
const fromBase64 = text => Uint8Array.from(atob(String(text).trim()), c=>c.charCodeAt(0));
const fromHex = text => Uint8Array.from(text.match(/../g), part=>parseInt(part,16));
const base64 = bytes => btoa(String.fromCharCode(...bytes));
async function sha256(bytes) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)));
}
function roster() {
  if(!client) return;
  try {
    const members = Array.from(client.members());
    $("members").replaceChildren();
    const selector=$("remove-leaf");
    selector.replaceChildren(new Option("Bitte Mitglied wählen",""));
    for(const member of members) {
      const div=document.createElement("p");
      div.textContent=`Leaf ${member.leaf} · ${member.credentialHex.slice(0,48)} · Signatur ${member.signatureKeyHex}`;
      $("members").append(div);
      if(isOwner && member.signatureKeyHex !== $("own-signer").value) {
        selector.add(new Option(`Leaf ${member.leaf} · ${member.signatureKeyHex.slice(0,20)}`,String(member.leaf)));
      }
    }
    $("send").disabled=!client.synchronized() || socket?.readyState!==WebSocket.OPEN;
    message(`MLS-Epoche ${client.epoch()} · ${members.length} Mitglied(er)`);
  }catch { $("send").disabled=true; }
}
async function makeIdentity() {
  if(socket || (client && client.synchronized())) return;
  if(client) client.dispose();
  const label=$("name").value.trim();
  client=new BrowserMlsClient(label);
  const keyPackage=client.key_package();
  $("own-package").value=base64(keyPackage);
  $("mine").value=await sha256(keyPackage);
  $("own-signer").value="";
  message("Einmaliges KeyPackage erstellt. Fingerprint separat verifizieren.");
}
function readCredentials() {
  const room=$("room").value.trim(), token=$("token").value.trim();
  if(!/^[0-9a-f]{32}$/.test(room)||!/^[0-9a-f]{64}$/.test(token))
    throw Error("Raum-ID und Zugangstoken erforderlich");
  return {room,token};
}
function render(payload) {
  const text=td.decode(payload);
  const div=document.createElement("article");
  div.className="entry";
  // No HTML interpretation or innerHTML: encrypted messages are always text.
  div.textContent=text;
  $("feed").append(div);
  $("feed").scrollTop=$("feed").scrollHeight;
}
async function onPacket(buffer) {
  if(!client||!socket || buffer.byteLength>MAX_WIRE||buffer.byteLength<3) return;
  const wire=new Uint8Array(buffer);
  if(wire[0]!==3) { message("Falsches Protokoll verworfen"); socket.close(); return; }
  const id=base64(wire);
  if(sentFrames.delete(id)) return;
  if(wire[1]!==1 && wire[1]!==2) return; // Welcome exchanged off-band.
  try {
    const result=client.process(wire);
    if(result.kind==="application") render(result.payload);
    if(result.kind==="membership") roster();
    if(result.kind==="removed") {
      $("send").disabled=true;
      message("Du wurdest aus der MLS-Gruppe entfernt. Alte Epoche ungültig.");
      socket.close();
    }
  }catch {
    // Never silently continue with unverified or out-of-order MLS control data.
    client.mark_transport_interrupted();
    $("send").disabled=true;
    message("MLS-Epoche nicht mehr vertrauenswürdig. Neue Welcome-Einladung nötig.");
    socket.close();
  }
}
async function connect() {
  const {room,token}=readCredentials();
  if(socket) throw Error("Bereits verbunden");
  roomId=room;
  return new Promise((resolve,reject)=>{
    const ws=new WebSocket(`${location.protocol==="https:"?"wss:":"ws:"}//${location.host}/ws/${room}`,["picto.v1",`auth.${token}`]);
    ws.binaryType="arraybuffer";
    socket=ws;
    let open=false;
    ws.onopen=()=>{open=true;roster();resolve();};
    ws.onmessage=event=>{
      if(!(event.data instanceof ArrayBuffer)) { ws.close();return; }
      // Preserve total MLS Commit order even when processing is extended.
      receiveChain=receiveChain.then(()=>onPacket(event.data)).catch(()=>{
        client?.mark_transport_interrupted();ws.close();
      });
    };
    ws.onerror=()=>{if(!open)reject(Error("WebSocket-Zugriff abgelehnt"));};
    ws.onclose=()=>{
      client?.mark_transport_interrupted();
      $("send").disabled=true;
      socket=null;
      sentFrames.clear();
      message("Verbindung verloren: MLS fail-closed; neue Einladung erforderlich");
      if(!open)reject(Error("WebSocket wurde geschlossen"));
    };
  });
}
function transmit(bytes) {
  if(socket?.readyState!==WebSocket.OPEN || !client?.synchronized())
    throw Error("MLS-Gruppe ist nicht synchronisiert");
  const wire=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
  if(wire[0]!==3 || wire.length>MAX_WIRE)throw Error("Ungültige MLS-Daten");
  sentFrames.add(base64(wire));
  socket.send(wire);
}
$("new-room").addEventListener("click",async()=>{
  try {
    if(socket)throw Error("Bereits verbunden");
    const r=await fetch("/new-room",{method:"POST",cache:"no-store"});
    if(!r.ok)throw Error("Raumerstellung gesperrt: "+r.status);
    const data=await r.json();
    $("room").value=data.roomId;
    $("token").value=data.token;
    message("Temporärer Raum angelegt. Zugangstoken nicht öffentlich teilen.");
  }catch(e){message(e.message);}
});
$("start").addEventListener("click",async()=>{
  try {
    if(!client || client.synchronized())throw Error("Identität nicht bereit oder Gruppe existiert");
    client.start_group();isOwner=true;
    $("own-signer").value=client.members()[0].signatureKeyHex;
    await connect();
    roster();
  }catch(e){client?.mark_transport_interrupted();message("Gruppenstart fehlgeschlagen: "+e.message);}
});
$("join").addEventListener("click",async()=>{
  try {
    if(!client || client.synchronized() || socket)throw Error("Neue lokale Identität erforderlich");
    const pinned=$("trusted-owner").value.trim().toLowerCase();
    if(!/^[0-9a-f]{64}$/.test(pinned))throw Error("Verifizierten Ersteller-Signaturschlüssel eingeben");
    const invite=JSON.parse($("welcome").value);
    if(invite.v!==1 || typeof invite.welcome!=="string" || typeof invite.tree!=="string")
      throw Error("Welcome-Format ungültig");
    if(!/^[0-9a-f]{32}$/.test(invite.roomId) || !/^[0-9a-f]{64}$/.test(invite.token))
      throw Error("Einladung ohne eigenes Geräte-Zugangstoken");
    if($("room").value.trim() && $("room").value.trim()!==invite.roomId)
      throw Error("Einladung ist für einen anderen Raum");
    $("room").value=invite.roomId;
    $("token").value=invite.token;
    const welcome=fromBase64(invite.welcome), tree=fromBase64(invite.tree);
    if(welcome.length>MAX_WIRE || tree.length>MAX_WIRE)throw Error("Einladung zu groß");
    client.accept_welcome(welcome,tree);
    if(!client.members().some(member=>member.signatureKeyHex===pinned))
      throw Error("Verifizierter Gruppen-Ersteller nicht im signierten MLS-Baum");
    // Enforced again in the Rust core on every MLS membership Commit.
    client.pin_owner(fromHex(pinned));
    isOwner=false;
    $("own-signer").value=client.members().find(m=>m.credentialHex===hex(te.encode($("name").value.trim())))?.signatureKeyHex || "";
    await connect();
    $("welcome").value="";
    roster();
  }catch(e){
    client?.mark_transport_interrupted();
    message("Beitritt abgelehnt: "+e.message);
  }
});
$("admit").addEventListener("click",async()=>{
  let changedEpoch=false;
  try {
    if(!isOwner || !client?.synchronized())throw Error("Nur aktiver Ersteller kann einladen");
    const packageBytes=fromBase64($("invite-package").value);
    const expected=$("verified-fingerprint").value.trim().toLowerCase();
    if(!/^[0-9a-f]{64}$/.test(expected) || await sha256(packageBytes)!==expected)
      throw Error("Verifizierter KeyPackage-Fingerprint stimmt nicht überein");
    const previous=new Set(client.members().map(member=>member.signatureKeyHex));
    const [commit,welcome,tree]=client.add_member(packageBytes);
    changedEpoch=true;
    const member=client.members().find(item=>!previous.has(item.signatureKeyHex));
    if(!member)throw Error("Neues MLS-Mitglied nicht eindeutig zugeordnet");
    const {room,token}=readCredentials();
    const response=await fetch(`/mls/invite/${room}/${member.leaf}`,{
      method:"POST",cache:"no-store",headers:{Authorization:"Bearer "+token}
    });
    if(!response.ok)throw Error("Individueller Relay-Zugang nicht erstellt: "+response.status);
    const admission=await response.json();
    if(!/^[0-9a-f]{64}$/.test(admission.token))throw Error("Ungültiger Geräte-Zugang");
    // Local MLS state already advanced. If relay publication fails, fail closed.
    transmit(commit);
    $("issued-welcome").value=JSON.stringify({
      v:1,roomId:room,token:admission.token,
      welcome:base64(welcome),tree:base64(tree)
    });
    $("invite-package").value="";
    $("verified-fingerprint").value="";
    roster();
  }catch(e){if(changedEpoch)client?.mark_transport_interrupted();$("send").disabled=!client?.synchronized();message("Hinzufügen fehlgeschlagen: "+e.message);}
});
$("remove").addEventListener("click",async()=>{
  let changedEpoch=false;
  try {
    if(!isOwner || !client?.synchronized())throw Error("Erstellerberechtigung erforderlich");
    const leaf=Number($("remove-leaf").value);
    if(!Number.isSafeInteger(leaf)||$("remove-leaf").value==="")throw Error("Mitglied auswählen");
    const commit=client.remove_member(leaf);
    changedEpoch=true;
    transmit(commit);
    const {room,token}=readCredentials();
    const result=await fetch(`/mls/revoke/${room}/${leaf}`,{
      method:"POST",cache:"no-store",headers:{Authorization:"Bearer "+token}
    });
    if(!result.ok)throw Error("MLS entfernt, aber Relay-Zugang nicht widerrufen: "+result.status);
    roster();
  }catch(e){if(changedEpoch)client?.mark_transport_interrupted();$("send").disabled=!client?.synchronized();message("Ausschluss fehlgeschlagen: "+e.message);}
});
$("send").addEventListener("click",()=>{
  try {
    const value=$("message").value.trim();
    if(!value)return;
    const wire=client.send(te.encode(value));
    transmit(wire);
    render(te.encode("Ich: "+value));
    $("message").value="";
  }catch(e){client?.mark_transport_interrupted();$("send").disabled=true;message("Senden fehlgeschlagen: "+e.message);}
});
$("reset").addEventListener("click",()=>{
  socket?.close();socket=null;
  client?.dispose();client=null;isOwner=false;sentFrames.clear();
  for(const id of ["token","room","mine","own-signer","own-package","welcome","trusted-owner","invite-package","verified-fingerprint","issued-welcome","message"])
    $(id).value="";
  $("feed").replaceChildren();$("members").replaceChildren();
  $("send").disabled=true;
  makeIdentity().catch(e=>message(e.message));
});
$("name").addEventListener("change",()=>makeIdentity().catch(e=>message(e.message)));
window.addEventListener("beforeunload",()=>socket?.close());
try {
  await init();
  await makeIdentity();
  message("OpenMLS WASM bereit · temporärer Gruppenmodus, noch nicht sicherheitsauditiert");
}catch(e){
  $("send").disabled=true;
  message("MLS-WASM fehlt oder konnte nicht initialisiert werden: "+e.message);
}
