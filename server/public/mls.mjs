import init, { BrowserMlsClient } from "/mls/pkg/pictorust_mls_web.js";
import { preparePictoRustPrint } from "/pictorust-export.mjs";

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
    $("mls-epoch").textContent=String(client.epoch());
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
const CHAT_MAX_POINTS=1200;
const history=[];
let drawingStrokes=[],activeStroke=null,pointTotal=0,penMode=false;
const board=$("ds-board"),paint=$("mls-drawing"),pen=paint.getContext("2d");
function drawLines(lines,context) {
  context.strokeStyle="#111";context.lineWidth=2.5;context.lineJoin="round";context.lineCap="round";
  for(const stroke of lines) {
    if(!stroke.length)continue;
    context.beginPath();
    context.moveTo(stroke[0][0],stroke[0][1]);
    for(const xy of stroke.slice(1))context.lineTo(xy[0],xy[1]);
    if(stroke.length===1)context.lineTo(stroke[0][0]+0.1,stroke[0][1]+0.1);
    context.stroke();
  }
}
function redraw() {
  pen.clearRect(0,0,paint.width,paint.height);
  drawLines(drawingStrokes,pen);
}
function clearDrawing(){drawingStrokes=[];activeStroke=null;pointTotal=0;redraw();}
function pointerCoords(e) {
  const rect=paint.getBoundingClientRect();
  return [
    Math.max(0,Math.min(512,Math.round((e.clientX-rect.left)*512/rect.width))),
    Math.max(0,Math.min(170,Math.round((e.clientY-rect.top)*170/rect.height)))
  ];
}
paint.addEventListener("pointerdown",e=>{
  if(!penMode||pointTotal>=CHAT_MAX_POINTS)return;
  activeStroke=[pointerCoords(e)];drawingStrokes.push(activeStroke);pointTotal++;
  paint.setPointerCapture(e.pointerId);redraw();
});
paint.addEventListener("pointermove",e=>{
  if(!activeStroke||pointTotal>=CHAT_MAX_POINTS)return;
  const xy=pointerCoords(e),last=activeStroke[activeStroke.length-1];
  if(xy[0]!==last[0]||xy[1]!==last[1]){
    activeStroke.push(xy);pointTotal++;redraw();
  }
});
for(const ev of ["pointerup","pointercancel","lostpointercapture"]){
  paint.addEventListener(ev,()=>{activeStroke=null;});
}
function choosePen(on) {
  penMode=on;board.classList.toggle("pen-mode",on);
  board.classList.toggle("text-mode",!on);
  $("mls-pen-tool").setAttribute("aria-pressed",String(on));
  $("mls-text-tool").setAttribute("aria-pressed",String(!on));
  if(!on)$("message").focus();
}
$("mls-pen-tool").addEventListener("click",()=>choosePen(true));
$("mls-text-tool").addEventListener("click",()=>choosePen(false));
$("mls-clear").addEventListener("click",clearDrawing);
$("mls-undo").addEventListener("click",()=>{
  const removed=drawingStrokes.pop();if(removed)pointTotal-=removed.length;
  activeStroke=null;redraw();
});
document.querySelectorAll("#mls-ds-keyboard [data-char]").forEach(button=>{
  button.addEventListener("click",()=>{
    choosePen(false);
    const input=$("message"),pos=input.selectionStart;
    input.setRangeText(button.dataset.char,pos,input.selectionEnd,"end");
    input.focus();
  });
});
function validDrawMessage(item){
  if(!item||item.v!==2||typeof item.text!=="string"||item.text.length>1900
     ||typeof item.nickname!=="string"||item.nickname.length>40
     ||!Array.isArray(item.strokes))return false;
  let points=0;
  for(const line of item.strokes) {
    if(!Array.isArray(line))return false;
    for(const xy of line) {
      if(++points>CHAT_MAX_POINTS || !Array.isArray(xy)||xy.length!==2
         ||!xy.every(Number.isInteger)||xy[0]<0||xy[0]>512||xy[1]<0||xy[1]>170)return false;
    }
  }
  return true;
}
function parseMessage(payload) {
  const decoded=td.decode(payload);
  try{
    const value=JSON.parse(decoded);
    if(validDrawMessage(value))return value;
  }catch{}
  return {v:2,text:decoded,nickname:"Mitglied",strokes:[]};
}
function render(payload) {
  const data=parseMessage(payload);
  // Keep bounded, volatile history; nothing is persisted by the relay.
  if(history.length>=200)history.shift();
  history.push({nickname:data.nickname,text:data.text,strokes:data.strokes});
  const div=document.createElement("article");div.className="entry";
  if(data.nickname!=="Mitglied") {
    const name=document.createElement("div");name.className="who";
    name.textContent=data.nickname;div.append(name);
  }
  if(data.text){const text=document.createElement("span");text.textContent=data.text;div.append(text);}
  if(data.strokes.length){
    const canvas=document.createElement("canvas");canvas.width=512;canvas.height=170;
    drawLines(data.strokes,canvas.getContext("2d"));
    const image=document.createElement("img");image.alt="Verschlüsselte Zeichnung";
    image.src=canvas.toDataURL("image/png");div.append(image);
  }
  $("feed").append(div);
  $("feed").scrollTop=$("feed").scrollHeight;
}
$("mls-pdf").addEventListener("click",async()=>{
  if(!history.length){message("Keine Nachrichten zum Export vorhanden");return;}
  const button=$("mls-pdf");button.disabled=true;
  try{
    await preparePictoRustPrint(history,"A",$("pixel-print"));
    window.print();
  }catch{message("Original-Pixel-PDF konnte nicht erstellt werden");}
  finally{button.disabled=false;}
});
$("mls-clear-history").addEventListener("click",()=>{
  history.length=0;$("feed").replaceChildren();$("pixel-print").replaceChildren();
});
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
    const ws=new WebSocket(`ws://${location.host}/ws/${room}`,["picto.v1",`auth.${token}`]);
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
    if(!value && !drawingStrokes.length)return;
    const nickname=$("name").value.trim().slice(0,40)||"Gast";
    // JSON v2 contains plaintext only INSIDE the MLS authenticated encryption.
    const draft={v:2,nickname,text:value,
      strokes:drawingStrokes.map(line=>line.map(pt=>[...pt]))};
    const plaintext=te.encode(JSON.stringify(draft));
    if(plaintext.length>8000)throw Error("Text und Zeichnung sind zu groß");
    const wire=client.send(plaintext);
    transmit(wire);
    render(plaintext);
    $("message").value="";clearDrawing();
  }catch(e){client?.mark_transport_interrupted();$("send").disabled=true;message("Senden fehlgeschlagen: "+e.message);}
});
$("reset").addEventListener("click",()=>{
  socket?.close();socket=null;
  client?.dispose();client=null;isOwner=false;sentFrames.clear();
  for(const id of ["token","room","mine","own-signer","own-package","welcome","trusted-owner","invite-package","verified-fingerprint","issued-welcome","message"])
    $(id).value="";
  history.length=0;$("feed").replaceChildren();$("pixel-print").replaceChildren();
  clearDrawing();$("members").replaceChildren();
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
