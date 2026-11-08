// Invisible MLS transport for the ORIGINAL PictoRust stage.
// Do not create or modify HTML, sprites, keyboard hitboxes or message cards here.
// All long-term private keys live in endpoint-owned OpenMLS WASM memory.
// Invitation secrets travel in URL fragments (not HTTP paths), and are wiped
// from the location bar immediately after opening the invitation.
const encoder=new TextEncoder();
const decoder=new TextDecoder("utf-8",{fatal:true});
const MAX_WIRE=16384;
const hex=b=>Array.from(b,v=>v.toString(16).padStart(2,"0")).join("");
const toBase64=b=>btoa(String.fromCharCode(...b));
const fromBase64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const fromHex=s=>Uint8Array.from(s.match(/../g),v=>parseInt(v,16));
const validHex=(s,n)=>typeof s==="string"&&new RegExp("^[0-9a-f]{"+n+"}$").test(s);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let wasmReady;
async function loadWasm(){
  if(!wasmReady)wasmReady=import("/mls/pkg/pictorust_mls_web.js").then(async m=>{
    await m.default();
    return m.BrowserMlsClient;
  });
  return wasmReady;
}
function decodeInvite(hash){
  const raw=String(hash||"").replace(/^#/,"");
  const params=new URLSearchParams(raw);
  if(params.get("pictorust")!=="mls1")return null;
  const invite={
    room:params.get("room"),secret:params.get("invite"),
    owner:params.get("owner"),letter:params.get("letter")
  };
  if(!validHex(invite.room,32)||!validHex(invite.secret,64)||
     !validHex(invite.owner,64)||! /^[A-E]$/.test(invite.letter||"")){
    throw Error("Ungültiger PictoRust-Einladungslink");
  }
  return invite;
}
export function consumeMlsLink(){
  const link=decodeInvite(location.hash);
  if(link)history.replaceState(null,"",location.pathname+location.search);
  return link;
}
export function createMlsSession({name,room,token,onMessage,onStatus,onDisconnect,onReady}) {
  let client=null,ws=null,owner=false,joinSecret=null,ownerKey=null,
      pendingPoll=null,closed=false,receiveQueue=Promise.resolve(),
      joinInvite=null,memberToken=null,rejoinAttempts=0,rejoining=false;
  const sent=new Set(),processed=new Set();
  const status=s=>onStatus?.(s);
  const auth=()=>({Authorization:"Bearer "+token()});
  const post=async(url,payload,headers={})=>{
    const response=await fetch(url,{method:"POST",cache:"no-store",
      headers:{"Content-Type":"application/json",...headers},
      body:JSON.stringify(payload)});
    if(!response.ok)throw Error("MLS Server "+response.status);
    return response;
  };
  function fail(text){
    if(closed)return;
    status(text);
    client?.mark_transport_interrupted();
    closed=true;
    if(pendingPoll)clearInterval(pendingPoll);
    ws?.close();
    onDisconnect?.();
    // Preserve the specific verified-transport failure instead of replacing it
    // immediately with a generic "disconnected" message.
    status(text);
  }
  async function connect(capability){
    if(ws)throw Error("Bereits verbunden");
    const id=room();
    if(!validHex(id,32)||!validHex(capability,64))throw Error("Raumzugang ungültig");
    await new Promise((resolve,reject)=>{
      const socket=new WebSocket((location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws/"+id,
        ["picto.v1","auth."+capability]);
      ws=socket;socket.binaryType="arraybuffer";let opened=false;
      socket.onopen=()=>{opened=true;resolve();};
      socket.onerror=()=>{if(!opened)reject(Error("Verbindung verweigert"));};
      socket.onclose=()=>{
        if(!opened){reject(Error("Verbindung unterbrochen"));return;}
        if(closed)return;
        // Never reuse a potentially stale MLS epoch after a transport gap.
        // Only a guest with its previously issued member bearer may do one
        // bounded replacement, verified by the owner and the Rust relay.
        if(!owner && joinInvite && memberToken && !rejoining && rejoinAttempts<1){
          rejoinAttempts++;
          rejoining=true;
          client?.mark_transport_interrupted();
          onDisconnect?.();
          status("MLS-Verbindung verloren · neuer sicherer Gruppenbeitritt …");
          const previous=memberToken,invite=joinInvite;
          ws=null;
          client?.dispose();client=null;
          sent.clear();processed.clear();receiveQueue=Promise.resolve();
          (async()=>{
            await sleep(700);
            if(closed)return;
            await joinWithInvite(invite,previous);
            rejoining=false;
            status("MLS wiederverbunden · neue Schlüssel bestätigt");
          })().catch(e=>fail("Sichere Wiederverbindung fehlgeschlagen: "+(e?.message||String(e))));
          return;
        }
        fail("Verbindung beendet. Neue sichere Einladung erforderlich.");
      };
      socket.onmessage=event=>{
        if(!(event.data instanceof ArrayBuffer))return fail("Ungültige Transportdaten");
        receiveQueue=receiveQueue.then(()=>{
          if(closed||!client||!client.synchronized())return;
          const bytes=new Uint8Array(event.data);
          if(bytes.length>MAX_WIRE||bytes.length<3||bytes[0]!==3||
             ![1,2].includes(bytes[1]))throw Error("Ungültiger MLS-Rahmen");
          const signature=toBase64(bytes);
          if(sent.delete(signature))return;
          if(processed.has(signature))throw Error("Wiederholter MLS-Rahmen");
          if(processed.size>1000)processed.clear();
          processed.add(signature);
          const message=client.process(bytes);
          if(message.kind==="application"){
            const data=JSON.parse(decoder.decode(message.payload));
            onMessage?.(data);
          }else if(message.kind==="removed"){
            throw Error("Aus MLS-Gruppe entfernt");
          }
        }).catch(e=>fail("MLS-Sicherheitsprüfung fehlgeschlagen: "+(e?.message||String(e))));
      };
    });
    onReady?.();
  }
  function transmit(bytes){
    if(closed||ws?.readyState!==WebSocket.OPEN||!client?.synchronized())
      throw Error("MLS-Sitzung nicht verbunden");
    if(bytes.length<3||bytes.length>MAX_WIRE||bytes[0]!==3)
      throw Error("MLS-Nachricht ungültig");
    sent.add(toBase64(bytes));
    ws.send(bytes);
  }
  async function handlePending(){
    if(closed||!owner||!client?.synchronized()||!ws||pendingPoll===-1)return;
    // Serialize changes: a second owner Commit must never overtake the first.
    if(handlePending.busy)return;
    handlePending.busy=true;
    try{
      const response=await fetch("/mls/join/pending/"+room(),{
        method:"POST",cache:"no-store",headers:auth()});
      if(!response.ok)throw Error("Einladungsabfrage "+response.status);
      const requests=await response.json();
      for(const request of requests){
        if(closed)break;
        // The relay verified possession of the old member-only bearer,
        // so only that member may ask to replace its previous leaf.
        if(request.previous_leaf!==null && request.previous_leaf!==undefined){
          const oldLeaf=request.previous_leaf;
          if(!Number.isInteger(oldLeaf)||oldLeaf<=0)
            throw Error("Ungültige vorherige MLS-Mitgliedschaft");
          const removal=client.remove_member(oldLeaf);
          transmit(removal);
          const revoke=await fetch("/mls/revoke/"+room()+"/"+oldLeaf,{
            method:"POST",cache:"no-store",headers:auth()
          });
          if(!revoke.ok)throw Error("Altgerät konnte nicht widerrufen werden: "+revoke.status);
        }
        const previous=new Set(client.members().map(m=>m.signatureKeyHex));
        const [commit,welcome,tree]=client.add_member(fromBase64(request.key_package));
        const member=client.members().find(m=>!previous.has(m.signatureKeyHex));
        if(!member)throw Error("MLS-Identität nicht eindeutig");
        const result=await post("/mls/invite/"+room()+"/"+member.leaf,{},auth());
        const admission=await result.json();
        if(!validHex(admission.token,64))throw Error("Mitglied-Zugang ungültig");
        transmit(commit);
        await post("/mls/join/complete/"+room()+"/"+request.id,{
          welcome:toBase64(welcome),tree:toBase64(tree),token:admission.token
        },auth());
      }
    }catch(e){fail("MLS-Gruppenverwaltung unterbrochen: "+(e?.message||String(e)));}
    finally{handlePending.busy=false;}
  }
  async function joinWithInvite(invite,previousToken=null){
      if(client||closed)throw Error("MLS-Sitzung bereits gestartet");
      if(previousToken && !validHex(previousToken,64))throw Error("Vorheriger Gerätezugang ungültig");
      const C=await loadWasm();
      client=new C(name());
      const publicPackage=client.key_package();
      const req=await post("/mls/join/request/"+invite.room,{
        secret:invite.secret,key_package:toBase64(publicPackage),
        previous_token:previousToken
      });
      const {id}=await req.json();
      if(!validHex(id,32))throw Error("Ungültige Beitrittsbestätigung");
      status("Sicherer Beitritt wird vorbereitet …");
      const until=Date.now()+100000;
      let joined=null;
      while(Date.now()<until&&!closed){
        await sleep(450);
        const r=await post("/mls/join/result/"+invite.room+"/"+id,{secret:invite.secret});
        if(r.status===202)continue;
        joined=await r.json();break;
      }
      if(!joined)throw Error("Einladung abgelaufen. Gruppeninhaber muss online sein");
      if(!validHex(joined.token,64))throw Error("Ungültiger Mitgliederzugang");
      client.accept_welcome(fromBase64(joined.welcome),fromBase64(joined.tree));
      if(!client.members().some(m=>m.signatureKeyHex===invite.owner))
        throw Error("Signatur des Gruppenerstellers weicht vom Einladungslink ab");
      client.pin_owner(fromHex(invite.owner));
      await connect(joined.token);
      memberToken=joined.token;
      joinInvite=invite;
      status("MLS verschlüsselt · Gruppenbeitritt erfolgreich");
  }

  return {
    async startOwner(){
      if(client||closed)throw Error("MLS-Sitzung bereits gestartet");
      const C=await loadWasm();
      client=new C(name());client.start_group();
      ownerKey=client.members()[0].signatureKeyHex;
      owner=true;
      const secret=crypto.getRandomValues(new Uint8Array(32));
      joinSecret=hex(secret);secret.fill(0);
      await connect(token());
      await post("/mls/join/register/"+room(),{secret:joinSecret},auth());
      pendingPoll=setInterval(handlePending,700);
      status("MLS verschlüsselt · Einladung kann kopiert werden");
    },
    invitationUrl(letter){
      if(!owner||!joinSecret||closed||!ownerKey)throw Error("Erst mit eigenem Raum verbinden");
      const fragment=new URLSearchParams({
        pictorust:"mls1",room:room(),invite:joinSecret,owner:ownerKey,letter
      });
      return location.origin+location.pathname+"#"+fragment;
    },
    async join(invite){return joinWithInvite(invite);},
    send(data){
      const bytes=encoder.encode(JSON.stringify(data));
      if(bytes.length>8000)throw Error("Text oder Zeichnung zu groß");
      transmit(client.send(bytes));
      onMessage?.(data);
    },
    active(){return !closed&&!!client?.synchronized()&&ws?.readyState===WebSocket.OPEN;},
    close(){
      if(pendingPoll)clearInterval(pendingPoll);
      closed=true;ws?.close();client?.dispose();client=null;joinSecret=null;
      joinInvite=null;memberToken=null;
      sent.clear();processed.clear();
    },
  };
}
