//! Development-only loopback WebSocket relay.
//! Client-side experimental AES-GCM with bearer room admission. No verified identities,
//! automatic key distribution, forward secrecy, or TLS yet.
mod admissions;
mod invites;
use invites::InviteBroker;
use admissions::MembershipAdmissions;
use std::{net::SocketAddr, sync::{Arc, Mutex}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use rand::{rngs::OsRng, RngCore};
use rust_embed::RustEmbed;
use axum::{body::Body, response::Response};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State, Json, DefaultBodyLimit,
    },
    http::{header::{AUTHORIZATION, ORIGIN, SEC_WEBSOCKET_PROTOCOL}, HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use futures_util::{SinkExt, StreamExt};
use pictochat_relay::{auth::RoomAuth, Rooms, MAX_FRAME_BYTES};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

const MAX_CONNECTIONS: usize = 128;
const MAX_MESSAGES_PER_SECOND: u32 = 20;
const TEMP_ROOM_TTL_SECONDS: u64 = 6 * 3600;
const MAX_ROOM_CREATIONS_PER_MINUTE: u32 = 32;

#[derive(Clone)]
struct AppState {
    rooms: Arc<Rooms>,
    slots: Arc<Semaphore>,
    auth: Arc<RoomAuth>,
    issuance: Arc<Mutex<RoomIssuanceQuota>>,
    admissions: Arc<MembershipAdmissions>,
    invitations: Arc<InviteBroker>,
}

// Global, bounded, process-local admission throttle. An unauthenticated caller
// must not be allowed to force unlimited cryptographic token generation.
// This is not per-IP protection and remains loopback-only.
struct RoomIssuanceQuota {
    window_start: Instant,
    count: u32,
}

impl RoomIssuanceQuota {
    fn new() -> Self {
        Self { window_start: Instant::now(), count: 0 }
    }

    fn permit(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(60) {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= MAX_ROOM_CREATIONS_PER_MINUTE { return false; }
        self.count += 1;
        true
    }
}

// Fixed one-second quota per session, including clients on the same room.
struct MessageQuota {
    window_start: Instant,
    accepted: u32,
}

impl MessageQuota {
    fn new() -> Self {
        Self { window_start: Instant::now(), accepted: 0 }
    }

    fn permit(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.accepted = 0;
        }
        if self.accepted >= MAX_MESSAGES_PER_SECOND { return false; }
        self.accepted += 1;
        true
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let secret = std::env::var("PICTOCHAT_RELAY_SECRET")
        .map_err(|_| std::io::Error::other("set PICTOCHAT_RELAY_SECRET to 64 hex digits"))?;
    let auth = Arc::new(RoomAuth::from_hex(&secret).map_err(std::io::Error::other)?);
    if let Ok(origin)=std::env::var("PICTORUST_PUBLIC_ORIGIN") {
        if !valid_public_origin(&origin) {
            return Err(std::io::Error::other(
                "PICTORUST_PUBLIC_ORIGIN must be one valid explicit https:// origin"));
        }
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "invite" {
        let token = auth.issue(&args[2]).map_err(std::io::Error::other)?;
        println!("{token}");
        return Ok(());
    }
    if args.len() != 1 {
        return Err(std::io::Error::other("usage: cargo run -- [invite 32-hex-room-id]"));
    }
    let state = AppState {
        rooms: Arc::new(Rooms::default()),
        slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        auth,
        issuance: Arc::new(Mutex::new(RoomIssuanceQuota::new())),
            admissions: Arc::new(MembershipAdmissions::default()),
            invitations: Arc::new(InviteBroker::default()),
    };
    let app = router(state);
    // Bind exclusively to loopback until the protocol is authenticated and E2EE.
    let addr = SocketAddr::from(([127, 0, 0, 1], 8787));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("EXPERIMENTAL PSK relay listening at {addr} (loopback only; NOT production-ready)");
    axum::serve(listener, app).await
}

// Serve only the original static Nintendo DS artwork, never the legacy
// application's JavaScript or HTML (which are tied to the old plaintext API).
#[derive(RustEmbed)]
#[folder = "../src/main/resources/www/"]
struct OriginalPictoAssets;

async fn original_picto_image(Path(name): Path<String>) -> Result<Response, StatusCode> {
    if name.contains('/') || !name.ends_with(".png")
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let key = format!("images/{name}");
    let asset = OriginalPictoAssets::get(&key).ok_or(StatusCode::NOT_FOUND)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "image/png")
        .header(axum::http::header::CACHE_CONTROL, "public, max-age=86400")
        .header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(asset.data.into_owned()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn original_picto_font() -> Result<Response, StatusCode> {
    let asset = OriginalPictoAssets::get("nds.ttf").ok_or(StatusCode::NOT_FOUND)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "font/ttf")
        .header(axum::http::header::CACHE_CONTROL, "public, max-age=86400")
        .header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(asset.data.into_owned()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dev_home))
        .route("/healthz", get(healthz))
        .route("/mls", get(mls_home))
        .route("/mls/healthz", get(mls_readiness))
        .route("/mls/app.mjs", get(mls_app_module))
        .route("/mls/session.mjs", get(mls_session_module))
        .route("/mls/pkg/{name}", get(mls_wasm_asset))
        .route("/original/images/{name}", get(original_picto_image))
        .route("/original/nds.ttf", get(original_picto_font))
        .route("/crypto.mjs", get(crypto_module))
        .route("/app.mjs", get(app_module))
        .route("/session.mjs", get(session_module))
        .route("/pictorust-export.mjs", get(pictorust_export_module))
        .route("/identity.mjs", get(identity_module))
        .route("/new-room", post(create_temporary_room))
        .route("/mls/invite/{room_id}/{leaf}", post(issue_mls_member))
        .route("/mls/revoke/{room_id}/{leaf}", post(revoke_mls_member))
        .route("/mls/join/register/{room_id}", post(register_join_link))
        .route("/mls/join/request/{room_id}", post(request_join))
        .route("/mls/join/pending/{room_id}", get(pending_joins))
        .route("/mls/join/complete/{room_id}/{id}", post(complete_join))
        .route("/mls/join/result/{room_id}/{id}", post(join_result))
        .route("/ws/{room_id}", get(connect))
        .layer(DefaultBodyLimit::max(48 * 1024))
        .with_state(state)
}

async fn app_module() -> ([(axum::http::header::HeaderName, &'static str); 2], &'static str) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("../public/app.mjs"),
    )
}

async fn pictorust_export_module() -> ([(axum::http::header::HeaderName, &'static str); 2], &'static str) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("../public/pictorust-export.mjs"),
    )
}

async fn session_module() -> ([(axum::http::header::HeaderName, &'static str); 2], &'static str) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("../public/session.mjs"),
    )
}

async fn identity_module() -> ([(axum::http::header::HeaderName, &'static str); 2], &'static str) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("../public/identity.mjs"),
    )
}

async fn crypto_module() -> ([(axum::http::header::HeaderName, &'static str); 2], &'static str) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("../public/crypto.mjs"),
    )
}

// Readiness is intentionally shallow: no room counts, capabilities or keys.
// WASM assets are built by wasm-pack into mls-web/pkg (never served from
// arbitrary paths). Only explicit generated files are exposed. This local
// developer endpoint is unavailable until the WASM package is built.
fn mls_asset_directory() -> String {
    std::env::var("PICTORUST_MLS_ASSETS")
        .unwrap_or_else(|_| "../mls-web/pkg".to_owned())
}

// The relay can be healthy even if optional frontend assets were omitted.
// MLS-specific readiness therefore reports failure until the real WASM/JS
// package is deployed, without exposing filesystem paths or key material.
async fn mls_readiness() -> Result<
    ([(axum::http::header::HeaderName, &'static str); 2], &'static str),
    StatusCode
> {
    let dir=mls_asset_directory();
    for file in ["pictorust_mls_web.js","pictorust_mls_web_bg.wasm"] {
        let metadata=tokio::fs::metadata(format!("{dir}/{file}")).await
            .map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
        if !metadata.is_file() || metadata.len()<64 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    Ok(([
        (axum::http::header::CONTENT_TYPE,"text/plain; charset=utf-8"),
        (axum::http::header::CACHE_CONTROL,"no-store"),
    ],"ok"))
}

async fn mls_wasm_asset(Path(name): Path<String>) -> Result<Response, StatusCode> {
    let media = match name.as_str() {
        "pictorust_mls_web.js" => "text/javascript; charset=utf-8",
        "pictorust_mls_web_bg.wasm" => "application/wasm",
        _ => return Err(StatusCode::NOT_FOUND),
    };
    let directory = mls_asset_directory();
    let bytes = tokio::fs::read(format!("{directory}/{name}"))
        .await.map_err(|_| StatusCode::NOT_FOUND)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, media)
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn public_csp(style_self: bool) -> String {
    let mut connect=String::from("ws://127.0.0.1:8787 ws://localhost:8787");
    if let Ok(origin)=std::env::var("PICTORUST_PUBLIC_ORIGIN") {
        if valid_public_origin(&origin) {
            connect.push(' ');
            connect.push_str(&origin.replacen("https://","wss://",1));
        }
    }
    let style=if style_self {"'self' 'unsafe-inline'"} else {"'unsafe-inline'"};
    format!("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src {style}; img-src 'self' data:; font-src 'self'; connect-src 'self' {connect}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}

fn serve_html(document: &'static str, style_self: bool) -> Response {
    let csp=public_csp(style_self);
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE,"text/html; charset=utf-8")
        .header(axum::http::header::CACHE_CONTROL,"no-store")
        .header(axum::http::header::CONTENT_SECURITY_POLICY,csp)
        .header(axum::http::header::REFERRER_POLICY,"no-referrer")
        .header(axum::http::header::X_CONTENT_TYPE_OPTIONS,"nosniff")
        .header("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        .body(Body::from(document))
        .expect("valid static HTML response")
}

async fn mls_home() -> Response {
    serve_html(include_str!("../public/mls.html"),true)
}

async fn mls_session_module() -> (
    [(axum::http::header::HeaderName, &'static str); 2], &'static str,
) {
    ([
        (axum::http::header::CONTENT_TYPE,"text/javascript; charset=utf-8"),
        (axum::http::header::CACHE_CONTROL,"no-store"),
    ],include_str!("../public/mls-session.mjs"))
}

async fn mls_app_module() -> (
    [(axum::http::header::HeaderName, &'static str); 2],
    &'static str,
) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("../public/mls.mjs"),
    )
}

async fn healthz() -> (
    [(axum::http::header::HeaderName, &'static str); 3],
    &'static str,
) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        "ok",
    )
}

async fn dev_home() -> Response {
    serve_html(include_str!("../public/index.html"),false)
}

// Stateless, time-limited HMAC bearer invitation. Never persisted.
// Legacy administratively issued IDs stay supported for the development tests.
fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default().as_secs()
}

fn temporary_room_deadline(id: &str) -> Option<u64> {
    if id.len() != 32 || !id.starts_with("ee") {
        return None;
    }
    // Invalid temporary identifiers are rejected in the admission path.
    let created = u64::from_str_radix(&id[2..10], 16).unwrap_or(0);
    Some(created.saturating_add(TEMP_ROOM_TTL_SECONDS))
}

fn temporary_room_is_expired(id: &str) -> bool {
    let Some(deadline) = temporary_room_deadline(id) else { return false; };
    let now = unix_seconds();
    let created = deadline.saturating_sub(TEMP_ROOM_TTL_SECONDS);
    created > now.saturating_add(60) || now >= deadline
}

async fn create_temporary_room(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<([(axum::http::header::HeaderName, &'static str); 3], String), StatusCode> {
    if !origin_is_allowed(&headers) {
        return Err(StatusCode::FORBIDDEN);
    }
    {
        let mut quota = state.issuance.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !quota.permit(Instant::now()) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    let now = unix_seconds();
    let mut bytes = [0u8; 11];
    OsRng.fill_bytes(&mut bytes);
    let id = format!("ee{:08x}{}", now as u32, hex::encode(bytes));
    let token = state.auth.issue(&id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let expires = now.saturating_add(TEMP_ROOM_TTL_SECONDS);
    // Values are exclusively generated ASCII hex and numeric characters.
    let body = format!("{{\"roomId\":\"{id}\",\"token\":\"{token}\",\"expiresAt\":{expires}}}");
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::REFERRER_POLICY, "no-referrer"),
        ],
        body,
    ))
}

// The sole room owner capability is never delivered to group members.
// A random per-leaf MLS bearer is minted only when the owner provides its
// distinct HMAC room capability in the Authorization header.
fn owner_http_authorized(headers: &HeaderMap, room: &str, auth: &RoomAuth) -> bool {
    let mut iter=headers.get_all(AUTHORIZATION).iter();
    let (Some(value),None)=(iter.next(),iter.next()) else {return false;};
    value.to_str().ok().and_then(|text|text.strip_prefix("Bearer "))
        .is_some_and(|token|auth.verify(room,token))
}


#[derive(serde::Deserialize)]
struct JoinSecret { secret: String }
#[derive(serde::Deserialize)]
struct JoinSubmission { secret: String, key_package: String, previous_token: Option<String> }
#[derive(serde::Serialize,serde::Deserialize)]
struct JoinCompletion { welcome: String, tree: String, token: String }
#[derive(serde::Serialize)]
struct JoinReceipt { id: String }
#[derive(serde::Serialize)]
struct PendingJoin { id: String, key_package: String, previous_leaf: Option<u32> }

fn owner_join_authorized(headers: &HeaderMap,room:&str,state:&AppState)->bool{
    origin_is_allowed(headers) && !temporary_room_is_expired(room) &&
    owner_http_authorized(headers,room,&state.auth)
}

async fn register_join_link(
    State(state):State<AppState>,Path(room_id):Path<String>,
    headers:HeaderMap,Json(data):Json<JoinSecret>
)->Result<StatusCode,StatusCode>{
    if !owner_join_authorized(&headers,&room_id,&state){return Err(StatusCode::FORBIDDEN);}
    state.invitations.register(&room_id,&data.secret).map_err(|_|StatusCode::BAD_REQUEST)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn request_join(
    State(state):State<AppState>,Path(room_id):Path<String>,headers:HeaderMap,
    Json(data):Json<JoinSubmission>
)->Result<Json<JoinReceipt>,StatusCode>{
    if !origin_is_allowed(&headers) || temporary_room_is_expired(&room_id){
        return Err(StatusCode::FORBIDDEN);
    }
    // Only the actual previous device bearer may request a replacement leaf.
    let previous_leaf=match data.previous_token {
        Some(ref bearer)=>Some(state.admissions.leaf_for_token(&room_id,bearer)
            .ok_or(StatusCode::FORBIDDEN)?),
        None=>None,
    };
    let id=state.invitations.request(&room_id,&data.secret,&data.key_package,previous_leaf)
        .map_err(|_|StatusCode::FORBIDDEN)?;
    Ok(Json(JoinReceipt{id}))
}

async fn pending_joins(
    State(state):State<AppState>,Path(room_id):Path<String>,headers:HeaderMap
)->Result<Json<Vec<PendingJoin>>,StatusCode>{
    if !owner_join_authorized(&headers,&room_id,&state){return Err(StatusCode::FORBIDDEN);}
    Ok(Json(state.invitations.pending(&room_id).into_iter().map(|(id,key_package,previous_leaf)|
        PendingJoin{id,key_package,previous_leaf}).collect()))
}

async fn complete_join(
    State(state):State<AppState>,Path((room_id,id)):Path<(String,String)>,
    headers:HeaderMap,Json(data):Json<JoinCompletion>
)->Result<StatusCode,StatusCode>{
    if !owner_join_authorized(&headers,&room_id,&state){return Err(StatusCode::FORBIDDEN);}
    if data.welcome.len()>16000 || data.tree.len()>16000 || !data.welcome.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'+'||b==b'/'||b==b'=') ||
       !data.tree.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'+'||b==b'/'||b==b'=') ||
       data.token.len()!=64 || !data.token.bytes().all(|b|b.is_ascii_hexdigit()){
        return Err(StatusCode::BAD_REQUEST);
    }
    let payload=serde_json::to_string(&data)
        .map_err(|_|StatusCode::BAD_REQUEST)?;
    state.invitations.complete(&room_id,&id,&payload)
        .map_err(|_|StatusCode::CONFLICT)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn join_result(
    State(state):State<AppState>,Path((room_id,id)):Path<(String,String)>,
    headers:HeaderMap,Json(data):Json<JoinSecret>
)->Result<axum::response::Response,StatusCode>{
    if !origin_is_allowed(&headers) || temporary_room_is_expired(&room_id){
        return Err(StatusCode::FORBIDDEN);
    }
    let result=state.invitations.result(&room_id,&id,&data.secret)
        .map_err(|_|StatusCode::FORBIDDEN)?;
    match result {
        Some(payload)=>Response::builder().status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE,"application/json; charset=utf-8")
            .header(axum::http::header::CACHE_CONTROL,"no-store")
            .body(Body::from(payload)).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR),
        None=>Response::builder().status(StatusCode::ACCEPTED)
            .header(axum::http::header::CACHE_CONTROL,"no-store")
            .body(Body::empty()).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn issue_mls_member(
    State(state): State<AppState>,
    Path((room_id,leaf)): Path<(String,u32)>,
    headers: HeaderMap,
) -> Result<([(axum::http::header::HeaderName, &'static str);2],String),StatusCode> {
    if !origin_is_allowed(&headers) || temporary_room_is_expired(&room_id)
        || !owner_http_authorized(&headers,&room_id,&state.auth) {
        return Err(StatusCode::FORBIDDEN);
    }
    let token=state.admissions.mint(&room_id,leaf)
        .map_err(|_|StatusCode::CONFLICT)?;
    Ok(([
        (axum::http::header::CONTENT_TYPE,"application/json; charset=utf-8"),
        (axum::http::header::CACHE_CONTROL,"no-store"),
    ],format!("{{\"token\":\"{token}\",\"leaf\":{leaf}}}")))
}

async fn revoke_mls_member(
    State(state): State<AppState>,
    Path((room_id,leaf)): Path<(String,u32)>,
    headers: HeaderMap,
) -> Result<StatusCode,StatusCode> {
    if !origin_is_allowed(&headers)
        || !owner_http_authorized(&headers,&room_id,&state.auth) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !state.admissions.revoke(&room_id,leaf) {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn connect(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, StatusCode> {
    if !origin_is_allowed(&headers) {
        return Err(StatusCode::FORBIDDEN);
    }
    if temporary_room_is_expired(&room_id) {return Err(StatusCode::FORBIDDEN);}
    let revoked = if room_capability_valid(&headers, &room_id, &state.auth) {
        None // owner/admin token, never shared with participants
    } else {
        let token=requested_capability(&headers).ok_or(StatusCode::FORBIDDEN)?;
        Some(state.admissions.verify(&room_id, token).ok_or(StatusCode::FORBIDDEN)?)
    };
    let permit = state.slots.clone().try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let room = state.rooms.join(&room_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let room_permit = room.try_enter().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // Register the subscriber BEFORE completing the handshake. Otherwise a peer
    // may send a frame just after HTTP 101, but before session() subscribes.
    let receiver = room.subscribe();
    let time_to_live = temporary_room_deadline(&room_id)
        .map(|deadline| Duration::from_secs(deadline.saturating_sub(unix_seconds())));
    Ok(ws.protocols(["picto.v1"]).max_message_size(MAX_FRAME_BYTES).max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| session(socket, room, receiver, permit, room_permit, SessionPolicy {
            time_to_live, revocation: revoked, require_mls_v3: public_tls_mode()
        })))
}

struct SessionPolicy {
    time_to_live: Option<Duration>,
    revocation: Option<watch::Receiver<bool>>,
    require_mls_v3: bool,
}

async fn session(socket: WebSocket, room: Arc<pictochat_relay::Room>, mut receiver: tokio::sync::broadcast::Receiver<Vec<u8>>, _permit: OwnedSemaphorePermit, _room_permit: OwnedSemaphorePermit, policy: SessionPolicy) {
    let SessionPolicy { time_to_live, revocation, require_mls_v3 } = policy;
    let (mut outgoing, mut incoming) = socket.split();
    let mut quota = MessageQuota::new();
    // Not even an already connected peer may extend a temporary room past expiry.
    let expiry = async move {
        match time_to_live {
            Some(duration) => tokio::time::sleep(duration).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(expiry);
    // Per-device bearer revocation immediately terminates an existing socket.
    let revoked = async move {
        match revocation {
            Some(mut receiver) => {
                if *receiver.borrow_and_update() {return;}
                let _ = receiver.changed().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(revoked);
    loop {
        tokio::select! {
            _ = &mut expiry => break,
            _ = &mut revoked => break,
            received = incoming.next() => {
                match received {
                    Some(Ok(Message::Binary(data))) => {
                        if !frame_allowed_for_mode(&data, require_mls_v3) ||
                            !quota.permit(Instant::now()) || room.publish(data.to_vec()).is_err() { break; }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Text(_))) => break, // encrypted envelopes must be binary
                    _ => {}
                }
            }
            delivered = receiver.recv() => {
                match delivered {
                    Ok(payload) => {
                        if outgoing.send(Message::Binary(payload.into())).await.is_err() { break; }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}



// The browser sends both subprotocol values; only the public protocol identifier
// is echoed. The admission token is never placed in a URL or echoed to the client.
// This is bearer-token room admission, not participant identity nor E2EE.
fn public_tls_mode() -> bool {
    std::env::var("PICTORUST_PUBLIC_ORIGIN").ok()
        .is_some_and(|origin|valid_public_origin(&origin))
}

fn frame_allowed_for_mode(payload: &[u8], require_mls_v3: bool) -> bool {
    !require_mls_v3 || payload.first()==Some(&3)
}

fn room_capability_valid(headers: &HeaderMap, room: &str, auth: &RoomAuth) -> bool {
    requested_capability(headers).is_some_and(|token|auth.verify(room,token))
}

fn requested_capability(headers: &HeaderMap) -> Option<&str> {
    let mut saw_protocol = false;
    let mut candidate: Option<&str> = None;
    for header in headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter() {
        let Ok(header) = header.to_str() else { return None; };
        for part in header.split(',').map(str::trim) {
            if part == "picto.v1" {
                if saw_protocol { return None; }
                saw_protocol = true;
            } else {
                let value = part.strip_prefix("auth.")?;
                if candidate.is_some() { return None; }
                candidate = Some(value);
            }
        }
    }
    if saw_protocol {candidate} else {None}
}

// Browsers always send Origin on WebSocket handshakes; CLI clients may omit it.
// This is CSWSH protection, NOT authentication or authorization.
fn origin_is_allowed(headers: &HeaderMap) -> bool {
    let configured=std::env::var("PICTORUST_PUBLIC_ORIGIN").ok()
        .filter(|value|valid_public_origin(value));
    origin_allowed_for_config(headers,configured.as_deref())
}

/// Missing Origin is supported for local CLI integration tests only.
/// Public deployments require a single exact HTTPS Origin even for
/// privileged JSON endpoints. Never trust spoofable X-Forwarded headers.
fn origin_allowed_for_config(headers: &HeaderMap, public: Option<&str>) -> bool {
    let mut origins=headers.get_all(ORIGIN).iter();
    match (origins.next(),origins.next()) {
        (None,None) => public.is_none(),
        (Some(value),None) => {
            let Ok(value)=value.to_str() else {return false;};
            if public.is_some_and(|expected|value==expected) {return true;}
            public.is_none() &&
                matches!(value,"http://127.0.0.1:8787"|"http://localhost:8787")
        }
        _ => false,
    }
}

fn valid_public_origin(value: &str) -> bool {
    let Some(host) = value.strip_prefix("https://") else { return false; };
    !host.is_empty() && host.len() <= 253 &&
    !host.chars().any(|ch| matches!(ch, '/' | '?' | '#' | '@' | '\\' | '%' | ' ' | '\t' | '\n' | '\r')) &&
    host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b':')) &&
    !host.starts_with('.') && !host.ends_with('.') && !host.starts_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;



    #[test]
    fn public_mode_refuses_experimental_legacy_v2_frames() {
        let legacy=[2u8,1u8,2u8];
        let mls=[3u8,1u8,2u8];
        assert!(frame_allowed_for_mode(&legacy,false),
            "local-only backwards compatibility remains testable");
        assert!(!frame_allowed_for_mode(&legacy,true));
        assert!(frame_allowed_for_mode(&mls,true));
        assert!(!frame_allowed_for_mode(&[],true));
    }

    #[test]
    fn configured_https_origin_is_strictly_validated() {
        assert!(valid_public_origin("https://picto.example.org"));
        assert!(valid_public_origin("https://picto.example.org:8443"));
        for invalid in ["http://picto.example.org", "https://", "https://evil.example/path",
            "https://user@picto.example.org", "https://*.example.org",
            "https://evil.example?hi=1", "https://evil.example/#x",
            "https://evil.example\\nX-Foo: bar"] {
            assert!(!valid_public_origin(invalid), "accepted invalid origin: {invalid}");
        }
    }

    #[test]
    fn public_endpoints_require_a_single_matching_origin() {
        let mut headers=HeaderMap::new();
        assert!(!origin_allowed_for_config(&headers,Some("https://picto.example.org")));
        assert!(origin_allowed_for_config(&headers,None));
        headers.insert(ORIGIN,HeaderValue::from_static("http://localhost:8787"));
        assert!(!origin_allowed_for_config(&headers,Some("https://picto.example.org")));
        headers.insert(ORIGIN,HeaderValue::from_static("https://picto.example.org"));
        assert!(origin_allowed_for_config(&headers,Some("https://picto.example.org")));
        headers.append(ORIGIN,HeaderValue::from_static("https://picto.example.org"));
        assert!(!origin_allowed_for_config(&headers,Some("https://picto.example.org")));
    }

    #[test]
    fn rejects_duplicate_or_foreign_websocket_origins() {
        let mut headers = HeaderMap::new();
        assert!(origin_is_allowed(&headers), "local CLI clients may omit Origin");
        headers.insert(ORIGIN, HeaderValue::from_static("http://127.0.0.1:8787"));
        assert!(origin_is_allowed(&headers));
        headers.append(ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert!(!origin_is_allowed(&headers), "duplicate Origin must be rejected");
        headers.remove(ORIGIN);
        headers.insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert!(!origin_is_allowed(&headers));
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:8787"));
        assert!(origin_is_allowed(&headers));
    }

    #[tokio::test]
    async fn readiness_endpoint_returns_no_sensitive_state() {
        let (headers, body) = healthz().await;
        assert_eq!(body, "ok");
        assert_eq!(headers[0].1, "text/plain; charset=utf-8");
        assert_eq!(headers[1].1, "no-store");
        assert!(!body.contains("secret"));
    }

    #[test]
    fn room_creation_quota_has_bounded_window_and_resets() {
        let mut quota = RoomIssuanceQuota::new();
        let start = quota.window_start;
        for _ in 0..MAX_ROOM_CREATIONS_PER_MINUTE {
            assert!(quota.permit(start));
        }
        assert!(!quota.permit(start), "thirty-third request must be rejected");
        assert!(!quota.permit(start + Duration::from_secs(59)));
        assert!(quota.permit(start + Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn temporary_room_endpoint_rejects_creation_flood() {
        let state = AppState {
            rooms: Arc::new(Rooms::default()),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            auth: Arc::new(RoomAuth::from_hex(&"11".repeat(32)).unwrap()),
            issuance: Arc::new(Mutex::new(RoomIssuanceQuota::new())),
            admissions: Arc::new(MembershipAdmissions::default()),
            invitations: Arc::new(InviteBroker::default()),
        };
        for _ in 0..MAX_ROOM_CREATIONS_PER_MINUTE {
            assert!(create_temporary_room(State(state.clone()), HeaderMap::new()).await.is_ok());
        }
        assert!(matches!(
            create_temporary_room(State(state), HeaderMap::new()).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
    }

    #[test]
    fn limits_incoming_frames_per_session() {
        let mut quota = MessageQuota::new();
        let origin = quota.window_start;
        for _ in 0..MAX_MESSAGES_PER_SECOND {
            assert!(quota.permit(origin));
        }
        assert!(!quota.permit(origin), "burst must not exceed 20 frames per second");
        assert!(quota.permit(origin + Duration::from_secs(1)));
    }

    #[test]
    fn local_dev_page_contains_no_external_resources_and_has_pdf_action() {
        let html = include_str!("../public/index.html");
        assert!(include_str!("../public/app.mjs").contains("window.print()"));
        assert!(html.contains("ÄÖÜ"));
        assert!(html.contains("EXPERIMENTELLE AES-GCM- UND P-256-SIGNATUREN"));
        assert!(include_str!("../public/app.mjs").contains("identity.mjs"));
        assert!(html.contains("app.mjs"));
        assert!(!html.contains("<script type=\"module\">"));
        assert!(include_str!("main.rs").contains("wasm-unsafe-eval"));
        assert!(html.contains("session.mjs") || include_str!("../public/app.mjs").contains("session.mjs"));
        let app = include_str!("../public/app.mjs");
        assert!(app.contains("verifyMessage("));
        assert!(app.contains("encryptPacket("));
        assert!(app.contains("decryptPacket("));
        assert!(!html.contains("https://"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("localStorage"));
    }

    #[tokio::test]
    async fn active_temporary_room_disconnects_at_expiry() {
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};
        use tokio::time::timeout;
        let auth = Arc::new(RoomAuth::from_hex(&"11".repeat(32)).unwrap());
        let state = AppState {
            rooms: Arc::new(Rooms::default()),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            auth: auth.clone(),
            issuance: Arc::new(Mutex::new(RoomIssuanceQuota::new())),
            admissions: Arc::new(MembershipAdmissions::default()),
            invitations: Arc::new(InviteBroker::default()),
        };
        // Create a valid temporary room whose six-hour lifetime ends shortly.
        let created = unix_seconds().saturating_sub(TEMP_ROOM_TTL_SECONDS - 3);
        let id = format!("ee{:08x}{}", created as u32, "ab".repeat(11));
        let token = auth.issue(&id).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap(); });
        let mut request = format!("ws://{address}/ws/{id}").into_client_request().unwrap();
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            format!("picto.v1, auth.{token}").parse().unwrap()
        );
        let (mut socket, _) = connect_async(request).await.unwrap();
        let ended = timeout(Duration::from_secs(6), socket.next()).await
            .expect("expired temporary room must close active WebSocket");
        assert!(matches!(ended, None | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | Some(Err(_))));
        server.abort();
    }

    #[tokio::test]
    async fn real_websocket_rejects_wrong_capability_and_relays_for_valid_peers() {
        use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, Message as ClientMessage}};
        use tokio::time::{timeout, Duration};

        let auth = Arc::new(RoomAuth::from_hex(&"11".repeat(32)).unwrap());
        let room = "0123456789abcdef0123456789abcdef";
        let token = auth.issue(room).unwrap();
        let state = AppState {
            rooms: Arc::new(Rooms::default()),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            auth,
            issuance: Arc::new(Mutex::new(RoomIssuanceQuota::new())),
            admissions: Arc::new(MembershipAdmissions::default()),
            invitations: Arc::new(InviteBroker::default()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        let url = format!("ws://{address}/ws/{room}");

        let make_request = |capability: &str| {
            let mut request = url.as_str().into_client_request().unwrap();
            request.headers_mut().insert(
                SEC_WEBSOCKET_PROTOCOL,
                format!("picto.v1, auth.{capability}").parse().unwrap()
            );
            request
        };

        let invalid = timeout(Duration::from_secs(3), connect_async(make_request(&"00".repeat(32))))
            .await.unwrap();
        assert!(matches!(invalid, Err(tokio_tungstenite::tungstenite::Error::Http(response))
            if response.status() == StatusCode::FORBIDDEN));

        let (mut alice, alice_response) = timeout(Duration::from_secs(3), connect_async(make_request(&token)))
            .await.unwrap().unwrap();
        assert_eq!(alice_response.headers().get(SEC_WEBSOCKET_PROTOCOL).unwrap(), "picto.v1");
        let (mut bob, _) = timeout(Duration::from_secs(3), connect_async(make_request(&token)))
            .await.unwrap().unwrap();
        let envelope = vec![2u8; pictochat_relay::MIN_ENVELOPE_BYTES];
        alice.send(ClientMessage::Binary(envelope.clone().into())).await.unwrap();
        let received = timeout(Duration::from_secs(3), bob.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(received.into_data().as_ref(), envelope.as_slice());
        server.abort();
    }

    #[tokio::test]
    async fn temporary_room_issues_valid_expiring_bearer() {
        use axum::extract::State;
        let auth = Arc::new(RoomAuth::from_hex(&"11".repeat(32)).unwrap());
        let state = AppState {
            rooms: Arc::new(Rooms::default()),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            auth: auth.clone(),
            issuance: Arc::new(Mutex::new(RoomIssuanceQuota::new())),
            admissions: Arc::new(MembershipAdmissions::default()),
            invitations: Arc::new(InviteBroker::default()),
        };
        let (_, json) = create_temporary_room(State(state), HeaderMap::new()).await.unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let id = value["roomId"].as_str().unwrap();
        let token = value["token"].as_str().unwrap();
        assert!(id.starts_with("ee"));
        assert_eq!(id.len(), 32);
        assert!(auth.verify(id, token));
        assert!(!temporary_room_is_expired(id));
        assert_eq!(value["expiresAt"].as_u64().unwrap(), unix_seconds() + TEMP_ROOM_TTL_SECONDS);
        let old = format!("ee{:08x}{}", (unix_seconds() - TEMP_ROOM_TTL_SECONDS - 1) as u32, "aa".repeat(11));
        assert!(temporary_room_is_expired(&old));
        let future = format!("ee{:08x}{}", (unix_seconds() + 1000) as u32, "bb".repeat(11));
        assert!(temporary_room_is_expired(&future));
    }

    #[test]
    fn room_admission_requires_exact_capability() {
        let auth = RoomAuth::from_hex(&"11".repeat(32)).unwrap();
        let room = "0123456789abcdef0123456789abcdef";
        let other = "ffffffffffffffffffffffffffffffff";
        let token = auth.issue(room).unwrap();
        let mut headers = HeaderMap::new();
        assert!(!room_capability_valid(&headers, room, &auth));
        headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(&format!("picto.v1, auth.{token}")).unwrap());
        assert!(room_capability_valid(&headers, room, &auth));
        assert!(!room_capability_valid(&headers, other, &auth));
        headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("picto.v1, auth.bad"));
        assert!(!room_capability_valid(&headers, room, &auth));
        headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(&format!("picto.v1, auth.{token}, auth.{token}")).unwrap());
        assert!(!room_capability_valid(&headers, room, &auth));
    }

    #[test]
    fn forbids_foreign_browser_origins() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert!(!origin_is_allowed(&headers));
        headers.insert(ORIGIN, HeaderValue::from_static("null"));
        assert!(!origin_is_allowed(&headers));
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:8787"));
        assert!(origin_is_allowed(&headers));
        headers.insert(ORIGIN, HeaderValue::from_static("http://127.0.0.1:8787"));
        assert!(origin_is_allowed(&headers));
    }

    #[test]
    fn session_quota_enforces_rate_and_resets() {
        let mut quota = MessageQuota::new();
        let start = quota.window_start;
        for _ in 0..MAX_MESSAGES_PER_SECOND {
            assert!(quota.permit(start));
        }
        assert!(!quota.permit(start));
        assert!(quota.permit(start + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn session_slots_are_bounded_and_released() {
        let slots = Arc::new(Semaphore::new(1));
        let first = slots.clone().try_acquire_owned().unwrap();
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(first);
        assert!(slots.clone().try_acquire_owned().is_ok());
    }

    #[test]
    fn permits_headless_client_without_origin() {
        assert!(origin_is_allowed(&HeaderMap::new()));
    }
}
