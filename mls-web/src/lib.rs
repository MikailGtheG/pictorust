//! Endpoint-owned WASM bridge for OpenMLS. Never call these APIs on the relay.
//! Membership changes require an explicitly pinned out-of-band fingerprint.
use js_sys::{Array, Object, Reflect, Uint8Array};
use openmls::prelude::tls_codec::*;
use pictochat_mls_lab::client::{Client, Incoming};
use wasm_bindgen::prelude::*;

fn failure(error: &'static str) -> JsValue { JsValue::from_str(error) }
fn put(obj: &Object, key: &str, value: JsValue) -> Result<(), JsValue> {
    Reflect::set(obj, &JsValue::from_str(key), &value).map(|_| ())
}

#[wasm_bindgen]
pub struct BrowserMlsClient {
    client: Client,
}

#[wasm_bindgen]
impl BrowserMlsClient {
    #[wasm_bindgen(constructor)]
    pub fn new(label: &str) -> Result<BrowserMlsClient, JsValue> {
        Ok(Self { client: Client::new(label.as_bytes()).map_err(failure)? })
    }

    /// Plaintext is returned only to an endpoint-managed authenticated
    /// encryption vault. NEVER send this snapshot to the relay or expose it
    /// in logs. The original chat does not enable automatic restore yet.
    pub fn checkpoint_plaintext(&self) -> Result<Vec<u8>, JsValue> {
        self.client.checkpoint_bytes().map_err(failure)
    }

    /// Restore a previously authenticated checkpoint. Deliberately FAILS
    /// CLOSED: the new client cannot send until ordered, verified MLS
    /// catch-up proves it has the current epoch.
    pub fn restore_checkpoint_untrusted(bytes: &[u8]) -> Result<BrowserMlsClient, JsValue> {
        Ok(Self {
            client: Client::restore_checkpoint_untrusted(bytes).map_err(failure)?
        })
    }

    pub fn start_group(&mut self) -> Result<(), JsValue> {
        self.client.start_group().map_err(failure)
    }

    pub fn key_package(&self) -> Result<Vec<u8>, JsValue> {
        self.client.key_package_wire().map_err(failure)
    }

    /// Array [addCommitWire, welcomeWire, ratchetTreeWire].
    /// The operator must check the new participant's signed KeyPackage
    /// fingerprint over an independent trusted channel BEFORE calling this.
    pub fn add_member(&mut self, package: &[u8]) -> Result<Array, JsValue> {
        let (commit, welcome, tree) = self.client.add_wire(package).map_err(failure)?;
        let out = Array::new();
        out.push(&Uint8Array::from(commit.as_slice()));
        out.push(&Uint8Array::from(welcome.as_slice()));
        out.push(&Uint8Array::from(tree.as_slice()));
        Ok(out)
    }

    /// A Welcome alone does NOT authenticate the identity of the inviter.
    /// The UI must separately verify a pinned creator credential before sending.
    pub fn accept_welcome(&mut self, welcome: &[u8], tree: &[u8]) -> Result<(), JsValue> {
        self.client.accept_welcome_wire(welcome, tree).map_err(failure)
    }

    /// The browser MUST call this after a Welcome, before opening a socket.
    /// expected is the out-of-band verified 32-byte Ed25519 public key.
    pub fn pin_owner(&mut self, expected: &[u8]) -> Result<(), JsValue> {
        self.client.pin_group_owner(expected).map_err(failure)
    }

    pub fn send(&mut self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.client.send(message).map_err(failure)
    }

    /// Result has kind=application|membership|removed; application has payload.
    pub fn process(&mut self, frame: &[u8]) -> Result<JsValue, JsValue> {
        if frame.len() < 3 { return Err(failure("incomplete MLS frame")); }
        let message = self.client.process(frame, frame[1]).map_err(failure)?;
        let result = Object::new();
        match message {
            Incoming::Application(payload) => {
                put(&result, "kind", JsValue::from_str("application"))?;
                put(&result, "payload", Uint8Array::from(payload.as_slice()).into())?;
            }
            Incoming::MembershipChanged =>
                put(&result, "kind", JsValue::from_str("membership"))?,
            Incoming::Removed =>
                put(&result, "kind", JsValue::from_str("removed"))?,
        }
        Ok(result.into())
    }

    pub fn remove_member(&mut self, leaf: u32) -> Result<Vec<u8>, JsValue> {
        self.client.remove_leaf(leaf).map_err(failure)
    }

    /// Returns [{leaf, credentialHex, signatureKeyHex}]. Verify these
    /// fingerprints out of band; ephemeral labels are not authorization.
    pub fn members(&self) -> Result<Array, JsValue> {
        let out = Array::new();
        for member in self.client.members().map_err(failure)? {
            let obj = Object::new();
            put(&obj, "leaf", JsValue::from_f64(f64::from(member.leaf)))?;
            put(&obj, "credentialHex", JsValue::from_str(&hex::encode(member.credential)))?;
            put(&obj, "signatureKeyHex", JsValue::from_str(&hex::encode(member.signature_key)))?;
            out.push(&obj);
        }
        Ok(out)
    }

    pub fn own_signature_key_hex(&self) -> String {
        hex::encode(self.client.own_signature_key())
    }

    pub fn epoch(&self) -> Result<u64, JsValue> {
        self.client.epoch().map_err(failure)
    }

    pub fn synchronized(&self) -> bool { self.client.synchronized() }
    pub fn mark_transport_interrupted(&mut self) { self.client.mark_transport_interrupted(); }
    pub fn abandon_group_for_rejoin(&mut self) { self.client.abandon_group_for_rejoin(); }

    /// Reset ephemeral private keys and group state at the end of a session.
    /// Dropping WASM memory is best effort, not certified physical zeroization.
    pub fn dispose(self) {}
}
