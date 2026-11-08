//! Endpoint-owned, volatile MLS state. This is a test client, not an identity service.
//! All externally influenced operations return errors rather than terminating the process.
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

pub const CIPHER_SUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const FRAME_VERSION: u8 = 3;
pub const KIND_APPLICATION: u8 = 1;
pub const KIND_COMMIT: u8 = 2;
pub const KIND_WELCOME: u8 = 3;
pub const KIND_KEY_PACKAGE: u8 = 4;
pub const MAX_WIRE_SIZE: usize = 16 * 1024;
// Leave ample room for MLS framing, authentication metadata and tree overhead.
pub const MAX_APPLICATION_PLAINTEXT_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    Application(Vec<u8>),
    MembershipChanged,
    Removed,
}

pub type ClientResult<T> = Result<T, &'static str>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub leaf: u32,
    pub credential: Vec<u8>,
    pub signature_key: Vec<u8>,
}

pub fn wrap(kind: u8, data: Vec<u8>) -> ClientResult<Vec<u8>> {
    if !matches!(kind, KIND_APPLICATION | KIND_COMMIT | KIND_WELCOME | KIND_KEY_PACKAGE)
        || data.is_empty() || data.len().saturating_add(2) > MAX_WIRE_SIZE
    {
        return Err("invalid MLS transport envelope");
    }
    let mut out = Vec::with_capacity(data.len() + 2);
    out.extend_from_slice(&[FRAME_VERSION, kind]);
    out.extend(data);
    Ok(out)
}

pub fn unwrap(frame: &[u8], kind: u8) -> ClientResult<MlsMessageIn> {
    if frame.len() < 3 || frame.len() > MAX_WIRE_SIZE
        || frame[0] != FRAME_VERSION || frame[1] != kind
    {
        return Err("wrong MLS envelope version or kind");
    }
    let mut bytes = &frame[2..];
    let message = MlsMessageIn::tls_deserialize(&mut bytes)
        .map_err(|_| "invalid MLS TLS encoding")?;
    if !bytes.is_empty() {
        return Err("trailing bytes after MLS message");
    }
    Ok(message)
}

pub struct Client {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: Option<MlsGroup>,
    // A disconnected client may have missed MLS commits; fail closed.
    synchronized: bool,
}

impl Client {
    pub fn new(label: &[u8]) -> ClientResult<Self> {
        if label.is_empty() || label.len() > 64 {
            return Err("invalid ephemeral identity label");
        }
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHER_SUITE.signature_algorithm())
            .map_err(|_| "cannot create signing identity")?;
        signer.store(provider.storage())
            .map_err(|_| "cannot store signing identity")?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(label.to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self { provider, signer, credential, group: None, synchronized: false })
    }

    pub fn key_package(&self) -> ClientResult<KeyPackage> {
        let bundle = KeyPackage::builder().build(
            CIPHER_SUITE, &self.provider, &self.signer, self.credential.clone()
        ).map_err(|_| "cannot create key package")?;
        Ok(bundle.key_package().clone())
    }

    /// Export a one-use public KeyPackage for out-of-band authenticated onboarding.
    pub fn key_package_wire(&self) -> ClientResult<Vec<u8>> {
        self.key_package()?.tls_serialize_detached()
            .map_err(|_| "cannot encode key package")
    }

    /// Validate a received KeyPackage before the owner authorizes the add.
    /// Signature validity alone is NOT an identity check; callers must pin
    /// the expected participant fingerprint through a separate verified channel.
    pub fn add_wire(&mut self, wire: &[u8]) -> ClientResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if wire.is_empty() || wire.len() > MAX_WIRE_SIZE {
            return Err("invalid key package size");
        }
        let package_in = KeyPackageIn::tls_deserialize_exact(wire)
            .map_err(|_| "invalid key package TLS encoding")?;
        let package = package_in.validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| "invalid key package signature or lifetime")?;
        let (commit, welcome) = self.add(&package)?;
        let tree = self.ratchet_tree()?.tls_serialize_detached()
            .map_err(|_| "cannot serialize ratchet tree")?;
        if tree.len() > MAX_WIRE_SIZE { return Err("ratchet tree too large"); }
        Ok((commit, welcome, tree))
    }

    pub fn accept_welcome_wire(&mut self, welcome: &[u8], tree: &[u8]) -> ClientResult<()> {
        if tree.is_empty() || tree.len() > MAX_WIRE_SIZE {
            return Err("invalid ratchet tree size");
        }
        let parsed = RatchetTreeIn::tls_deserialize_exact(tree)
            .map_err(|_| "invalid ratchet tree TLS encoding")?;
        self.accept_welcome(welcome, parsed)
    }

    pub fn start_group(&mut self) -> ClientResult<()> {
        if self.group.is_some() { return Err("group already initialized"); }
        let group = MlsGroup::new(
            &self.provider, &self.signer,
            &MlsGroupCreateConfig::default(), self.credential.clone()
        ).map_err(|_| "cannot create MLS group")?;
        self.group = Some(group);
        self.synchronized = true;
        Ok(())
    }

    pub fn add(&mut self, package: &KeyPackage) -> ClientResult<(Vec<u8>, Vec<u8>)> {
        if !self.synchronized { return Err("group epoch may be stale; rejoin required"); }
        let group = self.group.as_mut().ok_or("client needs a group")?;
        if !group.is_active() { return Err("client has been removed"); }
        let (commit, welcome, _) = group.add_members(
            &self.provider, &self.signer, std::slice::from_ref(package)
        ).map_err(|_| "cannot add MLS participant")?;
        // Serialize before merging. After the merge, a failed transmission still
        // requires an explicit recovery policy; this is NOT durable delivery.
        let commit = wrap(
            KIND_COMMIT,
            commit.tls_serialize_detached().map_err(|_| "cannot encode MLS add commit")?
        )?;
        let welcome = wrap(
            KIND_WELCOME,
            welcome.tls_serialize_detached().map_err(|_| "cannot encode MLS Welcome")?
        )?;
        group.merge_pending_commit(&self.provider)
            .map_err(|_| "cannot merge MLS add commit")?;
        Ok((commit, welcome))
    }

    pub fn accept_welcome(&mut self, wire: &[u8], tree: RatchetTreeIn) -> ClientResult<()> {
        if self.group.is_some() { return Err("group already initialized"); }
        let welcome = match unwrap(wire, KIND_WELCOME)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err("not an MLS Welcome"),
        };
        let staged = StagedWelcome::new_from_welcome(
            &self.provider, &MlsGroupJoinConfig::default(), welcome, Some(tree)
        ).map_err(|_| "cannot authenticate MLS Welcome")?;
        self.group = Some(staged.into_group(&self.provider)
            .map_err(|_| "cannot join MLS group")?);
        self.synchronized = true;
        Ok(())
    }

    pub fn send(&mut self, message: &[u8]) -> ClientResult<Vec<u8>> {
        if message.is_empty() || message.len() > MAX_APPLICATION_PLAINTEXT_BYTES {
            return Err("message empty or oversized");
        }
        if !self.synchronized { return Err("group epoch may be stale; rejoin required"); }
        let group = self.group.as_mut().ok_or("client needs group")?;
        if !group.is_active() { return Err("client has been removed"); }
        let encrypted = group.create_message(&self.provider, &self.signer, message)
            .map_err(|_| "cannot encrypt MLS application message")?;
        wrap(
            KIND_APPLICATION,
            encrypted.tls_serialize_detached().map_err(|_| "cannot encode MLS ciphertext")?
        )
    }

    pub fn process(&mut self, wire: &[u8], kind: u8) -> ClientResult<Incoming> {
        if !matches!(kind, KIND_APPLICATION | KIND_COMMIT) {
            return Err("not a processable MLS message");
        }
        let protocol = unwrap(wire, kind)?
            .try_into_protocol_message().map_err(|_| "not a protocol message")?;
        if !self.synchronized { return Err("group epoch may be stale; rejoin required"); }
        let group = self.group.as_mut().ok_or("no joined MLS group")?;
        if !group.is_active() { return Err("client has been removed"); }
        let processed = group.process_message(&self.provider, protocol)
            .map_err(|_| "MLS message invalid for this member or epoch")?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) if kind == KIND_APPLICATION =>
                Ok(Incoming::Application(message.into_bytes())),
            ProcessedMessageContent::StagedCommitMessage(staged) if kind == KIND_COMMIT => {
                group.merge_staged_commit(&self.provider, *staged)
                    .map_err(|_| "cannot merge MLS commit")?;
                if group.is_active() { Ok(Incoming::MembershipChanged) }
                else { Ok(Incoming::Removed) }
            }
            _ => Err("message type does not match wire kind"),
        }
    }

    pub fn remove(&mut self, leaf: LeafNodeIndex) -> ClientResult<Vec<u8>> {
        if !self.synchronized { return Err("group epoch may be stale; rejoin required"); }
        let group = self.group.as_mut().ok_or("group needed")?;
        if !group.is_active() { return Err("client has been removed"); }
        let (commit, _, _) = group.remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(|_| "cannot remove MLS member")?;
        let wire = wrap(
            KIND_COMMIT,
            commit.tls_serialize_detached().map_err(|_| "cannot encode MLS removal")?
        )?;
        group.merge_pending_commit(&self.provider)
            .map_err(|_| "cannot merge MLS removal")?;
        Ok(wire)
    }

    /// Call as soon as transport drops or messages may have been missed.
    /// No server-held timestamps or unauthenticated epoch claim can clear this state.
    pub fn mark_transport_interrupted(&mut self) {
        self.synchronized = false;
    }

    /// Explicitly abandon old MLS state before an authenticated new Welcome.
    /// Callers MUST verify the inviter's credential out of band.
    /// This is not a secure automatic recovery handshake.
    pub fn abandon_group_for_rejoin(&mut self) {
        self.group = None;
        self.synchronized = false;
    }

    pub fn synchronized(&self) -> bool {
        self.synchronized && self.group.as_ref().is_some_and(MlsGroup::is_active)
    }

    pub fn own_leaf(&self) -> ClientResult<LeafNodeIndex> {
        Ok(self.group.as_ref().ok_or("group needed")?.own_leaf_index())
    }
    pub fn epoch(&self) -> ClientResult<u64> {
        Ok(self.group.as_ref().ok_or("group needed")?.epoch().as_u64())
    }
    pub fn count(&self) -> ClientResult<usize> {
        Ok(self.group.as_ref().ok_or("group needed")?.members().count())
    }
    pub fn active(&self) -> bool {
        self.group.as_ref().is_some_and(MlsGroup::is_active)
    }
    /// The caller must verify both credential bytes and signature keys out of band.
    /// Leaf indices are ephemeral and change on membership updates; never treat
    /// them as stable identities or authorization records.
    pub fn members(&self) -> ClientResult<Vec<MemberInfo>> {
        let group = self.group.as_ref().ok_or("group needed")?;
        Ok(group.members().map(|member| MemberInfo {
            leaf: member.index.u32(),
            credential: member.credential.serialized_content().to_vec(),
            signature_key: member.signature_key.to_vec(),
        }).collect())
    }

    pub fn remove_leaf(&mut self, leaf: u32) -> ClientResult<Vec<u8>> {
        let member_index = self.members()?;
        if !member_index.iter().any(|member| member.leaf == leaf) {
            return Err("leaf not present in MLS group");
        }
        if self.own_leaf()?.u32() == leaf { return Err("cannot remove own leaf"); }
        self.remove(LeafNodeIndex::new(leaf))
    }

    pub fn ratchet_tree(&self) -> ClientResult<RatchetTreeIn> {
        Ok(self.group.as_ref().ok_or("group needed")?.export_ratchet_tree().into())
    }
}
