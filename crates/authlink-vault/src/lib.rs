use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const ALGORITHM: &str = "XCHACHA20-POLY1305";
pub const AAD_VERSION: u8 = 1;
pub const MASTER_KEY_BYTES: usize = 32;
pub const DATA_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    bytes: [u8; MASTER_KEY_BYTES],
    version: u32,
}

impl MasterKey {
    pub fn new(bytes: [u8; MASTER_KEY_BYTES], version: u32) -> Self {
        Self { bytes, version }
    }

    pub fn random(version: u32) -> Result<Self, VaultError> {
        let mut bytes = [0_u8; MASTER_KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|error| VaultError::Entropy(error.to_string()))?;
        Ok(Self::new(bytes, version))
    }

    pub fn from_base64(encoded: &str, version: u32) -> Result<Self, VaultError> {
        let decoded = Zeroizing::new(B64.decode(encoded)?);
        let bytes: [u8; MASTER_KEY_BYTES] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::InvalidMasterKeyLength(decoded.len()))?;
        Ok(Self::new(bytes, version))
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.bytes)
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}

pub struct KeyRing {
    active_version: u32,
    keys: BTreeMap<u32, MasterKey>,
}

impl KeyRing {
    pub fn new(active_version: u32, keys: impl IntoIterator<Item = MasterKey>) -> Result<Self, VaultError> {
        let mut map = BTreeMap::new();
        for key in keys {
            let version = key.version();
            if map.insert(version, key).is_some() {
                return Err(VaultError::DuplicateKeyVersion(version));
            }
        }
        if !map.contains_key(&active_version) {
            return Err(VaultError::ActiveKeyMissing(active_version));
        }
        Ok(Self { active_version, keys: map })
    }

    /// Parses `version/base64` entries separated by commas or new lines.
    pub fn from_encoded(active_version: u32, encoded: &str) -> Result<Self, VaultError> {
        let mut keys = Vec::new();
        for raw in encoded.split([',', '\n', '\r']) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let (version, material) = raw
                .split_once('/')
                .ok_or_else(|| VaultError::InvalidKeyEntry(raw.to_owned()))?;
            let version = version
                .parse::<u32>()
                .map_err(|_| VaultError::InvalidKeyEntry(raw.to_owned()))?;
            keys.push(MasterKey::from_base64(material, version)?);
        }
        if keys.is_empty() {
            return Err(VaultError::EmptyKeyRing);
        }
        Self::new(active_version, keys)
    }

    pub fn active_version(&self) -> u32 {
        self.active_version
    }

    pub fn encrypt(&self, binding: &VaultBinding, plaintext: &[u8]) -> Result<EncryptedEnvelope, VaultError> {
        let key = self
            .keys
            .get(&self.active_version)
            .ok_or(VaultError::ActiveKeyMissing(self.active_version))?;
        encrypt(key, binding, plaintext)
    }

    pub fn decrypt(&self, binding: &VaultBinding, envelope: &EncryptedEnvelope) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let key = self
            .keys
            .get(&envelope.key_version)
            .ok_or(VaultError::KeyUnavailable(envelope.key_version))?;
        decrypt(key, binding, envelope)
    }

    pub fn rewrap_to_active(
        &self,
        binding: &VaultBinding,
        envelope: &EncryptedEnvelope,
    ) -> Result<EncryptedEnvelope, VaultError> {
        if envelope.key_version == self.active_version {
            return Ok(envelope.clone());
        }
        let old = self
            .keys
            .get(&envelope.key_version)
            .ok_or(VaultError::KeyUnavailable(envelope.key_version))?;
        let new = self
            .keys
            .get(&self.active_version)
            .ok_or(VaultError::ActiveKeyMissing(self.active_version))?;
        rewrap(old, new, binding, envelope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultBinding {
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub item_id: Uuid,
    pub purpose: String,
}

impl VaultBinding {
    pub fn new(tenant_id: Uuid, identity_id: Uuid, item_id: Uuid, purpose: impl Into<String>) -> Self {
        Self { tenant_id, identity_id, item_id, purpose: purpose.into() }
    }

    fn payload_aad(&self) -> Vec<u8> {
        format!(
            "authlink:v{AAD_VERSION}:payload:{}:{}:{}:{}",
            self.tenant_id, self.identity_id, self.item_id, self.purpose
        )
        .into_bytes()
    }

    fn wrap_aad(&self, key_version: u32) -> Vec<u8> {
        format!(
            "authlink:v{AAD_VERSION}:dek:{}:{}:{}:{key_version}",
            self.tenant_id, self.identity_id, self.item_id
        )
        .into_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub algorithm: String,
    pub aad_version: u8,
    pub key_version: u32,
    pub payload_nonce_b64: String,
    pub ciphertext_b64: String,
    pub wrapped_dek_nonce_b64: String,
    pub wrapped_dek_b64: String,
}

impl EncryptedEnvelope {
    pub fn validate_metadata(&self) -> Result<(), VaultError> {
        if self.algorithm != ALGORITHM {
            return Err(VaultError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        if self.aad_version != AAD_VERSION {
            return Err(VaultError::UnsupportedAadVersion(self.aad_version));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("entropy source failed: {0}")]
    Entropy(String),
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("master key must decode to {MASTER_KEY_BYTES} bytes, got {0}")]
    InvalidMasterKeyLength(usize),
    #[error("nonce must decode to {NONCE_BYTES} bytes, got {0}")]
    InvalidNonceLength(usize),
    #[error("wrapped data key must decrypt to {DATA_KEY_BYTES} bytes, got {0}")]
    InvalidDataKeyLength(usize),
    #[error("unsupported envelope algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("unsupported AAD version: {0}")]
    UnsupportedAadVersion(u8),
    #[error("envelope key version {envelope} does not match provided key version {provided}")]
    KeyVersionMismatch { envelope: u32, provided: u32 },
    #[error("invalid key-ring entry: {0}")]
    InvalidKeyEntry(String),
    #[error("key ring cannot be empty")]
    EmptyKeyRing,
    #[error("duplicate master-key version: {0}")]
    DuplicateKeyVersion(u32),
    #[error("active master-key version is missing: {0}")]
    ActiveKeyMissing(u32),
    #[error("master-key version is unavailable: {0}")]
    KeyUnavailable(u32),
    #[error("authenticated encryption/decryption failed")]
    Crypto,
}

pub fn encrypt(
    master_key: &MasterKey,
    binding: &VaultBinding,
    plaintext: &[u8],
) -> Result<EncryptedEnvelope, VaultError> {
    let mut dek = Zeroizing::new([0_u8; DATA_KEY_BYTES]);
    getrandom::fill(dek.as_mut()).map_err(|error| VaultError::Entropy(error.to_string()))?;

    let mut payload_nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut payload_nonce).map_err(|error| VaultError::Entropy(error.to_string()))?;
    let payload_cipher = XChaCha20Poly1305::new(Key::from_slice(dek.as_ref()));
    let payload_aad = binding.payload_aad();
    let ciphertext = payload_cipher
        .encrypt(
            XNonce::from_slice(&payload_nonce),
            Payload { msg: plaintext, aad: &payload_aad },
        )
        .map_err(|_| VaultError::Crypto)?;

    let mut wrap_nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut wrap_nonce).map_err(|error| VaultError::Entropy(error.to_string()))?;
    let wrapping_cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key.bytes));
    let wrap_aad = binding.wrap_aad(master_key.version);
    let wrapped_dek = wrapping_cipher
        .encrypt(
            XNonce::from_slice(&wrap_nonce),
            Payload { msg: dek.as_ref(), aad: &wrap_aad },
        )
        .map_err(|_| VaultError::Crypto)?;

    Ok(EncryptedEnvelope {
        algorithm: ALGORITHM.into(),
        aad_version: AAD_VERSION,
        key_version: master_key.version,
        payload_nonce_b64: B64.encode(payload_nonce),
        ciphertext_b64: B64.encode(ciphertext),
        wrapped_dek_nonce_b64: B64.encode(wrap_nonce),
        wrapped_dek_b64: B64.encode(wrapped_dek),
    })
}

pub fn decrypt(
    master_key: &MasterKey,
    binding: &VaultBinding,
    envelope: &EncryptedEnvelope,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    envelope.validate_metadata()?;
    if envelope.key_version != master_key.version {
        return Err(VaultError::KeyVersionMismatch {
            envelope: envelope.key_version,
            provided: master_key.version,
        });
    }

    let wrap_nonce = decode_nonce(&envelope.wrapped_dek_nonce_b64)?;
    let wrapped_dek = B64.decode(&envelope.wrapped_dek_b64)?;
    let wrapping_cipher = XChaCha20Poly1305::new(Key::from_slice(&master_key.bytes));
    let wrap_aad = binding.wrap_aad(master_key.version);
    let dek_plain = wrapping_cipher
        .decrypt(
            XNonce::from_slice(&wrap_nonce),
            Payload { msg: &wrapped_dek, aad: &wrap_aad },
        )
        .map_err(|_| VaultError::Crypto)?;
    let dek = Zeroizing::new(dek_plain);
    if dek.len() != DATA_KEY_BYTES {
        return Err(VaultError::InvalidDataKeyLength(dek.len()));
    }

    let payload_nonce = decode_nonce(&envelope.payload_nonce_b64)?;
    let ciphertext = B64.decode(&envelope.ciphertext_b64)?;
    let payload_cipher = XChaCha20Poly1305::new(Key::from_slice(dek.as_slice()));
    let payload_aad = binding.payload_aad();
    let plaintext = payload_cipher
        .decrypt(
            XNonce::from_slice(&payload_nonce),
            Payload { msg: &ciphertext, aad: &payload_aad },
        )
        .map_err(|_| VaultError::Crypto)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn rewrap(
    old_master_key: &MasterKey,
    new_master_key: &MasterKey,
    binding: &VaultBinding,
    envelope: &EncryptedEnvelope,
) -> Result<EncryptedEnvelope, VaultError> {
    envelope.validate_metadata()?;
    if envelope.key_version != old_master_key.version {
        return Err(VaultError::KeyVersionMismatch {
            envelope: envelope.key_version,
            provided: old_master_key.version,
        });
    }

    let old_wrap_nonce = decode_nonce(&envelope.wrapped_dek_nonce_b64)?;
    let wrapped_dek = B64.decode(&envelope.wrapped_dek_b64)?;
    let old_cipher = XChaCha20Poly1305::new(Key::from_slice(&old_master_key.bytes));
    let old_aad = binding.wrap_aad(old_master_key.version);
    let dek = Zeroizing::new(
        old_cipher
            .decrypt(
                XNonce::from_slice(&old_wrap_nonce),
                Payload { msg: &wrapped_dek, aad: &old_aad },
            )
            .map_err(|_| VaultError::Crypto)?,
    );
    if dek.len() != DATA_KEY_BYTES {
        return Err(VaultError::InvalidDataKeyLength(dek.len()));
    }

    let mut new_wrap_nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut new_wrap_nonce).map_err(|error| VaultError::Entropy(error.to_string()))?;
    let new_cipher = XChaCha20Poly1305::new(Key::from_slice(&new_master_key.bytes));
    let new_aad = binding.wrap_aad(new_master_key.version);
    let new_wrapped_dek = new_cipher
        .encrypt(
            XNonce::from_slice(&new_wrap_nonce),
            Payload { msg: dek.as_slice(), aad: &new_aad },
        )
        .map_err(|_| VaultError::Crypto)?;

    let mut rotated = envelope.clone();
    rotated.key_version = new_master_key.version;
    rotated.wrapped_dek_nonce_b64 = B64.encode(new_wrap_nonce);
    rotated.wrapped_dek_b64 = B64.encode(new_wrapped_dek);
    Ok(rotated)
}

fn decode_nonce(encoded: &str) -> Result<[u8; NONCE_BYTES], VaultError> {
    let decoded = B64.decode(encoded)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidNonceLength(decoded.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> VaultBinding {
        VaultBinding::new(Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7(), "credential.read")
    }

    #[test]
    fn round_trip_and_rotation() {
        let binding = binding();
        let old = MasterKey::new([7; 32], 1);
        let new = MasterKey::new([9; 32], 2);
        let envelope = encrypt(&old, &binding, b"secret-value").unwrap();
        assert_eq!(decrypt(&old, &binding, &envelope).unwrap().as_slice(), b"secret-value");

        let rotated = rewrap(&old, &new, &binding, &envelope).unwrap();
        assert_eq!(rotated.ciphertext_b64, envelope.ciphertext_b64);
        assert_eq!(rotated.payload_nonce_b64, envelope.payload_nonce_b64);
        assert_eq!(rotated.key_version, 2);
        assert_eq!(decrypt(&new, &binding, &rotated).unwrap().as_slice(), b"secret-value");
    }

    #[test]
    fn key_ring_decrypts_old_versions_and_rewraps_to_active() {
        let binding = binding();
        let old = MasterKey::new([7; 32], 1);
        let old_envelope = encrypt(&old, &binding, b"rotatable").unwrap();
        let ring = KeyRing::new(2, [old, MasterKey::new([9; 32], 2)]).unwrap();

        assert_eq!(ring.decrypt(&binding, &old_envelope).unwrap().as_slice(), b"rotatable");
        let rotated = ring.rewrap_to_active(&binding, &old_envelope).unwrap();
        assert_eq!(rotated.key_version, 2);
        assert_eq!(rotated.ciphertext_b64, old_envelope.ciphertext_b64);
        assert_eq!(ring.decrypt(&binding, &rotated).unwrap().as_slice(), b"rotatable");
    }

    #[test]
    fn encoded_key_ring_requires_active_version() {
        let one = B64.encode([1_u8; 32]);
        let two = B64.encode([2_u8; 32]);
        let ring = KeyRing::from_encoded(2, &format!("1/{one},2/{two}")).unwrap();
        assert_eq!(ring.active_version(), 2);
        assert!(matches!(KeyRing::from_encoded(3, &format!("1/{one}")), Err(VaultError::ActiveKeyMissing(3))));
    }

    #[test]
    fn binding_prevents_cross_identity_decryption() {
        let key = MasterKey::new([7; 32], 1);
        let binding = binding();
        let envelope = encrypt(&key, &binding, b"secret").unwrap();
        let wrong = VaultBinding::new(binding.tenant_id, Uuid::now_v7(), binding.item_id, binding.purpose.clone());
        assert!(matches!(decrypt(&key, &wrong, &envelope), Err(VaultError::Crypto)));
    }

    #[test]
    fn purpose_is_authenticated() {
        let key = MasterKey::new([7; 32], 1);
        let binding = binding();
        let envelope = encrypt(&key, &binding, b"secret").unwrap();
        let wrong = VaultBinding::new(binding.tenant_id, binding.identity_id, binding.item_id, "different-purpose");
        assert!(matches!(decrypt(&key, &wrong, &envelope), Err(VaultError::Crypto)));
    }

    #[test]
    fn ciphertext_tampering_is_detected() {
        let key = MasterKey::new([7; 32], 1);
        let binding = binding();
        let mut envelope = encrypt(&key, &binding, b"secret").unwrap();
        let mut bytes = B64.decode(&envelope.ciphertext_b64).unwrap();
        bytes[0] ^= 0x80;
        envelope.ciphertext_b64 = B64.encode(bytes);
        assert!(matches!(decrypt(&key, &binding, &envelope), Err(VaultError::Crypto)));
    }

    #[test]
    fn wrong_master_key_is_rejected() {
        let binding = binding();
        let key = MasterKey::new([7; 32], 1);
        let wrong = MasterKey::new([8; 32], 1);
        let envelope = encrypt(&key, &binding, b"secret").unwrap();
        assert!(matches!(decrypt(&wrong, &binding, &envelope), Err(VaultError::Crypto)));
    }

    #[test]
    fn master_key_base64_requires_32_bytes() {
        let encoded = B64.encode([3_u8; 32]);
        let key = MasterKey::from_base64(&encoded, 4).unwrap();
        assert_eq!(key.version(), 4);
        assert_eq!(key.to_base64(), encoded);
        assert!(matches!(MasterKey::from_base64(&B64.encode([1_u8; 31]), 1), Err(VaultError::InvalidMasterKeyLength(31))));
    }
}
