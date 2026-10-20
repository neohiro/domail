//! Cryptographic primitives for the MX Node

use crate::error::*;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret, StaticSecret as X25519StaticSecret};
use zeroize::ZeroizeOnDrop;

/// Length of the derived symmetric keys in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the ChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of the key derivation salt in bytes.
pub const SALT_LEN: usize = 16;

/// Master key derived from passphrase using Argon2id
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; KEY_LEN],
}

impl MasterKey {
    /// Derive master key from passphrase and salt
    pub fn derive(passphrase: &str, salt: &[u8], params: &Argon2Params) -> Result<Self> {
        let mut key = [0u8; KEY_LEN];
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(params.memory_kb, params.time, params.parallelism, Some(KEY_LEN))
                .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?,
        );

        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

        Ok(Self { key })
    }

    /// Get the raw key bytes
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// Create a cipher from this master key
    pub fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }
}

/// Argon2 parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_kb: u32,
    pub time: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kb: 64 * 1024,
            time: 3,
            parallelism: 4,
        }
    }
}

/// Encrypted data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub salt: [u8; SALT_LEN],
}

impl EncryptedData {
    /// Encrypt data with a master key.
    ///
    /// The stored salt is not decorative: the encryption key is derived from the
    /// master key and the salt with HKDF, so two records that share a master
    /// key never share a key stream.
    pub fn encrypt(data: &[u8], master_key: &MasterKey) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let key = derive_key(master_key.as_bytes(), &salt, b"domail-mx-node-record", KEY_LEN)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        Ok(Self {
            nonce,
            ciphertext,
            salt,
        })
    }

    /// Decrypt data with a master key
    pub fn decrypt(&self, master_key: &MasterKey) -> Result<Vec<u8>> {
        let key = derive_key(master_key.as_bytes(), &self.salt, b"domail-mx-node-record", KEY_LEN)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

/// Ed25519 key pair for signing
#[derive(Clone, ZeroizeOnDrop)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new key pair
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Load from private key bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;
        Ok(Self { signing_key })
    }

    /// Get the verifying (public) key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key as base64
    pub fn public_key_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.verifying_key().as_bytes())
    }

    /// Get the private key as base64
    pub fn private_key_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.signing_key.to_bytes())
    }

    /// Sign a message
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key.sign(msg).to_bytes().to_vec()
    }

    /// Verify a signature
    pub fn verify(pubkey: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<()> {
        let sig = Signature::from_slice(sig)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;
        pubkey
            .verify_strict(msg, &sig)
            .map_err(|e| CryptoError::Verification(e.to_string()))
    }
}

/// X25519 key pair for key exchange
#[derive(Clone, ZeroizeOnDrop)]
pub struct X25519KeyPair {
    static_secret: X25519StaticSecret,
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new key pair
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let static_secret = X25519StaticSecret::random_from_rng(&mut csprng);
        let public_key = X25519PublicKey::from(&static_secret);
        Self {
            static_secret,
            public_key,
        }
    }

    /// Load from private key bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let static_secret = X25519StaticSecret::from(*bytes);
        let public_key = X25519PublicKey::from(&static_secret);
        Self {
            static_secret,
            public_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }

    /// Get the public key as base64
    pub fn public_key_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key.as_bytes())
    }

    /// Get the private key as base64
    pub fn private_key_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.static_secret.as_bytes())
    }

    /// Perform key exchange
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> SharedSecret {
        self.static_secret.diffie_hellman(peer_public)
    }

    /// Perform key exchange and derive a symmetric key
    pub fn derive_key(&self, peer_public: &X25519PublicKey, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
        let shared = self.diffie_hellman(peer_public);
        let material = derive_key(shared.as_bytes(), salt, b"domail-mx-node-x25519", KEY_LEN)?;
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&material);
        Ok(key)
    }
}

/// Generate a random salt
pub fn generate_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random nonce (12 bytes for ChaCha20Poly1305)
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HKDF-SHA256 based key derivation
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

/// Encrypt data for a recipient using their X25519 public key (ECIES-like)
pub fn encrypt_for_recipient(
    data: &[u8],
    recipient_pub: &X25519PublicKey,
    sender_keypair: &X25519KeyPair,
) -> Result<EncryptedData> {
    let shared = sender_keypair.diffie_hellman(recipient_pub);
    let salt = generate_salt(SALT_LEN);
    let key = derive_key(shared.as_bytes(), &salt, b"domail-ecies", KEY_LEN)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let mut salt_array = [0u8; SALT_LEN];
    salt_array.copy_from_slice(&salt);

    Ok(EncryptedData {
        nonce,
        ciphertext,
        salt: salt_array,
    })
}

/// Decrypt data encrypted with [`encrypt_for_recipient`]
pub fn decrypt_for_recipient(
    encrypted: &EncryptedData,
    recipient_keypair: &X25519KeyPair,
    sender_pub: &X25519PublicKey,
) -> Result<Vec<u8>> {
    let shared = recipient_keypair.diffie_hellman(sender_pub);
    let key = derive_key(shared.as_bytes(), &encrypted.salt, b"domail-ecies", KEY_LEN)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(&encrypted.nonce), encrypted.ciphertext.as_ref())
        .map_err(|e| CryptoError::Decryption(e.to_string()))
}

/// Sign data with Ed25519
pub fn sign_data(data: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    signing_key.sign(data).to_bytes().to_vec()
}

/// Verify Ed25519 signature
pub fn verify_signature(data: &[u8], signature: &[u8], verifying_key: &VerifyingKey) -> Result<()> {
    let sig = Signature::from_slice(signature)
        .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;
    verifying_key
        .verify_strict(data, &sig)
        .map_err(|e| CryptoError::Verification(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap_params() -> Argon2Params {
        Argon2Params {
            memory_kb: 8 * 1024,
            time: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn test_ed25519_keypair() {
        let kp = Ed25519KeyPair::generate();
        let msg = b"test message";
        let sig = kp.sign(msg);
        assert!(Ed25519KeyPair::verify(&kp.verifying_key(), msg, &sig).is_ok());
    }

    #[test]
    fn test_x25519_keypair() {
        let kp1 = X25519KeyPair::generate();
        let kp2 = X25519KeyPair::generate();

        let shared1 = kp1.diffie_hellman(kp2.public_key());
        let shared2 = kp2.diffie_hellman(kp1.public_key());

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_encryption() {
        let master = MasterKey::derive("test passphrase", b"salt12345678", &cheap_params()).unwrap();
        let data = b"Hello, World!";
        let encrypted = EncryptedData::encrypt(data, &master).unwrap();
        let decrypted = encrypted.decrypt(&master).unwrap();
        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn encrypted_records_use_distinct_keys() {
        let master = MasterKey::derive("test passphrase", b"salt12345678", &cheap_params()).unwrap();
        let a = EncryptedData::encrypt(b"same plaintext", &master).unwrap();
        let b = EncryptedData::encrypt(b"same plaintext", &master).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn wrong_master_key_cannot_decrypt() {
        let master = MasterKey::derive("right", b"salt12345678", &cheap_params()).unwrap();
        let other = MasterKey::derive("wrong", b"salt12345678", &cheap_params()).unwrap();
        let encrypted = EncryptedData::encrypt(b"secret", &master).unwrap();
        assert!(encrypted.decrypt(&other).is_err());
    }

    #[test]
    fn ecies_round_trip() {
        let sender = X25519KeyPair::generate();
        let recipient = X25519KeyPair::generate();
        let encrypted =
            encrypt_for_recipient(b"secret message", recipient.public_key(), &sender).unwrap();
        let decrypted =
            decrypt_for_recipient(&encrypted, &recipient, sender.public_key()).unwrap();
        assert_eq!(b"secret message", &decrypted[..]);
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
