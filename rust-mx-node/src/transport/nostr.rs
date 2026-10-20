//! Nostr transport: store-and-forward delivery over Nostr relays.
//!
//! The message is delivered as a NIP-04 encrypted direct message. A NIP-04
//! payload is `AES-256-CBC(iv, message)` followed by `HMAC-SHA256(key,
//! iv || ciphertext)`, where the key is `SHA-256` of the x-coordinate of the
//! ECDH shared secret between the sender and the recipient.
//!
//! Configuration options:
//!
//! | option       | default                          | meaning                        |
//! |--------------|----------------------------------|--------------------------------|
//! | `relays`     | `wss://relay.damus.io,wss://nos.lol` | relays to publish to       |
//! | `secret_key` | –                                | hex encoded 32 byte secret key |
//! | `pubkeys`    | –                                | `address=hexpubkey` pairs      |

use crate::config::TransportConfig;
use crate::error::*;
use crate::transport::{Envelope, Transport, TransportStatus};
use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream};
use tokio::net::TcpStream;
use tracing::debug;

type HmacSha256 = Hmac<Sha256>;

/// Default relay list.
const DEFAULT_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://nos.lol"];

/// Size of the AES-256-CBC initialisation vector in bytes.
const IV_LEN: usize = 16;

/// Size of the NIP-04 message chunk.
const CHUNK_LEN: usize = 32;

/// Nostr relay transport.
pub struct NostrTransport {
    relays: Vec<String>,
    secret_key: Option<[u8; 32]>,
    pubkeys: HashMap<String, [u8; 32]>,
    connections: HashMap<String, WebSocketStream<MaybeTlsStream<TcpStream>>>,
    last_error: Option<String>,
}

impl NostrTransport {
    /// Build the transport from its configuration.
    pub fn new(config: TransportConfig) -> Self {
        let relays = match config.options.get("relays") {
            Some(list) => list
                .split(',')
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect(),
            None => DEFAULT_RELAYS.iter().map(|r| r.to_string()).collect(),
        };

        let secret_key = config
            .options
            .get("secret_key")
            .and_then(|key| hex_decode(key.trim()))
            .and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    Some(key)
                } else {
                    None
                }
            });

        let mut pubkeys = HashMap::new();
        if let Some(map) = config.options.get("pubkeys") {
            for entry in map.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                if let Some((address, key)) = entry.split_once('=') {
                    if let Some(bytes) = hex_decode(key.trim()) {
                        if bytes.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&bytes);
                            pubkeys.insert(address.trim().to_ascii_lowercase(), key);
                        }
                    }
                }
            }
        }

        Self {
            relays,
            secret_key,
            pubkeys,
            connections: HashMap::new(),
            last_error: None,
        }
    }

    /// Public key of this node, if a secret key is configured.
    pub fn public_key(&self) -> Option<[u8; 32]> {
        let secret = self.secret_key?;
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret).ok()?;
        let (xonly, _parity) = Keypair::from_secret_key(&secp, &sk).x_only_public_key();
        Some(xonly.serialize())
    }

    /// Look up the Nostr public key of a mail address.
    pub fn pubkey_for(&self, address: &str) -> Option<[u8; 32]> {
        self.pubkeys
            .get(&address.to_ascii_lowercase())
            .copied()
            .or_else(|| {
                // Fall back to treating the local part as a hex public key.
                hex_decode(address.trim()).and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        Some(key)
                    } else {
                        None
                    }
                })
            })
    }

    /// Encrypt a payload for a recipient using NIP-04.
    pub fn nip04_encrypt(secret: &[u8; 32], recipient: &[u8; 32], plaintext: &str) -> Result<Vec<u8>> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(secret)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        let xonly = XOnlyPublicKey::from_slice(recipient)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        // The x coordinate of the shared point is independent of the parity of
        // the peer key, so the even branch is sufficient.
        let peer = PublicKey::from_x_only_public_key(xonly, secp256k1::Parity::Even);
        let shared = secp256k1::ecdh::shared_secret_point(&peer, &sk);

        let mut hasher = Sha256::new();
        hasher.update(&shared[1..33]);
        let key = hasher.finalize();

        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);

        let padded = encode_message(plaintext.as_bytes());
        let ciphertext = aes_cbc_encrypt(&key, &iv, &padded)?;

        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        mac.update(&iv);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        let mut payload = Vec::with_capacity(IV_LEN + ciphertext.len() + tag.len());
        payload.extend_from_slice(&iv);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&tag);
        Ok(payload)
    }

    /// Decrypt a NIP-04 payload.
    pub fn nip04_decrypt(
        secret: &[u8; 32],
        sender: &[u8; 32],
        payload: &[u8],
    ) -> Result<String> {
        if payload.len() < IV_LEN + 32 {
            return Err(TransportError::ReceiveFailed(
                "NIP-04 payload is too short".to_string(),
            )
            .into());
        }
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(secret)
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
        let xonly = XOnlyPublicKey::from_slice(sender)
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
        let peer = PublicKey::from_x_only_public_key(xonly, secp256k1::Parity::Even);
        let shared = secp256k1::ecdh::shared_secret_point(&peer, &sk);

        let mut hasher = Sha256::new();
        hasher.update(&shared[1..33]);
        let key = hasher.finalize();

        let iv = &payload[..IV_LEN];
        let tag_start = payload.len() - 32;
        let ciphertext = &payload[IV_LEN..tag_start];
        let tag = &payload[tag_start..];

        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
        mac.update(iv);
        mac.update(ciphertext);
        let expected = mac.finalize().into_bytes();
        if !crate::crypto::constant_time_eq(&expected, tag) {
            return Err(TransportError::ReceiveFailed(
                "NIP-04 authentication tag mismatch".to_string(),
            )
            .into());
        }

        let plaintext = aes_cbc_decrypt(&key, iv, ciphertext)?;
        decode_message(&plaintext)
    }

    /// Build and sign the NIP-04 event that carries a message.
    pub fn build_event(
        secret: &[u8; 32],
        recipient: &[u8; 32],
        plaintext: &str,
        created_at: u64,
    ) -> Result<(serde_json::Value, String)> {
        let payload = Self::nip04_encrypt(secret, recipient, plaintext)?;
        let content = base64::engine::general_purpose::STANDARD.encode(&payload);

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(secret)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        let pubkey = hex_encode(&xonly.serialize());

        let recipient_hex = hex_encode(recipient);
        let tags = serde_json::json!([["p", recipient_hex]]);

        // The event id is the SHA-256 of the canonical serialisation.
        let canonical = format!(
            "[0,\"{pubkey}\",{created_at},4,{tags},\"{content}\"]",
            tags = serde_json::to_string(&tags).unwrap_or_else(|_| "[]".to_string()),
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let id = hex_encode(&hasher.finalize());

        let message = Message::from_slice(&hasher.finalize())
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        let signature = keypair.sign_schnorr(message);

        let event = serde_json::json!({
            "id": id,
            "pubkey": pubkey,
            "created_at": created_at,
            "kind": 4,
            "tags": tags,
            "content": content,
            "sig": hex_encode(&signature.serialize()),
        });

        Ok((event, id))
    }
}

/// The payload carried inside a NIP-04 message.
#[derive(Debug, Serialize)]
struct DirectMessage {
    sender: String,
    recipients: Vec<String>,
    body: String,
}

/// Pad a message into the NIP-04 chunk format.
fn encode_message(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in message.chunks(CHUNK_LEN) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        let mut padding = [0u8; CHUNK_LEN];
        OsRng.fill_bytes(&mut padding);
        out.extend_from_slice(&padding[..CHUNK_LEN - chunk.len()]);
    }
    if message.is_empty() {
        out.push(0);
        out.extend_from_slice(&[0u8; CHUNK_LEN]);
    }
    out
}

/// Undo the NIP-04 chunk format.
fn decode_message(padded: &[u8]) -> Result<String> {
    let mut out = Vec::new();
    for chunk in padded.chunks(CHUNK_LEN + 1) {
        if chunk.is_empty() {
            continue;
        }
        let len = chunk[0] as usize;
        if len > CHUNK_LEN {
            return Err(TransportError::ReceiveFailed(
                "NIP-04 chunk length is out of range".to_string(),
            )
            .into());
        }
        let available = chunk.len().saturating_sub(1).min(CHUNK_LEN);
        if len > available {
            return Err(TransportError::ReceiveFailed(
                "NIP-04 chunk is truncated".to_string(),
            )
            .into());
        }
        out.extend_from_slice(&chunk[1..=len]);
    }
    String::from_utf8(out)
        .map_err(|_| TransportError::ReceiveFailed("NIP-04 payload is not UTF-8".to_string()).into())
}

/// AES-256-CBC encryption with PKCS#7 padding.
fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use cipher::{BlockEncryptMut, KeyIvInit};

    let cipher = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|e| TransportError::SendFailed(e.to_string()))?;
    let mut buffer = vec![0u8; plaintext.len() + 16];
    let length = cipher
        .encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buffer, plaintext)
        .map_err(|e| TransportError::SendFailed(e.to_string()))?
        .len();
    buffer.truncate(length);
    Ok(buffer)
}

/// AES-256-CBC decryption, removing the PKCS#7 padding.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use cipher::{BlockDecryptMut, KeyIvInit};

    let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
    let mut buffer = ciphertext.to_vec();
    let length = cipher
        .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?
        .len();
    buffer.truncate(length);
    Ok(buffer)
}

/// Encode bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a lowercase hex string.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[async_trait]
impl Transport for NostrTransport {
    fn id(&self) -> &str {
        "nostr"
    }

    fn name(&self) -> &str {
        "Nostr"
    }

    fn status(&self) -> TransportStatus {
        TransportStatus {
            id: "nostr".to_string(),
            name: "Nostr".to_string(),
            connected: !self.connections.is_empty(),
            endpoint: self.relays.join(", "),
            last_error: self.last_error.clone(),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        if !self.connections.is_empty() {
            return Ok(());
        }
        if self.secret_key.is_none() {
            let error = TransportError::NotConfigured(
                "nostr: no secret_key configured".to_string(),
            );
            self.last_error = Some(error.to_string());
            return Err(error.into());
        }

        for relay in &self.relays {
            match tokio::time::timeout(Duration::from_secs(20), connect_async(relay)).await {
                Ok(Ok((socket, _))) => {
                    self.connections.insert(relay.clone(), socket);
                }
                Ok(Err(e)) => {
                    debug!(relay = %relay, error = %e, "nostr relay unreachable");
                    self.last_error = Some(format!("{relay}: {e}"));
                }
                Err(_) => {
                    debug!(relay = %relay, "nostr relay connection timed out");
                    self.last_error = Some(format!("{relay}: connection timed out"));
                }
            }
        }

        if self.connections.is_empty() {
            return Err(TransportError::ConnectionFailed(
                "no Nostr relay could be reached".to_string(),
            )
            .into());
        }
        self.last_error = None;
        Ok(())
    }

    async fn send(&mut self, envelope: &Envelope, payload: &[u8]) -> Result<()> {
        if self.connections.is_empty() {
            self.connect().await?;
        }
        let Some(secret) = self.secret_key else {
            return Err(TransportError::NotConfigured(
                "nostr: no secret_key configured".to_string(),
            )
            .into());
        };

        let recipient = envelope
            .recipients
            .first()
            .ok_or_else(|| TransportError::SendFailed("no recipient to deliver to".to_string()))?;
        let recipient_key = self.pubkey_for(recipient).ok_or_else(|| {
            TransportError::NotConfigured(format!(
                "nostr: no public key known for {recipient}"
            ))
        })?;

        let message = DirectMessage {
            sender: envelope.sender.clone(),
            recipients: envelope.recipients.clone(),
            body: base64::engine::general_purpose::STANDARD.encode(payload),
        };
        let plaintext = serde_json::to_string(&message)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let (event, id) = Self::build_event(&secret, &recipient_key, &plaintext, created_at)?;

        let mut published = 0usize;
        let mut failures = Vec::new();
        for (relay, socket) in self.connections.iter_mut() {
            let frame = serde_json::json!(["EVENT", event]);
            match socket.send(WsMessage::Text(frame.to_string().into())).await {
                Ok(()) => published += 1,
                Err(e) => failures.push(format!("{relay}: {e}")),
            }
        }

        if published == 0 {
            let error = TransportError::SendFailed(if failures.is_empty() {
                "no Nostr relay accepted the event".to_string()
            } else {
                failures.join("; ")
            });
            self.last_error = Some(error.to_string());
            return Err(error.into());
        }

        debug!(event = %id, "nostr event published");
        self.last_error = None;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        for (_, socket) in self.connections.iter_mut() {
            let _ = socket.close(None).await;
        }
        self.connections.clear();
        Ok(())
    }

    fn is_connected(&self) -> bool {
        !self.connections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn secret() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        key
    }

    #[test]
    fn nip04_round_trip() {
        let sender = secret();
        let recipient = secret();
        let plaintext = "hello nostr";
        let payload = NostrTransport::nip04_encrypt(&sender, &recipient, plaintext).unwrap();
        let decrypted = NostrTransport::nip04_decrypt(&recipient, &sender, &payload).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nip04_detects_tampering() {
        let sender = secret();
        let recipient = secret();
        let mut payload =
            NostrTransport::nip04_encrypt(&sender, &recipient, "hello nostr").unwrap();
        let last = payload.len() - 1;
        payload[last] ^= 0xff;
        assert!(NostrTransport::nip04_decrypt(&recipient, &sender, &payload).is_err());
    }

    #[test]
    fn message_padding_round_trip() {
        let message = b"a message that is exactly thirty two bytes long!!";
        let padded = encode_message(message);
        assert_eq!(decode_message(&padded).unwrap(), String::from_utf8_lossy(message));
    }

    #[test]
    fn event_is_signed_and_identified() {
        let sender = secret();
        let recipient = secret();
        let (event, id) = NostrTransport::build_event(&sender, &recipient, "hi", 1_700_000_000).unwrap();
        assert_eq!(event["kind"], 4);
        assert_eq!(event["id"], serde_json::Value::String(id.clone()));
        assert_eq!(event["sig"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn pubkey_map_is_parsed() {
        let mut options = HashMap::new();
        options.insert(
            "pubkeys".to_string(),
            "alice@example.org=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
        );
        let transport = NostrTransport::new(TransportConfig {
            id: "nostr".to_string(),
            enabled: true,
            options,
        });
        let key = transport
            .pubkey_for("Alice@Example.org")
            .expect("public key");
        assert_eq!(key[0], 0x01);
        assert!(transport.pubkey_for("bob@example.org").is_none());
    }
}
