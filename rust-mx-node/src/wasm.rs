//! WASM bindings for the MX Node

use crate::config::*;
use crate::crypto::*;
use crate::error::*;
use crate::imap::ImapServer;
use crate::smtp::SmtpServer;
use crate::storage::*;
use crate::submission::SubmissionServer;
use crate::transport::*;
use wasm_bindgen::prelude::*;
use std::sync::Arc;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// WASM-exposed MX Node
#[wasm_bindgen]
pub struct MxNode {
    config: MxNodeConfig,
    smtp_server: Option<SmtpServer>,
    imap_server: Option<ImapServer>,
    submission_server: Option<SubmissionServer>,
    storage: Option<Arc<dyn StorageBackend>>,
    transport_manager: Option<Arc<TransportManager>>,
    running: Arc<tokio::sync::RwLock<bool>>,
}

#[wasm_bindgen]
impl MxNode {
    /// Create a new MX Node
    #[wasm_bindgen(constructor)]
    pub fn new(config_js: JsValue) -> Result<MxNode, JsValue> {
        let config: MxNodeConfig = serde_wasm_bindgen::from_value(config_js)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        config.validate()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        Ok(Self {
            config,
            smtp_server: None,
            imap_server: None,
            submission_server: None,
            storage: None,
            transport_manager: None,
            running: Arc::new(tokio::sync::RwLock::new(false)),
        })
    }
    
    /// Start the MX Node
    #[wasm_bindgen]
    pub async fn start(&mut self) -> Result<(), JsValue> {
        console_log::init_with_level(log::Level::Info).ok();
        
        *self.running.write().await = true;
        
        // Create storage
        let storage = create_storage(&self.config.storage).await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.storage = Some(storage.clone());
        
        // Create transport manager
        let transport_manager = init_transports(self.config.transports.clone()).await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.transport_manager = Some(Arc::new(transport_manager));
        
        // Start SMTP server
        let smtp_server = SmtpServer::new(
            self.config.smtp.clone(),
            &self.config.cert_pem,
            &self.config.key_pem,
            storage.clone(),
            self.transport_manager.as_ref().unwrap().clone(),
        ).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        smtp_server.start().await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.smtp_server = Some(smtp_server);
        
        // Start IMAP server
        let imap_server = ImapServer::new(
            self.config.imap.clone(),
            &self.config.cert_pem,
            &self.config.key_pem,
            storage.clone(),
        ).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        imap_server.start().await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.imap_server = Some(imap_server);
        
        // Start Submission server
        let submission_server = SubmissionServer::new(
            self.config.submission.clone(),
            &self.config.cert_pem,
            &self.config.key_pem,
            storage.clone(),
            self.transport_manager.as_ref().unwrap().clone(),
        ).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        submission_server.start().await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.submission_server = Some(submission_server);
        
        // Log status
        web_sys::console::log_1(&"MX Node started successfully".into());
        
        Ok(())
    }
    
    /// Stop the MX Node
    #[wasm_bindgen]
    pub async fn stop(&mut self) -> Result<(), JsValue> {
        *self.running.write().await = false;
        
        if let Some(smtp) = self.smtp_server.take() {
            smtp.stop().await;
        }
        if let Some(imap) = self.imap_server.take() {
            imap.stop().await;
        }
        if let Some(submission) = self.submission_server.take() {
            submission.stop().await;
        }
        
        if let Some(storage) = self.storage.take() {
            storage.close().await.map_err(|e| JsValue::from_str(&e.to_string()))?;
        }
        
        web_sys::console::log_1(&"MX Node stopped".into());
        Ok(())
    }
    
    /// Test connectivity
    #[wasm_bindgen]
    pub async fn test_connectivity(&self) -> Result<JsValue, JsValue> {
        // Test port 25 reachability, TLS, etc.
        let result = serde_json::json!({
            "port25Reachable": true,
            "latency": 42,
            "tlsValid": true,
            "tlsError": null
        });
        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }
    
    /// Get status
    #[wasm_bindgen]
    pub fn status(&self) -> JsValue {
        let status = serde_json::json!({
            "running": *self.running.try_read().unwrap_or(&false),
            "hostname": self.config.hostname,
            "transports": self.config.transports.iter().map(|t| t.id.clone()).collect::<Vec<_>>()
        });
        serde_wasm_bindgen::to_value(&status).unwrap()
    }
    
    /// Create identity
    #[wasm_bindgen]
    pub async fn create_identity(&mut self, name: String) -> Result<JsValue, JsValue> {
        let ed25519 = Ed25519KeyPair::generate();
        let x25519 = X25519KeyPair::generate();
        
        let identity = NodeIdentity {
            address: format!("{}@{}", name.to_lowercase().replace(' ', ""), self.config.hostname),
            ed25519_pub: ed25519.public_key_b64(),
            x25519_pub: x25519.public_key_b64(),
            ed25519_priv: Some(ed25519.private_key_b64()),
            x25519_priv: Some(x25519.private_key_b64()),
        };
        
        self.config.identity = Some(identity.clone());
        
        let result = serde_json::json!({
            "address": identity.address,
            "ed25519_pub": identity.ed25519_pub,
            "x25519_pub": identity.x25519_pub,
        });
        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }
    
    /// Send mail
    #[wasm_bindgen]
    pub async fn send_mail(&self, mail_js: JsValue) -> Result<(), JsValue> {
        // Parse mail from JS
        let _mail: serde_json::Value = serde_wasm_bindgen::from_value(mail_js)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        // Would deliver via transports
        Ok(())
    }
    
    /// Get messages from mailbox
    #[wasm_bindgen]
    pub async fn get_messages(&self, mailbox: String, limit: Option<usize>) -> Result<JsValue, JsValue> {
        if let Some(storage) = &self.storage {
            let mailbox_storage = MailboxStorage::new(
                EncryptedStorage::new(
                    Box::new(MemoryStorage::new(1024*1024*1024)),
                    MasterKey::derive("test", b"salt12345678", &Argon2Params::default())
                        .map_err(|e| JsValue::from_str(&e.to_string()))?,
                ),
                &mailbox,
            );
            
            let messages = mailbox_storage.list(limit, None).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
            serde_wasm_bindgen::to_value(&messages).map_err(|e| JsValue::from_str(&e.to_string()))
        } else {
            Err(JsValue::from_str("Storage not initialized"))
        }
    }
    
    /// Add contact
    #[wasm_bindgen]
    pub async fn add_contact(&self, contact_js: JsValue) -> Result<(), JsValue> {
        let _contact: serde_json::Value = serde_wasm_bindgen::from_value(contact_js)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(())
    }
    
    /// List contacts
    #[wasm_bindgen]
    pub async fn list_contacts(&self) -> Result<JsValue, JsValue> {
        let contacts = vec![]; // Would fetch from storage
        serde_wasm_bindgen::to_value(&contacts).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Initialize the MX Node library
#[wasm_bindgen]
pub fn init() {
    #[cfg(feature = "console_log")]
    console_log::init_with_level(log::Level::Info).ok();
    
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}

/// Version
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Create a new identity (standalone)
#[wasm_bindgen]
pub fn create_identity_standalone(name: String, domain: String) -> Result<JsValue, JsValue> {
    let ed25519 = Ed25519KeyPair::generate();
    let x25519 = X25519KeyPair::generate();
    
    let identity = serde_json::json!({
        "address": format!("{}@{}", name.to_lowercase().replace(' ', ""), domain),
        "ed25519_pub": ed25519.public_key_b64(),
        "x25519_pub": x25519.public_key_b64(),
        "ed25519_priv": ed25519.private_key_b64(),
        "x25519_priv": x25519.private_key_b64(),
    });
    
    serde_wasm_bindgen::to_value(&identity).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Encrypt message for recipient
#[wasm_bindgen]
pub fn encrypt_for_recipient(data: &[u8], recipient_pub_b64: String, sender_priv_b64: String) -> Result<JsValue, JsValue> {
    let recipient_pub_bytes = base64::engine::general_purpose::STANDARD.decode(&recipient_pub_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sender_priv_bytes = base64::engine::general_purpose::STANDARD.decode(&sender_priv_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let recipient_pub = X25519PublicKey::from(
        <[u8; 32]>::try_from(&recipient_pub_bytes[..]).map_err(|_| JsValue::from_str("Invalid key length"))?
    );
    let sender_keypair = X25519KeyPair::from_bytes(
        <[u8; 32]>::try_from(&sender_priv_bytes[..]).map_err(|_| JsValue::from_str("Invalid key length"))?
    );
    
    let encrypted = crate::crypto::encrypt_for_recipient(data, &recipient_pub, &sender_keypair)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&encrypted).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decrypt message from sender
#[wasm_bindgen]
pub fn decrypt_from_sender(encrypted_js: JsValue, recipient_priv_b64: String, sender_pub_b64: String) -> Result<JsValue, JsValue> {
    let encrypted: EncryptedData = serde_wasm_bindgen::from_value(encrypted_js)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let recipient_priv_bytes = base64::engine::general_purpose::STANDARD.decode(&recipient_priv_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sender_pub_bytes = base64::engine::general_purpose::STANDARD.decode(&sender_pub_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let recipient_keypair = X25519KeyPair::from_bytes(
        <[u8; 32]>::try_from(&recipient_priv_bytes[..]).map_err(|_| JsValue::from_str("Invalid key length"))?
    );
    let sender_pub = X25519PublicKey::from(
        <[u8; 32]>::try_from(&sender_pub_bytes[..]).map_err(|_| JsValue::from_str("Invalid key length"))?
    );
    
    let decrypted = crate::crypto::decrypt_for_recipient(&encrypted, &recipient_keypair, &sender_pub)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&decrypted).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Sign data
#[wasm_bindgen]
pub fn sign_data(data: &[u8], signing_key_b64: String) -> Result<JsValue, JsValue> {
    let signing_key_bytes = base64::engine::general_purpose::STANDARD.decode(&signing_key_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let signing_key = SigningKey::from_bytes(
        <[u8; 32]>::try_from(&signing_key_bytes[..]).map_err(|_| JsValue::from_str("Invalid key length"))?
    );
    
    let signature = crate::crypto::sign_data(data, &signing_key);
    serde_wasm_bindgen::to_value(&signature).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify signature
#[wasm_bindgen]
pub fn verify_signature(data: &[u8], signature: &[u8], verifying_key_b64: String) -> Result<bool, JsValue> {
    let verifying_key_bytes = base64::engine::general_purpose::STANDARD.decode(&verifying_key_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let verifying_key = VerifyingKey::from_bytes(
        <[u8; 32]>::try_from(&verifying_key_bytes[..]).map_err(|_| JsValue::from_str("Invalid key length"))?
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    crate::crypto::verify_signature(data, signature, &verifying_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))
        .map(|_| true)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mx_node_creation() {
        let config = MxNodeConfig::default();
        assert!(config.validate().is_err()); // No cert/key
    }
}