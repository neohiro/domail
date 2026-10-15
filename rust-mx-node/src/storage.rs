//! Storage layer for the MX Node

use crate::config::*;
use crate::crypto::*;
use crate::error::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage backend trait
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>>;
    async fn size(&self) -> Result<u64>;
    async fn close(&self) -> Result<()>;
}

/// In-memory storage for WASM
pub struct MemoryStorage {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    max_size: u64,
}

impl MemoryStorage {
    pub fn new(max_size: u64) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            max_size,
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for MemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.data.read().await.get(key).cloned())
    }
    
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut data = self.data.write().await;
        let current_size: u64 = data.values().map(|v| v.len() as u64).sum();
        if current_size + value.len() as u64 > self.max_size {
            return Err(StorageError::QuotaExceeded.into());
        }
        data.insert(key.to_string(), value.to_vec());
        Ok(())
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        self.data.write().await.remove(key);
        Ok(())
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.data.read().await.contains_key(key))
    }
    
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self.data.read().await
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    
    async fn size(&self) -> Result<u64> {
        Ok(self.data.read().await.values().map(|v| v.len() as u64).sum())
    }
    
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Encrypted storage wrapper
pub struct EncryptedStorage {
    backend: Box<dyn StorageBackend>,
    master_key: MasterKey,
}

impl EncryptedStorage {
    pub fn new(backend: Box<dyn StorageBackend>, master_key: MasterKey) -> Self {
        Self { backend, master_key }
    }
    
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if let Some(encrypted_data) = self.backend.get(key).await? {
            let encrypted: EncryptedData = bincode::deserialize(&encrypted_data)
                .map_err(|e| StorageError::Deserialization(e.to_string()))?;
            let decrypted = encrypted.decrypt(&self.master_key)?;
            Ok(Some(decrypted))
        } else {
            Ok(None)
        }
    }
    
    pub async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let encrypted = EncryptedData::encrypt(value, &self.master_key)?;
        let serialized = bincode::serialize(&encrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.backend.set(key, &serialized).await
    }
    
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await
    }
    
    pub async fn exists(&self, key: &str) -> Result<bool> {
        self.backend.exists(key).await
    }
}

/// Message storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub mailbox: String,
    pub from: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    pub headers: HashMap<String, String>,
    pub date: i64,
    pub read: bool,
    pub flagged: bool,
    pub raw: Option<String>,
    pub encrypted: bool,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    pub name: Option<String>,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
    pub inline: bool,
}

/// Mailbox storage
pub struct MailboxStorage {
    storage: EncryptedStorage,
    prefix: String,
}

impl MailboxStorage {
    pub fn new(storage: EncryptedStorage, mailbox: &str) -> Self {
        Self {
            storage,
            prefix: format!("mbox:{}:", mailbox),
        }
    }
    
    pub async fn save(&self, msg: &StoredMessage) -> Result<()> {
        let key = format!("{}{}", self.prefix, msg.id);
        let data = bincode::serialize(msg)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage.set(&key, &data).await
    }
    
    pub async fn get(&self, id: &str) -> Result<Option<StoredMessage>> {
        let key = format!("{}{}", self.prefix, id);
        if let Some(data) = self.storage.get(&key).await? {
            let msg: StoredMessage = bincode::deserialize(&data)
                .map_err(|e| StorageError::Deserialization(e.to_string()))?;
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }
    
    pub async fn delete(&self, id: &str) -> Result<()> {
        let key = format!("{}{}", self.prefix, id);
        self.storage.delete(&key).await
    }
    
    pub async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<StoredMessage>> {
        let keys = self.storage.backend.list_prefix(&self.prefix).await?;
        let mut messages = Vec::new();
        
        for key in keys {
            if let Some(data) = self.backend.get(&key).await? {
                if let Ok(msg) = bincode::deserialize::<StoredMessage>(&data) {
                    messages.push(msg);
                }
            }
        }
        
        // Sort by date descending (newest first)
        messages.sort_by(|a, b| b.date.cmp(&a.date));
        
        if let Some(offset) = offset {
            messages.drain(..offset.min(messages.len()));
        }
        if let Some(limit) = limit {
            messages.truncate(limit);
        }
        
        Ok(messages)
    }
    
    pub async fn count(&self) -> Result<usize> {
        let keys = self.storage.backend.list_prefix(&self.prefix).await?;
        Ok(keys.len())
    }
    
    pub async fn count_unread(&self) -> Result<usize> {
        let messages = self.list(None, None).await?;
        Ok(messages.iter().filter(|m| !m.read).count())
    }
}

/// Contact storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub address: String,
    pub public_key_ed25519: Option<String>,
    pub public_key_x25519: Option<String>,
    pub created: i64,
    pub updated: i64,
}

pub struct ContactStorage {
    storage: EncryptedStorage,
}

impl ContactStorage {
    pub fn new(storage: EncryptedStorage) -> Self {
        Self { storage }
    }
    
    pub async fn save(&self, contact: &Contact) -> Result<()> {
        let key = format!("contact:{}", contact.address);
        let data = bincode::serialize(contact)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage.set(&key, &data).await
    }
    
    pub async fn get(&self, address: &str) -> Result<Option<Contact>> {
        let key = format!("contact:{}", address);
        if let Some(data) = self.storage.get(&key).await? {
            let contact: Contact = bincode::deserialize(&data)
                .map_err(|e| StorageError::Deserialization(e.to_string()))?;
            Ok(Some(contact))
        } else {
            Ok(None)
        }
    }
    
    pub async fn delete(&self, address: &str) -> Result<()> {
        let key = format!("contact:{}", address);
        self.storage.delete(&key).await
    }
    
    pub async fn list(&self) -> Result<Vec<Contact>> {
        let keys = self.storage.backend.list_prefix("contact:").await?;
        let mut contacts = Vec::new();
        
        for key in keys {
            if let Some(data) = self.storage.get(&key).await? {
                if let Ok(contact) = bincode::deserialize::<Contact>(&data) {
                    contacts.push(contact);
                }
            }
        }
        
        contacts.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(contacts)
    }
}

/// Settings storage
pub struct SettingsStorage {
    storage: EncryptedStorage,
}

impl SettingsStorage {
    pub fn new(storage: EncryptedStorage) -> Self {
        Self { storage }
    }
    
    pub async fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let full_key = format!("setting:{}", key);
        if let Some(data) = self.storage.get(&full_key).await? {
            let value = bincode::deserialize(&data)
                .map_err(|e| StorageError::Deserialization(e.to_string()))?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
    
    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let full_key = format!("setting:{}", key);
        let data = bincode::serialize(value)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage.set(&full_key, &data).await
    }
    
    pub async fn delete(&self, key: &str) -> Result<()> {
        let full_key = format!("setting:{}", key);
        self.storage.delete(&full_key).await
    }
}

/// Create storage backend based on config
pub async fn create_storage(config: &StorageConfig) -> Result<Box<dyn StorageBackend>> {
    // For now, use memory storage
    // In production, this would create SQLite/IndexedDB backend
    Ok(Box::new(MemoryStorage::new(config.max_size)))
}