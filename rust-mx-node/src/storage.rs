//! Storage layer for the MX Node.
//!
//! Two backends are available: an in-memory map used by the browser build and
//! a directory-backed store used by the native OS service. Both are wrapped by
//! [`EncryptedStorage`], which encrypts every record with the node master key
//! before it reaches the backend.

use crate::config::StorageConfig;
use crate::crypto::*;
use crate::error::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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

/// In-memory storage, used by the browser build and by tests.
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
        Ok(self
            .data
            .read()
            .await
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

/// Directory backed storage used by the native service.
///
/// Every key is stored as a single file whose name is the hex encoding of the
/// key, so the on-disk layout stays flat and portable between platforms.
pub struct FileStorage {
    root: PathBuf,
    max_size: u64,
}

impl FileStorage {
    /// Create (or open) a file store rooted at `root`.
    pub fn new(root: impl AsRef<Path>, max_size: u64) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)
            .map_err(|e| StorageError::Database(format!("cannot create {}: {e}", root.display())))?;
        Ok(Self { root, max_size })
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(hex_encode(key.as_bytes()))
    }

    fn key_for(&self, file_name: &str) -> Option<String> {
        hex_decode(file_name)
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }
}

#[async_trait::async_trait]
impl StorageBackend for FileStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(key);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string()).into()),
        }
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let used = self.size().await?;
        if used + value.len() as u64 > self.max_size {
            return Err(StorageError::QuotaExceeded.into());
        }

        let path = self.path_for(key);
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, value)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Database(e.to_string()).into()),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(tokio::fs::try_exists(self.path_for(key))
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?)
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let mut entries = tokio::fs::read_dir(&self.root)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let mut keys = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp") {
                continue;
            }
            if let Some(key) = self.key_for(&name) {
                if key.starts_with(prefix) {
                    keys.push(key);
                }
            }
        }
        Ok(keys)
    }

    async fn size(&self) -> Result<u64> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(StorageError::Database(e.to_string()).into()),
        };

        let mut total = 0u64;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            if let Ok(meta) = entry.metadata().await {
                total += meta.len();
            }
        }
        Ok(total)
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Encrypted storage wrapper.
///
/// The wrapper is cheap to clone: the backend is shared, so every mailbox
/// view of the node reads and writes the same records.
#[derive(Clone)]
pub struct EncryptedStorage {
    backend: Arc<dyn StorageBackend>,
    master_key: MasterKey,
}

impl EncryptedStorage {
    pub fn new(backend: Arc<dyn StorageBackend>, master_key: MasterKey) -> Self {
        Self {
            backend,
            master_key,
        }
    }

    /// Encrypt and store a value.
    pub async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let encrypted = EncryptedData::encrypt(value, &self.master_key)?;
        let serialized = bincode::serialize(&encrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.backend.set(key, &serialized).await
    }

    /// Decrypt and return a value.
    pub async fn take(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(encrypted_data) = self.backend.get(key).await? else {
            return Ok(None);
        };
        let encrypted: EncryptedData = bincode::deserialize(&encrypted_data)
            .map_err(|e| StorageError::Deserialization(e.to_string()))?;
        Ok(Some(encrypted.decrypt(&self.master_key)?))
    }
}

#[async_trait::async_trait]
impl StorageBackend for EncryptedStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.take(key).await
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.put(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.backend.exists(key).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        self.backend.list_prefix(prefix).await
    }

    async fn size(&self) -> Result<u64> {
        self.backend.size().await
    }

    async fn close(&self) -> Result<()> {
        self.backend.close().await
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
    /// The message is marked for removal by the client.
    #[serde(default)]
    pub deleted: bool,
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
#[derive(Clone)]
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

    /// Mailbox this store is bound to.
    pub fn mailbox(&self) -> &str {
        self.prefix.trim_start_matches("mbox:").trim_end_matches(':')
    }

    pub async fn save(&self, msg: &StoredMessage) -> Result<()> {
        let key = format!("{}{}", self.prefix, msg.id);
        let data =
            bincode::serialize(msg).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage.put(&key, &data).await
    }

    pub async fn get(&self, id: &str) -> Result<Option<StoredMessage>> {
        let key = format!("{}{}", self.prefix, id);
        match self.storage.take(&key).await? {
            Some(data) => {
                let msg: StoredMessage = bincode::deserialize(&data)
                    .map_err(|e| StorageError::Deserialization(e.to_string()))?;
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        let key = format!("{}{}", self.prefix, id);
        self.storage.delete(&key).await
    }

    pub async fn list(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<StoredMessage>> {
        let keys = self.storage.list_prefix(&self.prefix).await?;
        let mut messages = Vec::with_capacity(keys.len());

        for key in keys {
            if let Some(data) = self.storage.take(&key).await? {
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
        Ok(self.storage.list_prefix(&self.prefix).await?.len())
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

/// Contact storage
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
        self.storage.put(&key, &data).await
    }

    pub async fn get(&self, address: &str) -> Result<Option<Contact>> {
        let key = format!("contact:{}", address);
        match self.storage.take(&key).await? {
            Some(data) => {
                let contact: Contact = bincode::deserialize(&data)
                    .map_err(|e| StorageError::Deserialization(e.to_string()))?;
                Ok(Some(contact))
            }
            None => Ok(None),
        }
    }

    pub async fn delete(&self, address: &str) -> Result<()> {
        let key = format!("contact:{}", address);
        self.storage.delete(&key).await
    }

    pub async fn list(&self) -> Result<Vec<Contact>> {
        let keys = self.storage.list_prefix("contact:").await?;
        let mut contacts = Vec::with_capacity(keys.len());

        for key in keys {
            if let Some(data) = self.storage.take(&key).await? {
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
        match self.storage.take(&full_key).await? {
            Some(data) => {
                let value = bincode::deserialize(&data)
                    .map_err(|e| StorageError::Deserialization(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let full_key = format!("setting:{}", key);
        let data =
            bincode::serialize(value).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage.put(&full_key, &data).await
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        let full_key = format!("setting:{}", key);
        self.storage.delete(&full_key).await
    }
}

/// Create the storage backend described by the configuration.
///
/// A directory backed store is used when the configuration points at a real
/// path, otherwise the in-memory store is used.
pub async fn create_storage(config: &StorageConfig) -> Result<Arc<dyn StorageBackend>> {
    let root = Path::new(&config.db_path);
    if root.is_absolute() || root.components().count() > 1 {
        let store = FileStorage::new(root, config.max_size)?;
        return Ok(Arc::new(store));
    }
    Ok(Arc::new(MemoryStorage::new(config.max_size)))
}

/// Load the master key of the node, creating it when it is missing.
///
/// The key lives next to the mailbox files. On a unix system only the owner
/// may read it, because it protects every stored message.
pub fn load_or_create_master_key(path: &Path) -> Result<MasterKey> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            MxNodeError::Storage(StorageError::Corruption(
                "the master key must be 32 bytes long".to_string(),
            ))
        })?;
        return MasterKey::from_bytes(&bytes);
    }

    let key = MasterKey::generate();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, key.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(key)
}

/// Encode bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Decode a lowercase hex string.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        MasterKey::derive(
            "passphrase",
            b"salt12345678",
            &Argon2Params {
                memory_kb: 8 * 1024,
                time: 1,
                parallelism: 1,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn encrypted_storage_round_trip() {
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new(1024 * 1024));
        let storage = EncryptedStorage::new(backend, master());
        storage.put("k", b"value").await.unwrap();
        assert_eq!(storage.take("k").await.unwrap().unwrap(), b"value");
        assert!(storage.take("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn encrypted_storage_hides_plaintext() {
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new(1024 * 1024));
        let storage = EncryptedStorage::new(backend, master());
        storage.put("k", b"secret").await.unwrap();
        let raw = storage.backend.get("k").await.unwrap().unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("secret"));
    }

    #[tokio::test]
    async fn mailbox_storage_lists_newest_first() {
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new(1024 * 1024));
        let storage = EncryptedStorage::new(backend, master());
        let mailbox = MailboxStorage::new(storage, "INBOX");

        for (id, date) in [("a", 1i64), ("b", 2), ("c", 3)] {
            mailbox
                .save(&StoredMessage {
                    id: id.to_string(),
                    mailbox: "INBOX".into(),
                    from: vec![],
                    to: vec![],
                    cc: vec![],
                    bcc: vec![],
                    subject: id.into(),
                    body_text: String::new(),
                    body_html: None,
                    headers: HashMap::new(),
                    date,
                    read: false,
                    flagged: false,
                    raw: None,
                    encrypted: false,
                    attachments: vec![],
                })
                .await
                .unwrap();
        }

        let listed = mailbox.list(None, None).await.unwrap();
        let ids: Vec<&str> = listed.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "b", "a"]);
        assert_eq!(mailbox.count().await.unwrap(), 3);
        assert_eq!(mailbox.count_unread().await.unwrap(), 3);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode(b"hi"), "6869");
        assert_eq!(hex_decode("6869").unwrap(), b"hi");
        assert!(hex_decode("abc").is_none());
    }
}
