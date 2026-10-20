//! Sneakernet transport: air-gapped delivery through a file drop.
//!
//! The message is written as a JSON file into a spool directory. The operator
//! carries that directory to the recipient (USB stick, QR code, printed
//! media) and the receiving node picks the file up. Nothing in this path
//! touches the network, which is the whole point of the vector.

use crate::config::TransportConfig;
use crate::error::*;
use crate::transport::{Envelope, Transport, TransportStatus};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default spool directory.
const DEFAULT_SPOOL: &str = "sneakernet-spool";

/// A message written to the spool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SneakernetEnvelope {
    /// Reverse-path address.
    pub sender: String,
    /// Forward-path addresses.
    pub recipients: Vec<String>,
    /// Base64 encoded raw message.
    pub body: String,
    /// Unix timestamp of the drop.
    pub created_at: u64,
}

/// File based air-gap transport.
pub struct SneakernetTransport {
    spool: PathBuf,
    connected: bool,
    last_error: Option<String>,
}

impl SneakernetTransport {
    /// Build the transport from its configuration.
    pub fn new(config: TransportConfig) -> Self {
        let spool = config
            .options
            .get("spool")
            .cloned()
            .or_else(|| config.options.get("directory").cloned())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SPOOL));

        Self {
            spool,
            connected: false,
            last_error: None,
        }
    }

    /// Directory the messages are written to.
    pub fn spool(&self) -> &PathBuf {
        &self.spool
    }
}

#[async_trait]
impl Transport for SneakernetTransport {
    fn id(&self) -> &str {
        "sneakernet"
    }

    fn name(&self) -> &str {
        "Sneakernet"
    }

    fn status(&self) -> TransportStatus {
        TransportStatus {
            id: "sneakernet".to_string(),
            name: "Sneakernet".to_string(),
            connected: self.connected,
            endpoint: self.spool.display().to_string(),
            last_error: self.last_error.clone(),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        match tokio::fs::create_dir_all(&self.spool).await {
            Ok(()) => {
                self.connected = true;
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                let error = TransportError::ConnectionFailed(format!(
                    "sneakernet: cannot create {}: {e}",
                    self.spool.display()
                ));
                self.last_error = Some(error.to_string());
                Err(error.into())
            }
        }
    }

    async fn send(&mut self, envelope: &Envelope, payload: &[u8]) -> Result<()> {
        if !self.connected {
            self.connect().await?;
        }

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        let drop = SneakernetEnvelope {
            sender: envelope.sender.clone(),
            recipients: envelope.recipients.clone(),
            body: base64::engine::general_purpose::STANDARD.encode(payload),
            created_at,
        };

        let encoded = serde_json::to_vec_pretty(&drop)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        let name = format!(
            "{:016x}-{}.domail.json",
            created_at,
            crate::storage::hex_encode(&crate::crypto::generate_salt(8))
        );
        let path = self.spool.join(name);

        match tokio::fs::write(&path, &encoded).await {
            Ok(()) => {
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                let error = TransportError::SendFailed(format!(
                    "sneakernet: cannot write {}: {e}",
                    path.display()
                ));
                self.last_error = Some(error.to_string());
                Err(error.into())
            }
        }
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn uses_configured_spool() {
        let transport = SneakernetTransport::new(TransportConfig {
            id: "sneakernet".to_string(),
            enabled: true,
            options: HashMap::from([("spool".to_string(), "/tmp/drop".to_string())]),
        });
        assert_eq!(transport.spool().to_string_lossy(), "/tmp/drop");
    }

    #[tokio::test]
    async fn writes_a_drop_file() {
        let dir = std::env::temp_dir().join(format!(
            "domail-sneakernet-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let mut transport = SneakernetTransport::new(TransportConfig {
            id: "sneakernet".to_string(),
            enabled: true,
            options: HashMap::from([("spool".to_string(), dir.display().to_string())]),
        });

        let envelope = Envelope::new("a@example.org", vec!["b@example.org".to_string()]);
        transport.send(&envelope, b"raw").await.unwrap();

        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let content = std::fs::read(entries[0].path()).unwrap();
        let drop: SneakernetEnvelope = serde_json::from_slice(&content).unwrap();
        assert_eq!(drop.sender, "a@example.org");
        assert_eq!(drop.recipients, vec!["b@example.org".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
