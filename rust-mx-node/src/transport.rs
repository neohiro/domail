//! Transport layer for the MX Node.
//!
//! A transport is the carrier a message is handed to after the SMTP server
//! has accepted it. Every transport implements the same [`Transport`] trait, so
//! the MX node can offer all of them at the same time and pick whichever one
//! is reachable for a given recipient.
//!
//! Most peer-to-peer vectors speak the *DOM Mail Bridge Protocol*: a
//! length-prefixed JSON frame carrying the envelope and the raw message. The
//! framing is documented in `docs/bridge-protocol.md`.

use crate::config::TransportConfig;
use crate::error::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

pub mod bridge;
pub mod direct;
pub mod dns;
pub mod ens;
pub mod federation;
pub mod nostr;
pub mod sneakernet;

/// Maximum size of a single bridge frame (8 MiB).
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

/// Envelope handed to a transport.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// Reverse-path address (`MAIL FROM`).
    pub sender: String,
    /// Forward-path addresses (`RCPT TO`).
    pub recipients: Vec<String>,
}

impl Envelope {
    /// Build an envelope from a sender and a list of recipients.
    pub fn new(sender: impl Into<String>, recipients: Vec<String>) -> Self {
        Self {
            sender: sender.into(),
            recipients,
        }
    }
}

/// Snapshot of a transport's runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStatus {
    /// Stable transport identifier, e.g. `nostr`.
    pub id: String,
    /// Human readable name.
    pub name: String,
    /// Whether the transport currently holds a usable connection.
    pub connected: bool,
    /// Endpoint the transport is bound to.
    pub endpoint: String,
    /// Last error observed on this transport.
    pub last_error: Option<String>,
}

/// A message carrier.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Stable identifier used in the configuration and the control API.
    fn id(&self) -> &str;

    /// Human readable name.
    fn name(&self) -> &str;

    /// Current state of the transport.
    fn status(&self) -> TransportStatus;

    /// Establish the connection. Must be idempotent.
    async fn connect(&mut self) -> Result<()>;

    /// Hand a message to the transport.
    async fn send(&mut self, envelope: &Envelope, payload: &[u8]) -> Result<()>;

    /// Close the connection. Must be idempotent.
    async fn disconnect(&mut self) -> Result<()>;

    /// Whether the transport currently holds a usable connection.
    fn is_connected(&self) -> bool;
}

/// Outcome of a delivery attempt across all transports.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeliveryReport {
    /// Transports that accepted the message.
    pub delivered_by: Vec<String>,
    /// Transports that refused the message, with the reason.
    pub failed: Vec<(String, String)>,
}

impl DeliveryReport {
    /// True when at least one transport accepted the message.
    pub fn is_success(&self) -> bool {
        !self.delivered_by.is_empty()
    }
}

/// Registry of the transports offered by this node.
pub struct TransportManager {
    transports: Arc<RwLock<HashMap<String, Arc<RwLock<Box<dyn Transport>>>>>>,
    default_transport: String,
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self {
            transports: Arc::new(RwLock::new(HashMap::new())),
            default_transport: "direct".to_string(),
        }
    }

    /// Register a transport, replacing any previous transport with the same id.
    pub async fn register(&self, transport: Box<dyn Transport>) -> Result<()> {
        let id = transport.id().to_string();
        let mut transports = self.transports.write().await;
        transports.insert(id, Arc::new(RwLock::new(transport)));
        Ok(())
    }

    /// Remove a transport.
    pub async fn unregister(&self, id: &str) -> Result<()> {
        self.transports.write().await.remove(id);
        Ok(())
    }

    /// Look up a transport by id.
    pub async fn get(&self, id: &str) -> Option<Arc<RwLock<Box<dyn Transport>>>> {
        let transports = self.transports.read().await;
        transports.get(id).cloned()
    }

    /// Ids of every registered transport, sorted.
    pub async fn ids(&self) -> Vec<String> {
        let transports = self.transports.read().await;
        let mut ids: Vec<String> = transports.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// State of every registered transport, sorted by id.
    pub async fn statuses(&self) -> Vec<TransportStatus> {
        let transports = self.transports.read().await;
        let mut ids: Vec<&String> = transports.keys().collect();
        ids.sort();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(transport) = transports.get(id) {
                out.push(transport.read().await.status());
            }
        }
        out
    }

    /// Connect a single transport.
    pub async fn activate(&self, id: &str) -> Result<()> {
        let Some(transport) = self.get(id).await else {
            return Err(TransportError::UnsupportedTransport(id.to_string()).into());
        };
        let mut transport = transport.write().await;
        transport.connect().await
    }

    /// Disconnect a single transport.
    pub async fn deactivate(&self, id: &str) -> Result<()> {
        let Some(transport) = self.get(id).await else {
            return Err(TransportError::UnsupportedTransport(id.to_string()).into());
        };
        let mut transport = transport.write().await;
        transport.disconnect().await
    }

    /// Connect every registered transport.
    ///
    /// Transports that fail to connect are reported but do not abort the
    /// activation of the remaining ones: a missing peer must not take the
    /// whole node down.
    pub async fn activate_all(&self) -> Vec<(String, Result<()>)> {
        let ids = self.ids().await;
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let outcome = match self.get(&id).await {
                Some(transport) => {
                    let mut transport = transport.write().await;
                    transport.connect().await
                }
                None => Err(TransportError::UnsupportedTransport(id.clone()).into()),
            };
            results.push((id, outcome));
        }
        results
    }

    /// Send a message through one specific transport.
    pub async fn send_via(
        &self,
        transport_id: &str,
        envelope: &Envelope,
        payload: &[u8],
    ) -> Result<()> {
        let Some(transport) = self.get(transport_id).await else {
            return Err(TransportError::UnsupportedTransport(transport_id.to_string()).into());
        };
        let mut transport = transport.write().await;
        transport.send(envelope, payload).await
    }

    /// Send a message through every connected transport.
    pub async fn broadcast(&self, envelope: &Envelope, payload: &[u8]) -> DeliveryReport {
        let mut report = DeliveryReport::default();
        let ids = self.ids().await;

        for id in ids {
            let Some(transport) = self.get(&id).await else {
                continue;
            };
            let mut transport = transport.write().await;
            if !transport.is_connected() {
                continue;
            }
            match transport.send(envelope, payload).await {
                Ok(()) => report.delivered_by.push(id),
                Err(e) => {
                    warn!(transport = %id, error = %e, "transport send failed");
                    report.failed.push((id, e.to_string()));
                }
            }
        }
        report
    }

    /// Deliver a message, trying the default transport first and then every
    /// other connected transport until one accepts the message.
    pub async fn deliver(&self, envelope: &Envelope, payload: &[u8]) -> DeliveryReport {
        let mut report = DeliveryReport::default();
        let mut ids = self.ids().await;

        // The default transport gets the first attempt.
        if let Some(pos) = ids.iter().position(|id| *id == self.default_transport) {
            let default = ids.remove(pos);
            ids.insert(0, default);
        }

        for id in ids {
            let Some(transport) = self.get(&id).await else {
                continue;
            };
            let mut transport = transport.write().await;
            if !transport.is_connected() {
                continue;
            }
            match transport.send(envelope, payload).await {
                Ok(()) => {
                    report.delivered_by.push(id);
                    return report;
                }
                Err(e) => {
                    warn!(transport = %id, error = %e, "transport send failed");
                    report.failed.push((id, e.to_string()));
                }
            }
        }

        if report.failed.is_empty() {
            report.failed.push((
                "none".to_string(),
                "no transport is currently connected".to_string(),
            ));
        }
        report
    }
}

/// Build a transport from its configuration entry.
pub fn create_transport(config: TransportConfig) -> Result<Box<dyn Transport>> {
    match config.id.as_str() {
        "direct" => Ok(Box::new(direct::DirectTransport::new(config))),
        "tor" => Ok(Box::new(bridge::BridgeTransport::tor(config))),
        "i2p" => Ok(Box::new(bridge::BridgeTransport::i2p(config))),
        "ens" => Ok(Box::new(ens::EnsTransport::new(config))),
        "radicle" => Ok(Box::new(bridge::BridgeTransport::radicle(config))),
        "yggdrasil" => Ok(Box::new(bridge::BridgeTransport::yggdrasil(config))),
        "nostr" => Ok(Box::new(nostr::NostrTransport::new(config))),
        "reticulum" => Ok(Box::new(bridge::BridgeTransport::reticulum(config))),
        "webrtc" => Ok(Box::new(bridge::BridgeTransport::webrtc(config))),
        "ble" => Ok(Box::new(bridge::BridgeTransport::ble(config))),
        "lora" => Ok(Box::new(bridge::BridgeTransport::lora(config))),
        "packet_radio" => Ok(Box::new(bridge::BridgeTransport::packet_radio(config))),
        "dns" => Ok(Box::new(dns::DnsTransport::new(config))),
        "sneakernet" => Ok(Box::new(sneakernet::SneakernetTransport::new(config))),
        "federation" => Ok(Box::new(federation::FederationTransport::new(config))),
        _ => Err(TransportError::UnsupportedTransport(config.id).into()),
    }
}

/// Instantiate every enabled transport from the configuration.
pub async fn init_transports(configs: Vec<TransportConfig>) -> Result<TransportManager> {
    let manager = TransportManager::new();

    for config in configs {
        if !config.enabled {
            continue;
        }
        let transport = create_transport(config)?;
        manager.register(transport).await?;
    }

    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(id: &str) -> TransportConfig {
        TransportConfig {
            id: id.to_string(),
            enabled: true,
            options: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn registers_every_known_transport() {
        let ids = [
            "direct", "tor", "i2p", "ens", "radicle", "yggdrasil", "nostr", "reticulum",
            "webrtc", "ble", "lora", "packet_radio", "dns", "sneakernet", "federation",
        ];
        for id in ids {
            let transport = create_transport(config(id)).expect("transport");
            assert_eq!(transport.id(), id);
        }
    }

    #[tokio::test]
    async fn unknown_transport_is_rejected() {
        assert!(create_transport(config("does-not-exist")).is_err());
    }

    #[tokio::test]
    async fn manager_tracks_transports() {
        let manager = init_transports(vec![config("direct"), config("sneakernet")])
            .await
            .unwrap();
        assert_eq!(manager.ids().await, vec!["direct", "sneakernet"]);
        assert!(manager.get("direct").await.is_some());
        assert!(manager.get("nostr").await.is_none());
    }

    #[tokio::test]
    async fn disabled_transports_are_skipped() {
        let mut sneakernet = config("sneakernet");
        sneakernet.enabled = false;
        let manager = init_transports(vec![sneakernet]).await.unwrap();
        assert!(manager.ids().await.is_empty());
    }
}
