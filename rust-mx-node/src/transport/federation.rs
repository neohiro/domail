//! Federation transport: hand the message to a federated network gateway.
//!
//! The gateway is an HTTP endpoint (an ActivityPub inbox, a Matrix room
//! bridge, an XMPP component, …). The node posts the envelope and the raw
//! message as JSON and lets the gateway deal with the protocol details.

use crate::config::TransportConfig;
use crate::error::*;
use crate::transport::{Envelope, Transport, TransportStatus};
use async_trait::async_trait;
use base64::Engine;
use serde::Serialize;
use std::time::Duration;

/// Default federation gateway.
const DEFAULT_GATEWAY: &str = "http://127.0.0.1:8788/federation/inbox";

/// Body posted to the gateway.
#[derive(Debug, Serialize)]
struct FederationPayload {
    /// Protocol the gateway should use, e.g. `activitypub`.
    protocol: String,
    /// Reverse-path address.
    sender: String,
    /// Forward-path addresses.
    recipients: Vec<String>,
    /// Base64 encoded raw message.
    body: String,
}

/// Federation gateway transport.
pub struct FederationTransport {
    gateway: String,
    protocol: String,
    token: Option<String>,
    client: Option<reqwest::Client>,
    last_error: Option<String>,
}

impl FederationTransport {
    /// Build the transport from its configuration.
    pub fn new(config: TransportConfig) -> Self {
        let gateway = config
            .options
            .get("gateway")
            .cloned()
            .unwrap_or_else(|| DEFAULT_GATEWAY.to_string());
        let protocol = config
            .options
            .get("protocol")
            .cloned()
            .unwrap_or_else(|| "activitypub".to_string());
        let token = config.options.get("token").cloned();

        Self {
            gateway,
            protocol,
            token,
            client: None,
            last_error: None,
        }
    }

    fn build_client(&self) -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("domail-mx-node/0.2")
            .build()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }
}

#[async_trait]
impl Transport for FederationTransport {
    fn id(&self) -> &str {
        "federation"
    }

    fn name(&self) -> &str {
        "Federation (ActivityPub/Matrix/XMPP)"
    }

    fn status(&self) -> TransportStatus {
        TransportStatus {
            id: "federation".to_string(),
            name: "Federation (ActivityPub/Matrix/XMPP)".to_string(),
            connected: self.client.is_some(),
            endpoint: self.gateway.clone(),
            last_error: self.last_error.clone(),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        if self.client.is_some() {
            return Ok(());
        }
        match self.build_client() {
            Ok(client) => {
                self.client = Some(client);
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    async fn send(&mut self, envelope: &Envelope, payload: &[u8]) -> Result<()> {
        if self.client.is_none() {
            self.connect().await?;
        }
        let Some(client) = self.client.as_ref() else {
            return Err(TransportError::NotConnected.into());
        };

        let body = FederationPayload {
            protocol: self.protocol.clone(),
            sender: envelope.sender.clone(),
            recipients: envelope.recipients.clone(),
            body: base64::engine::general_purpose::STANDARD.encode(payload),
        };

        let mut request = client.post(&self.gateway).json(&body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| TransportError::SendFailed(format!("gateway request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let error = TransportError::SendFailed(format!("gateway returned {status}"));
            self.last_error = Some(error.to_string());
            return Err(error.into());
        }

        self.last_error = None;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.client = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.client.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn uses_configured_gateway() {
        let transport = FederationTransport::new(TransportConfig {
            id: "federation".to_string(),
            enabled: true,
            options: HashMap::from([("gateway".to_string(), "https://x.test/inbox".to_string())]),
        });
        assert_eq!(transport.status().endpoint, "https://x.test/inbox");
        assert_eq!(transport.status().id, "federation");
    }

    #[test]
    fn defaults_to_local_gateway() {
        let transport = FederationTransport::new(TransportConfig {
            id: "federation".to_string(),
            enabled: true,
            options: HashMap::new(),
        });
        assert_eq!(transport.status().endpoint, DEFAULT_GATEWAY);
    }
}
