//! Direct transport: outbound SMTP over the public internet.
//!
//! The node does not run a full SMTP client stack of its own here; it hands
//! the message to `lettre`, which performs the SMTP dialogue with the
//! configured relay. The relay is the clearnet egress point for the `direct`
//! vector.

use crate::config::TransportConfig;
use crate::error::*;
use crate::transport::{Envelope, Transport, TransportStatus};
use async_trait::async_trait;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Envelope as LettreEnvelope, Tokio1Executor,
};
use std::time::Duration;

/// Default relay used when none is configured.
const DEFAULT_RELAY: &str = "127.0.0.1";

/// Default relay port.
const DEFAULT_PORT: u16 = 25;

/// How the connection to the relay is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelaySecurity {
    /// No transport security at all. Only usable on a trusted loopback hop.
    None,
    /// Opportunistic STARTTLS (RFC 3207).
    StartTls,
    /// Implicit TLS on the relay port (RFC 8314).
    ImplicitTls,
}

impl RelaySecurity {
    fn parse(value: Option<&String>) -> Result<Self> {
        match value.map(|s| s.to_ascii_lowercase()).as_deref() {
            None | Some("none") | Some("plain") => Ok(RelaySecurity::None),
            Some("starttls") => Ok(RelaySecurity::StartTls),
            Some("tls") | Some("implicit") | Some("wrapper") => Ok(RelaySecurity::ImplicitTls),
            Some(other) => Err(TransportError::NotConfigured(format!(
                "direct: unknown relay security '{other}'"
            ))
            .into()),
        }
    }
}

/// Outbound SMTP transport.
pub struct DirectTransport {
    relay: String,
    port: u16,
    security: RelaySecurity,
    credentials: Option<(String, String)>,
    client: Option<AsyncSmtpTransport<Tokio1Executor>>,
    last_error: Option<String>,
}

impl DirectTransport {
    /// Build the transport from its configuration.
    pub fn new(config: TransportConfig) -> Self {
        let relay = config
            .options
            .get("relay_host")
            .cloned()
            .or_else(|| config.options.get("relay").cloned())
            .unwrap_or_else(|| DEFAULT_RELAY.to_string());
        let port = config
            .options
            .get("relay_port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);
        let security =
            RelaySecurity::parse(config.options.get("security")).unwrap_or(RelaySecurity::StartTls);
        let credentials = match (
            config.options.get("username"),
            config.options.get("password"),
        ) {
            (Some(user), Some(pass)) => Some((user.clone(), pass.clone())),
            _ => None,
        };

        Self {
            relay,
            port,
            security,
            credentials,
            client: None,
            last_error: None,
        }
    }

    fn build_client(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let builder = match self.security {
            RelaySecurity::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(self.relay.clone())
            }
            RelaySecurity::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.relay)
                    .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            }
            RelaySecurity::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&self.relay)
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?,
        };

        let builder = builder
            .port(self.port)
            .timeout(Some(Duration::from_secs(60)))
            .hello_name("mx.domail.local".to_string());

        let builder = match &self.credentials {
            Some((user, pass)) => builder.credentials(Credentials::new(user.clone(), pass.clone())),
            None => builder,
        };

        Ok(builder.build())
    }
}

#[async_trait]
impl Transport for DirectTransport {
    fn id(&self) -> &str {
        "direct"
    }

    fn name(&self) -> &str {
        "Direct"
    }

    fn status(&self) -> TransportStatus {
        TransportStatus {
            id: "direct".to_string(),
            name: "Direct".to_string(),
            connected: self.client.is_some(),
            endpoint: format!("{}:{}", self.relay, self.port),
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

        let from = Address::new(envelope.sender.clone(), envelope.sender.clone())
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        let mut recipients = Vec::with_capacity(envelope.recipients.len());
        for recipient in &envelope.recipients {
            recipients.push(
                Address::new(recipient.clone(), recipient.clone())
                    .map_err(|e| TransportError::SendFailed(e.to_string()))?,
            );
        }

        let lettre_envelope = LettreEnvelope::new(Some(from), recipients)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        match client.send_raw(&lettre_envelope, payload).await {
            Ok(_) => {
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
                Err(TransportError::SendFailed(e.to_string()).into())
            }
        }
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(client) = self.client.take() {
            let _ = client.shutdown().await;
        }
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

    fn config(options: &[(&str, &str)]) -> TransportConfig {
        let mut map = HashMap::new();
        for (key, value) in options {
            map.insert(key.to_string(), value.to_string());
        }
        TransportConfig {
            id: "direct".to_string(),
            enabled: true,
            options: map,
        }
    }

    #[test]
    fn uses_configured_relay() {
        let transport = DirectTransport::new(config(&[
            ("relay_host", "mail.example.org"),
            ("relay_port", "2525"),
        ]));
        let status = transport.status();
        assert_eq!(status.endpoint, "mail.example.org:2525");
        assert_eq!(status.id, "direct");
    }

    #[test]
    fn defaults_to_loopback_relay() {
        let transport = DirectTransport::new(config(&[]));
        assert_eq!(transport.status().endpoint, "127.0.0.1:25");
    }

    #[test]
    fn rejects_unknown_security() {
        assert!(RelaySecurity::parse(Some(&"quantum".to_string())).is_err());
        assert_eq!(
            RelaySecurity::parse(Some(&"starttls".to_string())).unwrap(),
            RelaySecurity::StartTls
        );
    }
}
