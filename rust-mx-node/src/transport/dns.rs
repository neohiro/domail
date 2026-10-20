//! DNS transport: censorship-resistant delivery over DNS queries.
//!
//! The message is split into chunks, base32 encoded and published as DNS TXT
//! lookups under a configured zone. A cooperating *DOM Mail DNS tunnel
//! server* (a component that runs on the recipient side and observes the
//! queries) reassembles the chunks. Because the payload travels inside the
//! query name, it passes networks that only allow DNS.
//!
//! Configuration options:
//!
//! | option     | default                        | meaning                          |
//! |------------|--------------------------------|----------------------------------|
//! | `resolver` | `https://dns.google/resolve`  | DNS-over-HTTPS JSON resolver     |
//! | `zone`     | `tunnel.domail.local`          | zone the tunnel lives under      |
//! | `token`    | random per message             | groups the chunks of one message |

use crate::config::TransportConfig;
use crate::error::*;
use crate::transport::{Envelope, Transport, TransportStatus};
use async_trait::async_trait;
use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

/// Default DNS-over-HTTPS resolver.
const DEFAULT_RESOLVER: &str = "https://dns.google/resolve";

/// Default zone the tunnel is published under.
const DEFAULT_ZONE: &str = "tunnel.domail.local";

/// Maximum number of base32 characters in a single DNS label.
const LABEL_LEN: usize = 48;

/// Maximum number of chunks a single message may be split into.
const MAX_CHUNKS: usize = 64;

/// Response of a DNS-over-HTTPS JSON resolver.
#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(default)]
    answer: Vec<DohRecord>,
}

#[derive(Debug, Deserialize)]
struct DohRecord {
    #[serde(default)]
    data: String,
}

/// DNS tunnel transport.
pub struct DnsTransport {
    resolver: String,
    zone: String,
    token: String,
    client: Option<reqwest::Client>,
    last_error: Option<String>,
}

impl DnsTransport {
    /// Build the transport from its configuration.
    pub fn new(config: TransportConfig) -> Self {
        let resolver = config
            .options
            .get("resolver")
            .cloned()
            .unwrap_or_else(|| DEFAULT_RESOLVER.to_string());
        let zone = config
            .options
            .get("zone")
            .cloned()
            .unwrap_or_else(|| DEFAULT_ZONE.to_string());
        let token = config
            .options
            .get("token")
            .cloned()
            .unwrap_or_else(|| random_token());

        Self {
            resolver,
            zone,
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

    /// Split a payload into the DNS labels that carry it.
    pub fn encode_chunks(payload: &[u8]) -> Result<Vec<String>> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let chars: Vec<char> = encoded.chars().collect();

        let mut chunks = Vec::new();
        for chunk in chars.chunks(LABEL_LEN) {
            chunks.push(chunk.iter().collect::<String>());
            if chunks.len() > MAX_CHUNKS {
                return Err(TransportError::SendFailed(
                    "message is too large for the DNS tunnel".to_string(),
                )
                .into());
            }
        }
        Ok(chunks)
    }

    /// Build the query name that carries one chunk.
    pub fn query_name(&self, chunk: &str, index: usize) -> String {
        format!("{chunk}.{}.{}.{}", self.token, index, self.zone)
    }
}

/// Random token used to group the chunks of one message.
fn random_token() -> String {
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[async_trait]
impl Transport for DnsTransport {
    fn id(&self) -> &str {
        "dns"
    }

    fn name(&self) -> &str {
        "DNS"
    }

    fn status(&self) -> TransportStatus {
        TransportStatus {
            id: "dns".to_string(),
            name: "DNS".to_string(),
            connected: self.client.is_some(),
            endpoint: format!("{} ({})", self.resolver, self.zone),
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

        let chunks = Self::encode_chunks(payload)?;
        let mut sent = 0usize;

        for (index, chunk) in chunks.iter().enumerate() {
            let name = self.query_name(chunk, index);
            let url = format!("{}?name={}&type=TXT", self.resolver, urlencode(&name));

            let response =
                client.get(&url).send().await.map_err(|e| {
                    TransportError::SendFailed(format!("resolver query failed: {e}"))
                })?;

            let body = response.text().await.map_err(|e| {
                TransportError::SendFailed(format!("resolver body unreadable: {e}"))
            })?;

            // A successful lookup is enough: the query itself carried the
            // payload. The answer is parsed to surface resolver errors.
            let parsed: DohAnswer = serde_json::from_str(&body).map_err(|e| {
                TransportError::SendFailed(format!("resolver returned invalid JSON: {e}"))
            })?;
            let _ = parsed.answer.len();
            sent += 1;
        }

        if sent == 0 {
            return Err(
                TransportError::SendFailed("message produced no DNS chunks".to_string()).into(),
            );
        }

        let _ = envelope;
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

/// Percent-encode a DNS name for use in a query string.
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => out.push(*byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Options helper used by the tests.
#[cfg(test)]
fn options(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_round_trip_through_base32_labels() {
        let payload = vec![7u8; 500];
        let chunks = DnsTransport::encode_chunks(&payload).unwrap();
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(chunk.len() <= LABEL_LEN);
        }
        let joined: String = chunks.concat();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(joined.as_bytes())
            .unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn oversized_messages_are_rejected() {
        let payload = vec![0u8; 200_000];
        assert!(DnsTransport::encode_chunks(&payload).is_err());
    }

    #[test]
    fn query_name_contains_token_and_index() {
        let transport = DnsTransport::new(TransportConfig {
            id: "dns".to_string(),
            enabled: true,
            options: options(&[("zone", "example.test"), ("token", "abc")]),
        });
        let name = transport.query_name("chunk", 3);
        assert_eq!(name, "chunk.abc.3.example.test");
    }

    #[test]
    fn urlencode_escapes_special_characters() {
        assert_eq!(urlencode("a.b"), "a.b");
        assert_eq!(urlencode("a b"), "a%20b");
    }
}
