//! ENS transport: resolve an ENS name to an address, then deliver.
//!
//! ENS names are resolved through the ENS registry on Ethereum. The node
//! calls `resolver(bytes32)` on the registry and then `addr(bytes32)` on the
//! resolver, exactly like every other ENS client, and finally hands the
//! message to the resolved address using the DOM Mail bridge protocol.
//!
//! Configuration options:
//!
//! | option     | default                                     | meaning                        |
//! |------------|---------------------------------------------|--------------------------------|
//! | `rpc`      | `https://ethereum-rpc.publicnode.com`       | Ethereum JSON-RPC endpoint     |
//! | `registry` | `0x00000000000C22...2e1e` (ENS registry)    | ENS registry contract          |
//! | `port`     | `2525`                                      | bridge port on the peer        |

use crate::config::TransportConfig;
use crate::error::*;
use crate::transport::bridge::{write_frame, BridgeMessage, ByteStream};
use crate::transport::{Envelope, Transport, TransportStatus};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Default Ethereum JSON-RPC endpoint.
const DEFAULT_RPC: &str = "https://ethereum-rpc.publicnode.com";

/// ENS registry contract.
const DEFAULT_REGISTRY: &str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";

/// Default bridge port on the resolved peer.
const DEFAULT_PORT: u16 = 2525;

/// `resolver(bytes32)` selector.
const SELECTOR_RESOLVER: &str = "0178b8bf";

/// `addr(bytes32)` selector.
const SELECTOR_ADDR: &str = "3b3b57de";

/// JSON-RPC response.
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    #[serde(default)]
    message: String,
}

/// ENS resolution transport.
pub struct EnsTransport {
    rpc: String,
    registry: String,
    port: u16,
    client: Option<reqwest::Client>,
    connection: Option<Box<dyn ByteStream>>,
    resolved: Option<String>,
    last_error: Option<String>,
}

impl EnsTransport {
    /// Build the transport from its configuration.
    pub fn new(config: TransportConfig) -> Self {
        let rpc = config
            .options
            .get("rpc")
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC.to_string());
        let registry = config
            .options
            .get("registry")
            .cloned()
            .unwrap_or_else(|| DEFAULT_REGISTRY.to_string());
        let port = config
            .options
            .get("port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);

        Self {
            rpc,
            registry,
            port,
            client: None,
            connection: None,
            resolved: None,
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

    /// Compute the ENS namehash of a name.
    pub fn namehash(name: &str) -> [u8; 32] {
        let mut node = [0u8; 32];
        for label in name.trim_end_matches('.').split('.').rev() {
            let mut label_hash = Keccak256::new();
            label_hash.update(label.as_bytes());
            let label_hash = label_hash.finalize();

            let mut hasher = Keccak256::new();
            hasher.update(node);
            hasher.update(label_hash);
            node = hasher.finalize().into();
        }
        node
    }

    async fn eth_call(&self, to: &str, selector: &str, node: &[u8; 32]) -> Result<Vec<u8>> {
        let client = self.client.as_ref().ok_or(TransportError::NotConnected)?;

        let mut data = String::from(selector);
        for byte in node {
            data.push_str(&format!("{byte:02x}"));
        }

        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{ "to": to, "data": format!("0x{data}") }, "latest"]
        });

        let response = client
            .post(&self.rpc)
            .json(&request)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("ENS RPC failed: {e}")))?;

        let body: RpcResponse = response.json().await.map_err(|e| {
            TransportError::ConnectionFailed(format!("ENS RPC response invalid: {e}"))
        })?;

        if let Some(error) = body.error {
            return Err(TransportError::ConnectionFailed(format!(
                "ENS RPC error: {}",
                error.message
            ))
            .into());
        }

        let result = body
            .result
            .ok_or_else(|| TransportError::ConnectionFailed("ENS RPC returned no result".into()))?;

        let hex = result.trim_start_matches("0x");
        let bytes = hex_decode(hex).ok_or_else(|| {
            TransportError::ConnectionFailed("ENS RPC returned invalid hex".into())
        })?;
        Ok(bytes)
    }

    /// Resolve an ENS name to an IPv4 or IPv6 address.
    pub async fn resolve(&self, name: &str) -> Result<String> {
        let node = Self::namehash(name);

        let resolver_bytes = self
            .eth_call(&self.registry, SELECTOR_RESOLVER, &node)
            .await?;
        if resolver_bytes.len() < 20 {
            return Err(TransportError::NotConfigured(format!(
                "ENS name '{name}' has no resolver"
            ))
            .into());
        }
        let resolver = format!(
            "0x{}",
            hex_encode(&resolver_bytes[resolver_bytes.len() - 20..])
        );

        let address_bytes = self.eth_call(&resolver, SELECTOR_ADDR, &node).await?;
        if address_bytes.len() < 20 {
            return Err(TransportError::NotConfigured(format!(
                "ENS name '{name}' does not resolve to an address"
            ))
            .into());
        }
        let address = &address_bytes[address_bytes.len() - 20..];
        if address.iter().all(|b| *b == 0) {
            return Err(TransportError::NotConfigured(format!(
                "ENS name '{name}' resolves to the zero address"
            ))
            .into());
        }
        Ok(format!("0x{}", hex_encode(address)))
    }
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
impl Transport for EnsTransport {
    fn id(&self) -> &str {
        "ens"
    }

    fn name(&self) -> &str {
        "ENS"
    }

    fn status(&self) -> TransportStatus {
        TransportStatus {
            id: "ens".to_string(),
            name: "ENS".to_string(),
            connected: self.connection.is_some(),
            endpoint: self
                .resolved
                .clone()
                .unwrap_or_else(|| format!("{}:{}", self.registry, self.port)),
            last_error: self.last_error.clone(),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        if self.client.is_none() {
            match self.build_client() {
                Ok(client) => self.client = Some(client),
                Err(e) => {
                    self.last_error = Some(e.to_string());
                    return Err(e);
                }
            }
        }
        self.last_error = None;
        Ok(())
    }

    async fn send(&mut self, envelope: &Envelope, payload: &[u8]) -> Result<()> {
        self.connect().await?;

        let target = envelope
            .recipients
            .first()
            .and_then(|r| r.rsplit_once('@').map(|(_, domain)| domain.to_string()))
            .ok_or_else(|| {
                TransportError::SendFailed("recipient has no domain to resolve".to_string())
            })?;

        let address = match self.resolve(&target).await {
            Ok(address) => address,
            Err(e) => {
                self.last_error = Some(e.to_string());
                return Err(e);
            }
        };
        self.resolved = Some(address.clone());

        let endpoint = format!("{}:{}", strip_ipv6_brackets(&address), self.port);
        if self.connection.is_none() {
            let stream = timeout(Duration::from_secs(20), TcpStream::connect(&endpoint))
                .await
                .map_err(|_| {
                    TransportError::ConnectionFailed(format!("ENS peer {endpoint} timed out"))
                })?
                .map_err(|e| {
                    TransportError::ConnectionFailed(format!("ENS peer {endpoint}: {e}"))
                })?;
            self.connection = Some(Box::new(stream));
        }

        let message = BridgeMessage::new(envelope, payload);
        let encoded =
            serde_json::to_vec(&message).map_err(|e| TransportError::SendFailed(e.to_string()))?;

        let Some(connection) = self.connection.as_mut() else {
            return Err(TransportError::NotConnected.into());
        };

        match write_frame(connection.as_mut(), &encoded).await {
            Ok(()) => {
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                self.connection = None;
                let error = TransportError::SendFailed(e.to_string());
                self.last_error = Some(error.to_string());
                Err(error.into())
            }
        }
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connection = None;
        self.client = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection.is_some()
    }
}

/// Remove the brackets from an IPv6 literal.
fn strip_ipv6_brackets(address: &str) -> String {
    address
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namehash_matches_known_vector() {
        // namehash("") is 32 zero bytes.
        assert_eq!(EnsTransport::namehash(""), [0u8; 32]);
        // namehash("eth") is a stable, well known value.
        assert_eq!(
            hex_encode(&EnsTransport::namehash("eth")),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
    }

    #[test]
    fn hex_helpers_round_trip() {
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
        assert!(hex_decode("0f0").is_none());
    }

    #[test]
    fn strips_ipv6_brackets() {
        assert_eq!(strip_ipv6_brackets("[::1]"), "::1");
        assert_eq!(strip_ipv6_brackets("1.2.3.4"), "1.2.3.4");
    }
}
