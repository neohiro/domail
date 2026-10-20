//! Generic peer-to-peer transports.
//!
//! Every vector in this module speaks the *DOM Mail Bridge Protocol*: the
//! message is serialised as JSON and written as a single length-prefixed
//! frame. What differs per vector is only how the connection is established:
//!
//! | vector        | connection                                        |
//! |---------------|---------------------------------------------------|
//! | `tor`         | SOCKS5 proxy (Tor)                                |
//! | `i2p`         | I2P SAM bridge                                    |
//! | `yggdrasil`   | TCP to a Yggdrasil peer                           |
//! | `reticulum`   | TCP to a Reticulum node                           |
//! | `webrtc`      | WebSocket signalling channel                      |
//! | `ble`         | TCP to a local BLE companion daemon                |
//! | `lora`        | TCP to a local LoRa companion daemon               |
//! | `packet_radio`| TCP to a local KISS TNC bridge                     |
//! | `radicle`     | TCP to a local Radicle publishing daemon           |

use crate::config::TransportConfig;
use crate::error::*;
use crate::transport::{Envelope, Transport, TransportStatus, MAX_FRAME_LEN};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::debug;

/// Default timeout for establishing a transport connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// A byte stream that can carry bridge frames.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}

/// The payload carried by a bridge frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMessage {
    /// Reverse-path address.
    pub sender: String,
    /// Forward-path addresses.
    pub recipients: Vec<String>,
    /// Base64 encoded raw RFC 5322 message.
    pub body: String,
}

impl BridgeMessage {
    /// Build a bridge message from an envelope and a raw message.
    pub fn new(envelope: &Envelope, payload: &[u8]) -> Self {
        Self {
            sender: envelope.sender.clone(),
            recipients: envelope.recipients.clone(),
            body: base64::engine::general_purpose::STANDARD.encode(payload),
        }
    }

    /// Decode the frame back into the raw message.
    pub fn decode(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(self.body.as_bytes())
            .map_err(|e| TransportError::SendFailed(format!("invalid body encoding: {e}")))
    }
}

/// Write a length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds the maximum size",
        ));
    }
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

/// Read a length-prefixed frame.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds the maximum size",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

/// How a bridge transport reaches its peer.
#[derive(Debug, Clone)]
enum Mode {
    /// Plain TCP connection.
    Tcp,
    /// TCP connection through a SOCKS5 proxy.
    Socks5 {
        proxy: String,
        username: Option<String>,
        password: Option<String>,
    },
    /// WebSocket connection.
    WebSocket,
    /// I2P SAM bridge.
    I2pSam { sam: String, destination: String },
}

/// A live bridge connection.
enum Connection {
    Stream(Box<dyn ByteStream>),
    WebSocket(WebSocketStream<MaybeTlsStream<TcpStream>>),
}

/// Transport that hands messages to a peer over the bridge protocol.
pub struct BridgeTransport {
    id: &'static str,
    name: &'static str,
    mode: Mode,
    endpoint: String,
    connection: Option<Connection>,
    last_error: Option<String>,
}

impl BridgeTransport {
    /// Build a transport that connects over plain TCP.
    fn tcp(id: &'static str, name: &'static str, config: TransportConfig) -> Self {
        let endpoint = config
            .options
            .get("endpoint")
            .cloned()
            .or_else(|| config.options.get("peer").cloned())
            .unwrap_or_default();
        Self {
            id,
            name,
            mode: Mode::Tcp,
            endpoint,
            connection: None,
            last_error: None,
        }
    }

    /// Build a transport that connects through a SOCKS5 proxy.
    fn socks5(id: &'static str, name: &'static str, config: TransportConfig) -> Self {
        let endpoint = config
            .options
            .get("endpoint")
            .cloned()
            .or_else(|| config.options.get("onion").cloned())
            .unwrap_or_default();
        let proxy = config
            .options
            .get("proxy")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:9050".to_string());
        Self {
            id,
            name,
            mode: Mode::Socks5 {
                proxy,
                username: config.options.get("username").cloned(),
                password: config.options.get("password").cloned(),
            },
            endpoint,
            connection: None,
            last_error: None,
        }
    }

    /// Build a transport that connects over a WebSocket.
    fn websocket(id: &'static str, name: &'static str, config: TransportConfig) -> Self {
        let endpoint = config
            .options
            .get("endpoint")
            .cloned()
            .or_else(|| config.options.get("signaling").cloned())
            .unwrap_or_default();
        Self {
            id,
            name,
            mode: Mode::WebSocket,
            endpoint,
            connection: None,
            last_error: None,
        }
    }

    /// Tor transport: SOCKS5 to an onion service.
    pub fn tor(config: TransportConfig) -> Self {
        Self::socks5("tor", "Tor", config)
    }

    /// I2P transport: SAM bridge to an eepsite.
    pub fn i2p(config: TransportConfig) -> Self {
        let sam = config
            .options
            .get("sam")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:7656".to_string());
        let destination = config
            .options
            .get("destination")
            .cloned()
            .or_else(|| config.options.get("endpoint").cloned())
            .unwrap_or_default();
        Self {
            id: "i2p",
            name: "I2P",
            mode: Mode::I2pSam {
                sam,
                destination: destination.clone(),
            },
            endpoint: destination,
            connection: None,
            last_error: None,
        }
    }

    /// Yggdrasil transport: TCP to a mesh peer.
    pub fn yggdrasil(config: TransportConfig) -> Self {
        // Yggdrasil peers are configured as a comma separated list; the first
        // reachable peer is used for the session.
        let peers = config
            .options
            .get("peers")
            .map(|list| {
                list.split(',')
                    .map(|p| p.trim())
                    .find(|p| !p.is_empty())
                    .unwrap_or_default()
                    .to_string()
            })
            .unwrap_or_default();
        let mut config = config;
        if !peers.is_empty() {
            config
                .options
                .entry("endpoint".to_string())
                .or_insert(peers);
        }
        Self::tcp("yggdrasil", "Yggdrasil", config)
    }

    /// Reticulum transport: TCP to a Reticulum node.
    pub fn reticulum(config: TransportConfig) -> Self {
        Self::tcp("reticulum", "Reticulum", config)
    }

    /// WebRTC transport: WebSocket signalling channel.
    pub fn webrtc(config: TransportConfig) -> Self {
        Self::websocket("webrtc", "WebRTC", config)
    }

    /// Bluetooth Low Energy transport: local companion daemon.
    pub fn ble(config: TransportConfig) -> Self {
        Self::tcp("ble", "Bluetooth Low Energy", config)
    }

    /// LoRa transport: local companion daemon.
    pub fn lora(config: TransportConfig) -> Self {
        Self::tcp("lora", "LoRa Radio", config)
    }

    /// Packet radio transport: local KISS TNC bridge.
    pub fn packet_radio(config: TransportConfig) -> Self {
        Self::tcp("packet_radio", "Packet Radio (AX.25/KISS)", config)
    }

    /// Radicle transport: local publishing daemon.
    pub fn radicle(config: TransportConfig) -> Self {
        Self::tcp("radicle", "Radicle", config)
    }

    async fn open(&mut self) -> Result<Connection> {
        match &self.mode {
            Mode::Tcp => {
                if self.endpoint.is_empty() {
                    return Err(TransportError::NotConfigured(format!(
                        "{}: no endpoint configured",
                        self.id
                    ))
                    .into());
                }
                let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(self.endpoint.trim()))
                    .await
                    .map_err(|_| {
                        TransportError::ConnectionFailed(format!(
                            "{}: connection timed out",
                            self.id
                        ))
                    })?
                    .map_err(|e| TransportError::ConnectionFailed(format!("{}: {e}", self.id)))?;
                debug!(transport = %self.id, endpoint = %self.endpoint, "bridge connected");
                Ok(Connection::Stream(Box::new(stream)))
            }
            Mode::Socks5 {
                proxy,
                username,
                password,
            } => {
                if self.endpoint.is_empty() {
                    return Err(TransportError::NotConfigured(format!(
                        "{}: no onion endpoint configured",
                        self.id
                    ))
                    .into());
                }
                let (host, port) = split_host_port(&self.endpoint).ok_or_else(|| {
                    TransportError::NotConfigured(format!(
                        "{}: endpoint must be host:port, got {}",
                        self.id, self.endpoint
                    ))
                })?;

                let connect = match (username, password) {
                    (Some(user), Some(pass)) => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password(
                            proxy.as_str(),
                            (host.as_str(), port),
                            user.as_str(),
                            pass.as_str(),
                        )
                    }
                    _ => tokio_socks::tcp::Socks5Stream::connect(
                        proxy.as_str(),
                        (host.as_str(), port),
                    ),
                };

                let stream = timeout(CONNECT_TIMEOUT, connect)
                    .await
                    .map_err(|_| {
                        TransportError::ConnectionFailed(format!("{}: proxy timed out", self.id))
                    })?
                    .map_err(|e| TransportError::ConnectionFailed(format!("{}: {e}", self.id)))?;
                debug!(transport = %self.id, endpoint = %self.endpoint, "bridge connected via proxy");
                Ok(Connection::Stream(Box::new(stream)))
            }
            Mode::WebSocket => {
                if self.endpoint.is_empty() {
                    return Err(TransportError::NotConfigured(format!(
                        "{}: no signaling endpoint configured",
                        self.id
                    ))
                    .into());
                }
                let (stream, _) = timeout(CONNECT_TIMEOUT, connect_async(&self.endpoint))
                    .await
                    .map_err(|_| {
                        TransportError::ConnectionFailed(format!("{}: connect timed out", self.id))
                    })?
                    .map_err(|e| TransportError::ConnectionFailed(format!("{}: {e}", self.id)))?;
                Ok(Connection::WebSocket(stream))
            }
            Mode::I2pSam { sam, destination } => {
                if destination.is_empty() {
                    return Err(TransportError::NotConfigured(format!(
                        "{}: no destination configured",
                        self.id
                    ))
                    .into());
                }
                let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(sam.as_str()))
                    .await
                    .map_err(|_| {
                        TransportError::ConnectionFailed(format!(
                            "{}: SAM bridge timed out",
                            self.id
                        ))
                    })?
                    .map_err(|e| TransportError::ConnectionFailed(format!("{}: {e}", self.id)))?;

                // SAM handshake: greet, then open a streaming session.
                stream
                    .write_all(b"HELLO VERSION=3.1\n")
                    .await
                    .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;
                let greeting = read_line(&mut stream).await?;
                if !greeting.starts_with("OK") {
                    return Err(TransportError::HandshakeFailed(format!(
                        "{}: SAM bridge refused the handshake: {greeting}",
                        self.id
                    ))
                    .into());
                }

                let request = format!("STREAMING CONNECT {destination} SILENT=false\n");
                stream
                    .write_all(request.as_bytes())
                    .await
                    .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;
                let response = read_line(&mut stream).await?;
                if !response.starts_with("OK") {
                    return Err(TransportError::HandshakeFailed(format!(
                        "{}: SAM bridge refused the destination: {response}",
                        self.id
                    ))
                    .into());
                }
                debug!(transport = %self.id, destination = %destination, "bridge connected");
                Ok(Connection::Stream(Box::new(stream)))
            }
        }
    }

    async fn write_message(&mut self, envelope: &Envelope, payload: &[u8]) -> Result<()> {
        let message = BridgeMessage::new(envelope, payload);
        let encoded =
            serde_json::to_vec(&message).map_err(|e| TransportError::SendFailed(e.to_string()))?;

        let Some(connection) = self.connection.as_mut() else {
            return Err(TransportError::NotConnected.into());
        };

        match connection {
            Connection::Stream(stream) => write_frame(stream.as_mut(), &encoded)
                .await
                .map_err(|e| TransportError::SendFailed(e.to_string())),
            Connection::WebSocket(socket) => socket
                .send(Message::Binary(encoded))
                .await
                .map_err(|e| TransportError::SendFailed(e.to_string())),
        }
    }
}

/// Read a single line from a stream, used by the SAM bridge handshake.
async fn read_line(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = timeout(CONNECT_TIMEOUT, stream.read(&mut byte)).await;
        match read {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                buffer.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Ok(Err(e)) => return Err(TransportError::HandshakeFailed(e.to_string()).into()),
            Err(_) => {
                return Err(
                    TransportError::HandshakeFailed("handshake timed out".to_string()).into(),
                )
            }
        }
    }
    Ok(String::from_utf8_lossy(&buffer).trim().to_string())
}

/// Split `host:port` into its parts.
fn split_host_port(endpoint: &str) -> Option<(String, u16)> {
    let (host, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

#[async_trait]
impl Transport for BridgeTransport {
    fn id(&self) -> &str {
        self.id
    }

    fn name(&self) -> &str {
        self.name
    }

    fn status(&self) -> TransportStatus {
        TransportStatus {
            id: self.id.to_string(),
            name: self.name.to_string(),
            connected: self.connection.is_some(),
            endpoint: self.endpoint.clone(),
            last_error: self.last_error.clone(),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        if self.connection.is_some() {
            return Ok(());
        }
        match self.open().await {
            Ok(connection) => {
                self.connection = Some(connection);
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
        if self.connection.is_none() {
            self.connect().await?;
        }
        match self.write_message(envelope, payload).await {
            Ok(()) => {
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                // A broken pipe invalidates the connection; drop it so the next
                // attempt reconnects.
                self.connection = None;
                self.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(Connection::WebSocket(socket)) = self.connection.as_mut() {
            let _ = socket.close(None).await;
        }
        self.connection = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connection.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn frames_round_trip() {
        let mut buffer: Vec<u8> = Vec::new();
        write_frame(&mut buffer, b"hello").await.unwrap();
        let mut cursor = std::io::Cursor::new(buffer);
        let payload = read_frame(&mut cursor, MAX_FRAME_LEN).await.unwrap();
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn oversized_frames_are_rejected() {
        let mut buffer: Vec<u8> = Vec::new();
        // Announce a length above the limit without sending the body.
        buffer.extend_from_slice(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buffer);
        assert!(read_frame(&mut cursor, MAX_FRAME_LEN).await.is_err());
    }

    #[test]
    fn bridge_message_round_trip() {
        let envelope = Envelope::new("a@example.org", vec!["b@example.org".to_string()]);
        let message = BridgeMessage::new(&envelope, b"raw message");
        assert_eq!(message.sender, "a@example.org");
        assert_eq!(message.decode().unwrap(), b"raw message");
    }

    #[test]
    fn host_port_split() {
        assert_eq!(
            split_host_port("abc.onion:25"),
            Some(("abc.onion".to_string(), 25))
        );
        assert_eq!(split_host_port("abc.onion"), None);
    }
}
