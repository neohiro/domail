//! Transport layer for the MX Node

use crate::config::*;
use crate::error::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::Arc;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{SinkExt, StreamExt};
#[cfg(not(target_arch = "wasm32"))]
use reqwest;

/// Transport trait
#[async_trait]
pub trait Transport: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    async fn connect(&mut self) -> Result<()>;
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn receive(&mut self) -> Result<Option<Vec<u8>>>;
    async fn disconnect(&mut self) -> Result<()>;
    fn is_connected(&self) -> bool;
}

/// Transport manager
pub struct TransportManager {
    transports: Arc<RwLock<HashMap<String, Box<dyn Transport>>>>,
    default_transport: String,
}

impl TransportManager {
    pub fn new() -> Self {
        Self {
            transports: Arc::new(RwLock::new(HashMap::new())),
            default_transport: "direct".to_string(),
        }
    }
    
    pub async fn register(&self, transport: Box<dyn Transport>) -> Result<()> {
        let id = transport.id().to_string();
        let mut transports = self.transports.write().await;
        transports.insert(id, transport);
        Ok(())
    }
    
    pub async fn unregister(&self, id: &str) -> Result<()> {
        self.transports.write().await.remove(id);
        Ok(())
    }
    
    pub async fn get(&self, id: &str) -> Option<Box<dyn Transport>> {
        // Can't really return Box from RwLock, need different approach
        None
    }
    
    pub async fn send_via(&self, transport_id: &str, data: &[u8]) -> Result<()> {
        let mut transports = self.transports.write().await;
        if let Some(transport) = transports.get_mut(transport_id) {
            transport.send(data).await
        } else {
            Err(TransportError::UnsupportedTransport(transport_id.to_string()).into())
        }
    }
    
    pub async fn broadcast(&self, data: &[u8]) -> Result<()> {
        let transports = self.transports.read().await;
        for transport in transports.values() {
            if transport.is_connected() {
                if let Err(e) = transport.send(data).await {
                    log::warn!("Transport {} send failed: {}", transport.id(), e);
                }
            }
        }
        Ok(())
    }
}

/// Direct transport (plain TCP/TLS)
pub struct DirectTransport {
    config: TransportConfig,
    connected: bool,
    // In real implementation: TcpStream with TLS
}

impl DirectTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false }
    }
}

#[async_trait]
impl Transport for DirectTransport {
    fn id(&self) -> &str { "direct" }
    fn name(&self) -> &str { "Direct" }
    
    async fn connect(&mut self) -> Result<()> {
        // In WASM: use WebSocket to a local proxy
        // In native: use TcpStream with rustls
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(TransportError::NotConnected.into());
        }
        // Send via appropriate channel
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected {
            return Err(TransportError::NotConnected.into());
        }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Tor transport via WebSocket to Tor proxy
pub struct TorTransport {
    config: TransportConfig,
    connected: bool,
    ws_sender: Option<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
}

impl TorTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false, ws_sender: None }
    }
    
    fn proxy_url(&self) -> String {
        self.config.options.get("proxy_url")
            .cloned()
            .unwrap_or_else(|| "wss://tor-proxy.example.com".to_string())
    }
    
    fn onion_service(&self) -> Option<String> {
        self.config.options.get("onion_service").cloned()
    }
}

#[async_trait]
impl Transport for TorTransport {
    fn id(&self) -> &str { "tor" }
    fn name(&self) -> &str { "Tor" }
    
    async fn connect(&mut self) -> Result<()> {
        let url = self.proxy_url();
        let (ws_stream, _) = connect_async(&url).await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        
        // Register onion service if configured
        if let Some(onion) = self.onion_service() {
            let msg = serde_json::json!({
                "type": "register_onion",
                "service": onion
            });
            // Send registration
        }
        
        self.ws_sender = Some(ws_stream);
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if let Some(ws) = &mut self.ws_sender {
            ws.send(Message::Binary(data.to_vec())).await
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        }
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if let Some(ws) = &mut self.ws_sender {
            while let Some(msg) = ws.next().await {
                match msg {
                    Ok(Message::Binary(data)) => return Ok(Some(data)),
                    Ok(Message::Close(_)) => break,
                    Err(e) => return Err(TransportError::ReceiveFailed(e.to_string())),
                    _ => continue,
                }
            }
        }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut ws) = self.ws_sender.take() {
            ws.close(None).await.ok();
        }
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// I2P transport via SAM bridge
pub struct I2pTransport {
    config: TransportConfig,
    connected: bool,
}

impl I2pTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false }
    }
}

#[async_trait]
impl Transport for I2pTransport {
    fn id(&self) -> &str { "i2p" }
    fn name(&self) -> &str { "I2P" }
    
    async fn connect(&mut self) -> Result<()> {
        // Connect to I2P SAM bridge (typically localhost:7656)
        // Then create session and register destination
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Nostr transport for decentralized relay
pub struct NostrTransport {
    config: TransportConfig,
    connected: bool,
    relays: Vec<String>,
    ws_connections: HashMap<String, tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
}

impl NostrTransport {
    pub fn new(config: TransportConfig) -> Self {
        let relays = config.options.get("relays")
            .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|| vec![
                "wss://relay.damus.io".to_string(),
                "wss://nos.lol".to_string(),
            ]);
        
        Self {
            config,
            connected: false,
            relays,
            ws_connections: HashMap::new(),
        }
    }
}

#[async_trait]
impl Transport for NostrTransport {
    fn id(&self) -> &str { "nostr" }
    fn name(&self) -> &str { "Nostr" }
    
    async fn connect(&mut self) -> Result<()> {
        for relay in &self.relays {
            match connect_async(relay).await {
                Ok((ws, _)) => {
                    self.ws_connections.insert(relay.clone(), ws);
                }
                Err(e) => {
                    log::warn!("Failed to connect to Nostr relay {}: {}", relay, e);
                }
            }
        }
        
        self.connected = !self.ws_connections.is_empty();
        if !self.connected {
            return Err(TransportError::ConnectionFailed("No Nostr relays connected".to_string()).into());
        }
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Send as NIP-17 encrypted DM
        for (_, ws) in &mut self.ws_connections {
            if let Err(e) = ws.send(Message::Binary(data.to_vec())).await {
                log::warn!("Nostr send failed: {}", e);
            }
        }
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        // Would need to handle multiple WebSocket streams
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        for (_, mut ws) in self.ws_connections.drain() {
            ws.close(None).await.ok();
        }
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// DNS transport for censorship circumvention
pub struct DnsTransport {
    config: TransportConfig,
    connected: bool,
}

impl DnsTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false }
    }
}

#[async_trait]
impl Transport for DnsTransport {
    fn id(&self) -> &str { "dns" }
    fn name(&self) -> &str { "DNS" }
    
    async fn connect(&mut self) -> Result<()> {
        // Use DNS-over-HTTPS or raw DNS
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        // Encode data in DNS TXT queries
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Sneakernet transport (QR code / USB / file)
pub struct SneakernetTransport {
    config: TransportConfig,
    connected: bool,
}

impl SneakernetTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: true } // Always "connected" locally
    }
}

#[async_trait]
impl Transport for SneakernetTransport {
    fn id(&self) -> &str { "sneakernet" }
    fn name(&self) -> &str { "Sneakernet" }
    
    async fn connect(&mut self) -> Result<()> {
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Generate QR code or file for physical transfer
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// WebRTC transport for direct P2P
pub struct WebRtcTransport {
    config: TransportConfig,
    connected: bool,
}

impl WebRtcTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false }
    }
}

#[async_trait]
impl Transport for WebRtcTransport {
    fn id(&self) -> &str { "webrtc" }
    fn name(&self) -> &str { "WebRTC" }
    
    async fn connect(&mut self) -> Result<()> {
        // Would use WebRTC data channels via signaling server
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Yggdrasil mesh transport
pub struct YggdrasilTransport {
    config: TransportConfig,
    connected: bool,
    peer_connections: HashMap<String, tokio::net::TcpStream>,
}

impl YggdrasilTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false, peer_connections: HashMap::new() }
    }
    
    fn get_peers(&self) -> Vec<String> {
        self.config.options.get("peers")
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default()
    }
}

#[async_trait]
impl Transport for YggdrasilTransport {
    fn id(&self) -> &str { "yggdrasil" }
    fn name(&self) -> &str { "Yggdrasil" }
    
    async fn connect(&mut self) -> Result<()> {
        let peers = self.get_peers();
        for peer in peers {
            if let Ok(stream) = TcpStream::connect(&peer).await {
                self.peer_connections.insert(peer, stream);
            }
        }
        self.connected = !self.peer_connections.is_empty();
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        // Send to all connected peers
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.peer_connections.clear();
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Reticulum transport
pub struct ReticulumTransport {
    config: TransportConfig,
    connected: bool,
}

impl ReticulumTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false }
    }
}

#[async_trait]
impl Transport for ReticulumTransport {
    fn id(&self) -> &str { "reticulum" }
    fn name(&self) -> &str { "Reticulum" }
    
    async fn connect(&mut self) -> Result<()> {
        // Connect to Reticulum network via TCP/UDP
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// BLE (Bluetooth Low Energy) transport
pub struct BleTransport {
    config: TransportConfig,
    connected: bool,
    peripheral: Option<String>,
}

impl BleTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false, peripheral: None }
    }
}

#[async_trait]
impl Transport for BleTransport {
    fn id(&self) -> &str { "ble" }
    fn name(&self) -> &str { "Bluetooth Low Energy" }
    
    async fn connect(&mut self) -> Result<()> {
        // In WASM: use Web Bluetooth API
        // In native: use platform Bluetooth stack (BlueZ, CoreBluetooth, etc.)
        #[cfg(target_arch = "wasm32")]
        {
            // Web Bluetooth API
            // navigator.bluetooth.requestDevice(...)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Native Bluetooth - would use platform-specific APIs
            // Linux: BlueZ D-Bus API
            // macOS: CoreBluetooth
            // Windows: Windows.Devices.Bluetooth
        }
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        // Send via GATT characteristic write
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        // Receive via GATT notification/indication
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// LoRa (Long Range) transport
pub struct LoRaTransport {
    config: TransportConfig,
    connected: bool,
    device_path: Option<String>,
    frequency: u32,
    spreading_factor: u8,
    bandwidth: u32,
    coding_rate: u8,
}

impl LoRaTransport {
    pub fn new(config: TransportConfig) -> Self {
        let frequency = config.options.get("frequency")
            .and_then(|s| s.parse().ok())
            .unwrap_or(915_000_000); // 915 MHz default (US)
        let spreading_factor = config.options.get("spreading_factor")
            .and_then(|s| s.parse().ok())
            .unwrap_or(7);
        let bandwidth = config.options.get("bandwidth")
            .and_then(|s| s.parse().ok())
            .unwrap_or(125_000); // 125 kHz
        let coding_rate = config.options.get("coding_rate")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        
        Self {
            config,
            connected: false,
            device_path: config.options.get("device").cloned(),
            frequency,
            spreading_factor,
            bandwidth,
            coding_rate,
        }
    }
}

#[async_trait]
impl Transport for LoRaTransport {
    fn id(&self) -> &str { "lora" }
    fn name(&self) -> &str { "LoRa Radio" }
    
    async fn connect(&mut self) -> Result<()> {
        // Initialize LoRa radio (SX1276/SX1262/SX1280 via SPI)
        // Would use Linux spidev or embedded-hal
        if self.device_path.is_none() {
            return Err(TransportError::ConnectionFailed("No LoRa device path specified".to_string()).into());
        }
        
        // Initialize radio with config:
        // - Frequency: self.frequency
        // - Spreading Factor: self.spreading_factor
        // - Bandwidth: self.bandwidth
        // - Coding Rate: self.coding_rate
        // - Preamble Length: 8
        // - Sync Word: 0x12 (private network)
        // - CRC: Enabled
        
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        
        // Send via LoRa packet
        // Max payload: 255 bytes (LoRaWAN) or 255 bytes (raw LoRa)
        if data.len() > 255 {
            return Err(TransportError::SendFailed("Payload too large for LoRa (max 255 bytes)".to_string()).into());
        }
        
        // Send via radio
        // radio.write(&data)?;
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        
        // Check for received packet
        // if radio.available() { ... }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Packet Radio transport (AX.25, KISS, etc.)
pub struct PacketRadioTransport {
    config: TransportConfig,
    connected: bool,
    device_path: Option<String>,
    callsign: String,
    baud_rate: u32,
}

impl PacketRadioTransport {
    pub fn new(config: TransportConfig) -> Self {
        let callsign = config.options.get("callsign")
            .cloned()
            .unwrap_or_else(|| "N0CALL".to_string());
        let baud_rate = config.options.get("baud_rate")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1200);
        
        Self {
            config,
            connected: false,
            device_path: config.options.get("device").cloned(),
            callsign,
            baud_rate,
        }
    }
}

#[async_trait]
impl Transport for PacketRadioTransport {
    fn id(&self) -> &str { "packet_radio" }
    fn name(&self) -> &str { "Packet Radio (AX.25/KISS)" }
    
    async fn connect(&mut self) -> Result<()> {
        // Connect to TNC (Terminal Node Controller) via serial/USB
        // Supports KISS protocol
        if self.device_path.is_none() {
            return Err(TransportError::ConnectionFailed("No TNC device path specified".to_string()).into());
        }
        
        // Open serial port at self.baud_rate
        // Send KISS init commands:
        // TXDELAY, PERSIST, SLOTTIME, TXTAIL, FULLDUP
        
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        
        // Frame as AX.25 UI frame:
        // [Flag][Dest][Source][Control][PID][Data][FCS][Flag]
        // Destination: "MAIL    " (or specific callsign)
        // Source: self.callsign
        // Control: 0x03 (UI frame)
        // PID: 0xF0 (No layer 3)
        
        // Send via KISS: [CMD_DATA][AX.25 Frame][FEND]
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        
        // Read KISS frames, extract AX.25 payload
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Federation transport (ActivityPub/Matrix/XMPP)
pub struct FederationTransport {
    config: TransportConfig,
    connected: bool,
    client: Option<reqwest::Client>,
}

impl FederationTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config, connected: false, client: None }
    }
}

#[async_trait]
impl Transport for FederationTransport {
    fn id(&self) -> &str { "federation" }
    fn name(&self) -> &str { "Federation (ActivityPub/Matrix/XMPP)" }
    
    async fn connect(&mut self) -> Result<()> {
        // Connect to federation relay/gateway
        self.client = Some(reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?);
        self.connected = true;
        Ok(())
    }
    
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        
        // Send via federation protocol
        // ActivityPub: POST to inbox
        // Matrix: send to room
        // XMPP: send stanza
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.connected { return Err(TransportError::NotConnected.into()); }
        Ok(None)
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.client = None;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Factory function to create transport from config
pub fn create_transport(config: TransportConfig) -> Result<Box<dyn Transport>> {
    match config.id.as_str() {
        "direct" => Ok(Box::new(DirectTransport::new(config))),
        "tor" => Ok(Box::new(TorTransport::new(config))),
        "i2p" => Ok(Box::new(I2pTransport::new(config))),
        "nostr" => Ok(Box::new(NostrTransport::new(config))),
        "yggdrasil" => Ok(Box::new(YggdrasilTransport::new(config))),
        "reticulum" => Ok(Box::new(ReticulumTransport::new(config))),
        "webrtc" => Ok(Box::new(WebRtcTransport::new(config))),
        "ble" => Ok(Box::new(BleTransport::new(config))),
        "lora" => Ok(Box::new(LoRaTransport::new(config))),
        "packet_radio" => Ok(Box::new(PacketRadioTransport::new(config))),
        "dns" => Ok(Box::new(DnsTransport::new(config))),
        "sneakernet" => Ok(Box::new(SneakernetTransport::new(config))),
        "federation" => Ok(Box::new(FederationTransport::new(config))),
        _ => Err(TransportError::UnsupportedTransport(config.id).into()),
    }
}

/// Initialize transports from config
pub async fn init_transports(configs: Vec<TransportConfig>) -> Result<TransportManager> {
    let manager = TransportManager::new();
    
    for config in configs {
        if config.enabled {
            let transport = create_transport(config)?;
            manager.register(transport).await?;
        }
    }
    
    Ok(manager)
}