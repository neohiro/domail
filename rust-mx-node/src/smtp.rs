//! SMTP protocol handler

use crate::config::*;
use crate::crypto::*;
use crate::error::*;
use crate::storage::*;
use crate::transport::*;
use mail_parser::MessageParser;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as LettreMessage};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{rustls, TlsAcceptor};
use tracing::{debug, error, info, warn};

/// SMTP server state
pub struct SmtpServer {
    config: SmtpConfig,
    tls_acceptor: Option<TlsAcceptor>,
    storage: Arc<dyn StorageBackend>,
    transport_manager: Arc<TransportManager>,
    running: Arc<tokio::sync::RwLock<bool>>,
}

impl SmtpServer {
    pub async fn new(
        config: SmtpConfig,
        cert_pem: &str,
        key_pem: &str,
        storage: Arc<dyn StorageBackend>,
        transport_manager: Arc<TransportManager>,
    ) -> Result<Self> {
        // Parse TLS config
        let cert = rustls::Certificate(cert_pem.as_bytes().to_vec());
        let key = rustls::PrivateKey(key_pem.as_bytes().to_vec());
        
        let tls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| MxNodeError::Tls(e.to_string()))?;
        
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        
        Ok(Self {
            config,
            tls_acceptor: Some(tls_acceptor),
            storage,
            transport_manager,
            running: Arc::new(tokio::sync::RwLock::new(false)),
        })
    }
    
    pub async fn start(&self) -> Result<()> {
        *self.running.write().await = true;
        let listener = TcpListener::bind(self.config.bind_addr).await
            .map_err(|e| MxNodeError::Io(e))?;
        
        info!("SMTP server listening on {}", self.config.bind_addr);
        
        let server = self.clone();
        tokio::spawn(async move {
            loop {
                if !*server.running.read().await {
                    break;
                }
                
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server.handle_connection(stream, addr).await {
                                error!("SMTP connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("SMTP accept error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }
    
    async fn handle_connection(&self, stream: TcpStream, addr: std::net::SocketAddr) -> Result<()> {
        debug!("New SMTP connection from {}", addr);
        
        let mut stream = if self.config.require_starttls {
            // Start with plain, upgrade to TLS later
            Stream::Plain(stream)
        } else if let Some(acceptor) = &self.tls_acceptor {
            let tls_stream = acceptor.accept(stream).await
                .map_err(|e| MxNodeError::Tls(e.to_string()))?;
            Stream::Tls(tls_stream)
        } else {
            Stream::Plain(stream)
        };
        
        let mut session = SmtpSession::new(addr, &self.config, self.storage.clone(), self.transport_manager.clone());
        session.handle(&mut stream).await
    }
}

#[derive(Clone)]
enum Stream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl Stream {
    async fn read_line(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        match self {
            Stream::Plain(s) => {
                let mut reader = BufReader::new(s);
                reader.read_until(b'\n', buf).await.map_err(Into::into)
            }
            Stream::Tls(s) => {
                let mut reader = BufReader::new(s);
                reader.read_until(b'\n', buf).await.map_err(Into::into)
            }
        }
    }
    
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            Stream::Plain(s) => s.write_all(buf).await.map_err(Into::into),
            Stream::Tls(s) => s.write_all(buf).await.map_err(Into::into),
        }
    }
}

/// SMTP session handler
struct SmtpSession {
    peer_addr: std::net::SocketAddr,
    config: SmtpConfig,
    storage: Arc<dyn StorageBackend>,
    transport_manager: Arc<TransportManager>,
    
    state: SmtpState,
    hello_domain: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_buffer: Vec<u8>,
    in_data: bool,
    tls: bool,
    authenticated: bool,
    auth_username: Option<String>,
    rate_limit: RateLimiter,
}

#[derive(Debug, Clone, PartialEq)]
enum SmtpState {
    Connected,
    HelloReceived,
    MailFromReceived,
    RcptToReceived,
    DataReceived,
    Quit,
}

struct RateLimiter {
    max_per_minute: u32,
    requests: Vec<std::time::Instant>,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self { max_per_minute, requests: Vec::new() }
    }
    
    fn check(&mut self) -> bool {
        let now = std::time::Instant::now();
        let minute_ago = now - std::time::Duration::from_secs(60);
        self.requests.retain(|t| *t > minute_ago);
        
        if self.requests.len() >= self.max_per_minute as usize {
            return false;
        }
        
        self.requests.push(now);
        true
    }
}

impl SmtpSession {
    fn new(
        peer_addr: std::net::SocketAddr,
        config: &SmtpConfig,
        storage: Arc<dyn StorageBackend>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            peer_addr,
            config: config.clone(),
            storage,
            transport_manager,
            state: SmtpState::Connected,
            hello_domain: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_buffer: Vec::new(),
            in_data: false,
            tls: false,
            authenticated: false,
            auth_username: None,
            rate_limit: RateLimiter::new(config.rate_limit_per_minute),
        }
    }
    
    async fn handle(&mut self, stream: &mut Stream) -> Result<()> {
        // Send greeting
        self.send_response(stream, 220, &format!("{} ESMTP DOM Mail MX Node ready", self.config.bind_addr)).await?;
        
        let mut line_buf = Vec::new();
        
        loop {
            if !self.rate_limit.check() {
                self.send_response(stream, 421, "4.7.0 Rate limit exceeded").await?;
                break;
            }
            
            line_buf.clear();
            let n = stream.read_line(&mut line_buf).await?;
            if n == 0 {
                break; // Connection closed
            }
            
            let line = String::from_utf8_lossy(&line_buf).trim_end_matches(&['\r', '\n'][..]).to_string();
            debug!("SMTP << {}", line);
            
            if self.in_data {
                if line == "." {
                    // End of data
                    self.handle_data_end().await?;
                    self.in_data = false;
                    self.data_buffer.clear();
                    self.send_response(stream, 250, "2.0.0 Message accepted for delivery").await?;
                    self.reset_transaction();
                } else {
                    // Handle dot-stuffing
                    let data_line = if line.starts_with("..") { &line[1..] } else { &line };
                    self.data_buffer.extend_from_slice(data_line.as_bytes());
                    self.data_buffer.push(b'\n');
                    
                    if self.data_buffer.len() > self.config.max_message_size {
                        self.send_response(stream, 552, "5.3.4 Message size exceeds limit").await?;
                        self.in_data = false;
                        self.data_buffer.clear();
                        self.reset_transaction();
                    }
                }
                continue;
            }
            
            // Parse command
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            let cmd = parts[0].to_uppercase();
            let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");
            
            match cmd.as_str() {
                "HELO" | "EHLO" => self.handle_helo(stream, cmd, arg).await?,
                "STARTTLS" => self.handle_starttls(stream).await?,
                "AUTH" => self.handle_auth(stream, arg).await?,
                "MAIL" => self.handle_mail(stream, arg).await?,
                "RCPT" => self.handle_rcpt(stream, arg).await?,
                "DATA" => self.handle_data(stream).await?,
                "RSET" => self.handle_rset(stream).await?,
                "QUIT" => {
                    self.send_response(stream, 221, "2.0.0 Bye").await?;
                    break;
                }
                "NOOP" => self.send_response(stream, 250, "2.0.0 OK").await?,
                _ => self.send_response(stream, 500, "5.5.1 Command unrecognized").await?,
            }
            
            if self.state == SmtpState::Quit {
                break;
            }
        }
        
        Ok(())
    }
    
    async fn send_response(&mut self, stream: &mut Stream, code: u16, msg: &str) -> Result<()> {
        let response = format!("{} {}\r\n", code, msg);
        debug!("SMTP >> {}", response.trim());
        stream.write_all(response.as_bytes()).await
    }
    
    async fn handle_helo(&mut self, stream: &mut Stream, cmd: String, arg: &str) -> Result<()> {
        if arg.is_empty() {
            self.send_response(stream, 501, "5.5.4 Syntax error in parameters").await?;
            return Ok(());
        }
        
        self.hello_domain = Some(arg.to_string());
        self.state = SmtpState::HelloReceived;
        
        if cmd == "EHLO" {
            let mut response = format!("250-{} Hello {}", self.config.bind_addr, arg);
            if !self.tls && self.config.require_starttls {
                response.push_str("\r\n250-STARTTLS");
            }
            response.push_str("\r\n250-AUTH PLAIN LOGIN");
            response.push_str("\r\n250-SIZE "); response.push_str(&self.config.max_message_size.to_string());
            response.push_str("\r\n250 8BITMIME");
            self.send_response(stream, 250, &response).await?;
        } else {
            self.send_response(stream, 250, &format!("Hello {}", arg)).await?;
        }
        Ok(())
    }
    
    async fn handle_starttls(&mut self, stream: &mut Stream) -> Result<()> {
        if self.tls {
            self.send_response(stream, 554, "5.5.1 TLS already active").await?;
            return Ok(());
        }
        
        // In real implementation, would upgrade the stream
        self.send_response(stream, 220, "2.0.0 Ready to start TLS").await?;
        self.tls = true;
        Ok(())
    }
    
    async fn handle_auth(&mut self, stream: &mut Stream, arg: &str) -> Result<()> {
        let parts: Vec<&str> = arg.splitn(2, ' ').collect();
        let mechanism = parts[0].to_uppercase();
        
        match mechanism.as_str() {
            "PLAIN" => {
                let credentials = parts.get(1).unwrap_or("");
                let decoded = base64::engine::general_purpose::STANDARD.decode(credentials)
                    .map_err(|_| SmtpError::AuthFailed("Invalid base64".to_string()))?;
                let parts: Vec<&str> = std::str::from_utf8(&decoded)
                    .map_err(|_| SmtpError::AuthFailed("Invalid UTF-8".to_string()))?
                    .split('\0').collect();
                
                if parts.len() >= 3 {
                    let username = parts[1];
                    let password = parts[2];
                    if self.verify_credentials(username, password).await? {
                        self.authenticated = true;
                        self.auth_username = Some(username.to_string());
                        self.send_response(stream, 235, "2.7.0 Authentication successful").await?;
                    } else {
                        self.send_response(stream, 535, "5.7.8 Authentication credentials invalid").await?;
                    }
                }
            }
            "LOGIN" => {
                // Two-step AUTH LOGIN
                self.send_response(stream, 334, "VXNlcm5hbWU6").await?; // base64("Username:")
                // Would need to read username then password
            }
            _ => {
                self.send_response(stream, 504, "5.5.4 Unrecognized authentication type").await?;
            }
        }
        Ok(())
    }
    
    async fn verify_credentials(&self, username: &str, password: &str) -> Result<bool> {
        // In real implementation, verify against stored credentials
        // For now, accept any non-empty
        Ok(!username.is_empty() && !password.is_empty())
    }
    
    async fn handle_mail(&mut self, stream: &mut Stream, arg: &str) -> Result<()> {
        if self.state != SmtpState::HelloReceived {
            self.send_response(stream, 503, "5.5.1 Bad sequence of commands").await?;
            return Ok(());
        }
        
        // Parse MAIL FROM:<address> [SIZE=xxx]
        let arg = arg.trim();
        if !arg.starts_with("FROM:") {
            self.send_response(stream, 501, "5.5.4 Syntax error").await?;
            return Ok(());
        }
        
        let addr = arg[5..].trim().trim_matches(|c| c == '<' || c == '>');
        self.mail_from = Some(addr.to_string());
        self.state = SmtpState::MailFromReceived;
        
        self.send_response(stream, 250, "2.1.0 OK").await?;
        Ok(())
    }
    
    async fn handle_rcpt(&mut self, stream: &mut Stream, arg: &str) -> Result<()> {
        if self.state != SmtpState::MailFromReceived && self.state != SmtpState::RcptToReceived {
            self.send_response(stream, 503, "5.5.1 Bad sequence of commands").await?;
            return Ok(());
        }
        
        let arg = arg.trim();
        if !arg.starts_with("TO:") {
            self.send_response(stream, 501, "5.5.4 Syntax error").await?;
            return Ok(());
        }
        
        let addr = arg[3..].trim().trim_matches(|c| c == '<' || c == '>');
        self.rcpt_to.push(addr.to_string());
        self.state = SmtpState::RcptToReceived;
        
        self.send_response(stream, 250, "2.1.5 OK").await?;
        Ok(())
    }
    
    async fn handle_data(&mut self, stream: &mut Stream) -> Result<()> {
        if self.state != SmtpState::RcptToReceived {
            self.send_response(stream, 503, "5.5.1 Bad sequence of commands").await?;
            return Ok(());
        }
        
        if self.rcpt_to.is_empty() {
            self.send_response(stream, 554, "5.5.1 No valid recipients").await?;
            return Ok(());
        }
        
        self.send_response(stream, 354, "Start mail input; end with <CRLF>.<CRLF>").await?;
        self.in_data = true;
        self.state = SmtpState::DataReceived;
        Ok(())
    }
    
    async fn handle_data_end(&mut self) -> Result<()> {
        // Parse the message
        let raw_message = String::from_utf8_lossy(&self.data_buffer);
        let parsed = MessageParser::default().parse(raw_message.as_bytes());
        
        // Store in mailbox
        // For now, just log
        info!("Received message from {:?} to {:?}", self.mail_from, self.rcpt_to);
        
        // Deliver via transports
        if let Some(transport_mgr) = &self.transport_manager {
            for rcpt in &self.rcpt_to {
                // Try each transport
                for transport_id in ["direct", "tor", "i2p", "nostr"] {
                    // Would actually deliver
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_rset(&mut self, stream: &mut Stream) -> Result<()> {
        self.reset_transaction();
        self.send_response(stream, 250, "2.0.0 OK").await?;
        Ok(())
    }
    
    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();
        self.state = if self.hello_domain.is_some() {
            SmtpState::HelloReceived
        } else {
            SmtpState::Connected
        };
    }
}