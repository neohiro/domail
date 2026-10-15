//! Submission protocol handler (RFC 6409)

use crate::config::*;
use crate::crypto::*;
use crate::error::*;
use crate::storage::*;
use crate::transport::*;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as LettreMessage};
use mail_parser::MessageParser;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{rustls, TlsAcceptor};
use tracing::{debug, error, info, warn};

/// Submission server (port 587/465)
pub struct SubmissionServer {
    config: SubmissionConfig,
    tls_acceptor: Option<TlsAcceptor>,
    implicit_tls_acceptor: Option<TlsAcceptor>,
    storage: Arc<dyn StorageBackend>,
    transport_manager: Arc<TransportManager>,
    running: Arc<tokio::sync::RwLock<bool>>,
}

impl SubmissionServer {
    pub async fn new(
        config: SubmissionConfig,
        cert_pem: &str,
        key_pem: &str,
        storage: Arc<dyn StorageBackend>,
        transport_manager: Arc<TransportManager>,
    ) -> Result<Self> {
        let cert = rustls::Certificate(cert_pem.as_bytes().to_vec());
        let key = rustls::PrivateKey(key_pem.as_bytes().to_vec());
        
        let tls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.clone())
            .map_err(|e| MxNodeError::Tls(e.to_string()))?;
        
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config.clone()));
        let implicit_tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        
        Ok(Self {
            config,
            tls_acceptor: Some(tls_acceptor),
            implicit_tls_acceptor: Some(implicit_tls_acceptor),
            storage,
            transport_manager,
            running: Arc::new(tokio::sync::RwLock::new(false)),
        })
    }
    
    pub async fn start(&self) -> Result<()> {
        *self.running.write().await = true;
        
        // Start explicit TLS listener (port 587)
        let listener_explicit = TcpListener::bind(self.config.bind_addr).await
            .map_err(|e| MxNodeError::Io(e))?;
        
        // Start implicit TLS listener (port 465)
        let listener_implicit = TcpListener::bind(self.config.implicit_tls_bind).await
            .map_err(|e| MxNodeError::Io(e))?;
        
        info!("Submission server listening on {} (STARTTLS) and {} (implicit TLS)", 
              self.config.bind_addr, self.config.implicit_tls_bind);
        
        // Explicit TLS handler
        let server_explicit = self.clone();
        tokio::spawn(async move {
            loop {
                if !*server_explicit.running.read().await { break; }
                match listener_explicit.accept().await {
                    Ok((stream, addr)) => {
                        let server = server_explicit.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server.handle_connection_explicit(stream, addr).await {
                                error!("Submission explicit TLS error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => { error!("Submission accept error: {}", e); tokio::time::sleep(tokio::time::Duration::from_secs(1)).await; }
                }
            }
        });
        
        // Implicit TLS handler
        let server_implicit = self.clone();
        tokio::spawn(async move {
            loop {
                if !*server_implicit.running.read().await { break; }
                match listener_implicit.accept().await {
                    Ok((stream, addr)) => {
                        let server = server_implicit.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server.handle_connection_implicit(stream, addr).await {
                                error!("Submission implicit TLS error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => { error!("Submission implicit accept error: {}", e); tokio::time::sleep(tokio::time::Duration::from_secs(1)).await; }
                }
            }
        });
        
        Ok(())
    }
    
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }
    
    async fn handle_connection_explicit(&self, stream: TcpStream, addr: std::net::SocketAddr) -> Result<()> {
        debug!("New Submission (explicit TLS) connection from {}", addr);
        
        let mut stream = Stream::Plain(stream);
        let mut session = SubmissionSession::new(addr, &self.config, self.storage.clone(), self.transport_manager.clone());
        session.handle_explicit(&mut stream).await
    }
    
    async fn handle_connection_implicit(&self, stream: TcpStream, addr: std::net::SocketAddr) -> Result<()> {
        debug!("New Submission (implicit TLS) connection from {}", addr);
        
        if let Some(acceptor) = &self.implicit_tls_acceptor {
            let tls_stream = acceptor.accept(stream).await
                .map_err(|e| MxNodeError::Tls(e.to_string()))?;
            let mut stream = Stream::Tls(tls_stream);
            let mut session = SubmissionSession::new(addr, &self.config, self.storage.clone(), self.transport_manager.clone());
            session.handle_implicit(&mut stream).await
        } else {
            Err(MxNodeError::Tls("No TLS acceptor for implicit mode".to_string()))
        }
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

/// Submission session handler (similar to SMTP but requires auth)
struct SubmissionSession {
    peer_addr: std::net::SocketAddr,
    config: SubmissionConfig,
    storage: Arc<dyn StorageBackend>,
    transport_manager: Arc<TransportManager>,
    
    state: SubmissionState,
    hello_domain: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_buffer: Vec<u8>,
    in_data: bool,
    tls: bool,
    authenticated: bool,
    auth_username: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum SubmissionState {
    Connected,
    HelloReceived,
    Authenticated,
    MailFromReceived,
    RcptToReceived,
    DataReceived,
    Quit,
}

impl SubmissionSession {
    fn new(
        peer_addr: std::net::SocketAddr,
        config: &SubmissionConfig,
        storage: Arc<dyn StorageBackend>,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            peer_addr,
            config: config.clone(),
            storage,
            transport_manager,
            state: SubmissionState::Connected,
            hello_domain: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_buffer: Vec::new(),
            in_data: false,
            tls: false,
            authenticated: false,
            auth_username: None,
        }
    }
    
    async fn handle_explicit(&mut self, stream: &mut Stream) -> Result<()> {
        // Send greeting
        self.send_response(stream, 220, &format!("{} ESMTP DOM Mail Submission Server ready", self.config.bind_addr)).await?;
        
        let mut line_buf = Vec::new();
        
        loop {
            line_buf.clear();
            let n = stream.read_line(&mut line_buf).await?;
            if n == 0 { break; }
            
            let line = String::from_utf8_lossy(&line_buf).trim_end_matches(&['\r', '\n'][..]).to_string();
            debug!("Submission << {}", line);
            
            if self.in_data {
                if line == "." {
                    self.handle_data_end().await?;
                    self.in_data = false;
                    self.data_buffer.clear();
                    self.send_response(stream, 250, "2.0.0 Message accepted for delivery").await?;
                    self.reset_transaction();
                } else {
                    let data_line = if line.starts_with("..") { &line[1..] } else { &line };
                    self.data_buffer.extend_from_slice(data_line.as_bytes());
                    self.data_buffer.push(b'\n');
                    
                    if self.data_buffer.len() > 50 * 1024 * 1024 {
                        self.send_response(stream, 552, "5.3.4 Message size exceeds limit").await?;
                        self.in_data = false;
                        self.data_buffer.clear();
                        self.reset_transaction();
                    }
                }
                continue;
            }
            
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
            
            if self.state == SubmissionState::Quit { break; }
        }
        
        Ok(())
    }
    
    async fn handle_implicit(&mut self, stream: &mut Stream) -> Result<()> {
        self.tls = true;
        self.send_response(stream, 220, &format!("{} ESMTP DOM Mail Submission Server ready (TLS)", self.config.implicit_tls_bind)).await?;
        
        let mut line_buf = Vec::new();
        
        loop {
            line_buf.clear();
            let n = stream.read_line(&mut line_buf).await?;
            if n == 0 { break; }
            
            let line = String::from_utf8_lossy(&line_buf).trim_end_matches(&['\r', '\n'][..]).to_string();
            debug!("Submission (implicit) << {}", line);
            
            if self.in_data {
                if line == "." {
                    self.handle_data_end().await?;
                    self.in_data = false;
                    self.data_buffer.clear();
                    self.send_response(stream, 250, "2.0.0 Message accepted for delivery").await?;
                    self.reset_transaction();
                } else {
                    let data_line = if line.starts_with("..") { &line[1..] } else { &line };
                    self.data_buffer.extend_from_slice(data_line.as_bytes());
                    self.data_buffer.push(b'\n');
                }
                continue;
            }
            
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            let cmd = parts[0].to_uppercase();
            let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");
            
            match cmd.as_str() {
                "HELO" | "EHLO" => self.handle_helo(stream, cmd, arg).await?,
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
            
            if self.state == SubmissionState::Quit { break; }
        }
        
        Ok(())
    }
    
    async fn send_response(&mut self, stream: &mut Stream, code: u16, msg: &str) -> Result<()> {
        let response = format!("{} {}\r\n", code, msg);
        debug!("Submission >> {}", response.trim());
        stream.write_all(response.as_bytes()).await
    }
    
    async fn handle_helo(&mut self, stream: &mut Stream, cmd: String, arg: &str) -> Result<()> {
        if arg.is_empty() {
            self.send_response(stream, 501, "5.5.4 Syntax error in parameters").await?;
            return Ok(());
        }
        
        self.hello_domain = Some(arg.to_string());
        self.state = SubmissionState::HelloReceived;
        
        if cmd == "EHLO" {
            let mut response = format!("250-{} Hello {}", self.config.bind_addr, arg);
            if !self.tls {
                response.push_str("\r\n250-STARTTLS");
            }
            response.push_str("\r\n250-AUTH PLAIN LOGIN");
            response.push_str("\r\n250-SIZE 52428800");
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
                    .map_err(|_| SubmissionError::AuthFailed("Invalid base64".to_string()))?;
                let parts: Vec<&str> = std::str::from_utf8(&decoded)
                    .map_err(|_| SubmissionError::AuthFailed("Invalid UTF-8".to_string()))?
                    .split('\0').collect();
                
                if parts.len() >= 3 {
                    let username = parts[1];
                    let password = parts[2];
                    if self.verify_credentials(username, password).await? {
                        self.authenticated = true;
                        self.auth_username = Some(username.to_string());
                        self.state = SubmissionState::Authenticated;
                        self.send_response(stream, 235, "2.7.0 Authentication successful").await?;
                    } else {
                        self.send_response(stream, 535, "5.7.8 Authentication credentials invalid").await?;
                    }
                }
            }
            "LOGIN" => {
                // Two-step
                self.send_response(stream, 334, "VXNlcm5hbWU6").await?;
            }
            _ => {
                self.send_response(stream, 504, "5.5.4 Unrecognized authentication type").await?;
            }
        }
        Ok(())
    }
    
    async fn verify_credentials(&self, username: &str, password: &str) -> Result<bool> {
        Ok(!username.is_empty() && !password.is_empty())
    }
    
    async fn handle_mail(&mut self, stream: &mut Stream, arg: &str) -> Result<()> {
        if self.config.require_auth && !self.authenticated {
            self.send_response(stream, 530, "5.7.0 Authentication required").await?;
            return Ok(());
        }
        
        if self.state != SubmissionState::HelloReceived && self.state != SubmissionState::Authenticated {
            self.send_response(stream, 503, "5.5.1 Bad sequence of commands").await?;
            return Ok(());
        }
        
        let arg = arg.trim();
        if !arg.starts_with("FROM:") {
            self.send_response(stream, 501, "5.5.4 Syntax error").await?;
            return Ok(());
        }
        
        let addr = arg[5..].trim().trim_matches(|c| c == '<' || c == '>');
        self.mail_from = Some(addr.to_string());
        self.state = SubmissionState::MailFromReceived;
        
        self.send_response(stream, 250, "2.1.0 OK").await?;
        Ok(())
    }
    
    async fn handle_rcpt(&mut self, stream: &mut Stream, arg: &str) -> Result<()> {
        if self.state != SubmissionState::MailFromReceived && self.state != SubmissionState::RcptToReceived {
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
        self.state = SubmissionState::RcptToReceived;
        
        self.send_response(stream, 250, "2.1.5 OK").await?;
        Ok(())
    }
    
    async fn handle_data(&mut self, stream: &mut Stream) -> Result<()> {
        if self.state != SubmissionState::RcptToReceived {
            self.send_response(stream, 503, "5.5.1 Bad sequence of commands").await?;
            return Ok(());
        }
        
        if self.rcpt_to.is_empty() {
            self.send_response(stream, 554, "5.5.1 No valid recipients").await?;
            return Ok(());
        }
        
        self.send_response(stream, 354, "Start mail input; end with <CRLF>.<CRLF>").await?;
        self.in_data = true;
        self.state = SubmissionState::DataReceived;
        Ok(())
    }
    
    async fn handle_data_end(&mut self) -> Result<()> {
        let raw_message = String::from_utf8_lossy(&self.data_buffer);
        let parsed = MessageParser::default().parse(raw_message.as_bytes());
        
        info!("Submission: Received message from {:?} to {:?}", self.mail_from, self.rcpt_to);
        
        // Deliver via transports
        if let Some(transport_mgr) = &self.transport_manager {
            for rcpt in &self.rcpt_to {
                // Try each transport
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
            if self.authenticated { SubmissionState::Authenticated } else { SubmissionState::HelloReceived }
        } else {
            SubmissionState::Connected
        };
    }
}