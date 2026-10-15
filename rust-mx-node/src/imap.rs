//! IMAP protocol handler

use crate::config::*;
use crate::crypto::*;
use crate::error::*;
use crate::storage::*;
use mail_builder::MessageBuilder;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{rustls, TlsAcceptor};
use tracing::{debug, error, info, warn};

/// IMAP server
pub struct ImapServer {
    config: ImapConfig,
    tls_acceptor: Option<TlsAcceptor>,
    storage: Arc<dyn StorageBackend>,
    running: Arc<tokio::sync::RwLock<bool>>,
}

impl ImapServer {
    pub async fn new(
        config: ImapConfig,
        cert_pem: &str,
        key_pem: &str,
        storage: Arc<dyn StorageBackend>,
    ) -> Result<Self> {
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
            running: Arc::new(tokio::sync::RwLock::new(false)),
        })
    }
    
    pub async fn start(&self) -> Result<()> {
        *self.running.write().await = true;
        let listener = TcpListener::bind(self.config.bind_addr).await
            .map_err(|e| MxNodeError::Io(e))?;
        
        info!("IMAP server listening on {}", self.config.bind_addr);
        
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
                                error!("IMAP connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("IMAP accept error: {}", e);
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
        debug!("New IMAP connection from {}", addr);
        
        let stream = if self.config.require_tls {
            if let Some(acceptor) = &self.tls_acceptor {
                let tls_stream = acceptor.accept(stream).await
                    .map_err(|e| MxNodeError::Tls(e.to_string()))?;
                Stream::Tls(tls_stream)
            } else {
                Stream::Plain(stream)
            }
        } else {
            Stream::Plain(stream)
        };
        
        let mut session = ImapSession::new(addr, self.storage.clone());
        session.handle(stream).await
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

/// IMAP session handler
struct ImapSession {
    peer_addr: std::net::SocketAddr,
    storage: Arc<dyn StorageBackend>,
    
    state: ImapState,
    tag: Option<String>,
    authenticated: bool,
    username: Option<String>,
    selected_mailbox: Option<String>,
    capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum ImapState {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

impl ImapSession {
    fn new(peer_addr: std::net::SocketAddr, storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            peer_addr,
            storage,
            state: ImapState::NotAuthenticated,
            tag: None,
            authenticated: false,
            username: None,
            selected_mailbox: None,
            capabilities: vec![
                "IMAP4rev1".to_string(),
                "AUTH=PLAIN".to_string(),
                "AUTH=LOGIN".to_string(),
                "STARTTLS".to_string(),
                "IDLE".to_string(),
                "NAMESPACE".to_string(),
            ],
        }
    }
    
    async fn handle(&mut self, stream: &mut Stream) -> Result<()> {
        // Send greeting
        self.send_response("* OK DOM Mail IMAP Server ready\r\n").await?;
        
        let mut line_buf = Vec::new();
        
        loop {
            line_buf.clear();
            let n = stream.read_line(&mut line_buf).await?;
            if n == 0 {
                break;
            }
            
            let line = String::from_utf8_lossy(&line_buf).trim_end_matches(&['\r', '\n'][..]).to_string();
            debug!("IMAP << {}", line);
            
            if line.is_empty() {
                continue;
            }
            
            // Parse tag and command
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() < 2 {
                self.send_response("* BAD Invalid command format\r\n").await?;
                continue;
            }
            
            let tag = parts[0];
            let rest = parts[1];
            
            self.tag = Some(tag.to_string());
            
            let cmd_parts: Vec<&str> = rest.splitn(2, ' ').collect();
            let cmd = cmd_parts[0].to_uppercase();
            let args = cmd_parts.get(1).unwrap_or("");
            
            let result = match cmd.as_str() {
                "CAPABILITY" => self.handle_capability().await,
                "NOOP" => self.handle_noop().await,
                "LOGOUT" => self.handle_logout().await,
                "STARTTLS" => self.handle_starttls().await,
                "AUTHENTICATE" => self.handle_authenticate(args).await,
                "LOGIN" => self.handle_login(args).await,
                "SELECT" => self.handle_select(args).await,
                "EXAMINE" => self.handle_examine(args).await,
                "CREATE" => self.handle_create(args).await,
                "DELETE" => self.handle_delete(args).await,
                "RENAME" => self.handle_rename(args).await,
                "SUBSCRIBE" => Ok(()),
                "UNSUBSCRIBE" => Ok(()),
                "LIST" => self.handle_list(args).await,
                "LSUB" => self.handle_lsub(args).await,
                "STATUS" => self.handle_status(args).await,
                "APPEND" => self.handle_append(args).await,
                "CHECK" => Ok(()),
                "CLOSE" => self.handle_close().await,
                "EXPUNGE" => self.handle_expunge().await,
                "SEARCH" => self.handle_search(args).await,
                "FETCH" => self.handle_fetch(args).await,
                "STORE" => self.handle_store(args).await,
                "COPY" => self.handle_copy(args).await,
                "UID" => self.handle_uid(args).await,
                "IDLE" => self.handle_idle().await,
                _ => {
                    self.send_response(&format!("{} BAD Command not supported\r\n", self.tag())).await?;
                    Ok(())
                }
            };
            
            if let Err(e) = result {
                error!("IMAP command error: {}", e);
            }
            
            if self.state == ImapState::Logout {
                break;
            }
        }
        
        Ok(())
    }
    
    fn tag(&self) -> String {
        self.tag.clone().unwrap_or_else(|| "*".to_string())
    }
    
    async fn send_response(&self, response: &str) -> Result<()> {
        debug!("IMAP >> {}", response.trim());
        // In real implementation, would write to stream
        Ok(())
    }
    
    async fn handle_capability(&mut self) -> Result<()> {
        self.send_response(&format!("* CAPABILITY {}\r\n", self.capabilities.join(" "))).await?;
        self.send_response(&format!("{} OK CAPABILITY completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_noop(&mut self) -> Result<()> {
        self.send_response(&format!("{} OK NOOP completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_logout(&mut self) -> Result<()> {
        self.send_response("* BYE DOM Mail IMAP Server logging out\r\n").await?;
        self.send_response(&format!("{} OK LOGOUT completed\r\n", self.tag())).await?;
        // Would close connection
        Ok(())
    }
    
    async fn handle_starttls(&mut self) -> Result<()> {
        if self.state != ImapState::NotAuthenticated {
            self.send_response(&format!("{} BAD STARTTLS not allowed in current state\r\n", self.tag())).await?;
            return Ok(());
        }
        
        self.send_response(&format!("{} OK Begin TLS negotiation now\r\n", self.tag())).await?;
        // Would upgrade stream to TLS
        Ok(())
    }
    
    async fn handle_authenticate(&mut self, mechanism: &str) -> Result<()> {
        // SASL authentication
        let mech = mechanism.to_uppercase();
        match mech.as_str() {
            "PLAIN" => {
                // Read base64 encoded authzid\0authcid\0password
            }
            "LOGIN" => {
                // Two-step
            }
            _ => {
                self.send_response(&format!("{} BAD Unsupported authentication mechanism\r\n", self.tag())).await?;
            }
        }
        Ok(())
    }
    
    async fn handle_login(&mut self, args: &str) -> Result<()> {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        if parts.len() < 2 {
            self.send_response(&format!("{} BAD LOGIN requires username and password\r\n", self.tag())).await?;
            return Ok(());
        }
        
        let username = parts[0];
        let password = parts[1];
        
        // Verify credentials (placeholder)
        if !username.is_empty() && !password.is_empty() {
            self.authenticated = true;
            self.username = Some(username.to_string());
            self.state = ImapState::Authenticated;
            self.send_response(&format!("{} OK LOGIN completed\r\n", self.tag())).await?;
        } else {
            self.send_response(&format!("{} NO LOGIN failed\r\n", self.tag())).await?;
        }
        Ok(())
    }
    
    async fn handle_select(&mut self, args: &str) -> Result<()> {
        let mailbox = args.trim().trim_matches('"');
        
        // Check if mailbox exists
        let mailbox_storage = MailboxStorage::new(
            EncryptedStorage::new(
                Box::new(MemoryStorage::new(1024*1024*1024)),
                MasterKey::derive("test", b"salt12345678", &Argon2Params::default()).unwrap(),
            ),
            mailbox,
        );
        
        let count = mailbox_storage.count().await.unwrap_or(0);
        let unread = mailbox_storage.count_unread().await.unwrap_or(0);
        
        self.selected_mailbox = Some(mailbox.to_string());
        self.state = ImapState::Selected;
        
        self.send_response(&format!("* {} EXISTS\r\n", count)).await?;
        self.send_response(&format!("* {} RECENT\r\n", unread)).await?;
        self.send_response("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n").await?;
        self.send_response("* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)] Flags permitted\r\n").await?;
        self.send_response(&format!("* OK [UIDVALIDITY 1] UIDs valid\r\n")).await?;
        self.send_response(&format!("{} OK [READ-WRITE] SELECT completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_examine(&mut self, args: &str) -> Result<()> {
        // Similar to SELECT but read-only
        self.handle_select(args).await
    }
    
    async fn handle_create(&mut self, args: &str) -> Result<()> {
        let mailbox = args.trim().trim_matches('"');
        // Create mailbox (in storage)
        self.send_response(&format!("{} OK CREATE completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_delete(&mut self, args: &str) -> Result<()> {
        let mailbox = args.trim().trim_matches('"');
        // Delete mailbox
        self.send_response(&format!("{} OK DELETE completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_rename(&mut self, args: &str) -> Result<()> {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        if parts.len() < 2 {
            self.send_response(&format!("{} BAD RENAME requires two arguments\r\n", self.tag())).await?;
            return Ok(());
        }
        // Rename mailbox
        self.send_response(&format!("{} OK RENAME completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_list(&mut self, args: &str) -> Result<()> {
        // List mailboxes
        self.send_response("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n").await?;
        self.send_response("* LIST (\\HasNoChildren) \"/\" \"Sent\"\r\n").await?;
        self.send_response("* LIST (\\HasNoChildren) \"/\" \"Drafts\"\r\n").await?;
        self.send_response("* LIST (\\HasNoChildren) \"/\" \"Trash\"\r\n").await?;
        self.send_response("* LIST (\\HasNoChildren) \"/\" \"Spam\"\r\n").await?;
        self.send_response(&format!("{} OK LIST completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_lsub(&mut self, args: &str) -> Result<()> {
        self.handle_list(args).await
    }
    
    async fn handle_status(&mut self, args: &str) -> Result<()> {
        // STATUS mailbox (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)
        self.send_response(&format!("* STATUS \"INBOX\" (MESSAGES 10 RECENT 2 UNSEEN 5)\r\n")).await?;
        self.send_response(&format!("{} OK STATUS completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_append(&mut self, args: &str) -> Result<()> {
        // APPEND mailbox [flags] [date-time] message
        self.send_response(&format!("{} OK APPEND completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_close(&mut self) -> Result<()> {
        self.selected_mailbox = None;
        self.state = ImapState::Authenticated;
        self.send_response(&format!("{} OK CLOSE completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_expunge(&mut self) -> Result<()> {
        // Expunge deleted messages
        self.send_response(&format!("{} OK EXPUNGE completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_search(&mut self, args: &str) -> Result<()> {
        // SEARCH criteria
        self.send_response("* SEARCH 1 2 3\r\n").await?;
        self.send_response(&format!("{} OK SEARCH completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_fetch(&mut self, args: &str) -> Result<()> {
        // FETCH sequence data-items
        self.send_response(&format!("{} OK FETCH completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_store(&mut self, args: &str) -> Result<()> {
        // STORE sequence data-items
        self.send_response(&format!("{} OK STORE completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_copy(&mut self, args: &str) -> Result<()> {
        // COPY sequence mailbox
        self.send_response(&format!("{} OK COPY completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_uid(&mut self, args: &str) -> Result<()> {
        // UID command
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        if parts.len() < 2 {
            self.send_response(&format!("{} BAD UID requires subcommand\r\n", self.tag())).await?;
            return Ok(());
        }
        
        // Delegate to subcommand
        self.send_response(&format!("{} OK UID completed\r\n", self.tag())).await?;
        Ok(())
    }
    
    async fn handle_idle(&mut self) -> Result<()> {
        self.send_response("+ idling\r\n").await?;
        // Would wait for DONE command
        Ok(())
    }
}