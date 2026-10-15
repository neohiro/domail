//! Error types for the MX Node

use thiserror::Error;

/// Main error type for the MX Node
#[derive(Error, Debug)]
pub enum MxNodeError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    
    #[error("SMTP error: {0}")]
    Smtp(#[from] SmtpError),
    
    #[error("IMAP error: {0}")]
    Imap(#[from] ImapError),
    
    #[error("Submission error: {0}")]
    Submission(#[from] SubmissionError),
    
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("TLS error: {0}")]
    Tls(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Rate limited")]
    RateLimited,
    
    #[error("Message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },
    
    #[error("Not running")]
    NotRunning,
    
    #[error("Already running")]
    AlreadyRunning,
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
    
    #[error("WASM error: {0}")]
    Wasm(String),
}

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid hostname")]
    InvalidHostname,
    
    #[error("Missing certificate or key")]
    MissingCertKey,
    
    #[error("Invalid certificate format")]
    InvalidCertFormat,
    
    #[error("Invalid private key format")]
    InvalidKeyFormat,
    
    #[error("Invalid transport configuration: {0}")]
    InvalidTransport(String),
    
    #[error("Port already in use: {0}")]
    PortInUse(u16),
}

/// Crypto errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGen(String),
    
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Signing failed: {0}")]
    Signing(String),
    
    #[error("Verification failed: {0}")]
    Verification(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("Algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),
}

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Quota exceeded")]
    QuotaExceeded,
    
    #[error("Corruption detected: {0}")]
    Corruption(String),
}

/// SMTP errors
#[derive(Error, Debug)]
pub enum SmtpError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("HELO/EHLO failed: {0}")]
    HeloFailed(String),
    
    #[error("STARTTLS failed: {0}")]
    StartTlsFailed(String),
    
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("MAIL FROM failed: {0}")]
    MailFromFailed(String),
    
    #[error("RCPT TO failed: {0}")]
    RcptToFailed(String),
    
    #[error("DATA failed: {0}")]
    DataFailed(String),
    
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
    
    #[error("Timeout")]
    Timeout,
    
    #[error("TLS required")]
    TlsRequired,
    
    #[error("Authentication required")]
    AuthRequired,
}

/// IMAP errors
#[derive(Error, Debug)]
pub enum ImapError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Mailbox not found: {0}")]
    MailboxNotFound(String),
    
    #[error("Message not found: {0}")]
    MessageNotFound(String),
    
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Timeout")]
    Timeout,
}

/// Submission errors
#[derive(Error, Debug)]
pub enum SubmissionError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    
    #[error("Recipient rejected: {0}")]
    RecipientRejected(String),
    
    #[error("Sender rejected: {0}")]
    SenderRejected(String),
    
    #[error("TLS required")]
    TlsRequired,
    
    #[error("Authentication required")]
    AuthRequired,
}

/// Transport errors
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Send failed: {0}")]
    SendFailed(String),
    
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    
    #[error("Not connected")]
    NotConnected,
    
    #[error("Unsupported transport: {0}")]
    UnsupportedTransport(String),
    
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, MxNodeError>;