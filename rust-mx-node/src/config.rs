//! Configuration for the MX Node

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use crate::error::*;

/// Main configuration for the MX Node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxNodeConfig {
    /// Hostname this MX node identifies as
    pub hostname: String,
    
    /// TLS certificate in PEM format
    pub cert_pem: String,
    
    /// TLS private key in PEM format
    pub key_pem: String,
    
    /// Local identity for this node
    pub identity: Option<NodeIdentity>,
    
    /// Enabled transports
    #[serde(default = "default_transports")]
    pub transports: Vec<TransportConfig>,
    
    /// SMTP server configuration
    #[serde(default)]
    pub smtp: SmtpConfig,
    
    /// IMAP server configuration
    #[serde(default)]
    pub imap: ImapConfig,
    
    /// Submission server configuration
    #[serde(default)]
    pub submission: SubmissionConfig,
    
    /// Security settings
    #[serde(default)]
    pub security: SecurityConfig,
    
    /// Storage settings
    #[serde(default)]
    pub storage: StorageConfig,
}

fn default_transports() -> Vec<TransportConfig> {
    vec![
        TransportConfig {
            id: "direct".to_string(),
            enabled: true,
            options: HashMap::new(),
        }
    ]
}

/// Node identity for cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Email address
    pub address: String,
    
    /// Ed25519 public key (base64)
    pub ed25519_pub: String,
    
    /// X25519 public key (base64)
    pub x25519_pub: String,
    
    /// Ed25519 private key (base64, encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_priv: Option<String>,
    
    /// X25519 private key (base64, encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_priv: Option<String>,
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub id: String,
    pub enabled: bool,
    #[serde(default)]
    pub options: HashMap<String, String>,
}

/// SMTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// Bind address for SMTP (port 25)
    #[serde(default = "default_smtp_bind")]
    pub bind_addr: SocketAddr,
    
    /// Require STARTTLS
    #[serde(default = "default_true")]
    pub require_starttls: bool,
    
    /// Allow plain auth over TLS only
    #[serde(default = "default_true")]
    pub auth_over_tls_only: bool,
    
    /// Maximum message size (bytes)
    #[serde(default = "default_max_msg_size")]
    pub max_message_size: usize,
    
    /// Rate limiting: max messages per minute per IP
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
    
    /// Enable MTA-STS
    #[serde(default)]
    pub mta_sts: bool,
    
    /// Enable DANE/TLSA
    #[serde(default)]
    pub dane: bool,
}

fn default_smtp_bind() -> SocketAddr {
    "0.0.0.0:25".parse().unwrap()
}
fn default_true() -> bool { true }
fn default_max_msg_size() -> usize { 50 * 1024 * 1024 } // 50MB
fn default_rate_limit() -> u32 { 100 }

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_smtp_bind(),
            require_starttls: true,
            auth_over_tls_only: true,
            max_message_size: default_max_msg_size(),
            rate_limit_per_minute: default_rate_limit(),
            mta_sts: true,
            dane: true,
        }
    }
}

/// IMAP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    /// Bind address for IMAP (port 143/993)
    #[serde(default = "default_imap_bind")]
    pub bind_addr: SocketAddr,
    
    /// Require TLS
    #[serde(default = "default_true")]
    pub require_tls: bool,
    
    /// Idle timeout (seconds)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    
    /// Max connections per IP
    #[serde(default = "default_max_connections")]
    pub max_connections_per_ip: u32,
}

fn default_imap_bind() -> SocketAddr {
    "0.0.0.0:143".parse().unwrap()
}
fn default_idle_timeout() -> u64 { 30 * 60 } // 30 minutes
fn default_max_connections() -> u32 { 20 }

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_imap_bind(),
            require_tls: true,
            idle_timeout: default_idle_timeout(),
            max_connections_per_ip: default_max_connections(),
        }
    }
}

/// Submission server configuration (port 587/465)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionConfig {
    /// Bind address for Submission (port 587)
    #[serde(default = "default_submission_bind")]
    pub bind_addr: SocketAddr,
    
    /// Implicit TLS port (465)
    #[serde(default = "default_implicit_tls_bind")]
    pub implicit_tls_bind: SocketAddr,
    
    /// Require authentication
    #[serde(default = "default_true")]
    pub require_auth: bool,
    
    /// Require STARTTLS on port 587
    #[serde(default = "default_true")]
    pub require_starttls: bool,
}

fn default_submission_bind() -> SocketAddr {
    "0.0.0.0:587".parse().unwrap()
}
fn default_implicit_tls_bind() -> SocketAddr {
    "0.0.0.0:465".parse().unwrap()
}

impl Default for SubmissionConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_submission_bind(),
            implicit_tls_bind: default_implicit_tls_bind(),
            require_auth: true,
            require_starttls: true,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Argon2id memory cost (KB)
    #[serde(default = "default_argon2_mem")]
    pub argon2_memory_kb: u32,
    
    /// Argon2id time cost (iterations)
    #[serde(default = "default_argon2_time")]
    pub argon2_time: u32,
    
    /// Argon2id parallelism
    #[serde(default = "default_argon2_parallel")]
    pub argon2_parallelism: u32,
    
    /// Session key rotation interval (hours)
    #[serde(default = "default_key_rotation")]
    pub key_rotation_hours: u64,
    
    /// Enable constant-time operations
    #[serde(default = "default_true")]
    pub constant_time: bool,
}

fn default_argon2_mem() -> u32 { 64 * 1024 } // 64MB
fn default_argon2_time() -> u32 { 3 }
fn default_argon2_parallel() -> u32 { 4 }
fn default_key_rotation() -> u64 { 24 }

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            argon2_memory_kb: default_argon2_mem(),
            argon2_time: default_argon2_time(),
            argon2_parallelism: default_argon2_parallel(),
            key_rotation_hours: default_key_rotation(),
            constant_time: true,
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Database path (relative to origin)
    #[serde(default = "default_db_path")]
    pub db_path: String,
    
    /// Maximum database size (bytes)
    #[serde(default = "default_db_size")]
    pub max_size: u64,
    
    /// Enable compression
    #[serde(default = "default_true")]
    pub compression: bool,
    
    /// Backup interval (hours)
    #[serde(default = "default_backup_interval")]
    pub backup_interval_hours: u64,
}

fn default_db_path() -> String { "mx-node.db".to_string() }
fn default_db_size() -> u64 { 1024 * 1024 * 1024 } // 1GB
fn default_backup_interval() -> u64 { 24 }

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            max_size: default_db_size(),
            compression: true,
            backup_interval_hours: default_backup_interval(),
        }
    }
}

impl Default for MxNodeConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            identity: None,
            transports: default_transports(),
            smtp: SmtpConfig::default(),
            imap: ImapConfig::default(),
            submission: SubmissionConfig::default(),
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

impl MxNodeConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.hostname.is_empty() {
            return Err(ConfigError::InvalidHostname);
        }
        
        if self.cert_pem.is_empty() || self.key_pem.is_empty() {
            return Err(ConfigError::MissingCertKey);
        }
        
        // Validate PEM format
        if !self.cert_pem.contains("-----BEGIN CERTIFICATE-----") 
            || !self.cert_pem.contains("-----END CERTIFICATE-----") {
            return Err(ConfigError::InvalidCertFormat);
        }
        
        if !(self.key_pem.contains("-----BEGIN PRIVATE KEY-----") 
            || self.key_pem.contains("-----BEGIN RSA PRIVATE KEY-----"))
            || !(self.key_pem.contains("-----END PRIVATE KEY-----") 
                || self.key_pem.contains("-----END RSA PRIVATE KEY-----")) {
            return Err(ConfigError::InvalidKeyFormat);
        }
        
        Ok(())
    }
}