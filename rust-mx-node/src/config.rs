//! Configuration for the MX Node.
//!
//! The node is configured by a single JSON document. It is read from a
//! platform-specific configuration directory (see [`config_dir`]) and can be
//! overridden with the `--config` command line flag.

use crate::error::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Main configuration for the MX Node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxNodeConfig {
    /// Mail domain handled by this node, e.g. `mail.example.org`.
    ///
    /// Recipients outside this domain are refused, which keeps the node from
    /// turning into an open relay.
    #[serde(default = "default_domain")]
    pub domain: String,

    /// Hostname this MX node identifies as, e.g. `mx.example.org`.
    pub hostname: String,

    /// TLS certificate in PEM format
    #[serde(default)]
    pub cert_pem: String,

    /// TLS private key in PEM format
    #[serde(default)]
    pub key_pem: String,

    /// Local identity for this node
    #[serde(default)]
    pub identity: Option<NodeIdentity>,

    /// Enabled transports
    #[serde(default = "default_transports")]
    pub transports: Vec<TransportConfig>,

    /// Users allowed to authenticate against SMTP/IMAP/Submission
    #[serde(default)]
    pub users: Vec<UserConfig>,

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

    /// Local control API settings
    #[serde(default)]
    pub control: ControlConfig,

    /// OS service settings
    #[serde(default)]
    pub service: ServiceConfig,
}

fn default_domain() -> String {
    "localhost".to_string()
}

fn default_transports() -> Vec<TransportConfig> {
    vec![TransportConfig {
        id: "direct".to_string(),
        enabled: true,
        options: HashMap::new(),
    }]
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

/// A user account allowed to authenticate against the mail services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// Login name
    pub username: String,
    /// Argon2id PHC string produced by `mx-node hash-password`
    pub password_hash: String,
    /// Mailbox that receives messages addressed to this user
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
}

fn default_mailbox() -> String {
    "INBOX".to_string()
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

    /// Rate limiting: max commands per minute per IP
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,

    /// Session timeout (seconds)
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,

    /// Enable MTA-STS
    #[serde(default)]
    pub mta_sts: bool,

    /// Enable DANE/TLSA
    #[serde(default)]
    pub dane: bool,

    /// Bind address of the implicit TLS listener (port 465).

    /// Only the submission server binds it; the plain SMTP listener ignores
    /// the address.
    #[serde(default = "default_smtp_implicit_tls_bind")]
    pub implicit_tls_bind: SocketAddr,
}

fn default_smtp_bind() -> SocketAddr {
    "0.0.0.0:25".parse().unwrap()
}

fn default_smtp_implicit_tls_bind() -> SocketAddr {
    "0.0.0.0:465".parse().unwrap()
}
fn default_true() -> bool {
    true
}
fn default_max_msg_size() -> usize {
    50 * 1024 * 1024
}
fn default_rate_limit() -> u32 {
    100
}
fn default_session_timeout() -> u64 {
    300
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_smtp_bind(),
            require_starttls: true,
            auth_over_tls_only: true,
            max_message_size: default_max_msg_size(),
            rate_limit_per_minute: default_rate_limit(),
            session_timeout_secs: default_session_timeout(),
            mta_sts: true,
            dane: true,
            implicit_tls_bind: default_smtp_implicit_tls_bind(),
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

    /// Bind address of the implicit TLS listener (port 993)
    #[serde(default = "default_imap_implicit_tls_bind")]
    pub implicit_tls_bind: SocketAddr,
}

fn default_imap_bind() -> SocketAddr {
    "0.0.0.0:143".parse().unwrap()
}

fn default_imap_implicit_tls_bind() -> SocketAddr {
    "0.0.0.0:993".parse().unwrap()
}
fn default_idle_timeout() -> u64 {
    30 * 60
}
fn default_max_connections() -> u32 {
    20
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_imap_bind(),
            require_tls: true,
            idle_timeout: default_idle_timeout(),
            max_connections_per_ip: default_max_connections(),
            implicit_tls_bind: default_imap_implicit_tls_bind(),
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

fn default_argon2_mem() -> u32 {
    64 * 1024
}
fn default_argon2_time() -> u32 {
    3
}
fn default_argon2_parallel() -> u32 {
    4
}
fn default_key_rotation() -> u64 {
    24
}

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
    /// Directory that holds the mailbox files.
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

fn default_db_path() -> String {
    "mailboxes".to_string()
}
fn default_db_size() -> u64 {
    1024 * 1024 * 1024
}
fn default_backup_interval() -> u64 {
    24
}

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

/// Local control API configuration.
///
/// The control API is the channel the browser wizard uses to install and
/// drive the native node. It is deliberately bound to loopback and requires a
/// bearer token, because anything else would let any web page on the machine
/// reconfigure the mail server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Whether the control API is started at all
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Loopback address the control API listens on
    #[serde(default = "default_control_bind")]
    pub bind_addr: SocketAddr,

    /// Bearer token required by every control request
    #[serde(default)]
    pub token: String,
}

fn default_control_bind() -> SocketAddr {
    "127.0.0.1:8787".parse().unwrap()
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: default_control_bind(),
            token: String::new(),
        }
    }
}

/// OS service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Platform service name (no spaces, unique per machine)
    #[serde(default = "default_service_name")]
    pub name: String,

    /// Human readable service name
    #[serde(default = "default_service_display_name")]
    pub display_name: String,

    /// Service description shown by the OS service manager
    #[serde(default = "default_service_description")]
    pub description: String,

    /// Install into the per-user service scope instead of the machine scope
    #[serde(default)]
    pub user_scope: bool,

    /// Start the service automatically at boot / login
    #[serde(default = "default_true")]
    pub autostart: bool,
}

fn default_service_name() -> String {
    "domail-mx-node".to_string()
}
fn default_service_display_name() -> String {
    "DOM Mail MX Node".to_string()
}
fn default_service_description() -> String {
    "DOM Mail decentralized mail server (SMTP/IMAP/Submission) with 13 transport vectors"
        .to_string()
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: default_service_name(),
            display_name: default_service_display_name(),
            description: default_service_description(),
            user_scope: false,
            autostart: true,
        }
    }
}

impl Default for MxNodeConfig {
    fn default() -> Self {
        Self {
            domain: default_domain(),
            hostname: "localhost".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            identity: None,
            transports: default_transports(),
            users: Vec::new(),
            smtp: SmtpConfig::default(),
            imap: ImapConfig::default(),
            submission: SubmissionConfig::default(),
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
            control: ControlConfig::default(),
            service: ServiceConfig::default(),
        }
    }
}

impl MxNodeConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.hostname.is_empty() {
            return Err(ConfigError::InvalidHostname);
        }

        if self.domain.is_empty() || !self.domain.contains('.') && self.domain != "localhost" {
            return Err(ConfigError::InvalidDomain(self.domain.clone()));
        }

        if self.cert_pem.is_empty() || self.key_pem.is_empty() {
            return Err(ConfigError::MissingCertKey);
        }

        if !self.cert_pem.contains("-----BEGIN CERTIFICATE-----")
            || !self.cert_pem.contains("-----END CERTIFICATE-----")
        {
            return Err(ConfigError::InvalidCertFormat);
        }

        if !(self.key_pem.contains("-----BEGIN PRIVATE KEY-----")
            || self.key_pem.contains("-----BEGIN RSA PRIVATE KEY-----")
            || self.key_pem.contains("-----BEGIN EC PRIVATE KEY-----"))
            || !(self.key_pem.contains("-----END PRIVATE KEY-----")
                || self.key_pem.contains("-----END RSA PRIVATE KEY-----")
                || self.key_pem.contains("-----END EC PRIVATE KEY-----"))
        {
            return Err(ConfigError::InvalidKeyFormat);
        }

        if self.control.enabled && self.control.token.is_empty() {
            return Err(ConfigError::InvalidTransport(
                "control.token must be set when the control API is enabled".to_string(),
            ));
        }

        Ok(())
    }

    /// Load a configuration document from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ConfigError::NotFound(path.display().to_string()),
            _ => ConfigError::Parse(e.to_string()),
        })?;
        let config: MxNodeConfig =
            serde_json::from_str(&raw).map_err(|e| ConfigError::Parse(e.to_string()))?;
        Ok(config)
    }

    /// Persist the configuration as pretty-printed JSON.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ConfigError::Write(e.to_string()))?;
        }
        let json =
            serde_json::to_string_pretty(self).map_err(|e| ConfigError::Write(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| ConfigError::Write(e.to_string()))?;
        Ok(())
    }

    /// Look up a user account by login name.
    pub fn user(&self, username: &str) -> Option<&UserConfig> {
        self.users
            .iter()
            .find(|u| u.username.eq_ignore_ascii_case(username))
    }

    /// True when the address belongs to the domain served by this node.
    pub fn is_local_domain(&self, domain: &str) -> bool {
        domain.eq_ignore_ascii_case(&self.domain)
    }
}

/// Platform configuration directory for the MX node.
pub fn config_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("DOMAIL_MX_CONFIG_DIR") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    if cfg!(windows) {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("domail-mx-node");
        }
    }
    if cfg!(target_os = "macos") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("domail-mx-node");
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("domail-mx-node");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("domail-mx-node");
    }
    std::env::temp_dir().join("domail-mx-node")
}

/// Default path of the configuration document.
pub fn default_config_path() -> PathBuf {
    config_dir().join("config.json")
}

/// Platform data directory for mailboxes.
pub fn data_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("DOMAIL_MX_DATA_DIR") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    if cfg!(windows) {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("domail-mx-node");
        }
    }
    if cfg!(target_os = "macos") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("domail-mx-node");
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("domail-mx-node");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("domail-mx-node");
    }
    std::env::temp_dir().join("domail-mx-node")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_config_without_certificate() {
        let config = MxNodeConfig::default();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MissingCertKey)
        ));
    }

    #[test]
    fn rejects_control_api_without_token() {
        let mut config = MxNodeConfig {
            cert_pem: "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----".into(),
            ..Default::default()
        };
        config.control.token = String::new();
        assert!(config.validate().is_err());
        config.control.token = "secret".into();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn local_domain_matching_is_case_insensitive() {
        let config = MxNodeConfig {
            domain: "Example.ORG".into(),
            ..Default::default()
        };
        assert!(config.is_local_domain("example.org"));
        assert!(!config.is_local_domain("example.com"));
    }
}
