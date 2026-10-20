//! Authentication for the mail services.
//!
//! Passwords are stored as Argon2id PHC strings. The parameters recorded in
//! the PHC string are the ones used for verification, so the stored cost
//! parameters can be raised later without invalidating existing accounts.

use crate::config::{MxNodeConfig, UserConfig};
use crate::error::*;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params};
use rand::rngs::OsRng;

/// Result of a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    /// Login name as configured.
    pub username: String,
    /// Mailbox that receives mail for this user.
    pub mailbox: String,
}

/// Hash a plaintext password with Argon2id.
///
/// The returned string is a PHC string that embeds the random salt and the
/// cost parameters, so it can be stored verbatim in the configuration file.
pub fn hash_password(password: &str, params: &crate::crypto::Argon2Params) -> Result<String> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(params.memory_kb, params.time, params.parallelism, Some(32))
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?,
    );

    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC string.
pub fn verify_password_hash(password: &str, phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Credential store built from the configuration.
#[derive(Debug, Clone, Default)]
pub struct CredentialStore {
    users: Vec<UserConfig>,
}

impl CredentialStore {
    /// Build a store from the configured users.
    pub fn from_config(config: &MxNodeConfig) -> Self {
        Self {
            users: config.users.clone(),
        }
    }

    /// True when at least one account is configured.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Number of configured accounts.
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Verify a login name and password.
    pub fn authenticate(&self, username: &str, password: &str) -> Option<AuthenticatedUser> {
        let user = self
            .users
            .iter()
            .find(|u| u.username.eq_ignore_ascii_case(username))?;

        if !verify_password_hash(password, &user.password_hash) {
            return None;
        }

        Some(AuthenticatedUser {
            username: user.username.clone(),
            mailbox: user.mailbox.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2Params;

    fn cheap_params() -> Argon2Params {
        Argon2Params {
            memory_kb: 8 * 1024,
            time: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn password_round_trip() {
        let phc = hash_password("correct horse", &cheap_params()).unwrap();
        assert!(verify_password_hash("correct horse", &phc));
        assert!(!verify_password_hash("wrong horse", &phc));
    }

    #[test]
    fn rejects_malformed_phc_string() {
        assert!(!verify_password_hash("anything", "not-a-phc-string"));
    }

    #[test]
    fn store_authenticates_known_user() {
        let phc = hash_password("s3cret", &cheap_params()).unwrap();
        let mut config = MxNodeConfig::default();
        config.users.push(UserConfig {
            username: "alice".into(),
            password_hash: phc,
            mailbox: "INBOX".into(),
        });
        let store = CredentialStore::from_config(&config);

        let user = store
            .authenticate("alice", "s3cret")
            .expect("authenticated");
        assert_eq!(user.username, "alice");
        assert!(store.authenticate("alice", "nope").is_none());
        assert!(store.authenticate("bob", "s3cret").is_none());
    }
}
