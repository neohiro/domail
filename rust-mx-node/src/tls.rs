//! TLS configuration shared by the SMTP, IMAP and Submission listeners.
//!
//! rustls 0.23 works with DER encoded certificates and keys
//! ([`CertificateDer`] / [`PrivateKeyDer`]); PEM decoding is done by
//! `rustls-pemfile`. Keeping that in one place means every listener uses
//! exactly the same certificate material.

use crate::error::{MxNodeError, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Decode a PEM certificate chain into DER certificates.
pub fn parse_certificates(cert_pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| MxNodeError::Tls(format!("invalid certificate chain: {e}")))?;

    if certs.is_empty() {
        return Err(MxNodeError::Tls(
            "no certificate found in PEM material".to_string(),
        ));
    }
    Ok(certs)
}

/// Decode the first private key found in a PEM document.
pub fn parse_private_key(key_pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| MxNodeError::Tls(format!("invalid private key: {e}")))?;

    key.ok_or_else(|| MxNodeError::Tls("no private key found in PEM material".to_string()))
}

/// Build a rustls server configuration from PEM material.
///
/// The default process crypto provider is used, which is `ring` because that
/// is the only provider this crate enables.
pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>> {
    let certs = parse_certificates(cert_pem)?;
    let key = parse_private_key(key_pem)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| MxNodeError::Tls(e.to_string()))?;

    Ok(Arc::new(config))
}

/// Build a TLS acceptor from PEM material.
pub fn acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    Ok(TlsAcceptor::from(server_config(cert_pem, key_pem)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed() -> (String, String) {
        let certified = rcgen::generate_simple_self_signed(vec!["mx.test".to_string()]).unwrap();
        (certified.cert.pem(), certified.key_pair.serialize_pem())
    }

    #[test]
    fn builds_server_config_from_pem() {
        let (cert, key) = self_signed();
        let config = server_config(&cert, &key).expect("server config");
        // The configuration is usable: rustls accepted the chain and the key.
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn rejects_pem_without_certificate() {
        let (_, key) = self_signed();
        assert!(server_config("", &key).is_err());
    }

    #[test]
    fn rejects_pem_without_private_key() {
        let (cert, _) = self_signed();
        assert!(server_config(&cert, "").is_err());
    }
}
