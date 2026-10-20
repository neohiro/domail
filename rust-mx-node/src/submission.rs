//! Submission server (RFC 6409).
//!
//! Submission is the entry point for mail clients: port 587 negotiates
//! STARTTLS, port 465 is protected by implicit TLS. It speaks the same
//! protocol as the incoming SMTP server, but a session must authenticate
//! before it may send mail and relaying is allowed afterwards.

use crate::error::*;
use crate::smtp::{handle_plain_connection, handle_tls_connection, SmtpContext, SmtpMode};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// Submission server.
#[derive(Clone)]
pub struct SubmissionServer {
    context: Arc<SmtpContext>,
    plain: Arc<tokio::sync::Mutex<Option<TcpListener>>>,
    implicit: Arc<tokio::sync::Mutex<Option<TcpListener>>>,
    stop_signal: watch::Sender<bool>,
}

impl SubmissionServer {
    /// Build a submission server. The context is switched into submission
    /// mode, which turns authentication into a requirement.
    pub fn new(mut context: SmtpContext) -> Self {
        context.mode = SmtpMode::Submission;
        let (stop_signal, _rx) = watch::channel(false);
        Self {
            context: Arc::new(context),
            plain: Arc::new(tokio::sync::Mutex::new(None)),
            implicit: Arc::new(tokio::sync::Mutex::new(None)),
            stop_signal,
        }
    }

    /// Bind the configured addresses.
    ///
    /// The implicit TLS listener is optional: on many systems port 465 needs
    /// elevated privileges, and the node must still start on port 587.
    pub async fn start(&self) -> Result<SocketAddr> {
        let plain = TcpListener::bind(self.context.config.bind_addr).await?;
        let address = plain.local_addr()?;
        info!(address = %address, "submission listener started");
        *self.plain.lock().await = Some(plain);

        let implicit = TcpListener::bind(self.context.config.implicit_tls_bind).await;
        match implicit {
            Ok(listener) => {
                let address = listener.local_addr()?;
                info!(address = %address, "submission (implicit TLS) listener started");
                *self.implicit.lock().await = Some(listener);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "the implicit TLS submission port could not be bound, continuing without it"
                );
            }
        }

        Ok(address)
    }

    /// Run the accept loops until the server is stopped.
    pub async fn serve(self) -> Result<()> {
        let plain = match self.plain.lock().await.take() {
            Some(listener) => listener,
            None => {
                return Err(MxNodeError::InvalidState(
                    "the server was not started".into(),
                ))
            }
        };
        let implicit = self.implicit.lock().await.take();

        let mut stop = self.stop_signal.subscribe();
        let mut implicit_stop = stop.clone();

        let plain_task = {
            let context = Arc::clone(&self.context);
            async move {
                loop {
                    tokio::select! {
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow() {
                                break;
                            }
                        }
                        accepted = plain.accept() => {
                            let (stream, peer) = match accepted {
                                Ok(pair) => pair,
                                Err(e) => {
                                    warn!(error = %e, "failed to accept a submission connection");
                                    continue;
                                }
                            };
                            let context = Arc::clone(&context);
                            tokio::spawn(async move {
                                let _ = handle_plain_connection(context, stream, peer).await;
                            });
                        }
                    }
                }
            }
        };

        let context = Arc::clone(&self.context);
        let implicit_task = async move {
            let Some(listener) = implicit else {
                return;
            };
            loop {
                tokio::select! {
                    changed = implicit_stop.changed() => {
                        if changed.is_err() || *implicit_stop.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let (stream, peer) = match accepted {
                            Ok(pair) => pair,
                            Err(e) => {
                                warn!(error = %e, "failed to accept a submission connection");
                                continue;
                            }
                        };
                        let context = Arc::clone(&context);
                        let acceptor = match context.tls_acceptor.clone() {
                            Some(acceptor) => acceptor,
                            None => {
                                warn!("no TLS certificate configured, dropping the connection");
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            let _ = handle_tls_connection(context, stream, peer, acceptor).await;
                        });
                    }
                }
            }
        };

        tokio::join!(plain_task, implicit_task);
        info!("submission listeners stopped");
        Ok(())
    }

    /// Ask the accept loops to stop.
    pub fn stop(&self) {
        let _ = self.stop_signal.send(true);
    }
}
