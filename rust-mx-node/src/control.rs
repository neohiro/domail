//! Control API for the settings wizard.
//!
//! A page in the browser cannot install an operating system service, so the
//! wizard drives this HTTP API instead. The API listens on the loopback
//! interface, requires a bearer token and never answers CORS preflight
//! requests, so only a page that knows the token can talk to it.

use crate::config::MxNodeConfig;
use crate::crypto::constant_time_eq;
use crate::error::*;
use crate::http::{Handler, HttpRequest, HttpResponse};
use crate::transport::TransportManager;
use async_trait::async_trait;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

/// The state that the control API reports and changes.
pub struct ControlContext {
    /// The effective configuration of the node.
    pub config: Arc<MxNodeConfig>,
    /// The transport layer of the node.
    pub transports: Arc<TransportManager>,
    /// The token that authenticates a request.
    pub token: String,
}

impl ControlContext {
    /// The configuration as it may leave the node: the secrets are removed.
    fn public_config(&self) -> serde_json::Value {
        let config = &self.config;
        json!({
            "domain": config.domain,
            "hostname": config.hostname,
            "version": crate::VERSION,
            "smtp": {
                "bind_addr": config.smtp.bind_addr.to_string(),
                "implicit_tls_bind": config.smtp.implicit_tls_bind.to_string(),
                "require_starttls": config.smtp.require_starttls,
                "auth_over_tls_only": config.smtp.auth_over_tls_only,
                "max_message_size": config.smtp.max_message_size,
            },
            "imap": {
                "bind_addr": config.imap.bind_addr.to_string(),
                "implicit_tls_bind": config.imap.implicit_tls_bind.to_string(),
                "require_tls": config.imap.require_tls,
            },
            "submission": {
                "bind_addr": config.submission.bind_addr.to_string(),
                "implicit_tls_bind": config.submission.implicit_tls_bind.to_string(),
                "require_auth": config.submission.require_auth,
            },
            "control": {
                "enabled": config.control.enabled,
                "bind_addr": config.control.bind_addr.to_string(),
            },
            "service": {
                "name": config.service.name,
                "display_name": config.service.display_name,
                "autostart": config.service.autostart,
            },
            "users": config
                .users
                .iter()
                .map(|user| json!({
                    "username": user.username,
                    "mailbox": user.mailbox,
                }))
                .collect::<Vec<_>>(),
            "transports": config
                .transports
                .iter()
                .map(|transport| json!({
                    "id": transport.id,
                    "enabled": transport.enabled,
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// The control API server.
#[derive(Clone)]
pub struct ControlServer {
    context: Arc<ControlContext>,
    listener: Arc<tokio::sync::Mutex<Option<TcpListener>>>,
    stop_signal: watch::Sender<bool>,
}

impl ControlServer {
    /// Build a control server for the given context.
    pub fn new(context: ControlContext) -> Self {
        let (stop_signal, _rx) = watch::channel(false);
        Self {
            context: Arc::new(context),
            listener: Arc::new(tokio::sync::Mutex::new(None)),
            stop_signal,
        }
    }

    /// Bind the configured address and start accepting requests.
    pub async fn start(&self) -> Result<SocketAddr> {
        let listener = TcpListener::bind(self.context.config.control.bind_addr).await?;
        let local = listener.local_addr()?;
        info!(address = %local, "the control API is listening");
        *self.listener.lock().await = Some(listener);
        Ok(local)
    }

    /// Run the accept loop until the server is stopped.
    pub async fn serve(self) -> Result<()> {
        let listener = match self.listener.lock().await.take() {
            Some(listener) => listener,
            None => return Err(MxNodeError::InvalidState("the server was not started".into())),
        };

        let handler: Arc<dyn Handler> = Arc::new(ControlHandler {
            context: Arc::clone(&self.context),
        });
        let mut stop = self.stop_signal.subscribe();

        crate::http::serve(listener, handler, stop.clone()).await?;
        info!("the control API stopped");
        Ok(())
    }

    /// Ask the server to stop.
    pub fn stop(&self) {
        let _ = self.stop_signal.send(true);
    }

    /// Address the server is bound to, if it is running.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.listener
            .lock()
            .await
            .as_ref()
            .map(|listener| listener.local_addr().ok())
            .flatten()
    }
}

/// The request handler of the control API.
struct ControlHandler {
    context: Arc<ControlContext>,
}

#[async_trait]
impl Handler for ControlHandler {
    async fn handle(&self, request: HttpRequest, peer: SocketAddr) -> HttpResponse {
        // Only a program on this machine may talk to the control API.
        if !peer.ip().is_loopback() {
            return HttpResponse::json(
                403,
                json!({"error": "the control API only accepts clients from this machine"})
                    .to_string(),
            );
        }

        // The wizard proves that it may talk to the node with the token.
        let expected = format!("Bearer {}", self.context.token);
        let given = request.header("authorization").unwrap_or_default();
        if !constant_time_eq(given.as_bytes(), expected.as_bytes()) {
            return HttpResponse::json(
                401,
                json!({"error": "a valid bearer token is required"}).to_string(),
            );
        }

        // A page from another origin must not learn that the API exists.
        if request.method == "OPTIONS" {
            return HttpResponse::text(405, "the control API does not allow cross origin calls");
        }

        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/v1/health") => HttpResponse::json(
                200,
                json!({"status": "ok", "version": crate::VERSION}).to_string(),
            ),
            ("GET", "/api/v1/status") => {
                let transports = self.context.transports.statuses().await;
                HttpResponse::json(
                    200,
                    json!({
                        "domain": self.context.config.domain,
                        "hostname": self.context.config.hostname,
                        "version": crate::VERSION,
                        "transport_count": transports.len(),
                        "connected_transports": transports
                            .iter()
                            .filter(|transport| transport.connected)
                            .count(),
                    })
                    .to_string(),
                )
            }
            ("GET", "/api/v1/transports") => {
                let transports = self.context.transports.statuses().await;
                let items: Vec<serde_json::Value> = transports
                    .iter()
                    .map(|transport| {
                        json!({
                            "id": transport.id,
                            "name": transport.name,
                            "connected": transport.connected,
                            "endpoint": transport.endpoint,
                            "last_error": transport.last_error,
                        })
                    })
                    .collect();
                HttpResponse::json(200, json!({"transports": items}).to_string())
            }
            ("GET", "/api/v1/config") => {
                HttpResponse::json(200, self.context.public_config().to_string())
            }
            ("GET", "/api/v1/service") => {
                let status = crate::service::status(&self.context.config.service);
                match status {
                    Ok(status) => HttpResponse::json(200, json!({
                        "installed": status.installed,
                        "running": status.running,
                        "kind": status.kind,
                    }).to_string()),
                    Err(e) => HttpResponse::json(500, json!({"error": e.to_string()}).to_string()),
                }
            }
            ("POST", path) if path.starts_with("/api/v1/transports/") => {
                self.handle_transport(path).await
            }
            ("POST", "/api/v1/service/start") => {
                match crate::service::start(&self.context.config.service) {
                    Ok(()) => HttpResponse::json(200, json!({"ok": true}).to_string()),
                    Err(e) => {
                        warn!(error = %e, "the service could not be started");
                        HttpResponse::json(500, json!({"error": e.to_string()}).to_string())
                    }
                }
            }
            ("POST", "/api/v1/service/stop") => {
                match crate::service::stop(&self.context.config.service) {
                    Ok(()) => HttpResponse::json(200, json!({"ok": true}).to_string()),
                    Err(e) => {
                        warn!(error = %e, "the service could not be stopped");
                        HttpResponse::json(500, json!({"error": e.to_string()}).to_string())
                    }
                }
            }
            ("GET", _) | ("POST", _) => HttpResponse::json(
                404,
                json!({"error": "unknown endpoint"}).to_string(),
            ),
            _ => HttpResponse::json(
                405,
                json!({"error": "the method is not allowed"}).to_string(),
            ),
        }
    }
}

impl ControlHandler {
    /// Activate or deactivate a single transport.
    async fn handle_transport(&self, path: &str) -> HttpResponse {
        let rest = path.trim_start_matches("/api/v1/transports/");
        let Some((id, action)) = rest.rsplit_once('/') else {
            return HttpResponse::json(404, json!({"error": "unknown endpoint"}).to_string());
        };

        let id = id.to_string();
        let result = match action {
            "activate" => self.context.transports.activate(&id).await,
            "deactivate" => self.context.transports.deactivate(&id).await,
            _ => {
                return HttpResponse::json(404, json!({"error": "unknown endpoint"}).to_string())
            }
        };

        match result {
            Ok(()) => HttpResponse::json(200, json!({"ok": true, "id": id}).to_string()),
            Err(e) => {
                warn!(transport = %id, error = %e, "the transport could not be switched");
                HttpResponse::json(500, json!({"error": e.to_string()}).to_string())
            }
        }
    }
}
