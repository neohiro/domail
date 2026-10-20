//! Minimal HTTP/1.1 server.
//!
//! The control API needs a server that is small enough to audit: it parses
//! the request line and the headers, limits the size of the body and always
//! answers with a well formed response. The server is loopback only unless
//! the configuration says otherwise.

use crate::error::*;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, warn};

/// Maximum size of the request head.
const MAX_HEAD: usize = 16 * 1024;

/// Maximum size of a request body.
const MAX_BODY: usize = 1024 * 1024;

/// A parsed HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request method, upper case.
    pub method: String,
    /// Request path, without the query string.
    pub path: String,
    /// Request target, including the query string.
    pub target: String,
    /// Header names in lower case with their values.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Look up a header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A response that the server sends back.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Content type of the body.
    pub content_type: &'static str,
    /// Response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A JSON response.
    pub fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into_bytes(),
        }
    }

    /// A plain text response.
    pub fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }
}

/// A handler that answers requests.
#[async_trait]
pub trait Handler: Send + Sync {
    /// Answer a request.
    async fn handle(&self, request: HttpRequest, peer: SocketAddr) -> HttpResponse;
}

/// The reason phrase of a status code.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Serialize a response into the bytes that go on the wire.
fn encode(response: &HttpResponse) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(&response.body);
    out
}

/// Serve requests until the server is told to stop.
pub async fn serve(
    listener: TcpListener,
    handler: Arc<dyn Handler>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "failed to accept an HTTP connection");
                        continue;
                    }
                };
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, handler).await {
                        debug!(peer = %peer, error = %e, "the HTTP connection ended with an error");
                    }
                });
            }
        }
    }

    Ok(())
}

/// Read one request from a connection and answer it.
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<dyn Handler>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);

    let mut head = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).await?;
        if read == 0 {
            return Ok(());
        }
        head.extend_from_slice(&line);
        if head.len() > MAX_HEAD {
            let response = HttpResponse::text(413, "the request head is too large");
            reader.get_mut().write_all(&encode(&response)).await?;
            return Ok(());
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }

    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.lines();

    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_string();

    if method.is_empty() || target.is_empty() {
        let response = HttpResponse::text(400, "the request line is malformed");
        reader.get_mut().write_all(&encode(&response)).await?;
        return Ok(());
    }

    let mut headers = Vec::new();
    for header in lines {
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);

    if length > MAX_BODY {
        let response = HttpResponse::text(413, "the request body is too large");
        reader.get_mut().write_all(&encode(&response)).await?;
        return Ok(());
    }

    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body).await?;
    }

    let path = target.split('?').next().unwrap_or("/").to_string();
    let request = HttpRequest {
        method,
        path,
        target,
        headers,
        body,
    };

    let response = handler.handle(request, peer).await;
    reader.get_mut().write_all(&encode(&response)).await?;
    reader.get_mut().flush().await?;
    Ok(())
}
