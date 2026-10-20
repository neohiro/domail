//! SMTP server (RFC 5321) with STARTTLS (RFC 3207) and AUTH (RFC 4954).
//!
//! The server is the entry point of the MX node: it accepts mail from other
//! MTAs on port 25 and mail from authenticated clients on the submission
//! ports. Messages addressed to the local domain are stored in the mailbox of
//! the receiving user, everything else is handed to the transport layer.
//!
//! Two rules keep the node from becoming an open relay:
//!
//! * A connection that is not authenticated may only accept recipients in the
//!   local domain.
//! * A connection that is not protected by TLS may not send mail at all when
//!   `require_starttls` is enabled.

use crate::auth::{AuthenticatedUser, CredentialStore};
use crate::config::{SmtpConfig, UserConfig};
use crate::error::*;
use crate::storage::{Address as MailAddress, EncryptedStorage, MailboxStorage, StoredMessage};
use crate::transport::{Envelope, TransportManager};
use base64::Engine;
use mail_parser::MessageParser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Maximum length of a command line, including the terminating CRLF.
const MAX_COMMAND_LEN: usize = 1024;

/// Maximum length of an address.
const MAX_ADDRESS_LEN: usize = 320;

/// Which role the SMTP listener plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpMode {
    /// Port 25: mail from other MTAs. No authentication, relay only for the
    /// local domain.
    Incoming,
    /// Port 587: mail from a mail client. Authentication is required and
    /// relaying is allowed once the client authenticated.
    Submission,
}

impl SmtpMode {
    /// Whether the mode demands an authenticated session before mail is
    /// accepted.
    pub fn requires_auth(self) -> bool {
        matches!(self, SmtpMode::Submission)
    }
}

/// The connection a session runs on.
///
/// The stream is wrapped in a `BufReader` that is kept for the whole session:
/// a fresh reader per command would drop whatever the client pipelined
/// behind the current line.
enum SessionStream {
    /// Plaintext connection.
    Plain(Option<BufReader<TcpStream>>),
    /// Connection protected by TLS.
    Tls(Option<BufReader<TlsStream<TcpStream>>>),
}

impl SessionStream {
    /// Whether the session is protected by TLS.
    fn is_tls(&self) -> bool {
        matches!(self, SessionStream::Tls(_))
    }

    /// Read one line, without the terminating CRLF.
    async fn read_line(&mut self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        match self {
            SessionStream::Plain(reader) => match reader.as_mut() {
                Some(reader) => reader.read_until(b'\n', buffer).await,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed",
                )),
            },
            SessionStream::Tls(reader) => match reader.as_mut() {
                Some(reader) => reader.read_until(b'\n', buffer).await,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed",
                )),
            },
        }
    }

    /// Write raw bytes to the peer.
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            SessionStream::Plain(reader) => match reader.as_mut() {
                Some(reader) => reader.write_all(data).await,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed",
                )),
            },
            SessionStream::Tls(reader) => match reader.as_mut() {
                Some(reader) => reader.write_all(data).await,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed",
                )),
            },
        }
    }

    /// Write a single line to the peer.
    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let mut framed = String::with_capacity(line.len() + 2);
        framed.push_str(line);
        framed.push_str("\r\n");
        self.write_all(framed.as_bytes()).await
    }

    /// Upgrade the connection to TLS.
    ///
    /// RFC 3207 requires the client to send nothing between the `STARTTLS`
    /// command and the handshake, so the read buffer has to be empty before
    /// the handshake starts.
    async fn upgrade(&mut self, acceptor: &TlsAcceptor) -> Result<()> {
        let reader = match self {
            SessionStream::Plain(reader) => reader.take().ok_or_else(|| {
                MxNodeError::InvalidState("the connection was already consumed".to_string())
            })?,
            SessionStream::Tls(_) => {
                return Err(MxNodeError::InvalidState(
                    "the connection is already protected by TLS".to_string(),
                ))
            }
        };

        if !reader.buffer().is_empty() {
            return Err(MxNodeError::Protocol(
                "the client sent data before the TLS handshake".to_string(),
            ));
        }

        let tls = acceptor
            .accept(reader.into_inner())
            .await
            .map_err(|e| MxNodeError::Tls(e.to_string()))?;

        *self = SessionStream::Tls(Some(BufReader::new(tls)));
        Ok(())
    }
}

/// State of the SMTP dialogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    /// The greeting was sent, no EHLO yet.
    Connected,
    /// EHLO or HELO was received.
    Greeted,
    /// MAIL FROM was received.
    Mail,
    /// At least one RCPT TO was received.
    Recipient,
}

/// Step of an ongoing AUTH exchange.
#[derive(Debug, Clone)]
enum AuthStep {
    /// Waiting for the base64 encoded `authzid\0authcid\0password` blob.
    Plain,
    /// Waiting for the base64 encoded user name.
    LoginUser,
    /// Waiting for the base64 encoded password.
    LoginPassword(String),
}

/// Shared state of the SMTP server.
pub struct SmtpContext {
    /// Listener configuration.
    pub config: Arc<SmtpConfig>,
    /// Role of this listener.
    pub mode: SmtpMode,
    /// Mail domain served by the node.
    pub domain: String,
    /// Hostname used in the greeting.
    pub hostname: String,
    /// TLS acceptor, if the node has a certificate.
    pub tls_acceptor: Option<TlsAcceptor>,
    /// Accounts that may authenticate.
    pub credentials: Arc<CredentialStore>,
    /// Users of the node, used to map an address to a mailbox.
    pub users: Vec<UserConfig>,
    /// Encrypted mailbox storage.
    pub storage: Arc<EncryptedStorage>,
    /// Transport layer used for outbound mail.
    pub transports: Arc<TransportManager>,
}

impl SmtpContext {
    /// Mailbox that receives mail for an address of the local domain.
    pub fn mailbox_for(&self, address: &str) -> String {
        let local = address.split('@').next().unwrap_or(address);
        self.users
            .iter()
            .find(|u| u.username.eq_ignore_ascii_case(local))
            .map(|u| u.mailbox.clone())
            .unwrap_or_else(|| "INBOX".to_string())
    }
}

/// SMTP server.
#[derive(Clone)]
pub struct SmtpServer {
    context: Arc<SmtpContext>,
    listener: Arc<tokio::sync::Mutex<Option<TcpListener>>>,
    stop_signal: watch::Sender<bool>,
}

impl SmtpServer {
    /// Build a server for the given context.
    pub fn new(context: SmtpContext) -> Self {
        let (stop_signal, _rx) = watch::channel(false);
        Self {
            context: Arc::new(context),
            listener: Arc::new(tokio::sync::Mutex::new(None)),
            stop_signal,
        }
    }

    /// Bind the configured address and start accepting connections.
    pub async fn start(&self) -> Result<SocketAddr> {
        let listener = TcpListener::bind(self.context.config.bind_addr).await?;
        let local = listener.local_addr()?;
        info!(
            address = %local,
            mode = ?self.context.mode,
            "SMTP listener started"
        );
        *self.listener.lock().await = Some(listener);
        Ok(local)
    }

    /// Run the accept loop until the server is stopped.
    pub async fn serve(self) -> Result<()> {
        let listener = match self.listener.lock().await.take() {
            Some(listener) => listener,
            None => return Err(MxNodeError::InvalidState("the server was not started".into())),
        };

        let mut stop = self.stop_signal.subscribe();

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
                            warn!(error = %e, "failed to accept an SMTP connection");
                            continue;
                        }
                    };
                    let context = Arc::clone(&self.context);
                    tokio::spawn(async move {
                        if let Err(e) = handle_plain_connection(context, stream, peer).await {
                            debug!(peer = %peer, error = %e, "SMTP session ended with an error");
                        }
                    });
                }
            }
        }

        info!("SMTP listener stopped");
        Ok(())
    }

    /// Ask the accept loop to stop.
    pub fn stop(&self) {
        let _ = self.stop_signal.send(true);
    }

    /// Address the server is bound to, if it is running.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.lock().await.as_ref().map(|l| l.local_addr().ok()).flatten()
    }
}

/// Serve a plaintext SMTP connection.
pub(crate) async fn handle_plain_connection(
    context: Arc<SmtpContext>,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let mut session = Session {
        context,
        stream: SessionStream::Plain(Some(BufReader::new(stream))),
        peer,
        state: SessionState::Connected,
        authenticated: None,
        mail_from: None,
        rcpt_to: Vec::new(),
        pending_auth: None,
        data: Vec::new(),
        data_overflow: false,
        commands: 0,
        window_start: Instant::now(),
    };
    session.run().await
}

/// Serve a connection that is protected by TLS from the start.
pub(crate) async fn handle_tls_connection(
    context: Arc<SmtpContext>,
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let tls = acceptor
        .accept(stream)
        .await
        .map_err(|e| MxNodeError::Tls(e.to_string()))?;

    let mut session = Session {
        context,
        stream: SessionStream::Tls(Some(BufReader::new(tls))),
        peer,
        state: SessionState::Connected,
        authenticated: None,
        mail_from: None,
        rcpt_to: Vec::new(),
        pending_auth: None,
        data: Vec::new(),
        data_overflow: false,
        commands: 0,
        window_start: Instant::now(),
    };
    session.run().await
}

/// A single SMTP session.
struct Session {
    context: Arc<SmtpContext>,
    stream: SessionStream,
    peer: SocketAddr,
    state: SessionState,
    authenticated: Option<AuthenticatedUser>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    pending_auth: Option<AuthStep>,
    data: Vec<u8>,
    data_overflow: bool,
    commands: u32,
    window_start: Instant,
}

impl Session {
    /// Run the session until the client disconnects.
    async fn run(&mut self) -> Result<()> {
        self.reply(&format!(
            "220 {} ESMTP DOM Mail MX Node",
            self.context.hostname
        ))
        .await?;

        let idle = Duration::from_secs(self.context.config.session_timeout_secs.max(30));

        loop {
            let mut buffer = Vec::new();
            let read = timeout(idle, self.stream.read_line(&mut buffer)).await;

            let count = match read {
                Err(_) => {
                    let _ = self.reply("421 4.4.2 Idle timeout, closing connection").await;
                    return Ok(());
                }
                Ok(Err(e)) => {
                    debug!(peer = %self.peer, error = %e, "SMTP connection closed");
                    return Ok(());
                }
                Ok(Ok(count)) => count,
            };

            if count == 0 {
                return Ok(());
            }

            if count > MAX_COMMAND_LEN {
                self.reply("500 5.5.2 Line too long").await?;
                continue;
            }

            while matches!(buffer.last(), Some(b'\n') | Some(b'\r')) {
                buffer.pop();
            }
            let line = String::from_utf8_lossy(&buffer).into_owned();

            if !self.check_rate_limit().await? {
                return Ok(());
            }

            if self.pending_auth.is_some() {
                self.continue_auth(&line).await?;
                continue;
            }

            let (verb, rest) = split_command(&line);
            match verb.as_str() {
                "EHLO" => self.handle_ehlo(&rest).await?,
                "HELO" => self.handle_helo(&rest).await?,
                "STARTTLS" => self.handle_starttls().await?,
                "AUTH" => self.handle_auth(&rest).await?,
                "MAIL" => self.handle_mail(&rest).await?,
                "RCPT" => self.handle_rcpt(&rest).await?,
                "DATA" => self.handle_data().await?,
                "RSET" => {
                    self.reset_transaction();
                    self.reply("250 2.0.0 Ok").await?;
                }
                "NOOP" => self.reply("250 2.0.0 Ok").await?,
                "VRFY" => {
                    self.reply("252 2.5.2 Cannot VRFY user, but will accept message and attempt delivery")
                        .await?
                }
                "HELP" => {
                    self.reply("214 2.0.0 See RFC 5321 for the command set").await?
                }
                "QUIT" => {
                    self.reply(&format!("221 2.0.0 {} closing connection", self.context.hostname))
                        .await?;
                    return Ok(());
                }
                "" => {}
                other => {
                    self.reply(&format!("500 5.5.1 Error: command not recognized: {other}"))
                        .await?
                }
            }
        }
    }

    /// Send a single line response.
    async fn reply(&mut self, line: &str) -> Result<()> {
        self.stream
            .write_line(line)
            .await
            .map_err(MxNodeError::Io)
    }

    /// Enforce the per minute command limit.
    async fn check_rate_limit(&mut self) -> Result<bool> {
        let limit = self.context.config.rate_limit_per_minute;
        if limit == 0 {
            return Ok(true);
        }

        if self.window_start.elapsed() >= Duration::from_secs(60) {
            self.window_start = Instant::now();
            self.commands = 0;
        }
        self.commands += 1;

        if self.commands > limit {
            self.reply(&format!(
                "421 4.7.0 Too many commands, closing connection (limit {limit} per minute)"
            ))
            .await?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Handle `EHLO`.
    async fn handle_ehlo(&mut self, domain: &str) -> Result<()> {
        if domain.trim().is_empty() {
            self.reply("501 5.5.4 Syntax: EHLO hostname").await?;
            return Ok(());
        }

        self.state = SessionState::Greeted;

        let mut lines = vec![format!("250-{} Hello", self.context.hostname)];
        lines.push(format!(
            "250-SIZE {}",
            self.context.config.max_message_size
        ));
        lines.push("250-8BITMIME".to_string());
        lines.push("250-PIPELINING".to_string());
        lines.push("250-ENHANCEDSTATUSCODES".to_string());

        if !self.stream.is_tls() && self.context.tls_acceptor.is_some() {
            lines.push("250-STARTTLS".to_string());
        }

        if !self.context.credentials.is_empty()
            && (!self.context.config.auth_over_tls_only || self.stream.is_tls())
        {
            lines.push("250-AUTH PLAIN LOGIN".to_string());
        }

        let last = lines.pop().unwrap_or_else(|| format!("250 {}", self.context.hostname));
        let body = format!("{}\r\n{}", lines.join("\r\n"), last);
        self.stream
            .write_all(body.as_bytes())
            .await
            .map_err(MxNodeError::Io)
    }

    /// Handle `HELO`.
    async fn handle_helo(&mut self, domain: &str) -> Result<()> {
        if domain.trim().is_empty() {
            self.reply("501 5.5.4 Syntax: HELO hostname").await?;
            return Ok(());
        }
        self.state = SessionState::Greeted;
        self.reply(&format!("250 {}", self.context.hostname)).await
    }

    /// Handle `STARTTLS`.
    async fn handle_starttls(&mut self) -> Result<()> {
        if self.stream.is_tls() {
            self.reply("503 5.5.1 TLS is already active").await?;
            return Ok(());
        }

        let Some(acceptor) = self.context.tls_acceptor.clone() else {
            self.reply("454 4.7.0 TLS is not available on this server").await?;
            return Ok(());
        };

        self.reply("220 2.0.0 Ready to start TLS").await?;

        if let Err(e) = self.stream.upgrade(&acceptor).await {
            debug!(peer = %self.peer, error = %e, "TLS handshake failed");
            return Err(e);
        }

        // RFC 3207: everything learned before the handshake is discarded.
        self.state = SessionState::Connected;
        self.authenticated = None;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.pending_auth = None;

        info!(peer = %self.peer, "SMTP session upgraded to TLS");
        Ok(())
    }

    /// Handle `AUTH`.
    async fn handle_auth(&mut self, rest: &str) -> Result<()> {
        if self.context.credentials.is_empty() {
            self.reply("503 5.5.1 Authentication is not configured on this server")
                .await?;
            return Ok(());
        }

        if self.context.mode.requires_auth() && self.authenticated.is_some() {
            self.reply("503 5.5.1 Already authenticated").await?;
            return Ok(());
        }

        if self.context.config.auth_over_tls_only && !self.stream.is_tls() {
            self.reply("538 5.7.11 Encryption required for requested authentication mechanism")
                .await?;
            return Ok(());
        }

        let mut parts = rest.splitn(2, ' ');
        let mechanism = parts.next().unwrap_or_default().trim().to_ascii_uppercase();
        let initial = parts
            .next()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        match mechanism.as_str() {
            "PLAIN" => match initial {
                Some(blob) => self.verify_plain(&blob).await?,
                None => {
                    self.reply("334 ").await?;
                    self.pending_auth = Some(AuthStep::Plain);
                }
            },
            "LOGIN" => match initial {
                Some(user) => match decode_base64(&user) {
                    Ok(user) => {
                        self.reply("334 UGFzc3dvcmQ6").await?;
                        self.pending_auth = Some(AuthStep::LoginPassword(user));
                    }
                    Err(()) => self.reply("501 5.5.2 Invalid base64 data").await?,
                },
                None => {
                    self.reply("334 VXNlcm5hbWU6").await?;
                    self.pending_auth = Some(AuthStep::LoginUser);
                }
            },
            _ => self.reply("504 5.5.4 Unrecognized authentication type").await?,
        }

        Ok(())
    }

    /// Continue an ongoing AUTH exchange.
    async fn continue_auth(&mut self, line: &str) -> Result<()> {
        if line.trim() == "*" {
            self.pending_auth = None;
            self.reply("501 5.7.0 Authentication cancelled by client").await?;
            return Ok(());
        }

        let step = self.pending_auth.take();
        match step {
            Some(AuthStep::Plain) => self.verify_plain(line).await?,
            Some(AuthStep::LoginUser) => match decode_base64(line) {
                Ok(user) => {
                    self.reply("334 UGFzc3dvcmQ6").await?;
                    self.pending_auth = Some(AuthStep::LoginPassword(user));
                }
                Err(()) => self.reply("501 5.5.2 Invalid base64 data").await?,
            },
            Some(AuthStep::LoginPassword(user)) => match decode_base64(line) {
                Ok(password) => self.finish_auth(&user, &password).await?,
                Err(()) => self.reply("501 5.5.2 Invalid base64 data").await?,
            },
            None => {}
        }
        Ok(())
    }

    /// Verify a `PLAIN` credential blob.
    async fn verify_plain(&mut self, blob: &str) -> Result<()> {
        let decoded = match decode_base64(blob) {
            Ok(decoded) => decoded,
            Err(()) => {
                self.reply("501 5.5.2 Invalid base64 data").await?;
                return Ok(());
            }
        };

        let parts: Vec<&[u8]> = decoded.split(|byte| *byte == 0).collect();
        if parts.len() < 3 {
            self.reply("501 5.5.2 Invalid PLAIN response").await?;
            return Ok(());
        }

        let user = String::from_utf8_lossy(parts[1]).into_owned();
        let password = String::from_utf8_lossy(parts[2]).into_owned();
        self.finish_auth(&user, &password).await
    }

    /// Check the credentials and report the result.
    async fn finish_auth(&mut self, user: &str, password: &str) -> Result<()> {
        match self.context.credentials.authenticate(user, password) {
            Some(authenticated) => {
                self.authenticated = Some(authenticated);
                self.pending_auth = None;
                self.reply("235 2.7.0 Authentication successful").await
            }
            None => {
                self.pending_auth = None;
                self.reply("535 5.7.8 Authentication credentials invalid").await
            }
        }
    }

    /// Reset the transaction state.
    fn reset_transaction(&mut self) {
        self.state = SessionState::Greeted;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data.clear();
        self.data_overflow = false;
    }
}

    /// Check whether the session may carry mail.
    async fn security_ok(&mut self) -> Result<bool> {
        if self.context.config.require_starttls && !self.stream.is_tls() {
            self.reply("530 5.7.0 Must issue a STARTTLS command first").await?;
            return Ok(false);
        }
        if self.context.mode.requires_auth() && self.authenticated.is_none() {
            self.reply("530 5.7.0 Authentication required").await?;
            return Ok(false);
        }
        Ok(true)
    }

    /// Handle `MAIL FROM`.
    async fn handle_mail(&mut self, rest: &str) -> Result<()> {
        if !self.security_ok().await? {
            return Ok(());
        }

        let Some((address, params)) = parse_path(rest, "FROM:") else {
            self.reply("501 5.5.4 Syntax: MAIL FROM:<address>").await?;
            return Ok(());
        };

        if !valid_address(&address) {
            self.reply("501 5.1.7 Bad sender address syntax").await?;
            return Ok(());
        }

        if let Some(size) = parameter_value(&params, "SIZE") {
            match size.parse::<usize>() {
                Ok(size) if size > self.context.config.max_message_size => {
                    self.reply("552 5.3.4 Message size exceeds the fixed maximum message size")
                        .await?;
                    return Ok(());
                }
                Ok(_) => {}
                Err(_) => {
                    self.reply("501 5.5.4 Syntax: SIZE parameter").await?;
                    return Ok(());
                }
            }
        }

        self.mail_from = Some(address);
        self.rcpt_to.clear();
        self.state = SessionState::Mail;
        self.reply("250 2.1.0 Ok").await
    }

    /// Handle `RCPT TO`.
    async fn handle_rcpt(&mut self, rest: &str) -> Result<()> {
        if self.mail_from.is_none() {
            self.reply("503 5.5.1 Error: need MAIL command").await?;
            return Ok(());
        }

        if !self.security_ok().await? {
            return Ok(());
        }

        let Some((address, _params)) = parse_path(rest, "TO:") else {
            self.reply("501 5.5.4 Syntax: RCPT TO:<address>").await?;
            return Ok(());
        };

        if address.is_empty() || !valid_address(&address) {
            self.reply("501 5.1.3 Bad recipient address syntax").await?;
            return Ok(());
        }

        let domain = address
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_ascii_lowercase())
            .unwrap_or_default();

        let local = self.context.domain.to_ascii_lowercase();
        if domain != local && self.authenticated.is_none() {
            // Relaying is only allowed for authenticated clients, which keeps
            // the node from being used as an open relay.
            self.reply("550 5.7.1 Relay access denied").await?;
            return Ok(());
        }

        self.rcpt_to.push(address);
        self.state = SessionState::Recipient;
        self.reply("250 2.1.5 Ok").await
    }

    /// Handle `DATA`.
    async fn handle_data(&mut self) -> Result<()> {
        if self.mail_from.is_none() {
            self.reply("503 5.5.1 Error: need MAIL command").await?;
            return Ok(());
        }
        if self.rcpt_to.is_empty() {
            self.reply("503 5.5.1 Error: need RCPT command").await?;
            return Ok(());
        }
        if !self.security_ok().await? {
            return Ok(());
        }

        self.reply("354 End data with <CR><LF>.<CR><LF>").await?;

        let max = self.context.config.max_message_size;
        self.data.clear();
        self.data_overflow = false;

        loop {
            let mut buffer = Vec::new();
            let read = timeout(
                Duration::from_secs(self.context.config.session_timeout_secs.max(30)),
                self.stream.read_line(&mut buffer),
            )
            .await;

            let count = match read {
                Err(_) => {
                    let _ = self.reply("421 4.4.2 Idle timeout during DATA").await;
                    return Ok(());
                }
                Ok(Err(_)) => return Ok(()),
                Ok(Ok(count)) => count,
            };

            if count == 0 {
                return Ok(());
            }

            while matches!(buffer.last(), Some(b'\n') | Some(b'\r')) {
                buffer.pop();
            }

            if buffer == b"." {
                break;
            }

            // RFC 5321 section 4.5.2: a leading dot is doubled by the
            // sender, so one dot is removed again here.
            if buffer.first() == Some(&b'.') {
                buffer.remove(0);
            }

            if self.data.len() + buffer.len() + 2 > max {
                // Keep reading until the terminator so the connection stays in
                // sync, but stop storing the payload.
                self.data_overflow = true;
                continue;
            }

            self.data.extend_from_slice(&buffer);
            self.data.extend_from_slice(b"\r\n");
        }

        if self.data_overflow {
            self.reset_transaction();
            self.reply(&format!(
                "552 5.3.4 Message size exceeds the fixed maximum of {max} bytes"
            ))
            .await?;
            return Ok(());
        }

        let sender = self.mail_from.clone().unwrap_or_default();
        let recipients = self.rcpt_to.clone();
        let payload = self.data.clone();
        self.reset_transaction();

        let (local, remote): (Vec<String>, Vec<String>) = recipients
            .iter()
            .cloned()
            .partition(|address| self.is_local_address(address));

        // Remote recipients are handed to the transport layer first: if that
        // fails the client is told so and can retry, and nothing was stored
        // locally yet.
        if !remote.is_empty() {
            let envelope = Envelope::new(sender.clone(), remote.clone());
            let report = self.context.transports.deliver(&envelope, &payload).await;
            if !report.is_success() {
                let reason = report
                    .failed
                    .iter()
                    .map(|(transport, error)| format!("{transport}: {error}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                self.reply(&format!("451 4.3.0 Temporary delivery failure: {reason}"))
                    .await?;
                return Ok(());
            }
        }

        for recipient in &local {
            if let Err(e) = self.store_message(recipient, &payload).await {
                warn!(recipient = %recipient, error = %e, "failed to store the message");
                self.reply("451 4.3.0 Failed to store the message").await?;
                return Ok(());
            }
        }

        let id = generate_message_id(&self.context.hostname);
        self.reply(&format!("250 2.0.0 Ok: queued as {id}")).await
    }

    /// Whether an address belongs to the local domain.
    fn is_local_address(&self, address: &str) -> bool {
        match address.rsplit_once('@') {
            Some((_, domain)) => domain.eq_ignore_ascii_case(&self.context.domain),
            None => true,
        }
    }

    /// Store a message in the mailbox of the recipient.
    async fn store_message(&self, recipient: &str, raw: &[u8]) -> Result<()> {
        let mailbox = self.context.mailbox_for(recipient);
        let store = MailboxStorage::new((*self.context.storage).clone(), &mailbox);
        let id = generate_message_id(&self.context.hostname);

        let message = match MessageParser::default().parse(raw) {
            Some(parsed) => {
                let headers = parsed
                    .headers_raw()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
                    .collect();
                StoredMessage {
                    id: id.clone(),
                    mailbox: mailbox.clone(),
                    from: collect_addresses(parsed.from()),
                    to: collect_addresses(parsed.to()),
                    cc: collect_addresses(parsed.cc()),
                    bcc: Vec::new(),
                    subject: parsed.subject().unwrap_or_default().to_string(),
                    body_text: parsed
                        .body_text(0)
                        .map(|text| text.into_owned())
                        .unwrap_or_default(),
                    body_html: parsed.body_html(0).map(|html| html.into_owned()),
                    headers,
                    date: parsed.date().map(|date| date.to_timestamp()).unwrap_or_else(now),
                    read: false,
                    flagged: false,
                    deleted: false,
                    raw: Some(String::from_utf8_lossy(raw).into_owned()),
                    encrypted: false,
                    attachments: Vec::new(),
                }
            }
            None => StoredMessage {
                id: id.clone(),
                mailbox: mailbox.clone(),
                from: Vec::new(),
                to: Vec::new(),
                cc: Vec::new(),
                bcc: Vec::new(),
                subject: String::new(),
                body_text: String::new(),
                body_html: None,
                headers: Default::default(),
                date: now(),
                read: false,
                flagged: false,
                deleted: false,
                raw: Some(String::from_utf8_lossy(raw).into_owned()),
                encrypted: false,
                attachments: Vec::new(),
            },
        };

        store.save(&message).await
    }
}

/// Split a command line into its verb and its arguments.
fn split_command(line: &str) -> (String, String) {
    let line = line.trim();
    match line.split_once(' ') {
        Some((verb, rest)) => (verb.trim().to_ascii_uppercase(), rest.trim().to_string()),
        None => (line.to_ascii_uppercase(), String::new()),
    }
}

/// Parse a `FROM:` or `TO:` argument into the address and its parameters.
fn parse_path(args: &str, prefix: &str) -> Option<(String, String)> {
    let rest = args.trim_start();
    let rest = rest.get(..prefix.len())?;
    if !rest.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = args.trim_start().get(prefix.len()..)?.trim_start();

    let (path, params) = match rest.find(' ') {
        Some(index) => (&rest[..index], rest[index + 1..].trim()),
        None => (rest, ""),
    };

    if path.len() < 2 || !path.starts_with('<') || !path.ends_with('>') {
        return None;
    }

    let inner = &path[1..path.len() - 1];

    // RFC 5321 allows a source route in front of the address.
    let inner = match inner.rfind(':') {
        Some(index) if inner.starts_with('@') => &inner[index + 1..],
        _ => inner,
    };

    Some((inner.to_string(), params.to_string()))
}

/// Read the value of an ESMTP parameter, e.g. `SIZE=1234`.
fn parameter_value(params: &str, name: &str) -> Option<String> {
    for part in params.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            if key.eq_ignore_ascii_case(name) {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Check that an address is syntactically plausible.
fn valid_address(address: &str) -> bool {
    if address.is_empty() {
        // The null reverse path is legal for bounces.
        return true;
    }
    if address.len() > MAX_ADDRESS_LEN {
        return false;
    }
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if local.chars().any(char::is_whitespace) || domain.chars().any(char::is_whitespace) {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    true
}

/// Decode a base64 credential blob.
fn decode_base64(value: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim().as_bytes())
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Collect the addresses of a header into the storage representation.
fn collect_addresses(address: Option<&mail_parser::Address>) -> Vec<MailAddress> {
    address
        .and_then(|address| address.as_list())
        .map(|list| {
            list.iter()
                .map(|entry| MailAddress {
                    name: entry.name().map(|name| name.to_string()),
                    address: entry.address().unwrap_or_default().to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Current unix timestamp in seconds.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or_default()
}

/// Build a unique message identifier.
fn generate_message_id(hostname: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default();
    let random = crate::storage::hex_encode(&crate::crypto::generate_salt(8));
    format!("<{millis:x}.{random}@{hostname}>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CredentialStore;
    use crate::config::UserConfig;
    use crate::crypto::{Argon2Params, MasterKey};
    use crate::storage::{MemoryStorage, StorageBackend};
    use std::collections::HashMap;

    fn test_config(bind: &str) -> SmtpConfig {
        SmtpConfig {
            bind_addr: bind.parse().unwrap(),
            require_starttls: false,
            auth_over_tls_only: false,
            max_message_size: 1024 * 1024,
            rate_limit_per_minute: 0,
            session_timeout_secs: 30,
            mta_sts: false,
            dane: false,
        }
    }

    fn test_context(bind: &str) -> SmtpContext {
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new(1024 * 1024));
        let master = MasterKey::derive(
            "test",
            b"salt12345678",
            &Argon2Params {
                memory_kb: 8 * 1024,
                time: 1,
                parallelism: 1,
            },
        )
        .unwrap();

        let hash = crate::auth::hash_password(
            "secret",
            &Argon2Params {
                memory_kb: 8 * 1024,
                time: 1,
                parallelism: 1,
            },
        )
        .unwrap();

        let users = vec![UserConfig {
            username: "alice".into(),
            password_hash: hash,
            mailbox: "INBOX".into(),
        }];

        SmtpContext {
            config: Arc::new(test_config(bind)),
            mode: SmtpMode::Incoming,
            domain: "example.org".into(),
            hostname: "mx.example.org".into(),
            tls_acceptor: None,
            credentials: Arc::new(CredentialStore::from_config(&{
                let mut config = crate::config::MxNodeConfig::default();
                config.users = users.clone();
                config
            })),
            users,
            storage: Arc::new(EncryptedStorage::new(backend, master)),
            transports: Arc::new(crate::transport::TransportManager::new()),
        }
    }

    #[test]
    fn splits_commands() {
        assert_eq!(
            split_command("EHLO mx.example.org"),
            ("EHLO".to_string(), "mx.example.org".to_string())
        );
        assert_eq!(split_command("QUIT"), ("QUIT".to_string(), String::new()));
    }

    #[test]
    fn parses_paths() {
        let (address, params) = parse_path("FROM:<a@example.org>", "FROM:").unwrap();
        assert_eq!(address, "a@example.org");
        assert_eq!(params, "");

        let (address, params) = parse_path("TO:<b@example.org> NOTIFY=SUCCESS", "TO:").unwrap();
        assert_eq!(address, "b@example.org");
        assert_eq!(params, "NOTIFY=SUCCESS");

        assert!(parse_path("FROM:a@example.org", "FROM:").is_none());
        assert!(parse_path("TO:<b@example.org>", "FROM:").is_none());
    }

    #[test]
    fn validates_addresses() {
        assert!(valid_address(""));
        assert!(valid_address("a@example.org"));
        assert!(!valid_address("a@example"));
        assert!(!valid_address("@example.org"));
        assert!(!valid_address("a b@example.org"));
        assert!(!valid_address("a@exam ple.org"));
    }

    #[test]
    fn reads_parameters() {
        assert_eq!(
            parameter_value("SIZE=100 BODY=8BITMIME", "SIZE"),
            Some("100".to_string())
        );
        assert_eq!(parameter_value("BODY=8BITMIME", "SIZE"), None);
    }

    #[tokio::test]
    async fn accepts_mail_for_the_local_domain() {
        let server = SmtpServer::new(test_context("127.0.0.1:0"));
        let address = server.start().await.unwrap();
        let worker = server.clone();
        tokio::spawn(async move {
            let _ = worker.serve().await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("220 "), "greeting was {line:?}");

        // EHLO
        reader.write_all(b"EHLO tester\r\n").await.unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250-"), "ehlo was {line:?}");
        loop {
            reader.read_line(&mut line).await.unwrap();
            if !line.starts_with("250-") {
                break;
            }
        }
        assert!(line.starts_with("250 "), "ehlo end was {line:?}");

        reader
            .write_all(b"MAIL FROM:<sender@example.org>\r\n")
            .await
            .unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250 "), "mail from was {line:?}");

        reader
            .write_all(b"RCPT TO:<alice@example.org>\r\n")
            .await
            .unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250 "), "rcpt to was {line:?}");

        reader.write_all(b"DATA\r\n").await.unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("354 "), "data was {line:?}");

        reader
            .write_all(b"Subject: hi\r\n\r\nbody\r\n.\r\n")
            .await
            .unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250 "), "data end was {line:?}");
    }

    #[tokio::test]
    async fn refuses_to_relay_for_unauthenticated_clients() {
        let server = SmtpServer::new(test_context("127.0.0.1:0"));
        let address = server.start().await.unwrap();
        let worker = server.clone();
        tokio::spawn(async move {
            let _ = worker.serve().await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        reader
            .write_all(b"MAIL FROM:<sender@example.org>\r\n")
            .await
            .unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250 "), "mail from was {line:?}");

        reader
            .write_all(b"RCPT TO:<someone@elsewhere.test>\r\n")
            .await
            .unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(
            line.starts_with("550 "),
            "relay should be denied, got {line:?}"
        );
    }

    #[tokio::test]
    async fn authenticates_with_plain() {
        let server = SmtpServer::new(test_context("127.0.0.1:0"));
        let address = server.start().await.unwrap();
        let worker = server.clone();
        tokio::spawn(async move {
            let _ = worker.serve().await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let blob = base64::engine::general_purpose::STANDARD.encode("\0alice\0secret");
        reader
            .write_all(format!("AUTH PLAIN {blob}\r\n").as_bytes())
            .await
            .unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("235 "), "auth was {line:?}");
    }

    #[tokio::test]
    async fn rejects_wrong_passwords() {
        let server = SmtpServer::new(test_context("127.0.0.1:0"));
        let address = server.start().await.unwrap();
        let worker = server.clone();
        tokio::spawn(async move {
            let _ = worker.serve().await;
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let blob = base64::engine::general_purpose::STANDARD.encode("\0alice\0wrong");
        reader
            .write_all(format!("AUTH PLAIN {blob}\r\n").as_bytes())
            .await
            .unwrap();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("535 "), "auth was {line:?}");
    }
}
