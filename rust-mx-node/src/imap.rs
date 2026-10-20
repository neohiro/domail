//! IMAP4rev1 server.
//!
//! The server exposes the mailboxes that the SMTP server fills to mail
//! clients. It implements the command set a desktop client needs: `LOGIN`,
//! `AUTHENTICATE`, `LIST`, `SELECT`, `STATUS`, `FETCH`, `STORE`, `SEARCH`,
//! `APPEND`, `EXPUNGE` and `CLOSE`.
//!
//! Two listeners are offered: the plain port negotiates TLS with `STARTTLS`,
//! the secure port uses implicit TLS. When `require_tls` is set, the server
//! refuses every command that would expose mailbox data before the handshake
//! finished.

use crate::auth::{AuthenticatedUser, CredentialStore};
use crate::config::{ImapConfig, UserConfig};
use crate::error::*;
use crate::storage::{EncryptedStorage, MailboxStorage, StoredMessage};
use base64::Engine;
use mail_parser::MessageParser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Maximum length of a command line.
const MAX_LINE: usize = 16 * 1024;

/// Maximum size of a literal sent with `APPEND`.
const MAX_LITERAL: usize = 64 * 1024 * 1024;

/// The connection an IMAP session runs on.
enum ImapStream {
    /// Plaintext connection.
    Plain(Option<BufReader<TcpStream>>),
    /// Connection protected by TLS.
    Tls(Option<BufReader<TlsStream<TcpStream>>>),
}

impl ImapStream {
    /// Whether the session is protected by TLS.
    fn is_tls(&self) -> bool {
        matches!(self, ImapStream::Tls(_))
    }

    /// A closed connection is reported as a broken pipe.
    fn broken() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "connection closed")
    }

    /// Read one line without its terminator.
    async fn read_line(&mut self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        match self {
            ImapStream::Plain(reader) => match reader.as_mut() {
                Some(reader) => reader.read_until(b'\n', buffer).await,
                None => Err(ImapStream::broken()),
            },
            ImapStream::Tls(reader) => match reader.as_mut() {
                Some(reader) => reader.read_until(b'\n', buffer).await,
                None => Err(ImapStream::broken()),
            },
        }
    }

    /// Read exactly `len` bytes, used for literals.
    async fn read_exact(&mut self, len: usize) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];
        match self {
            ImapStream::Plain(reader) => match reader.as_mut() {
                Some(reader) => reader.read_exact(&mut buffer).await?,
                None => return Err(ImapStream::broken()),
            },
            ImapStream::Tls(reader) => match reader.as_mut() {
                Some(reader) => reader.read_exact(&mut buffer).await?,
                None => return Err(ImapStream::broken()),
            },
        }
        Ok(buffer)
    }

    /// Write raw bytes to the peer.
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            ImapStream::Plain(reader) => match reader.as_mut() {
                Some(reader) => reader.write_all(data).await,
                None => Err(ImapStream::broken()),
            },
            ImapStream::Tls(reader) => match reader.as_mut() {
                Some(reader) => reader.write_all(data).await,
                None => Err(ImapStream::broken()),
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
    /// RFC 3501 requires the client to send nothing between the `STARTTLS`
    /// command and the handshake, so the read buffer has to be empty before
    /// the handshake starts.
    async fn upgrade(&mut self, acceptor: &TlsAcceptor) -> Result<()> {
        let reader = match self {
            ImapStream::Plain(reader) => reader.take().ok_or_else(|| {
                MxNodeError::InvalidState("the connection was already consumed".to_string())
            })?,
            ImapStream::Tls(_) => {
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

        *self = ImapStream::Tls(Some(BufReader::new(tls)));
        Ok(())
    }
}

/// Shared state of the IMAP server.
pub struct ImapContext {
    /// Listener configuration.
    pub config: Arc<ImapConfig>,
    /// Mail domain served by the node.
    pub domain: String,
    /// Hostname used in the greeting.
    pub hostname: String,
    /// TLS acceptor, if the node has a certificate.
    pub tls_acceptor: Option<TlsAcceptor>,
    /// Accounts that may authenticate.
    pub credentials: Arc<CredentialStore>,
    /// Users of the node, used to map an account to a mailbox.
    pub users: Vec<UserConfig>,
    /// Encrypted mailbox storage.
    pub storage: Arc<EncryptedStorage>,
}

impl ImapContext {
    /// Capabilities announced by the server.
    fn capabilities(&self) -> &'static str {
        "IMAP4rev1 STARTTLS AUTH=PLAIN"
    }

    /// Mailboxes the server offers to the given account.
    fn mailboxes_for(&self, user: &AuthenticatedUser) -> Vec<String> {
        let mut mailboxes = vec![user.mailbox.clone()];
        for candidate in self.users.iter().map(|u| u.mailbox.clone()) {
            if !mailboxes.contains(&candidate) {
                mailboxes.push(candidate);
            }
        }
        mailboxes
    }
}

/// IMAP server.
#[derive(Clone)]
pub struct ImapServer {
    context: Arc<ImapContext>,
    listener: Arc<tokio::sync::Mutex<Option<TcpListener>>>,
    implicit: Arc<tokio::sync::Mutex<Option<TcpListener>>>,
    stop_signal: watch::Sender<bool>,
}

impl ImapServer {
    /// Build a server for the given context.
    pub fn new(context: ImapContext) -> Self {
        let (stop_signal, _rx) = watch::channel(false);
        Self {
            context: Arc::new(context),
            listener: Arc::new(tokio::sync::Mutex::new(None)),
            implicit: Arc::new(tokio::sync::Mutex::new(None)),
            stop_signal,
        }
    }

    /// Bind the configured addresses and start accepting connections.
    ///
    /// The implicit TLS listener is optional: on many systems port 993 needs
    /// elevated privileges, and the node must still start on port 143.
    pub async fn start(&self) -> Result<SocketAddr> {
        let listener = TcpListener::bind(self.context.config.bind_addr).await?;
        let local = listener.local_addr()?;
        info!(address = %local, "IMAP listener started");
        *self.listener.lock().await = Some(listener);

        match TcpListener::bind(self.context.config.implicit_tls_bind).await {
            Ok(listener) => {
                let local = listener.local_addr()?;
                info!(address = %local, "IMAP (implicit TLS) listener started");
                *self.implicit.lock().await = Some(listener);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "the implicit TLS IMAP port could not be bound, continuing without it"
                );
            }
        }

        Ok(local)
    }

    /// Run the accept loops until the server is stopped.
    pub async fn serve(self) -> Result<()> {
        let listener = match self.listener.lock().await.take() {
            Some(listener) => listener,
            None => return Err(MxNodeError::InvalidState("the server was not started".into())),
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
                        accepted = listener.accept() => {
                            let (stream, peer) = match accepted {
                                Ok(pair) => pair,
                                Err(e) => {
                                    warn!(error = %e, "failed to accept an IMAP connection");
                                    continue;
                                }
                            };
                            let context = Arc::clone(&context);
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_plain_connection(context, stream, peer).await
                                {
                                    debug!(peer = %peer, error = %e, "IMAP session ended with an error");
                                }
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
                                warn!(error = %e, "failed to accept an IMAP connection");
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
        info!("IMAP listeners stopped");
        Ok(())
    }

    /// Ask the accept loops to stop.
    pub fn stop(&self) {
        let _ = self.stop_signal.send(true);
    }

    /// Address the server is bound to, if it is running.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.lock().await.as_ref().map(|l| l.local_addr().ok()).flatten()
    }
}

/// Serve a plaintext IMAP connection.
async fn handle_plain_connection(
    context: Arc<ImapContext>,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let session = Session::new(context, ImapStream::Plain(Some(BufReader::new(stream))));
    session.run(peer).await
}

/// Serve an IMAP connection that is protected by TLS from the start.
async fn handle_tls_connection(
    context: Arc<ImapContext>,
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .map_err(|e| MxNodeError::Tls(e.to_string()))?;
    let session = Session::new(context, ImapStream::Tls(Some(BufReader::new(tls))));
    session.run(peer).await
}

/// Split a command line into a tag and the rest of the line.
fn split_command(line: &str) -> (String, String) {
    let line = line.trim_end_matches(['\r', '\n']);
    match line.find(' ') {
        Some(index) => (
            line[..index].to_string(),
            line[index + 1..].trim_start().to_string(),
        ),
        None => (line.to_string(), String::new()),
    }
}

/// Split an argument list into tokens.
///
/// Quoted strings keep their content but lose the quotes, bracketed flag
/// lists keep their brackets.
fn tokenize(args: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;

    for ch in args.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            ' ' | '\t' if !quoted => {
                if started {
                    let token = std::mem::take(&mut current);
                    tokens.push(token.trim_matches(|c| c == '(' || c == ')').to_string());
                    started = false;
                }
            }
            _ => {
                current.push(ch);
                started = true;
            }
        }
    }

    if started {
        tokens.push(current.trim_matches(|c| c == '(' || c == ')').to_string());
    }

    tokens
}

/// Parse a sequence set such as `1`, `2,4` or `1:*` into message indexes.
///
/// The result holds the zero based positions of the addressed messages.
fn parse_sequence(set: &str, count: usize) -> Vec<usize> {
    let mut indexes = Vec::new();

    for part in set.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once(':') {
            Some((start, end)) => {
                let start = start.trim().parse::<usize>().unwrap_or(1).max(1);
                let end = match end.trim() {
                    "*" => count,
                    other => other.parse::<usize>().unwrap_or(start).max(start),
                };
                for index in start..=end {
                    if index >= 1 && index <= count {
                        indexes.push(index - 1);
                    }
                }
            }
            None => {
                if let Ok(index) = part.parse::<usize>() {
                    if index >= 1 && index <= count {
                        indexes.push(index - 1);
                    }
                }
            }
        }
    }

    indexes.sort_unstable();
    indexes.dedup();
    indexes
}

/// Render the flags of a message as an IMAP flag list.
fn format_flags(message: &StoredMessage) -> String {
    let mut flags = Vec::new();
    if message.read {
        flags.push("\\Seen");
    }
    if message.flagged {
        flags.push("\\Flagged");
    }
    if message.deleted {
        flags.push("\\Deleted");
    }
    if flags.is_empty() {
        "\\Seen".to_string()
    } else {
        flags.join(" ")
    }
}

/// Render the raw message, reconstructing it when the raw form is missing.
fn raw_bytes(message: &StoredMessage) -> Vec<u8> {
    if let Some(raw) = &message.raw {
        return raw.as_bytes().to_vec();
    }

    let mut out = String::new();
    for address in &message.from {
        out.push_str(&format!("From: {}\r\n", address.address));
    }
    for address in &message.to {
        out.push_str(&format!("To: {}\r\n", address.address));
    }
    out.push_str(&format!("Subject: {}\r\n", message.subject));
    out.push_str("\r\n");
    out.push_str(&message.body_text);
    out.into_bytes()
}

/// State of the IMAP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    /// The client has not authenticated yet.
    Anonymous,
    /// The client authenticated but no mailbox is selected.
    Authenticated,
    /// A mailbox is selected.
    Selected,
}

/// One IMAP session.
struct Session {
    context: Arc<ImapContext>,
    stream: ImapStream,
    state: SessionState,
    user: Option<AuthenticatedUser>,
    mailbox: Option<String>,
    messages: Vec<StoredMessage>,
    read_only: bool,
}

impl Session {
    /// Build a session for the given context and connection.
    fn new(context: Arc<ImapContext>, stream: ImapStream) -> Self {
        Self {
            context,
            stream,
            state: SessionState::Anonymous,
            user: None,
            mailbox: None,
            messages: Vec::new(),
            read_only: false,
        }
    }

    /// How long the session waits for the next command.
    fn idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.context.config.idle_timeout.max(60))
    }

    /// Run the command loop until the client disconnects.
    async fn run(mut self, peer: SocketAddr) -> Result<()> {
        let greeting = format!(
            "* OK [CAPABILITY {}] DOM Mail IMAP2 ready",
            self.context.capabilities()
        );
        self.stream.write_line(&greeting).await?;

        loop {
            let mut buffer = Vec::new();
            let read = timeout(self.idle(), self.stream.read_line(&mut buffer)).await;

            let read = match read {
                Ok(result) => result?,
                Err(_) => {
                    return Err(MxNodeError::Protocol("the session timed out".to_string()));
                }
            };

            if read == 0 {
                break;
            }

            if buffer.len() > MAX_LINE {
                self.stream
                    .write_line("* BAD The command line is too long")
                    .await?;
                break;
            }

            let line = String::from_utf8_lossy(&buffer).to_string();
            let (tag, rest) = split_command(&line);
            if tag.is_empty() {
                self.stream.write_line("* BAD Missing tag").await?;
                continue;
            }

            let (verb, args) = split_command(&rest);
            let keep_open = self.dispatch(&tag, &verb.to_ascii_uppercase(), &args).await?;
            if !keep_open {
                break;
            }
        }

        debug!(peer = %peer, "IMAP session closed");
        Ok(())
    }

    /// Send a tagged OK response.
    async fn ok(&mut self, tag: &str, text: &str) -> Result<()> {
        self.stream.write_line(&format!("{} OK {}", tag, text)).await?;
        Ok(())
    }

    /// Send a tagged NO response.
    async fn no(&mut self, tag: &str, text: &str) -> Result<()> {
        self.stream.write_line(&format!("{} NO {}", tag, text)).await?;
        Ok(())
    }

    /// Send a tagged BAD response.
    async fn bad(&mut self, tag: &str, text: &str) -> Result<()> {
        self.stream.write_line(&format!("{} BAD {}", tag, text)).await?;
        Ok(())
    }

    /// Execute one command. Returns `false` when the session has to end.
    async fn dispatch(&mut self, tag: &str, verb: &str, args: &str) -> Result<bool> {
        // Without TLS the server only answers the commands that do not
        // expose mailbox data.
        let needs_tls = self.context.config.require_tls && !self.stream.is_tls();
        if needs_tls
            && !matches!(
                verb,
                "CAPABILITY" | "NOOP" | "LOGOUT" | "STARTTLS" | "IDLE"
            )
        {
            self.no(tag, "[PRIVACYREQUIRED] TLS is required").await?;
            return Ok(true);
        }

        match verb {
            "CAPABILITY" => {
                let line = format!("* CAPABILITY {}", self.context.capabilities());
                self.stream.write_line(&line).await?;
                self.ok(tag, "CAPABILITY completed").await?;
            }
            "NOOP" => self.ok(tag, "NOOP completed").await?,
            "CHECK" => self.ok(tag, "CHECK completed").await?,
            "LOGOUT" => {
                self.stream
                    .write_line("* BYE DOM Mail IMAP server signing off")
                    .await?;
                self.ok(tag, "LOGOUT completed").await?;
                return Ok(false);
            }
            "STARTTLS" => {
                if self.stream.is_tls() {
                    self.bad(tag, "TLS is already active").await?;
                } else {
                    let acceptor = self.context.tls_acceptor.clone();
                    match acceptor {
                        Some(acceptor) => {
                            self.ok(tag, "Begin TLS negotiation now").await?;
                            self.stream.upgrade(&acceptor).await?;
                        }
                        None => self.no(tag, "TLS is not available").await?,
                    }
                }
            }
            "LOGIN" => self.handle_login(tag, args).await?,
            "AUTHENTICATE" => self.handle_authenticate(tag, args).await?,
            "LIST" | "LSUB" => self.handle_list(tag).await?,
            "STATUS" => self.handle_status(tag, args).await?,
            "SELECT" | "EXAMINE" => self.handle_select(tag, verb, args).await?,
            "FETCH" => self.handle_fetch(tag, args).await?,
            "STORE" => self.handle_store(tag, args).await?,
            "EXPUNGE" => self.handle_expunge(tag).await?,
            "SEARCH" => self.handle_search(tag, args).await?,
            "APPEND" => self.handle_append(tag, args).await?,
            "CLOSE" => self.handle_close(tag).await?,
            "IDLE" => self.handle_idle(tag).await?,
            _ => self.bad(tag, "Unknown command").await?,
        }

        Ok(true)
    }
}
impl Session {
    /// Handle the `LOGIN` command.
    async fn handle_login(&mut self, tag: &str, args: &str) -> Result<()> {
        if self.state != SessionState::Anonymous {
            self.bad(tag, "The session is already authenticated").await?;
            return Ok(());
        }

        let tokens = tokenize(args);
        if tokens.len() < 2 {
            self.bad(tag, "LOGIN needs a user name and a password").await?;
            return Ok(());
        }

        match self.context.credentials.authenticate(&tokens[0], &tokens[1]) {
            Some(user) => {
                self.user = Some(user);
                self.state = SessionState::Authenticated;
                self.ok(tag, "LOGIN completed").await?;
            }
            None => self.no(tag, "Authentication failed").await?,
        }

        Ok(())
    }

    /// Handle the `AUTHENTICATE` command.
    async fn handle_authenticate(&mut self, tag: &str, args: &str) -> Result<()> {
        if self.state != SessionState::Anonymous {
            self.bad(tag, "The session is already authenticated").await?;
            return Ok(());
        }

        if !args.trim().eq_ignore_ascii_case("PLAIN") {
            self.no(tag, "Unsupported authentication mechanism").await?;
            return Ok(());
        }

        self.stream.write_line("+ ").await?;

        let mut buffer = Vec::new();
        let read = self.stream.read_line(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }

        let blob = String::from_utf8_lossy(&buffer).trim().to_string();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(blob.as_bytes())
            .unwrap_or_default();
        let parts: Vec<&[u8]> = decoded.split(|byte| *byte == 0).collect();
        let username = parts
            .get(1)
            .map(|value| String::from_utf8_lossy(value).to_string())
            .unwrap_or_default();
        let password = parts
            .get(2)
            .map(|value| String::from_utf8_lossy(value).to_string())
            .unwrap_or_default();

        match self.context.credentials.authenticate(&username, &password) {
            Some(user) => {
                self.user = Some(user);
                self.state = SessionState::Authenticated;
                self.ok(tag, "AUTHENTICATE completed").await?;
            }
            None => self.no(tag, "Authentication failed").await?,
        }

        Ok(())
    }

    /// Handle the `LIST` and `LSUB` commands.
    async fn handle_list(&mut self, tag: &str) -> Result<()> {
        let Some(user) = self.user.clone() else {
            self.no(tag, "Please authenticate first").await?;
            return Ok(());
        };

        for mailbox in self.context.mailboxes_for(&user) {
            let line = format!("* LIST (\\HasNoChildren) \"/\" \"{}\"", mailbox);
            self.stream.write_line(&line).await?;
        }
        self.ok(tag, "LIST completed").await?;
        Ok(())
    }

    /// Handle the `STATUS` command.
    async fn handle_status(&mut self, tag: &str, args: &str) -> Result<()> {
        if self.user.is_none() {
            self.no(tag, "Please authenticate first").await?;
            return Ok(());
        }

        let tokens = tokenize(args);
        let mailbox = tokens
            .first()
            .cloned()
            .unwrap_or_else(|| "INBOX".to_string());
        let items = tokens
            .get(1)
            .cloned()
            .unwrap_or_default()
            .to_ascii_uppercase();

        let storage = self.context.storage.clone();
        let store = MailboxStorage::new((*storage).clone(), &mailbox);
        let messages = store.count().await?;
        let unseen = store.count_unread().await?;

        let mut parts = Vec::new();
        if items.contains("MESSAGES") {
            parts.push(format!("MESSAGES {}", messages));
        }
        if items.contains("UNSEEN") {
            parts.push(format!("UNSEEN {}", unseen));
        }
        if items.contains("RECENT") {
            parts.push("RECENT 0".to_string());
        }

        let line = format!("* STATUS \"{}\" ({})", mailbox, parts.join(" "));
        self.stream.write_line(&line).await?;
        self.ok(tag, "STATUS completed").await?;
        Ok(())
    }

    /// Handle the `SELECT` and `EXAMINE` commands.
    async fn handle_select(&mut self, tag: &str, verb: &str, args: &str) -> Result<()> {
        let Some(user) = self.user.clone() else {
            self.no(tag, "Please authenticate first").await?;
            return Ok(());
        };

        let tokens = tokenize(args);
        let mailbox = tokens
            .first()
            .cloned()
            .unwrap_or_else(|| user.mailbox.clone());
        let allowed = self.context.mailboxes_for(&user);

        if !allowed
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&mailbox))
        {
            self.no(tag, "The mailbox does not exist").await?;
            return Ok(());
        }

        let storage = self.context.storage.clone();
        let store = MailboxStorage::new((*storage).clone(), &mailbox);
        self.messages = store.list(None, None).await?;
        self.mailbox = Some(mailbox);
        self.state = SessionState::Selected;
        self.read_only = verb == "EXAMINE";

        let count = self.messages.len();
        self.stream.write_line(&format!("* {} EXISTS", count)).await?;
        self.stream.write_line("* 0 RECENT").await?;
        self.stream
            .write_line("* OK [UIDVALIDITY 1] The UIDs are valid")
            .await?;
        self.stream
            .write_line(&format!(
                "* OK [UIDNEXT {}] The predicted next UID",
                count + 1
            ))
            .await?;
        self.stream
            .write_line("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
            .await?;
        self.stream
            .write_line(
                "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] The flags are permitted",
            )
            .await?;

        if self.read_only {
            self.ok(tag, "[READ-ONLY] EXAMINE completed").await?;
        } else {
            self.ok(tag, "[READ-WRITE] SELECT completed").await?;
        }

        Ok(())
    }

    /// Handle the `FETCH` command.
    async fn handle_fetch(&mut self, tag: &str, args: &str) -> Result<()> {
        if self.state != SessionState::Selected {
            self.no(tag, "No mailbox is selected").await?;
            return Ok(());
        }

        let tokens = tokenize(args);
        if tokens.len() < 2 {
            self.bad(tag, "FETCH needs a message set and a data item")
                .await?;
            return Ok(());
        }

        let indexes = parse_sequence(&tokens[0], self.messages.len());
        let requested: Vec<String> = tokens[1..]
            .iter()
            .map(|item| item.to_ascii_uppercase())
            .collect();
        let items = requested.join(" ");
        let wants_body = requested.iter().any(|item| {
            item == "RFC822" || item.starts_with("BODY[") || item.starts_with("BODY.PEEK[")
        });

        for index in indexes {
            let message = self.messages[index].clone();
            let mut parts: Vec<String> = vec![format!("UID {}", index + 1)];

            if items.contains("FLAGS") {
                parts.push(format!("FLAGS ({})", format_flags(&message)));
            }
            if items.contains("RFC822.SIZE") {
                parts.push(format!("RFC822.SIZE {}", raw_bytes(&message).len()));
            }
            if items.contains("INTERNALDATE") {
                parts.push("INTERNALDATE \"01-Jan-2024 00:00:00 +0000\"".to_string());
            }
            if items.contains("ENVELOPE") {
                parts.push(format!("ENVELOPE ({})", envelope_of(&message)));
            }

            if wants_body {
                let body = raw_bytes(&message);
                parts.push(format!("BODY[] {{{}}}", body.len()));
                let head = format!("* {} FETCH ({})", index + 1, parts.join(" "));
                self.stream.write_line(&head).await?;
                self.stream.write_all(&body).await?;
                self.stream.write_all(b")\r\n").await?;
                continue;
            }

            let line = format!("* {} FETCH ({})", index + 1, parts.join(" "));
            self.stream.write_line(&line).await?;
        }

        self.ok(tag, "FETCH completed").await?;
        Ok(())
    }

    /// Handle the `STORE` command.
    async fn handle_store(&mut self, tag: &str, args: &str) -> Result<()> {
        if self.state != SessionState::Selected {
            self.no(tag, "No mailbox is selected").await?;
            return Ok(());
        }
        if self.read_only {
            self.no(tag, "The mailbox is read only").await?;
            return Ok(());
        }

        let tokens = tokenize(args);
        if tokens.len() < 3 {
            self.bad(tag, "STORE needs a message set, a mode and a flag list")
                .await?;
            return Ok(());
        }

        let indexes = parse_sequence(&tokens[0], self.messages.len());
        let mode = tokens[1].to_ascii_uppercase();
        let flags = tokens[2].to_ascii_lowercase();
        let set_seen = flags.contains("\\seen");
        let set_flagged = flags.contains("\\flagged");
        let set_deleted = flags.contains("\\deleted");

        let mailbox = self
            .mailbox
            .clone()
            .unwrap_or_else(|| "INBOX".to_string());
        let storage = self.context.storage.clone();
        let store = MailboxStorage::new((*storage).clone(), &mailbox);

        for index in indexes {
            let mut message = self.messages[index].clone();

            if mode.contains('+') {
                message.read |= set_seen;
                message.flagged |= set_flagged;
                message.deleted |= set_deleted;
            } else if mode.contains('-') {
                message.read &= !set_seen;
                message.flagged &= !set_flagged;
                message.deleted &= !set_deleted;
            } else {
                message.read = set_seen;
                message.flagged = set_flagged;
                message.deleted = set_deleted;
            }

            store.save(&message).await?;
            self.messages[index] = message.clone();

            let line = format!(
                "* {} FETCH (FLAGS ({}))",
                index + 1,
                format_flags(&message)
            );
            self.stream.write_line(&line).await?;
        }

        self.ok(tag, "STORE completed").await?;
        Ok(())
    }

    /// Handle the `EXPUNGE` command.
    async fn handle_expunge(&mut self, tag: &str) -> Result<()> {
        if self.state != SessionState::Selected {
            self.no(tag, "No mailbox is selected").await?;
            return Ok(());
        }
        if self.read_only {
            self.no(tag, "The mailbox is read only").await?;
            return Ok(());
        }

        let mailbox = self
            .mailbox
            .clone()
            .unwrap_or_else(|| "INBOX".to_string());
        let storage = self.context.storage.clone();
        let store = MailboxStorage::new((*storage).clone(), &mailbox);

        let mut index = 0;
        while index < self.messages.len() {
            if self.messages[index].deleted {
                let id = self.messages[index].id.clone();
                store.delete(&id).await?;
                self.messages.remove(index);
                self.stream
                    .write_line(&format!("* {} EXPUNGE", index + 1))
                    .await?;
                continue;
            }
            index += 1;
        }

        self.ok(tag, "EXPUNGE completed").await?;
        Ok(())
    }

    /// Handle the `SEARCH` command.
    async fn handle_search(&mut self, tag: &str, args: &str) -> Result<()> {
        if self.state != SessionState::Selected {
            self.no(tag, "No mailbox is selected").await?;
            return Ok(());
        }

        let criteria = args.to_ascii_uppercase();
        let mut found = Vec::new();

        for (index, message) in self.messages.iter().enumerate() {
            let matches = if criteria.contains("UNSEEN") {
                !message.read
            } else if criteria.contains("SEEN") {
                message.read
            } else if criteria.contains("FLAGGED") {
                message.flagged
            } else {
                true
            };

            if matches {
                found.push(index + 1);
            }
        }

        let numbers: Vec<String> = found.iter().map(|value| value.to_string()).collect();
        self.stream
            .write_line(&format!("* SEARCH {}", numbers.join(" ")))
            .await?;
        self.ok(tag, "SEARCH completed").await?;
        Ok(())
    }

    /// Handle the `APPEND` command.
    async fn handle_append(&mut self, tag: &str, args: &str) -> Result<()> {
        let Some(user) = self.user.clone() else {
            self.no(tag, "Please authenticate first").await?;
            return Ok(());
        };

        let tokens = tokenize(args);
        let Some(marker) = tokens.last() else {
            self.bad(tag, "APPEND needs a literal").await?;
            return Ok(());
        };

        let Some(open) = marker.find('{') else {
            self.bad(tag, "APPEND needs a literal").await?;
            return Ok(());
        };
        let Some(close) = marker.find('}') else {
            self.bad(tag, "APPEND needs a literal").await?;
            return Ok(());
        };
        let length: usize = marker[open + 1..close].parse().unwrap_or(0);

        if length > MAX_LITERAL {
            self.no(tag, "The message is too large").await?;
            return Ok(());
        }

        let mailbox = tokens
            .first()
            .cloned()
            .unwrap_or_else(|| user.mailbox.clone());

        let payload = self.stream.read_exact(length).await?;
        let mut trailing = Vec::new();
        let _ = self.stream.read_line(&mut trailing).await?;

        let message = build_message(&mailbox, &payload, generate_id());
        let storage = self.context.storage.clone();
        let store = MailboxStorage::new((*storage).clone(), &mailbox);
        store.save(&message).await?;

        self.ok(tag, "APPEND completed").await?;
        Ok(())
    }

    /// Handle the `CLOSE` command.
    async fn handle_close(&mut self, tag: &str) -> Result<()> {
        if self.state != SessionState::Selected {
            self.no(tag, "No mailbox is selected").await?;
            return Ok(());
        }

        if !self.read_only {
            let mailbox = self
                .mailbox
                .clone()
                .unwrap_or_else(|| "INBOX".to_string());
            let storage = self.context.storage.clone();
            let store = MailboxStorage::new((*storage).clone(), &mailbox);

            for message in self.messages.iter() {
                if message.deleted {
                    store.delete(&message.id).await?;
                }
            }
        }

        self.messages.clear();
        self.mailbox = None;
        self.state = SessionState::Authenticated;
        self.ok(tag, "CLOSE completed").await?;
        Ok(())
    }

    /// Handle the `IDLE` command.
    async fn handle_idle(&mut self, tag: &str) -> Result<()> {
        if self.user.is_none() {
            self.no(tag, "Please authenticate first").await?;
            return Ok(());
        }

        self.stream.write_line("+ idling").await?;

        loop {
            let mut buffer = Vec::new();
            let read = timeout(self.idle(), self.stream.read_line(&mut buffer)).await;
            match read {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(_)) => {
                    let line = String::from_utf8_lossy(&buffer).trim().to_string();
                    if line.eq_ignore_ascii_case("DONE") {
                        break;
                    }
                }
                _ => return Ok(()),
            }
        }

        self.ok(tag, "IDLE terminated").await?;
        Ok(())
    }
}
/// Escape a text so that it can be used inside an IMAP quoted string.
fn quote_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Render a minimal RFC 3501 envelope for a message.
fn envelope_of(message: &StoredMessage) -> String {
    fn addresses(list: &[crate::storage::Address]) -> String {
        if list.is_empty() {
            return "NIL".to_string();
        }
        let items: Vec<String> = list
            .iter()
            .map(|address| {
                format!(
                    "({} NIL {})",
                    quote_text(address.name.as_deref().unwrap_or("")),
                    quote_text(&address.address)
                )
            })
            .collect();
        format!("({})", items.join(""))
    }

    format!(
        "NIL {} {} {} NIL NIL NIL {}",
        quote_text(&message.subject),
        addresses(&message.from),
        addresses(&message.to),
        quote_text(&message.id)
    )
}

/// Build a stored message from a raw RFC 5322 message.
fn build_message(mailbox: &str, payload: &[u8], id: String) -> StoredMessage {
    let mut message = StoredMessage {
        id,
        mailbox: mailbox.to_string(),
        from: Vec::new(),
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: String::new(),
        body_text: String::new(),
        body_html: None,
        headers: Default::default(),
        date: now_seconds(),
        read: false,
        flagged: false,
        deleted: false,
        raw: Some(String::from_utf8_lossy(payload).into_owned()),
        encrypted: false,
        attachments: Vec::new(),
    };

    if let Some(parsed) = MessageParser::default().parse(payload) {
        message.subject = parsed.subject().unwrap_or_default().to_string();
        message.body_text = parsed
            .body_text(0)
            .map(|text| text.into_owned())
            .unwrap_or_default();
        message.body_html = parsed.body_html(0).map(|html| html.into_owned());
        message.date = parsed
            .date()
            .map(|date| date.to_timestamp())
            .unwrap_or_else(now_seconds);
        message.from = collect_addresses(parsed.from());
        message.to = collect_addresses(parsed.to());
        message.cc = collect_addresses(parsed.cc());
    }

    message
}

/// Collect the addresses of a header into the storage representation.
fn collect_addresses(address: Option<&mail_parser::Address>) -> Vec<crate::storage::Address> {
    address
        .and_then(|address| address.as_list())
        .map(|list| {
            list.iter()
                .map(|entry| crate::storage::Address {
                    name: entry.name().map(|name| name.to_string()),
                    address: entry.address().unwrap_or_default().to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Current unix timestamp in seconds.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or_default()
}

/// Build a unique identifier for a stored message.
fn generate_id() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default();
    let random = crate::storage::hex_encode(&crate::crypto::generate_salt(6));
    format!("{millis:x}-{random}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_tagged_command() {
        let (tag, rest) = split_command("a001 LOGIN user pass\r\n");
        assert_eq!(tag, "a001");
        assert_eq!(rest, "LOGIN user pass");
    }

    #[test]
    fn tokenizes_quoted_arguments() {
        let tokens = tokenize("\"INBOX\" (MESSAGES UNSEEN)");
        assert_eq!(tokens, vec!["INBOX", "MESSAGES", "UNSEEN"]);
    }

    #[test]
    fn parses_sequence_sets() {
        assert_eq!(parse_sequence("1", 3), vec![0]);
        assert_eq!(parse_sequence("1:*", 3), vec![0, 1, 2]);
        assert_eq!(parse_sequence("2,3", 3), vec![1, 2]);
        assert_eq!(parse_sequence("9", 3), Vec::<usize>::new());
    }

    #[test]
    fn quotes_text_for_imap() {
        assert_eq!(quote_text("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn builds_a_message_from_a_raw_payload() {
        let raw = b"Subject: Hello\r\nFrom: a@example.org\r\n\r\nBody text\r\n";
        let message = build_message("INBOX", raw, "id-1".to_string());
        assert_eq!(message.subject, "Hello");
        assert_eq!(message.mailbox, "INBOX");
        assert!(message.body_text.contains("Body text"));
        assert_eq!(message.from.len(), 1);
    }
}