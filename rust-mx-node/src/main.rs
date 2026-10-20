//! DOM Mail MX Node - the server binary.
//!
//! The binary is the node itself: it serves the mail protocols, it runs as
//! an operating system service and it manages its own configuration file.

use domail_mx_node::auth::CredentialStore;
use domail_mx_node::config::{self, MxNodeConfig, SmtpConfig};
use domail_mx_node::control::{ControlContext, ControlServer};
use domail_mx_node::crypto::{generate_salt, Argon2Params};
use domail_mx_node::imap::{ImapContext, ImapServer};
use domail_mx_node::smtp::{SmtpContext, SmtpMode, SmtpServer};
use domail_mx_node::storage::{
    create_storage, hex_encode, load_or_create_master_key, EncryptedStorage,
};
use domail_mx_node::submission::SubmissionServer;
use domail_mx_node::transport::init_transports;
use domail_mx_node::{service, tls, VERSION};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::info;

/// The commands that the binary understands.
const COMMANDS: &[(&str, &str)] = &[
    ("serve", "run the node in the foreground"),
    ("install", "install the operating system service"),
    ("uninstall", "remove the operating system service"),
    ("status", "show the state of the operating system service"),
    ("token", "print the token of the control API"),
    (
        "hash-password",
        "hash a password for the configuration file",
    ),
    ("doctor", "check the installation and report problems"),
    ("config", "print the effective configuration"),
    ("help", "show this text"),
    ("version", "show the version"),
];

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = match arguments.split_first() {
        Some((first, rest)) => (first.clone(), rest.to_vec()),
        None => ("serve".to_string(), Vec::new()),
    };

    let result = match command.as_str() {
        "serve" => run_serve(&rest),
        "install" => run_install(&rest),
        "uninstall" => run_uninstall(&rest),
        "status" => run_status(&rest),
        "token" => run_token(&rest),
        "hash-password" => run_hash_password(&rest),
        "doctor" => run_doctor(&rest),
        "config" => run_config(&rest),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "version" | "--version" => {
            println!("DOM Mail MX Node {VERSION}");
            Ok(())
        }
        other => Err(format!("unknown command: {other}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Print the list of commands.
fn print_help() {
    println!("DOM Mail MX Node {VERSION}");
    println!();
    println!("Usage: mx-node <command> [options]");
    println!();
    for (name, description) in COMMANDS {
        println!("  {name:<14} {description}");
    }
    println!();
    println!("Options:");
    println!("  --config <path>   use another configuration file");
    println!("  --domain <name>   serve another domain");
}

/// The path of the configuration file.
fn config_path(arguments: &[String]) -> Result<PathBuf, String> {
    let mut index = 0;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--config" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| "--config needs a path".to_string())?;
                return Ok(PathBuf::from(value));
            }
            other if other.starts_with("--config=") => {
                return Ok(PathBuf::from(&other["--config=".len()..]));
            }
            _ => index += 1,
        }
    }

    Ok(config::default_config_path())
}

/// Load the configuration file, creating it when it is missing.
fn load_or_create_config(path: &Path) -> Result<MxNodeConfig, String> {
    let mut config = if path.exists() {
        MxNodeConfig::load(path).map_err(|e| e.to_string())?
    } else {
        MxNodeConfig::default()
    };

    let mut changed = false;

    if config.control.token.is_empty() {
        config.control.token = generate_token();
        changed = true;
    }

    if config.cert_pem.is_empty() || config.key_pem.is_empty() {
        ensure_certificate(&mut config)?;
        changed = true;
    }

    if changed {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        config.save(path).map_err(|e| e.to_string())?;
    }

    Ok(config)
}

/// Apply the domain given on the command line.
fn apply_domain(config: &mut MxNodeConfig, arguments: &[String]) -> Result<(), String> {
    let mut index = 0;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--domain" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| "--domain needs a name".to_string())?;
                if value.trim().is_empty() {
                    return Err("--domain needs a name".to_string());
                }
                config.domain = value.clone();
                config.hostname = value.clone();
                index += 2;
            }
            other if other.starts_with("--domain=") => {
                let value = other["--domain=".len()..].to_string();
                if value.trim().is_empty() {
                    return Err("--domain needs a name".to_string());
                }
                config.domain = value.clone();
                config.hostname = value.clone();
                index += 1;
            }
            _ => index += 1,
        }
    }

    Ok(())
}

/// Build a random token for the control API.
fn generate_token() -> String {
    hex_encode(&generate_salt(32))
}

/// Give the node a self signed certificate when it has none.
fn ensure_certificate(config: &mut MxNodeConfig) -> Result<(), String> {
    let names = vec![config.hostname.clone()];
    let certificate = rcgen::generate_simple_self_signed(names).map_err(|e| e.to_string())?;
    config.cert_pem = certificate.cert.pem();
    config.key_pem = certificate.key_pair.serialize_pem();
    Ok(())
}

/// Run the node.
fn run_serve(arguments: &[String]) -> Result<(), String> {
    let path = config_path(arguments)?;
    let mut config = load_or_create_config(&path)?;
    apply_domain(&mut config, arguments)?;

    let (stop, stop_rx) = watch::channel(false);

    // The service control manager owns the process when the node runs as a
    // service. Everywhere else the node runs in the foreground.
    #[cfg(windows)]
    {
        let service_config = config.service.clone();
        let action: service::ServiceAction = {
            let config = config.clone();
            let stop_rx = stop_rx.clone();
            Arc::new(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                runtime
                    .block_on(serve_node(config, stop_rx))
                    .map_err(|e| e.to_string())
            })
        };

        match service::run_as_service(&service_config, action, Arc::new(stop.clone())) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::debug!(error = %e, "the node does not run under a service manager");
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    runtime
        .block_on(serve_node(config, stop_rx))
        .map_err(|e| e.to_string())
}

/// Start every listener of the node and wait until it is asked to stop.
async fn serve_node(config: MxNodeConfig, mut stop: watch::Receiver<bool>) -> Result<(), String> {
    let tls_acceptor = if config.cert_pem.is_empty() || config.key_pem.is_empty() {
        None
    } else {
        Some(tls::acceptor(&config.cert_pem, &config.key_pem).map_err(|e| e.to_string())?)
    };

    let backend = create_storage(&config.storage)
        .await
        .map_err(|e| e.to_string())?;
    let key_path = Path::new(&config.storage.db_path).join("master.key");
    let master_key = load_or_create_master_key(&key_path).map_err(|e| e.to_string())?;
    let storage = Arc::new(EncryptedStorage::new(backend, master_key));

    let transports = Arc::new(
        init_transports(config.transports.clone())
            .await
            .map_err(|e| e.to_string())?,
    );
    for (id, result) in transports.activate_all().await {
        if let Err(e) = result {
            tracing::warn!(transport = %id, error = %e, "the transport could not be activated");
        }
    }

    let credentials = Arc::new(CredentialStore::from_config(&config));

    let smtp_context = SmtpContext {
        config: Arc::new(config.smtp.clone()),
        mode: SmtpMode::Incoming,
        domain: config.domain.clone(),
        hostname: config.hostname.clone(),
        tls_acceptor: tls_acceptor.clone(),
        credentials: Arc::clone(&credentials),
        users: config.users.clone(),
        storage: Arc::clone(&storage),
        transports: Arc::clone(&transports),
    };
    let smtp = SmtpServer::new(smtp_context);
    let smtp_address = smtp.start().await.map_err(|e| e.to_string())?;
    info!(address = %smtp_address, "the SMTP listener is ready");

    let submission_config = SmtpConfig {
        bind_addr: config.submission.bind_addr,
        implicit_tls_bind: config.submission.implicit_tls_bind,
        require_starttls: config.submission.require_starttls,
        ..config.smtp.clone()
    };
    let submission_context = SmtpContext {
        config: Arc::new(submission_config),
        mode: SmtpMode::Submission,
        domain: config.domain.clone(),
        hostname: config.hostname.clone(),
        tls_acceptor: tls_acceptor.clone(),
        credentials: Arc::clone(&credentials),
        users: config.users.clone(),
        storage: Arc::clone(&storage),
        transports: Arc::clone(&transports),
    };
    let submission = SubmissionServer::new(submission_context);
    match submission.start().await {
        Ok(address) => info!(address = %address, "the submission listener is ready"),
        Err(e) => tracing::warn!(error = %e, "the submission listener could not be started"),
    }

    let imap_context = ImapContext {
        config: Arc::new(config.imap.clone()),
        domain: config.domain.clone(),
        hostname: config.hostname.clone(),
        tls_acceptor: tls_acceptor.clone(),
        credentials: Arc::clone(&credentials),
        users: config.users.clone(),
        storage: Arc::clone(&storage),
    };
    let imap = ImapServer::new(imap_context);
    match imap.start().await {
        Ok(address) => info!(address = %address, "the IMAP listener is ready"),
        Err(e) => tracing::warn!(error = %e, "the IMAP listener could not be started"),
    }

    let control = if config.control.enabled {
        let server = ControlServer::new(ControlContext {
            config: Arc::new(config.clone()),
            transports: Arc::clone(&transports),
            token: config.control.token.clone(),
        });
        match server.start().await {
            Ok(address) => info!(address = %address, "the control API is ready"),
            Err(e) => {
                tracing::warn!(error = %e, "the control API could not be started");
                None
            }
        }
    } else {
        None
    };

    info!(
        domain = %config.domain,
        hostname = %config.hostname,
        "the node is serving mail"
    );

    tokio::select! {
        changed = stop.changed() => {
            if changed.is_err() {
                info!("the node was asked to stop");
            }
        }
        result = tokio::signal::ctrl_c() => {
            info!(?result, "the node was asked to stop");
        }
    }

    smtp.stop();
    submission.stop();
    imap.stop();
    if let Some(control) = control {
        control.stop();
    }

    info!("the node stopped");
    Ok(())
}

/// Install the operating system service.
fn run_install(arguments: &[String]) -> Result<(), String> {
    let path = config_path(arguments)?;
    let config = load_or_create_config(&path)?;

    let status = service::install(&config.service).map_err(|e| e.to_string())?;
    println!("the service {} is installed", status.kind);

    if config.control.enabled {
        println!();
        println!("The control API listens on {}", config.control.bind_addr);
        println!("The settings wizard needs this token:");
        println!("  {}", config.control.token);
    }

    println!();
    println!("The configuration lives in {}", path.display());
    Ok(())
}

/// Remove the operating system service.
fn run_uninstall(arguments: &[String]) -> Result<(), String> {
    let path = config_path(arguments)?;
    let config = MxNodeConfig::load(&path).map_err(|e| e.to_string())?;
    service::uninstall(&config.service).map_err(|e| e.to_string())?;
    println!("the service was removed");
    Ok(())
}

/// Show the state of the operating system service.
fn run_status(arguments: &[String]) -> Result<(), String> {
    let path = config_path(arguments)?;
    let config = MxNodeConfig::load(&path).map_err(|e| e.to_string())?;
    let status = service::status(&config.service).map_err(|e| e.to_string())?;

    println!("kind:     {}", status.kind);
    println!("installed: {}", status.installed);
    println!("running:   {}", status.running);
    Ok(())
}

/// Print the token of the control API.
fn run_token(arguments: &[String]) -> Result<(), String> {
    let path = config_path(arguments)?;
    let config = load_or_create_config(&path)?;
    println!("{}", config.control.token);
    Ok(())
}

/// Hash a password so that it can be put into the configuration file.
fn run_hash_password(arguments: &[String]) -> Result<(), String> {
    let password = arguments
        .iter()
        .find(|value| !value.starts_with("--"))
        .ok_or_else(|| "hash-password needs a password".to_string())?;

    let params = Argon2Params::default();
    let hash = domail_mx_node::auth::hash_password(password, &params).map_err(|e| e.to_string())?;
    println!("{hash}");
    Ok(())
}

/// Print the effective configuration.
fn run_config(arguments: &[String]) -> Result<(), String> {
    let path = config_path(arguments)?;
    let config = MxNodeConfig::load(&path).map_err(|e| e.to_string())?;
    let text = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    println!("{text}");
    Ok(())
}

/// Check the installation and report the problems that were found.
fn run_doctor(arguments: &[String]) -> Result<(), String> {
    let path = config_path(arguments)?;
    let config = MxNodeConfig::load(&path).map_err(|e| e.to_string())?;
    let mut problems: Vec<String> = Vec::new();

    if let Err(e) = config.validate() {
        problems.push(format!("the configuration is not valid: {e}"));
    }

    if config.cert_pem.is_empty() || config.key_pem.is_empty() {
        problems.push("no TLS certificate is configured, STARTTLS is not available".to_string());
    } else if let Err(e) = tls::parse_certificates(&config.cert_pem) {
        problems.push(format!("the TLS certificate cannot be read: {e}"));
    }

    let storage_path = Path::new(&config.storage.db_path);
    if storage_path.is_absolute() {
        if let Some(parent) = storage_path.parent() {
            if !parent.exists() {
                problems.push(format!(
                    "the storage directory {} does not exist",
                    parent.display()
                ));
            }
        }
    }

    if config.control.enabled && config.control.token.is_empty() {
        problems.push("the control API is enabled but has no token".to_string());
    }

    if config.users.is_empty() {
        problems.push("no accounts are configured, so no mail can be read".to_string());
    }

    println!("DOM Mail MX Node {VERSION}");
    println!("  domain:     {}", config.domain);
    println!("  hostname:   {}", config.hostname);
    println!("  smtp:       {}", config.smtp.bind_addr);
    println!("  submission: {}", config.submission.bind_addr);
    println!("  imap:       {}", config.imap.bind_addr);
    println!("  control:    {}", config.control.bind_addr);
    println!("  transports: {}", config.transports.len());
    println!("  accounts:   {}", config.users.len());

    if problems.is_empty() {
        println!("no problems found");
        return Ok(());
    }

    println!();
    for problem in &problems {
        println!("  problem: {problem}");
    }
    Err(format!("{} problem(s) found", problems.len()))
}
