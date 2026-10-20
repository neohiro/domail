//! DOM Mail MX Node - core library.
//!
//! The node is a self-hosted mail server: it acts as the MX for its own
//! domain, serves SMTP, IMAP and Submission, and hands outbound mail to a
//! set of transport vectors.
//!
//! The server modules need a network stack, so they are only built for
//! native targets. The WebAssembly build carries the configuration and the
//! crypto core, which lets the browser drive the same code that the
//! service runs.

#[cfg(not(target_arch = "wasm32"))]
pub mod auth;
#[cfg(not(target_arch = "wasm32"))]
pub mod control;
#[cfg(not(target_arch = "wasm32"))]
pub mod http;
#[cfg(not(target_arch = "wasm32"))]
pub mod imap;
#[cfg(not(target_arch = "wasm32"))]
pub mod service;
#[cfg(not(target_arch = "wasm32"))]
pub mod smtp;
#[cfg(not(target_arch = "wasm32"))]
pub mod submission;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;

pub mod config;
pub mod crypto;
pub mod error;
pub mod storage;
pub mod transport;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub mod wasm;

pub use config::*;
pub use error::*;

/// Version of the MX node.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
