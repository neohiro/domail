//! DOM Mail MX Node - Core library
//!
//! A self-hosted mail server that runs in the browser via WebAssembly.
//! Supports SMTP, IMAP, and Submission protocols with multiple transport layers.

pub mod config;
pub mod crypto;
pub mod error;
pub mod imap;
pub mod smtp;
pub mod submission;
pub mod storage;
pub mod transport;
pub mod wasm;

pub use config::*;
pub use error::*;
pub use wasm::*;

/// Version of the MX Node
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the MX Node library
pub fn init() {
    #[cfg(feature = "console_log")]
    console_log::init_with_level(log::Level::Info).ok();
    
    #[cfg(target_arch = "wasm32")]
    {
        // Initialize panic hook for better error messages in WASM
        console_error_panic_hook::set_once();
    }
}