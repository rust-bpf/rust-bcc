//! Rust bindings for the BCC compiler collection to enable eBPF instrumentation
//!
//! # Goals
//! * Provide idiomatic Rust bindings for the BCC compiler collection
//! * Mimic the Python BCC bindings <https://github.com/iovisor/bcc>
//!
//! # Examples
//! * see <https://github.com/rust-bpf/rust-bcc/tree/master/examples>

pub mod core;
mod cpuonline;
mod error;
pub mod perf;
pub mod symbol;
pub mod table;
mod types;

pub use error::BccError;
