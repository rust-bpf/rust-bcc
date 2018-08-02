//! Rust bindings for the BCC compiler collection to enable eBPF instrumentation
//!
//! # Goals
//! * Provide idiomatic Rust bindings for the BCC compiler collection
//! * Mimic the Python BCC bindings <https://github.com/iovisor/bcc>
//!
//! # Examples
//! * see <https://github.com/jvns/rust-bcc/examples>

pub mod core;
pub mod symbol;
pub mod perf;
pub mod table;
mod types;
mod cpuonline;

#[macro_use]
extern crate failure;
extern crate libc;
extern crate bcc_sys;
extern crate byteorder;
#[cfg(test)] #[macro_use]
extern crate lazy_static;
