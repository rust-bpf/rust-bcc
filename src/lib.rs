//! Rust bindings for the BCC compiler collection to enable eBPF instrumentation
//!
//! # Goals
//! * Provide idiomatic Rust bindings for the BCC compiler collection
//! * Mimic the Python BCC bindings <https://github.com/iovisor/bcc>
//!
//! # Examples
//! * see <https://github.com/rust-bpf/rust-bcc/tree/master/examples>

mod core;
pub mod cpuonline;
mod error;
mod kprobe;
pub mod perf_event;
mod raw_tracepoint;
pub mod symbol;
pub mod table;
mod tracepoint;
mod types;
mod uprobe;
mod xdp;

#[macro_use]
extern crate bitflags;

pub use crate::core::{BPFBuilder, BccDebug, BpfProgType, BPF};
pub use error::BccError;
pub use kprobe::{Kprobe, Kretprobe};
pub use perf_event::{PerfEvent, PerfEventArray, PerfMap};
pub use raw_tracepoint::RawTracepoint;
pub use tracepoint::Tracepoint;
pub use uprobe::{Uprobe, Uretprobe};
pub use xdp::{Mode as XDPMode, XDP};
