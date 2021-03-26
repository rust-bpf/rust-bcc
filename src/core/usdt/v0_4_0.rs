use std::path::Path;

use bcc_sys::bccapi::pid_t;

use crate::BPF;
use crate::error::BccError;

pub fn usdt_generate_args(
    mut _contexts: Vec<USDTContext>,
) -> Result<(String, Vec<USDTContext>), BccError> {
    Err(BccError::BccVersionTooLow {
        cause: "USDT support is not enabled".to_owned(),
        min_version: "0.6.1".to_owned(),
    })
}

/// A USDT context.
///
/// A context represents a collection of probes -- tracepoint to function mappings -- for either a
/// given PID and/or a given binary path.
///
/// Tracepoints which are already statically defined are mapped to a specific function, such that
/// when the tracepoint is hit, the given function -- a function that must be defined in the BPF
/// program -- is called, with all of the arguments passed to the tracepoint itself.
pub struct USDTContext;

impl USDTContext {
    /// Create a new USDT context from a PID.
    pub fn from_pid(pid: pid_t) -> Result<Self, BccError> {
        Self::new(Some(pid), None)
    }

    /// Create a new USDT context from a path to the binary.
    pub fn from_binary_path<T: AsRef<Path>>(path: T) -> Result<Self, BccError> {
        Self::new(None, path.as_ref().to_str())
    }

    /// Create a new USDT context from a path to the binary and a specific PID.
    pub fn from_binary_path_and_pid<P: AsRef<Path>>(path: P, pid: pid_t) -> Result<Self, BccError> {
        Self::new(Some(pid), path.as_ref().to_str())
    }

    #[cfg(not(feature = "usdt"))]
    fn new(_pid: Option<pid_t>, _path: Option<&str>) -> Result<Self, BccError> {
        Err(BccError::BccVersionTooLow {
            cause: "USDT support is not enabled".to_owned(),
            min_version: "0.6.1".to_owned(),
        })
    }

    /// Attaches this context to a given BPF program.
    ///
    /// If `attach_usdt_ignore_pid` is true, it will attach this context to all matching processes.
    /// Otherwise, it will attach this context to the specified PID only.
    pub(crate) fn attach(self, _bpf: &mut BPF, _attach_usdt_ignore_pid: bool) -> Result<(), BccError> {
        Err(BccError::BccVersionTooLow {
            cause: "USDT support is not enabled".to_owned(),
            min_version: "0.6.1".to_owned(),
        })
    }
}
