use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;

use bcc_sys::bccapi::{
    bcc_usdt_close, bcc_usdt_enable_fully_specified_probe, bcc_usdt_enable_probe,
    bcc_usdt_foreach_uprobe, bcc_usdt_genargs, bcc_usdt_new_frompath, bcc_usdt_new_frompid, pid_t,
};

use crate::error::BccError;
use crate::helpers::to_cstring;
use crate::types::MutPointer;
use crate::{Uprobe, BPF};

thread_local! {
    static PROBES: RefCell<Vec<USDTProbe>> = RefCell::new(Vec::new());
}

struct USDTProbe {
    binary: String,
    handler: String,
    address: u64,
    pid: Option<pid_t>,
}

/// Generates the C code for parsing the arguments of all enabled probes in each context.
pub fn usdt_generate_args(
    mut contexts: Vec<USDTContext>,
) -> Result<(String, Vec<USDTContext>), BccError> {
    // Build an array of pointers to each underlying USDT context.
    let mut ptrs = contexts.iter_mut().map(|c| c.context).collect::<Vec<_>>();
    let (ctx_array, len) = (ptrs.as_mut_ptr(), ptrs.len() as c_int);

    // Generate the C argument parsing code for all of the probes in all of the contexts.
    let result = unsafe { bcc_usdt_genargs(ctx_array, len) };
    if result.is_null() {
        Err(BccError::GenerateUSDTProbeArguments)
    } else {
        let code = unsafe { CStr::from_ptr(result).to_str().map(|s| s.to_owned())? };
        Ok((code, contexts))
    }
}

/// A USDT context.
///
/// A context represents a collection of probes -- tracepoint to function mappings -- for either a
/// given PID and/or a given binary path.
///
/// Tracepoints which are already statically defined are mapped to a specific function, such that
/// when the tracepoint is hit, the given function -- a function that must be defined in the BPF
/// program -- is called, with all of the arguments passed to the tracepoint itself.
pub struct USDTContext {
    context: MutPointer,
}

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

    fn new(pid: Option<pid_t>, path: Option<&str>) -> Result<Self, BccError> {
        let context = match (pid, path) {
            (None, None) => ptr::null_mut(),
            (None, Some(path)) => {
                let cpath = to_cstring(path, "path")?;
                unsafe { bcc_usdt_new_frompath(cpath.as_ptr()) }
            }
            (Some(pid), None) => unsafe { bcc_usdt_new_frompid(pid, ptr::null()) },
            (Some(pid), Some(path)) => {
                let cpath = to_cstring(path, "path")?;
                unsafe { bcc_usdt_new_frompid(pid, cpath.as_ptr()) }
            }
        };

        if context.is_null() {
            Err(BccError::CreateUSDTContext)
        } else {
            Ok(Self { context })
        }
    }

    /// Enables a probe, calling a function in the BPF program whenever the tracepoint is hit.
    ///
    /// The `probe` argument is the name of tracepoint to enable.  The probe name can either be in
    /// the generic form -- simply the name of the tracepoint itself -- or the prefixed form of
    /// `<provider>:<name>`.
    ///
    /// The `fn_name` argument is the name of the function in the BPF program to call when the given
    /// tracepoint is hit.  This function will be called with the given arguments for the
    /// tracepoint.
    pub fn enable_probe(
        &mut self,
        probe: impl Into<String>,
        fn_name: impl Into<String>,
    ) -> Result<(), BccError> {
        let probe = probe.into();
        let fn_name = fn_name.into();

        // The probe can be either `<symbol name>` or `<provider>:<symbol name>`.
        let mut probe_parts = probe.split(':').map(|s| s.to_string()).collect::<Vec<_>>();
        let cfn_name = to_cstring(fn_name, "fn_name")?;
        let result = if probe_parts.len() == 2 {
            let provider = probe_parts.remove(0);
            let cprovider = to_cstring(provider, "probe")?;
            let probe = probe_parts.remove(0);
            let cprobe = to_cstring(probe, "probe")?;

            unsafe {
                bcc_usdt_enable_fully_specified_probe(
                    self.context,
                    cprovider.as_ptr(),
                    cprobe.as_ptr(),
                    cfn_name.as_ptr(),
                )
            }
        } else {
            let cprobe = to_cstring(probe, "probe")?;
            unsafe { bcc_usdt_enable_probe(self.context, cprobe.as_ptr(), cfn_name.as_ptr()) }
        };

        if result != 0 {
            // Possible causes here: no permissions (need sudo), nonexistent probe.
            Err(BccError::EnableUSDTProbe)
        } else {
            Ok(())
        }
    }

    /// Attaches this context to a given BPF program.
    ///
    /// If `attach_usdt_ignore_pid` is true, it will attach this context to all matching processes.
    /// Otherwise, it will attach this context to the specified PID only.
    pub(crate) fn attach(
        self,
        bpf: &mut BPF,
        attach_usdt_ignore_pid: bool,
    ) -> Result<(), BccError> {
        // Query for all of the enabled probes.  This reads them into a TLS variable which we'll
        // swap out with a new, empty container.  Long story short, no way to pass user data for the
        // callback to use, so we need a TLS variable on the Rust side.
        unsafe {
            bcc_usdt_foreach_uprobe(self.context, Some(uprobe_foreach_cb));
        }

        let probes = PROBES.with(|probes| probes.replace(Vec::new()));
        for probe in probes {
            let pid = if attach_usdt_ignore_pid {
                None
            } else {
                probe.pid
            };

            let uprobe = Uprobe::new()
                .binary(probe.binary)
                .handler(probe.handler.as_str())
                .address(probe.address)
                .pid(pid);

            let _ = uprobe.attach(bpf)?;
        }

        Ok(())
    }
}

impl Drop for USDTContext {
    fn drop(&mut self) {
        unsafe {
            bcc_usdt_close(self.context);
        }
    }
}

/// Callback function for `bcc_usdt_foreach_uprobe`.
///
/// Uses a TLS variable to get around the fact that the function this callback is passed to has no
/// option to pass user data, so to do this safely on the Rust side, we need a TLS variable this
/// callback can statically reference and read out of after the operation.
unsafe extern "C" fn uprobe_foreach_cb(
    bin_path: *const c_char,
    fn_name: *const c_char,
    address: u64,
    pid: c_int,
) {
    PROBES.with(|probes| {
        let binary = CStr::from_ptr(bin_path).to_str().map(|s| s.to_owned()).ok();
        let handler = CStr::from_ptr(fn_name).to_str().map(|s| s.to_owned()).ok();

        if let Some(binary) = binary {
            if let Some(handler) = handler {
                probes.borrow_mut().push(USDTProbe {
                    binary,
                    handler,
                    address,
                    pid: Some(pid),
                });
            }
        }
    })
}
