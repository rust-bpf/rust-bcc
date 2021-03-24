use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr;
use std::os::unix::ffi::OsStrExt;

use bcc_sys::bccapi::{bcc_usdt_enable_fully_specified_probe, bcc_usdt_enable_probe, bcc_usdt_foreach_uprobe, bcc_usdt_genargs, pid_t};
use bcc_sys::bccapi::{bcc_usdt_new_frompath, bcc_usdt_new_frompid, bcc_usdt_close};
use libc::{c_int, c_void};

use crate::{BPF, Uprobe, error::BccError};

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
pub fn usdt_generate_args(mut contexts: Vec<USDTContext>) -> Result<(String, Vec<USDTContext>), BccError> {
    // Build an array of pointers to each underlying USDT context.
    let mut ptrs = contexts.iter_mut().map(|c| c.as_context_ptr()).collect::<Vec<_>>();
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
    context: *mut c_void,
    probes: HashSet<(String, String, String)>,
}

impl USDTContext {
    /// Create a new USDT context from a PID.
    pub fn from_pid(pid: pid_t) -> Result<Self, BccError> {
        Self::new(Some(pid), None)
    }

    /// Create a new USDT context from a path to the binary.
    pub fn from_binary_path<T: AsRef<Path>>(path: T) -> Result<Self, BccError> {
        Self::new(None, Some(PathBuf::from(path.as_ref())))
    }

    /// Create a new USDT context from a path to the binary and a specific PID.
    pub fn from_binary_path_and_pid<T: AsRef<Path>>(path: T, pid: pid_t) -> Result<Self, BccError> {
        Self::new(Some(pid), Some(PathBuf::from(path.as_ref())))
    }

    fn new(pid: Option<pid_t>, path: Option<PathBuf>) -> Result<Self, BccError> {
        let context = match (pid, path) {
            (None, None) => ptr::null_mut(),
            (None, Some(path)) => {
                let c_path = CString::new(path.as_os_str().as_bytes().to_owned())?;
                unsafe { bcc_usdt_new_frompath(c_path.as_ptr()) }
            },
            (Some(pid), None) => {
                unsafe { bcc_usdt_new_frompid(pid, ptr::null()) }
            },
            (Some(pid), Some(path)) => {
                let c_path = CString::new(path.as_os_str().as_bytes().to_owned())?;
                unsafe { bcc_usdt_new_frompid(pid, c_path.as_ptr()) } 
            },
        };

        if context.is_null() {
            Err(BccError::CreateUSDTContext { message: format!("failed to create USDT context") })
        } else {
            Ok(Self { context, probes: HashSet::new() })
        }
    }

    /// Enables a probe, calling a function in the BPF program whenever the tracepoint is hit.
    ///
    /// The `probe` argument is the name of tracepoint to enable.  The probe name can either be in
    /// the generic form -- simply the name of the tracepoint itself -- or the prefixed form of
    /// `<provider>:<name>`.
    ///
    /// The `fn_name` argument is the name of the function in the BPF program to call when the given
    /// tracepoint is hit.  This function will be called with the given arguments for the tracepoint.
    pub fn enable_probe(&mut self, probe: impl Into<String>, fn_name: impl Into<String>) -> Result<(), BccError> {
        let probe = probe.into();
        let fn_name = fn_name.into();

        let mut probe_parts = probe.split(":").map(|s| s.to_owned()).collect::<Vec<_>>();
        let fn_name_c = CString::new(fn_name.clone())?;
        let result = if probe_parts.len() == 2 {
            let provider = probe_parts.remove(0);
            let provider_c = CString::new(provider.clone())?;
            let probe = probe_parts.remove(0);
            let probe_c = CString::new(probe.clone())?;

            let result = unsafe { bcc_usdt_enable_fully_specified_probe(self.context, provider_c.as_ptr(), probe_c.as_ptr(), fn_name_c.as_ptr()) };
            if result == 0 {
                self.probes.insert((provider, probe.clone(), fn_name));
            }
            result
        } else {
            let probe_c = CString::new(probe.clone())?;
            let result = unsafe { bcc_usdt_enable_probe(self.context, probe_c.as_ptr(), fn_name_c.as_ptr()) };
            if result == 0 {
                self.probes.insert((String::new(), probe.clone(), fn_name));
            }
            result
        };

        if result != 0 {
            // Possible causes here: no permissions (need sudo), nonexistent probe.
            Err(BccError::USDTEnableProbe { probe })
        } else {
            Ok(())
        }
    }

    /// Attaches this context to a given BPF program.
    ///
    /// If `attach_usdt_ignore_pid` is true, it will attach this context to all matching processes.
    /// Otherwise, it will attach this context to the specified PID only.
    pub fn attach(mut self, bpf: &mut BPF, attach_usdt_ignore_pid: bool) -> Result<(), BccError> {
        let probes = self.enumerate_active_probes();
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

    fn as_context_ptr(&mut self) -> *mut c_void {
        self.context
    }

    fn enumerate_active_probes(&mut self) -> Vec<USDTProbe> {
        // Query for all of the enabled probes.  This reads them into a TLS variable which we'll
        // swap out with a new, empty container.  Long story short, no way to pass user data for the
        // callback to use, so we need a TLS variable on the Rust side.
        unsafe { bcc_usdt_foreach_uprobe(self.context, Some(uprobe_foreach_cb)); }
        PROBES.with(|probes| probes.replace(Vec::new()))
    }
}

impl Drop for USDTContext {
    fn drop(&mut self) {
        unsafe { bcc_usdt_close(self.context); }
    }
}

/// Callback function for `bcc_usdt_foreach_uprobe`.
///
/// Uses a TLS variable to get around the fact that the function this callback is passed to has no
/// option to pass user data, so to do this safely on the Rust side, we need a TLS variable this
/// callback can statically reference and read out of after the operation.
unsafe extern "C" fn uprobe_foreach_cb(
    bin_path: *const ::std::os::raw::c_char,
    fn_name: *const ::std::os::raw::c_char,
    address: u64,
    pid: ::std::os::raw::c_int
) {
    PROBES.with(|probes| {
        let binary = CStr::from_ptr(bin_path).to_str().map(|s| s.to_owned()).ok();
        let handler = CStr::from_ptr(fn_name).to_str().map(|s| s.to_owned()).ok();

        if binary.is_some() && handler.is_some() {
            probes.borrow_mut().push(USDTProbe {
                binary: binary.unwrap(),
                handler: handler.unwrap(),
                address,
                pid: Some(pid),
            });
        }
    })
}