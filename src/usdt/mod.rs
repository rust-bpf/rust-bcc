use std::{collections::HashSet, ffi::{CStr, CString}, path::{Path, PathBuf}, ptr};
use std::os::unix::ffi::OsStrExt;

use bcc_sys::bccapi::{bcc_usdt_enable_fully_specified_probe, bcc_usdt_enable_probe, bcc_usdt_genargs, bcc_usdt_get_location, bcc_usdt_location, bcc_usdt_uprobe_cb, pid_t};
use bcc_sys::bccapi::{bcc_usdt_new_frompath, bcc_usdt_new_frompid, bcc_usdt_close};
use libc::{c_int, c_void};

use crate::{BPF, Uprobe, error::BccError};

pub struct USDTProbe {
    binary: String,
    provider: String,
    probe: String,
    handler: String,
    address: u64,
    pid: Option<pid_t>,
}

#[derive(Default)]
pub struct USDTContexts(Vec<USDTContext>);

impl USDTContexts {
    pub fn add_contexts<I: Iterator<Item = USDTContext>>(&mut self, contexts: I) {
        self.0.extend(contexts);
    }

    pub fn generate_args(mut self) -> Result<(String, Vec<USDTContext>), BccError> {
        let mut ptrs = Vec::new();
        for context in &mut self.0 {
            ptrs.push(context.as_context_ptr());
        }
        let (ctx_array, len) = (ptrs.as_mut_ptr(), ptrs.len() as c_int);

        let result = unsafe { bcc_usdt_genargs(ctx_array, len) };
        if result.is_null() {
            Err(BccError::GenerateUSDTProbeArguments)
        } else {
            let code = unsafe { CStr::from_ptr(result).to_str().map(|s| s.to_owned())? };
            Ok((code, self.0))
        }
    }
}

pub struct USDTContext {
    context: *mut c_void,
    pid: Option<pid_t>,
    probes: HashSet<(String, String, String)>,
}

impl USDTContext {
    /// Create a new USDT context from a PID.
    pub fn with_pid(pid: pid_t) -> Result<Self, BccError> {
        Self::new(Some(pid), None)
    }

    /// Create a new USDT context from a path to the binary.
    pub fn with_binary_path<T: AsRef<Path>>(path: T) -> Result<Self, BccError> {
        Self::new(None, Some(PathBuf::from(path.as_ref())))
    }

    /// Create a new USDT context from a path to the binary and a specific PID.
    pub fn with_binary_path_and_pid<T: AsRef<Path>>(path: T, pid: pid_t) -> Result<Self, BccError> {
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
            Ok(Self { context, pid, probes: HashSet::new() })
        }
    }

    pub fn enable_probe(&mut self, probe: String, fn_name: String) -> Result<(), BccError> {
        let mut probe_parts = probe.split(":").map(|s| s.to_owned()).collect::<Vec<_>>();
        let fn_name_c = CString::new(fn_name.clone())?;
        let result = if probe_parts.len() == 1 {
            let probe_c = CString::new(probe.clone())?;
            let result = unsafe { bcc_usdt_enable_probe(self.context, probe_c.as_ptr(), fn_name_c.as_ptr()) };
            if result == 0 {
                self.probes.insert((String::new(), probe.clone(), fn_name));
            }
            result
        } else {
            let provider = probe_parts.remove(0);
            let provider_c = CString::new(provider.clone())?;
            let probe = probe_parts.remove(0);
            let probe_c = CString::new(probe.clone())?;

            let result = unsafe { bcc_usdt_enable_fully_specified_probe(self.context, provider_c.as_ptr(), probe_c.as_ptr(), fn_name_c.as_ptr()) };
            if result == 0 {
                self.probes.insert((provider, probe.clone(), fn_name));
            }
            result
        };

        if result != 0 {
            Err(BccError::USDTEnableProbe { probe })
        } else {
            Ok(())
        }
    }

    pub fn attach(self, bpf: &mut BPF, attach_usdt_ignore_pid: bool) -> Result<(), BccError> {
        let probes = self.enumerate_active_probes()?;
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

    pub(crate) fn as_context_ptr(&mut self) -> *mut c_void {
        self.context
    }

    fn enumerate_active_probes(&self) -> Result<Vec<USDTProbe>, BccError> {
        // we only keep a list of the logical probes we attached i.e. "attach to pid/binary X, for
        // probe Y", but Y might actually correspond to multiple locations in the target, so we
        // need to properly track all of the locations we're attached to, hence all of this.
        //
        // we don't use bcc_usdt_foreach_uprobe because closures in Rust and FFI don't really mix,
        // and it doesn't take a user data pointer :/
        let mut probes = Vec::new();

        for (provider, probe, fn_name) in &self.probes {
            let mut i = 0;
            let provider_c = CString::new(provider.clone())?;
            let probe_c = CString::new(probe.clone())?;
            loop {
                let mut loc = bcc_usdt_location::default();
                unsafe {
                    let result = bcc_usdt_get_location(self.context, provider_c.as_ptr(), probe_c.as_ptr(), i, &mut loc as *mut _);
                    if result != 0 {
                        break;
                    }
                }
                i += 1;

                let binary = unsafe { CStr::from_ptr(loc.bin_path).to_str().map(|s| s.to_string())? };
                probes.push(USDTProbe {
                    binary,
                    provider: provider.clone(),
                    probe: probe.clone(),
                    handler: fn_name.clone(),
                    address: loc.address,
                    pid: self.pid
                });
            }
        }

        Ok(probes)
    }
}

impl Drop for USDTContext {
    fn drop(&mut self) {
        unsafe { bcc_usdt_close(self.context); }
    }
}