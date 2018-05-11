use bcc_sys::bccapi::{bpf_attach_tracepoint, bpf_detach_tracepoint};
use failure::Error;

use types::MutPointer;
use util::make_alphanumeric;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;
use std::ptr;

#[derive(Debug)]
pub struct Tracepoint {
    subsystem: CString,
    name: CString,
    code_fd: File,
    p: MutPointer,
}

impl Drop for Tracepoint {
    fn drop(&mut self) {
        unsafe {
            bpf_detach_tracepoint(self.subsystem.as_ptr(), self.name.as_ptr());
        }
    }
}

impl Eq for Tracepoint {}

impl Hash for Tracepoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.subsystem.hash(state);
        self.name.hash(state);
    }
}

impl PartialEq for Tracepoint {
    fn eq(&self, other: &Tracepoint) -> bool {
        self.subsystem == other.subsystem && self.name == other.name
    }
}

impl Tracepoint {
    pub fn attach_tracepoint(subsystem: &str, name: &str, file: File) -> Result<Self, Error> {
        let csubsystem = CString::new(make_alphanumeric(subsystem)).map_err(|_| {
            format_err!("Nul byte in Tracepoint subsystem: {}", subsystem)
        })?;
        let cname = CString::new(make_alphanumeric(name)).map_err(|_| {
            format_err!("Nul byte in Tracepoint name: {}", name)
        })?;
        // NOTE: BPF tracepoints are system-wide and do not support CPU filter
        let (pid, cpu, group_fd) = (-1, 0, -1);
        let ptr = unsafe {
            bpf_attach_tracepoint(
                file.as_raw_fd(),
                csubsystem.as_ptr(),
                cname.as_ptr(),
                pid,
                cpu,
                group_fd,
                None,
                ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            Err(format_err!(
                "Failed to attach Tracepoint: {}:{}",
                subsystem,
                name
            ))
        } else {
            Ok(Self {
                p: ptr,
                subsystem: csubsystem,
                name: cname,
                code_fd: file,
            })
        }
    }
}
