use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::*;
use failure::*;

use crate::core::make_alphanumeric;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;

#[derive(Debug)]
pub struct Kprobe {
    code_fd: File,
    name: CString,
    p: i32,
}

impl Kprobe {
    fn new(name: &str, attach_type: u32, function: &str, code: File) -> Result<Self, Error> {
        let cname =
            CString::new(name).map_err(|_| format_err!("Nul byte in Kprobe name: {}", name))?;
        let cfunction = CString::new(function)
            .map_err(|_| format_err!("Nul byte in Kprobe function: {}", function))?;
        let ptr = unsafe {
            bpf_attach_kprobe(
                code.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cfunction.as_ptr(),
                0,
                -1,
            )
        };
        if ptr < 0 {
            Err(format_err!("Failed to attach Kprobe: {}", name))
        } else {
            Ok(Self {
                p: ptr,
                name: cname,
                code_fd: code,
            })
        }
    }

    pub fn attach_kprobe(function: &str, code: File) -> Result<Self, Error> {
        let name = format!("p_{}", &make_alphanumeric(function));
        Kprobe::new(&name, BPF_PROBE_ENTRY, function, code)
            .map_err(|_| format_err!("Failed to attach Kprobe: {}", name))
    }

    pub fn attach_kretprobe(function: &str, code: File) -> Result<Self, Error> {
        let name = format!("r_{}", &make_alphanumeric(function));
        Kprobe::new(&name, BPF_PROBE_RETURN, function, code)
            .map_err(|_| format_err!("Failed to attach Kretprobe: {}", name))
    }
}

impl Drop for Kprobe {
    fn drop(&mut self) {
        unsafe {
            bpf_detach_kprobe(self.name.as_ptr());
        }
    }
}

impl Eq for Kprobe {}

impl Hash for Kprobe {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for Kprobe {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
