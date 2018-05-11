use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::{bpf_attach_uprobe, bpf_detach_uprobe};
use failure::Error;
use libc::pid_t;

use symbol;
use types::MutPointer;
use util::make_alphanumeric;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;
use std::ptr;

#[derive(Debug)]
pub struct Uprobe {
    code_fd: File,
    name: CString,
    p: MutPointer,
}

impl Drop for Uprobe {
    fn drop(&mut self) {
        unsafe {
            bpf_detach_uprobe(self.name.as_ptr());
        }
    }
}

impl Eq for Uprobe {}

impl Hash for Uprobe {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for Uprobe {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Uprobe {
    fn new(
        name: &str,
        attach_type: u32,
        binary_path: &str,
        addr: u64,
        file: File,
        _pid: pid_t,
    ) -> Result<Self, Error> {
        let cname = CString::new(name).map_err(|_| {
            format_err!("Nul byte in Uprobe name: {}", name)
        })?;
        let cpath = CString::new(binary_path).map_err(|_| {
            format_err!("Nul byte in Uprobe binary path: {}", binary_path)
        })?;
        // TODO: maybe pass in the CPU & PID instead of
        let (pid, cpu, group_fd) = (-1, 0, -1);
        let ptr = unsafe {
            bpf_attach_uprobe(
                file.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cpath.as_ptr(),
                addr,
                pid,
                cpu,
                group_fd,
                None,
                ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            Err(format_err!("Failed to attach Uprobe: {}", name))
        } else {
            Ok(Self {
                p: ptr,
                name: cname,
                code_fd: file,
            })
        }
    }

    pub fn attach_uprobe(
        binary_path: &str,
        symbol: &str,
        file: File,
        pid: pid_t,
    ) -> Result<Self, Error> {
        let (path, addr) = symbol::resolve_symbol_path(binary_path, symbol, 0x0, pid)?;
        let path = make_alphanumeric(&path);
        let name = format!("r_{}_0x{:x}", &path, addr);
        Uprobe::new(&name, BPF_PROBE_ENTRY, &path, addr, file, pid)
            .map_err(|_| format_err!("Failed to attach Uprobe: {}", name))
    }

    pub fn attach_uretprobe(
        binary_path: &str,
        symbol: &str,
        file: File,
        pid: pid_t,
    ) -> Result<Self, Error> {
        let (path, addr) = symbol::resolve_symbol_path(binary_path, symbol, 0x0, pid)?;
        let path = make_alphanumeric(&path);
        let name = format!("r_{}_0x{:x}", &path, addr);
        Uprobe::new(&name, BPF_PROBE_RETURN, &path, addr, file, pid)
            .map_err(|_| format_err!("Failed to attach Uretprobe: {}", name))
    }
}
