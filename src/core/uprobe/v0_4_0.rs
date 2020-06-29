use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::*;

use crate::core::make_alphanumeric;
use crate::symbol;
use crate::types::MutPointer;
use crate::BccError;

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

impl Uprobe {
    fn new(
        name: &str,
        attach_type: u32,
        path: &str,
        addr: u64,
        file: File,
        pid: pid_t,
    ) -> Result<Self, BccError> {
        let cname = CString::new(name)?;
        let cpath = CString::new(path)?;
        // TODO: maybe pass in the CPU & PID instead of
        let (cpu, group_fd) = (0, -1);
        let uprobe_ptr = unsafe {
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
        if uprobe_ptr.is_null() {
            match attach_type {
                BPF_PROBE_ENTRY => Err(BccError::AttachUprobe {
                    name: name.to_string(),
                }),
                BPF_PROBE_RETURN => Err(BccError::AttachUretprobe {
                    name: name.to_string(),
                }),
                _ => unreachable!(),
            }
        } else {
            Ok(Self {
                code_fd: file,
                name: cname,
                p: uprobe_ptr,
            })
        }
    }

    pub fn attach_uprobe(
        binary_path: &str,
        symbol: &str,
        code: File,
        pid: pid_t,
    ) -> Result<Self, BccError> {
        let (path, addr) = symbol::resolve_symbol_path(binary_path, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        Uprobe::new(&ev_name, BPF_PROBE_ENTRY, &path, addr, code, pid)
    }

    pub fn attach_uretprobe(
        binary_path: &str,
        symbol: &str,
        code: File,
        pid: pid_t,
    ) -> Result<Self, BccError> {
        let (path, addr) = symbol::resolve_symbol_path(binary_path, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        Uprobe::new(&ev_name, BPF_PROBE_RETURN, &path, addr, code, pid)
    }
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
