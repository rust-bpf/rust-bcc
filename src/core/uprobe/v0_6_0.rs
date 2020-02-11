use anyhow::{self, bail, Result};
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::*;

use crate::core::make_alphanumeric;
use crate::symbol;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;

#[derive(Debug)]
pub struct Uprobe {
    code_fd: File,
    name: CString,
    p: i32,
}

impl Uprobe {
    fn new(
        name: &str,
        attach_type: u32,
        path: &str,
        addr: u64,
        file: File,
        pid: pid_t,
    ) -> Result<Self> {
        let cname =
            CString::new(name).map_err(|_| anyhow::anyhow!("Nul byte in Uprobe name: {}", name))?;
        let cpath =
            CString::new(path).map_err(|_| anyhow::anyhow!("Nul byte in Uprobe path: {}", name))?;
        let uprobe_ptr = unsafe {
            bpf_attach_uprobe(
                file.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cpath.as_ptr(),
                addr,
                pid,
            )
        };
        if uprobe_ptr < 0 {
            bail!(anyhow::anyhow!("Failed to attach Uprobe: {}", name))
        } else {
            Ok(Self {
                code_fd: file,
                name: cname,
                p: uprobe_ptr,
            })
        }
    }

    pub fn attach_uprobe(binary_path: &str, symbol: &str, code: File, pid: pid_t) -> Result<Self> {
        let (path, addr) = symbol::resolve_symbol_path(binary_path, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        Uprobe::new(&ev_name, BPF_PROBE_ENTRY, &path, addr, code, pid)
            .map_err(|_| anyhow::anyhow!("Failed to attach Uprobe to binary: {}", binary_path))
    }

    pub fn attach_uretprobe(
        binary_path: &str,
        symbol: &str,
        code: File,
        pid: pid_t,
    ) -> Result<Self> {
        let (path, addr) = symbol::resolve_symbol_path(binary_path, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        Uprobe::new(&ev_name, BPF_PROBE_RETURN, &path, addr, code, pid)
            .map_err(|_| anyhow::anyhow!("Failed to attach Uretprobe to binary: {}", binary_path))
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
