use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::*;

use crate::BccError;
use crate::helpers::to_cstring;

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
    pub fn new(
        name: &str,
        attach_type: u32,
        path: &str,
        addr: u64,
        file: File,
        pid: pid_t,
        ref_ctr_offset: u32,
    ) -> Result<Self, BccError> {
        let cname = to_cstring(name, "name")?;
        let cpath = to_cstring(path, "path")?;
        let uprobe_ptr = unsafe {
            bpf_attach_uprobe(
                file.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cpath.as_ptr(),
                addr,
                pid,
                ref_ctr_offset,
            )
        };
        if uprobe_ptr < 0 {
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
}

impl Drop for Uprobe {
    fn drop(&mut self) {
        unsafe {
            bpf_close_perf_event_fd(self.p);
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
