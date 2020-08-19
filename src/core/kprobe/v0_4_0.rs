use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::*;

use crate::types::MutPointer;
use crate::BccError;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;
use std::ptr;

#[derive(Debug)]
pub struct Kprobe {
    code_fd: File,
    name: CString,
    p: MutPointer,
}

impl Kprobe {
    pub fn new(name: &str, attach_type: u32, function: &str, code: File) -> Result<Self, BccError> {
        let cname = CString::new(name)?;
        let cfunction = CString::new(function)?;
        let (pid, cpu, group_fd) = (-1, 0, -1);
        let ptr = unsafe {
            bpf_attach_kprobe(
                code.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cfunction.as_ptr(),
                pid,
                cpu,
                group_fd,
                None,
                ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            match attach_type {
                BPF_PROBE_ENTRY => Err(BccError::AttachKprobe {
                    name: name.to_string(),
                }),
                BPF_PROBE_RETURN => Err(BccError::AttachKretprobe {
                    name: name.to_string(),
                }),
                _ => unreachable!(),
            }
        } else {
            Ok(Self {
                p: ptr,
                name: cname,
                code_fd: code,
            })
        }
    }
}

impl Drop for Kprobe {
    fn drop(&mut self) {
        unsafe {
            bpf_close_perf_event_fd(self.p);
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
