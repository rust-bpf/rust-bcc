use crate::BccError;
use bcc_sys::bccapi::*;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;

#[derive(Debug)]
pub struct RawTracepoint {
    name: CString,
    code_fd: File,
    p: i32,
}

impl RawTracepoint {
    pub fn attach_raw_tracepoint(name: &str, file: File) -> Result<Self, BccError> {
        let cname = CString::new(name)?;
        let ptr = unsafe { bpf_attach_raw_tracepoint(file.as_raw_fd(), cname.as_ptr() as *mut _) };
        if ptr < 0 {
            Err(BccError::AttachRawTracepoint {
                name: name.to_string(),
            })
        } else {
            Ok(Self {
                name: cname,
                code_fd: file,
                p: ptr,
            })
        }
    }
}

impl PartialEq for RawTracepoint {
    fn eq(&self, other: &RawTracepoint) -> bool {
        self.name == other.name
    }
}

impl Eq for RawTracepoint {}

impl Hash for RawTracepoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}
