use bcc_sys::bccapi::{bpf_attach_socket, bpf_open_raw_sock};

use crate::helpers::to_cstring;
use crate::BccError;

use std::ffi::CString;
use std::fs::File;
use std::os::unix::prelude::AsRawFd;

#[derive(Debug)]
pub struct Socket {
    iface: CString,
    code_fd: File,
    pub sock_fd: i32,
}

impl Socket {
    pub fn new(iface: &str, code_fd: File) -> Result<Self, BccError> {
        let ciface = to_cstring(iface, "iface")?;
        let sock_fd = unsafe { bpf_open_raw_sock(ciface.as_ptr()) };
        if sock_fd < 0 {
            return Err(BccError::AttachSocket {
                iface: iface.to_string(),
                os_error: std::io::Error::last_os_error(),
            });
        }

        let res = unsafe { bpf_attach_socket(sock_fd, code_fd.as_raw_fd()) };
        if res < 0 {
            return Err(BccError::AttachSocket {
                iface: iface.to_string(),
                os_error: std::io::Error::last_os_error(),
            });
        }

        Ok(Self {
            iface: ciface,
            code_fd,
            sock_fd,
        })
    }
}
