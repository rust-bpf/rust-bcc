use bcc_sys::bccapi::{bpf_attach_socket, bpf_open_raw_sock};

use crate::helpers::to_cstring;
use crate::BccError;

use std::fs::File;
use std::os::unix::prelude::AsRawFd;

#[derive(Debug)]
pub struct RawSocket;

impl RawSocket {
    pub fn attach(iface: &str, code_fd: &File) -> Result<i32, BccError> {
        let ciface = to_cstring(iface, "iface")?;
        let sock_fd = unsafe { bpf_open_raw_sock(ciface.as_ptr()) };
        if sock_fd < 0 {
            return Err(BccError::AttachSocket {
                iface: iface.to_string(),
                error: std::io::Error::last_os_error(),
            });
        }

        let res = unsafe { bpf_attach_socket(sock_fd, code_fd.as_raw_fd()) };
        if res < 0 {
            return Err(BccError::AttachSocket {
                iface: iface.to_string(),
                error: std::io::Error::last_os_error(),
            });
        }

        // set O_NONBLOCK to false
        // otherwise read/send will result in a "Resource temporarily unavailable" error
        let mut flags = unsafe { libc::fcntl(sock_fd, libc::F_GETFL) };
        flags = flags & !libc::O_NONBLOCK;
        unsafe {
            libc::fcntl(sock_fd, libc::F_SETFL, flags);
        }

        Ok(sock_fd)
    }
}
