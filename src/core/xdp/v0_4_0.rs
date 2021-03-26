use bcc_sys::bccapi::bpf_attach_xdp;

use crate::BccError;
use crate::helpers::to_cstring;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::io::AsRawFd;

#[derive(Debug)]
pub struct XDP {
    name: String,
    device: CString,
    flags: u32,
}

impl XDP {
    pub fn new(name: String, code: File, device: String, flags: u32) -> Result<Self, BccError> {
        let device = to_cstring(device, "device")?;
        unsafe {
            let code = bpf_attach_xdp(device.as_ptr(), code.as_raw_fd(), flags);
            if code != 0 {
                return Err(BccError::AttachXDP { name, code });
            }
        }

        Ok(Self {
            name,
            device,
            flags,
        })
    }
}

impl Drop for XDP {
    fn drop(&mut self) {
        unsafe {
            // Providing an invalid -1 file descriptor to the BPF attach function
            // unloads the program from the device.
            bpf_attach_xdp(self.device.as_ptr(), -1, self.flags);
        }
    }
}

impl Eq for XDP {}

impl Hash for XDP {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for XDP {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
