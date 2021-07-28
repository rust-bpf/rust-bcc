use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER as BPF_PROG_TYPE_SOCKET_FILTER;

use crate::core::BPF;
use crate::error::BccError;

#[derive(Debug, Default)]
pub struct Socket {
    handler: Option<String>,
    iface: Option<String>
}

impl Socket {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn handler(mut self, handler: &str) -> Self {
        self.handler = Some(handler.to_owned());
        self
    }

    pub fn iface(mut self, iface: &str) -> Self{
        self.iface = Some(iface.to_owned());
        self
    }

    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.iface.is_none() {
            return Err(BccError::InvalidSocket {
                message: "iface is required".to_string(),
            });
        }


        let code_fd = bpf.load(&self.handler.unwrap(), BPF_PROG_TYPE_SOCKET_FILTER, 0, 0)?;
        let socket = crate::core::Socket::new(&self.iface.unwrap(), code_fd)?;
    
        bpf.socket = Some(socket);
        Ok(())
    }
}