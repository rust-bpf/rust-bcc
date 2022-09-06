use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER as BPF_PROG_TYPE_SOCKET_FILTER;
use std::collections::HashSet;
use std::iter::Iterator;

use socket2;
use std::os::unix::io::FromRawFd;

use crate::core::BPF;
use crate::error::BccError;

// SocketWrapper holds the BPF raw socket and the interface the BPF program was attached to
#[derive(Debug)]
pub struct SocketWrapper {
    pub iface: String,
    // socket can be used to access the underlying raw socket
    pub socket: socket2::Socket,
}

impl SocketWrapper {
    // create a new Socket from an interface name and a socket file descriptor
    pub fn new(iface: String, socket_fd: i32) -> Self {
        let socket = unsafe { socket2::Socket::from_raw_fd(socket_fd) };
        Self { iface, socket }
    }
}

/// An object that can attach a bpf program to a socket which runs on every
/// packet on the given interfaces
#[derive(Debug, Default)]
pub struct SocketBuilder {
    handler: Option<String>,
    ifaces: HashSet<String>,
}

impl SocketBuilder {
    /// Create a new Socket with defaults. Further initialization is required
    /// before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// Specify the name of the probe handler within the BPF code. This is a
    /// required item.
    pub fn handler(mut self, handler: &str) -> Self {
        self.handler = Some(handler.to_owned());
        self
    }

    /// Add an interface to listen to
    pub fn add_interface(mut self, iface: &str) -> Self {
        self.ifaces.insert(iface.to_owned());
        self
    }

    /// Add multiple interfaces to listen to
    pub fn add_interfaces(mut self, ifaces: &[String]) -> Self {
        self.ifaces.extend(ifaces.iter().cloned());
        self
    }

    /// Attach a bpf program to the socket
    pub fn attach(self, bpf: &mut BPF) -> Result<Vec<SocketWrapper>, BccError> {
        if self.ifaces.len() == 0 {
            return Err(BccError::InvalidSocket {
                message: "interface is required".to_string(),
            });
        }

        if self.handler.is_none() {
            return Err(BccError::InvalidSocket {
                message: "handler is required".to_string(),
            });
        }

        let code_fd = bpf.load(&self.handler.unwrap(), BPF_PROG_TYPE_SOCKET_FILTER, 0, 0)?;
        let socket_map = self
            .ifaces
            .iter()
            // create a BPF socket and attach
            .map(|iface: &String| -> Result<SocketWrapper, BccError> {
                let socket_fd = crate::core::RawSocket::attach(iface, &code_fd)?;
                Ok(SocketWrapper::new(iface.to_owned(), socket_fd))
            })
            .collect::<Result<Vec<SocketWrapper>, BccError>>();

        socket_map
    }
}
