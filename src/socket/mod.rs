use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER as BPF_PROG_TYPE_SOCKET_FILTER;
use std::collections::{HashMap, HashSet};
use std::iter::Iterator;

use crate::core::BPF;
use crate::error::BccError;

/// An object that can attach a bpf program to a socket which runs on every
/// packet on the given interfaces
#[derive(Debug, Default)]
pub struct Socket {
    handler: Option<String>,
    ifaces: HashSet<String>,
}

impl Socket {
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
        self.ifaces.push(iface.to_owned());
        self
    }

    /// Add multiple interfaces to listen to
    pub fn add_interfaces(mut self, ifaces: &[String]) -> Self {
        self.ifaces.extend(ifaces.iter().cloned());
        self
    }

    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.ifaces.len() == 0 {
            return Err(BccError::InvalidSocket {
                message: "interface is required".to_string(),
            });
        }

        let code_fd = bpf.load(&self.handler.unwrap(), BPF_PROG_TYPE_SOCKET_FILTER, 0, 0)?;
        bpf.sockets = self
            .ifaces
            .iter()
            .map(|iface: &String| -> Result<crate::core::Socket, BccError> {
                crate::core::Socket::new(iface, &code_fd)
            })
            .try_fold(HashMap::new(), |mut acc, sock_res| match sock_res {
                Ok(sock) => {
                    acc.insert(sock.iface, sock.sock_fd);
                    Ok(acc)
                }
                Err(err) => Err(err),
            })?;

        Ok(())
    }
}
