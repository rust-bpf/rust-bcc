#[cfg(any(feature = "v0_4_0", feature = "v0_5_0",))]
mod v0_4_0;

#[cfg(any(feature = "v0_4_0", feature = "v0_5_0",))]
pub use v0_4_0::*;

#[cfg(any(
    feature = "v0_6_0",
    feature = "v0_6_1",
    feature = "v0_7_0",
    feature = "v0_8_0",
    feature = "v0_9_0",
    feature = "v0_10_0",
    feature = "v0_11_0",
    feature = "v0_12_0",
    feature = "v0_13_0",
    feature = "v0_14_0",
    feature = "v0_15_0",
    not(feature = "specific"),
))]
mod v0_6_0;

#[cfg(any(
    feature = "v0_6_0",
    feature = "v0_6_1",
    feature = "v0_7_0",
    feature = "v0_8_0",
    feature = "v0_9_0",
    feature = "v0_10_0",
    feature = "v0_11_0",
    feature = "v0_12_0",
    feature = "v0_13_0",
    feature = "v0_14_0",
    feature = "v0_15_0",
    not(feature = "specific"),
))]
pub use v0_6_0::*;

use crate::core::make_alphanumeric;
use crate::core::BPF;
use crate::error::BccError;

use bcc_sys::bccapi::pid_t;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_KPROBE as BPF_PROG_TYPE_KPROBE;

use std::path::{Path, PathBuf};


#[derive(Default)]
/// A `UserspaceProbe` is used to configure and then attach a uprobe to a
/// userspace function on entry into that function. Must be attached to a `BPF`
/// struct to be useful.
pub struct UserspaceProbe {
    binary: Option<PathBuf>,
    name: Option<String>,
    pid: Option<pid_t>,
    symbol: Option<String>,
}

impl UserspaceProbe {
    /// Create a new probe with the defaults. Further initialization is required
    /// before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// Specify the name of the probe handler within the BPF code. This is a
    /// required item.
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// Specify the path to the binary to probe. This is a required item.
    pub fn binary<T: AsRef<Path>>(mut self, path: T) -> Self {
        self.binary = Some(PathBuf::from(path.as_ref()));
        self
    }

    /// Specify the symbol to probe. This is required.
    pub fn symbol(mut self, symbol: &str) -> Self {
        self.symbol = Some(symbol.to_owned());
        self
    }

    /// Specify a pid to probe. This is optional.
    pub fn pid(mut self, pid: Option<pid_t>) -> Self {
        self.pid = pid;
        self
    }

    /// Consumes the probe and attaches it to the `BPF` struct. May return an
    /// error if there is a incomplete configuration or error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.name.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "name is required".to_string(),
            });
        }
        if self.binary.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "binary is required".to_string(),
            });
        }
        let binary = self.binary.unwrap().to_str().map(|v| v.to_owned());
        if binary.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "binary path is invalid".to_string(),
            });
        }
        if self.symbol.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "symbol is required".to_string(),
            });
        }
        let binary = binary.unwrap();
        let symbol = self.symbol.unwrap();
        let pid = self.pid.unwrap_or(-1);
        let name = self.name.unwrap();

        let (path, addr) = crate::symbol::resolve_symbol_path(&binary, &symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);

        let code_fd = bpf.load(&name, BPF_PROG_TYPE_KPROBE, 0, 0)?;

        let uprobe = Uprobe::new(&ev_name, BPF_PROBE_ENTRY, &path, addr, code_fd, pid)?;
        bpf.uprobes.insert(uprobe);
        Ok(())
    }
}

#[derive(Default)]
/// A `UserspaceReturnProbe` is used to configure and then attach a uprobe to a
/// userspace function on return from that function. Must be attached to a `BPF`
/// struct to be useful.
pub struct UserspaceReturnProbe {
    binary: Option<PathBuf>,
    name: Option<String>,
    pid: Option<pid_t>,
    symbol: Option<String>,
}

impl UserspaceReturnProbe {
    /// Create a new probe with the defaults. Further initialization is required
    /// before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// Specify the name of the probe handler within the BPF code. This is a
    /// required item.
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// Specify the path to the binary to probe. This is a required item.
    pub fn binary<T: AsRef<Path>>(mut self, path: T) -> Self {
        self.binary = Some(PathBuf::from(path.as_ref()));
        self
    }

    /// Specify the symbol to probe. This is required.
    pub fn symbol(mut self, symbol: &str) -> Self {
        self.symbol = Some(symbol.to_owned());
        self
    }

    /// Specify a pid to probe. This is optional.
    pub fn pid(mut self, pid: Option<pid_t>) -> Self {
        self.pid = pid;
        self
    }

    /// Consumes the probe and attaches it to the `BPF` struct. May return an
    /// error if there is a incomplete configuration or error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.name.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "name is required".to_string(),
            });
        }
        if self.binary.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "binary is required".to_string(),
            });
        }
        let binary = self.binary.unwrap().to_str().map(|v| v.to_owned());
        if binary.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "binary path is invalid".to_string(),
            });
        }
        if self.symbol.is_none() {
            return Err(BccError::IncompleteUserspaceProbe {
                message: "symbol is required".to_string(),
            });
        }
        let binary = binary.unwrap();
        let symbol = self.symbol.unwrap();
        let pid = self.pid.unwrap_or(-1);
        let name = self.name.unwrap();

        let (path, addr) = crate::symbol::resolve_symbol_path(&binary, &symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);

        let code_fd = bpf.load(&name, BPF_PROG_TYPE_KPROBE, 0, 0)?;

        let uprobe = Uprobe::new(&ev_name, BPF_PROBE_RETURN, &path, addr, code_fd, pid)?;
        bpf.uprobes.insert(uprobe);
        Ok(())
    }
}