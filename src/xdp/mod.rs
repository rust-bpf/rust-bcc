use crate::{BccError, BPF};
use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_XDP as BPF_PROG_TYPE_XDP;

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum Mode {
    /// XDP native mode. Runs the program on the driver.
    XDP_FLAGS_DRV_MODE = 1 << 2,
    /// XDP generic mode. Used as a fallback in cases where
    /// the driver doesn't support XDP.
    XDP_FLAGS_SKB_MODE = 1 << 1,
    /// XDP hardware offload mode. Offloads the program to run directly
    /// on the network interface card (NIC)
    XDP_FLAGS_HW_MODE = 1 << 3,
}

#[allow(non_camel_case_types)]
/// Flag that the XDP program should be loaded only
/// if there isn't already one running.
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;

/// An object that can run BPF code as an XDP program that runs
/// on every packet at the driver level.
pub struct XDP {
    /// The name of the BPF function to run.
    handler: Option<String>,
    /// The device on which to load the program.
    device: Option<String>,
    /// The mode in which the program will be run.
    mode: Mode,
    /// If set, an already existing running XDP program will be
    /// replaced by the new program.
    replace_existing_program: bool,
}

impl Default for XDP {
    fn default() -> Self {
        Self::new()
    }
}

impl XDP {
    /// Create a new XDP object with the defaults.
    /// By default, the XDP program is run in generic mode [`XDP_FLAGS_SKB_MODE`]
    /// and will replace any already running program on the driver.
    /// Further initialization is required before attaching.
    pub fn new() -> Self {
        Self {
            device: None,
            handler: None,
            mode: Mode::XDP_FLAGS_DRV_MODE,
            replace_existing_program: true,
        }
    }

    /// Specify the name of the XDP handler within the BPF code.
    /// This is a required configuration.
    pub fn handler<T: AsRef<str>>(mut self, name: T) -> Self {
        self.handler = Some(name.as_ref().into());
        self
    }

    /// Specify the name of the network device on which to run the BPF program.
    /// This is a required configuration.
    pub fn device<T: AsRef<str>>(mut self, name: T) -> Self {
        self.device = Some(name.as_ref().into());
        self
    }

    /// Specify the XDP mode under which to run the BPF program.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Load the configured handler as an XDP program onto the configured device
    /// and attach it to the [`BPF`] struct. The XDP program is unloaded from the
    /// device once the [`BPF`] struct goes out of scope.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        let device = self.device.ok_or_else(|| BccError::InvalidXDP {
            message: "device is required".into(),
        })?;
        let handler = self.handler.ok_or_else(|| BccError::InvalidXDP {
            message: "handler is required".into(),
        })?;
        let flags = if self.replace_existing_program {
            self.mode as u32
        } else {
            self.mode as u32 | XDP_FLAGS_UPDATE_IF_NOEXIST
        };

        let prog_fd = bpf.load(handler.as_str(), BPF_PROG_TYPE_XDP, 0, 0)?;
        bpf.xdp
            .insert(crate::core::XDP::new(handler, prog_fd, device, flags)?);

        Ok(())
    }
}
