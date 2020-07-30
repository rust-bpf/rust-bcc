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

use crate::core::BPF;
use crate::error::BccError;
use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT as BPF_PROG_TYPE_TRACEPOINT;

#[derive(Default)]
pub struct TracepointProbe {
    subsystem: Option<String>,
    tracepoint: Option<String>,
    name: Option<String>,
}

impl TracepointProbe {
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

    /// Specify the name of the tracepoint subsystem. This is a required item.
    pub fn subsystem(mut self, subsystem: &str) -> Self {
        self.subsystem = Some(subsystem.to_owned());
        self
    }

    /// Specify the specific tracepoint for this probe. This is a required item.
    pub fn tracepoint(mut self, tracepoint: &str) -> Self {
        self.tracepoint = Some(tracepoint.to_owned());
        self
    }

    /// Consumes the probe and attaches it to the `BPF` struct. May return an
    /// error if there is a incomplete configuration or error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.name.is_none() {
            return Err(BccError::IncompleteTracepointProbe {
                message: "name is required".to_string(),
            });
        }
        if self.subsystem.is_none() {
            return Err(BccError::IncompleteTracepointProbe {
                message: "subsystem is required".to_string(),
            });
        }
        if self.tracepoint.is_none() {
            return Err(BccError::IncompleteTracepointProbe {
                message: "tracepoint is required".to_string(),
            });
        }
        let name = self.name.unwrap();
        let subsystem = self.subsystem.unwrap();
        let tracepoint = self.tracepoint.unwrap();

        let code_fd = bpf.load(&name, BPF_PROG_TYPE_TRACEPOINT, 0, 0)?;
        let tracepoint = Tracepoint::new(&subsystem, &tracepoint, code_fd)?;
        bpf.tracepoints.insert(tracepoint);
        Ok(())
    }
}
