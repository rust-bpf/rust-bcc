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

use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT as BPF_PROG_TYPE_RAW_TRACEPOINT;

#[derive(Default)]
pub struct RawTracepointProbe {
    tracepoint: Option<String>,
    name: Option<String>,
}

impl RawTracepointProbe {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    pub fn tracepoint(mut self, tracepoint: &str) -> Self {
        self.tracepoint = Some(tracepoint.to_owned());
        self
    }

    #[cfg(any(feature = "v0_4_0", feature = "v0_5_0",))]
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        BccError::BccVersionTooLow {
            cause: "raw tracepoints".to_owned(),
            min_version: "0.6.0".to_owned(),
        }
    }

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
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.name.is_none() {
            return Err(BccError::IncompleteRawTracepointProbe {
                message: "name is required".to_string(),
            });
        }
        if self.tracepoint.is_none() {
            return Err(BccError::IncompleteRawTracepointProbe {
                message: "tracepoint is required".to_string(),
            });
        }
        let name = self.name.unwrap();
        let tracepoint = self.tracepoint.unwrap();
        let code_fd = bpf.load(&name, BPF_PROG_TYPE_RAW_TRACEPOINT, 0, 0)?;

        let tracepoint = RawTracepoint::new(&tracepoint, code_fd)?;
        bpf.raw_tracepoints.insert(tracepoint);
        Ok(())
    }
}
