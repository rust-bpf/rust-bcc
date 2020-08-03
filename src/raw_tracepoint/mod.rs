use crate::core::BPF;
use crate::error::BccError;

use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT as BPF_PROG_TYPE_RAW_TRACEPOINT;

#[derive(Default)]
pub struct RawTracepoint {
    tracepoint: Option<String>,
    handler: Option<String>,
}

impl RawTracepoint {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn handler(mut self, name: &str) -> Self {
        self.handler = Some(name.to_owned());
        self
    }

    pub fn tracepoint(mut self, name: &str) -> Self {
        self.tracepoint = Some(name.to_owned());
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
        if self.handler.is_none() {
            return Err(BccError::IncompleteRawTracepointProbe {
                message: "handler is required".to_string(),
            });
        }
        if self.tracepoint.is_none() {
            return Err(BccError::IncompleteRawTracepointProbe {
                message: "tracepoint is required".to_string(),
            });
        }
        let handler = self.handler.unwrap();
        let tracepoint = self.tracepoint.unwrap();
        let code_fd = bpf.load(&handler, BPF_PROG_TYPE_RAW_TRACEPOINT, 0, 0)?;

        let raw_tracepoint = crate::core::RawTracepoint::new(&tracepoint, code_fd)?;
        bpf.raw_tracepoints.insert(raw_tracepoint);
        Ok(())
    }
}
