use crate::core::BPF;
use crate::error::BccError;

use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT as BPF_PROG_TYPE_RAW_TRACEPOINT;

#[derive(Default)]
pub struct RawTracepoint {
    tracepoint: Option<String>,
    handler: Option<String>,
}

impl RawTracepoint {
    /// Create a new probe with the defaults. Further initialization is required
    /// before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// Specify the name of the probe handler within the BPF code. This is a
    /// required item.
    pub fn handler(mut self, name: &str) -> Self {
        self.handler = Some(name.to_owned());
        self
    }

    /// Specify the name of the raw tracepoint to probe.
    pub fn tracepoint(mut self, name: &str) -> Self {
        self.tracepoint = Some(name.to_owned());
        self
    }

    #[cfg(any(feature = "v0_4_0", feature = "v0_5_0",))]
    /// Consumes the probe and attaches it. May return an error if there is a
    /// incomplete or invalid configuration or other error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        Err(BccError::BccVersionTooLow {
            cause: "raw tracepoints".to_owned(),
            min_version: "0.6.0".to_owned(),
        })
    }

    #[cfg(not(any(feature = "v0_4_0", feature = "v0_5_0",)))]
    /// Consumes the probe and attaches it. May return an error if there is a
    /// incomplete or invalid configuration or other error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.handler.is_none() {
            return Err(BccError::InvalidRawTracepoint {
                message: "handler is required".to_string(),
            });
        }
        if self.tracepoint.is_none() {
            return Err(BccError::InvalidRawTracepoint {
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
