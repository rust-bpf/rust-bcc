use crate::core::BPF;
use crate::error::BccError;
use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT as BPF_PROG_TYPE_TRACEPOINT;

#[derive(Default)]
pub struct Tracepoint {
    handler: Option<String>,
    subsystem: Option<String>,
    tracepoint: Option<String>,
}

impl Tracepoint {
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

    /// Specify the name of the tracepoint subsystem. This is a required item.
    pub fn subsystem(mut self, name: &str) -> Self {
        self.subsystem = Some(name.to_owned());
        self
    }

    /// Specify the specific tracepoint for this probe. This is a required item.
    pub fn tracepoint(mut self, name: &str) -> Self {
        self.tracepoint = Some(name.to_owned());
        self
    }

    /// Consumes the probe and attaches it. May return an error if there is a
    /// incomplete or invalid configuration or other error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.handler.is_none() {
            return Err(BccError::InvalidTracepoint {
                message: "handler is required".to_string(),
            });
        }
        if self.subsystem.is_none() {
            return Err(BccError::InvalidTracepoint {
                message: "subsystem is required".to_string(),
            });
        }
        if self.tracepoint.is_none() {
            return Err(BccError::InvalidTracepoint {
                message: "tracepoint is required".to_string(),
            });
        }
        let handler = self.handler.unwrap();
        let subsystem = self.subsystem.unwrap();
        let tracepoint = self.tracepoint.unwrap();

        let code_fd = bpf.load(&handler, BPF_PROG_TYPE_TRACEPOINT, 0, 0)?;
        let tracepoint = crate::core::Tracepoint::new(&subsystem, &tracepoint, code_fd)?;
        bpf.tracepoints.insert(tracepoint);
        Ok(())
    }
}
