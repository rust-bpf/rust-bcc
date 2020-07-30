use crate::perf::Event;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BccError {
    #[error("failed to attach kprobe: ({name})")]
    AttachKprobe { name: String },
    #[error("failed to attach kretprobe ({name})")]
    AttachKretprobe { name: String },
    #[error("failed to attach perf event ({event:?})")]
    AttachPerfEvent { event: Event },
    #[error("failed to attach raw tracepoint ({name})")]
    AttachRawTracepoint { name: String },
    #[error("failed to attach tracepoint ({subsys}:{name})")]
    AttachTracepoint { subsys: String, name: String },
    #[error("failed to attach uprobe ({name})")]
    AttachUprobe { name: String },
    #[error("failed to attach uretprobe ({name})")]
    AttachUretprobe { name: String },
    #[error("error compiling bpf")]
    Compilation,
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("kernel probe has incomplete configuration: {message}")]
    IncompleteKernelProbe { message: String },
    #[error("perf event probe has incomplete configuration: {message}")]
    IncompletePerfEventProbe { message: String },
    #[error("tracepoint probe has incomplete configuration: {message}")]
    IncompleteTracepointProbe { message: String },
    #[error("userspace probe has incomplete configuration: {message}")]
    IncompleteUserspaceProbe { message: String },
    #[error("error initializing perf map")]
    InitializePerfMap,
    #[error("invalid cpu range ({range})")]
    InvalidCpuRange { range: String },
    #[error("error loading bpf probe ({name})")]
    Loading { name: String },
    #[error("null string")]
    NullString(#[from] std::ffi::NulError),
    #[error("error opening perf buffer")]
    OpenPerfBuffer,
    #[error("failed to delete key from table")]
    DeleteTableValue,
    #[error("failed to get value from table")]
    GetTableValue,
    #[error("failed to set value in table")]
    SetTableValue,
    #[error("table has wrong size for key or leaf")]
    TableInvalidSize,
    #[error("unknown symbol ({name}) in module ({module})")]
    UnknownSymbol { name: String, module: String },
    #[error("invalid utf8")]
    Utf8Error(#[from] std::str::Utf8Error),
}
