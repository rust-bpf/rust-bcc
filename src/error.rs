use crate::perf_event::Event;
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
    #[error("failed to attach XDP ({name}): code {code}")]
    AttachXDP { name: String, code: i32 },
    #[error("{cause} requires bcc >= ({min_version})")]
    BccVersionTooLow { cause: String, min_version: String },
    #[error("error compiling bpf")]
    Compilation,
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("kernel probe has invalid configuration: {message}")]
    InvalidKprobe { message: String },
    #[error("perf event probe has invalid configuration: {message}")]
    InvalidPerfEvent { message: String },
    #[error("raw tracepoint probe has invalid configuration: {message}")]
    InvalidRawTracepoint { message: String },
    #[error("tracepoint probe has invalid configuration: {message}")]
    InvalidTracepoint { message: String },
    #[error("userspace probe has invalid configuration: {message}")]
    InvalidUprobe { message: String },
    #[error("error initializing perf map")]
    InitializePerfMap,
    #[error("invalid cpu range ({range})")]
    InvalidCpuRange { range: String },
    #[error("error loading bpf program ({name}): {message}")]
    Loading { name: String, message: String },
    #[error("null string")]
    NullString(#[from] std::ffi::NulError),
    #[error("error opening perf buffer")]
    OpenPerfBuffer,
    #[error("error opening perf event: ({event:?}), reason `{message}`")]
    OpenPerfEvent { event: Event, message: String },
    #[error("failed to delete key from table: {message}")]
    DeleteTableValue { message: String },
    #[error("failed to get value from table: {message}")]
    GetTableValue { message: String },
    #[error("failed to set value in table: {message}")]
    SetTableValue { message: String },
    #[error("table has wrong size for key or leaf")]
    TableInvalidSize,
    #[error("unknown symbol ({name}) in module ({module})")]
    UnknownSymbol { name: String, module: String },
    #[error("invalid utf8")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("XDP has invalid configuration: {message}")]
    InvalidXDP { message: String },
}
