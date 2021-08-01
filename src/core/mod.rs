mod kprobe;
mod perf_event;
mod perf_event_array;
mod raw_tracepoint;
mod socket;
mod tracepoint;
mod uprobe;
mod usdt;
mod xdp;

use bcc_sys::bccapi::*;

pub(crate) use self::kprobe::Kprobe;
pub(crate) use self::perf_event::PerfEvent;
pub(crate) use self::perf_event_array::PerfEventArray;
pub(crate) use self::raw_tracepoint::RawTracepoint;
pub(crate) use self::socket::Socket;
pub(crate) use self::tracepoint::Tracepoint;
pub(crate) use self::uprobe::Uprobe;
pub use self::usdt::{usdt_generate_args, USDTContext};
pub(crate) use self::xdp::XDP;
use crate::helpers::to_cstring;
use crate::perf_event::{PerfMapBuilder, PerfReader};
use crate::symbol::SymbolCache;
use crate::table::Table;
use crate::types::MutPointer;
use crate::BccError;

use core::sync::atomic::{AtomicPtr, Ordering};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ffi::CString;
use std::fs::File;
use std::io::Error;
use std::os::raw::{c_char, c_void};
use std::os::unix::prelude::*;
use std::ptr;

const SYSCALL_PREFIXES: [&str; 7] = [
    "sys_",
    "__x64_sys_",
    "__x32_compat_sys_",
    "__ia32_compat_sys_",
    "__arm64_sys_",
    "__s390x_sys_",
    "__s390_sys_",
];

bitflags! {
    #[derive(Default)]
    pub struct BccDebug: u32 {
        const LLVM_IR = 0x1;
        const BPF = 0x2;
        const PREPROCESSOR = 0x4;
        const SOURCE = 0x8;
        const BPF_REGISTER_STATE = 0x10;
        const BTF = 0x20;
    }
}

#[repr(u32)]
pub enum BpfProgType {
    Kprobe = bpf_prog_type_BPF_PROG_TYPE_KPROBE,
    // Confusingly, Uprobes, internally are identified as Kprobes
    Tracepoint = bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT,
    PerfEvent = bpf_prog_type_BPF_PROG_TYPE_PERF_EVENT,
}

#[derive(Debug)]
/// The `BPF` struct contains the compiled BPF code, any probes or programs that
/// have been attached, and can provide access to a userspace view of the
/// results of the running BPF programs.
pub struct BPF {
    p: AtomicPtr<c_void>,
    pub(crate) kprobes: HashSet<Kprobe>,
    pub(crate) uprobes: HashSet<Uprobe>,
    pub(crate) tracepoints: HashSet<Tracepoint>,
    pub(crate) raw_tracepoints: HashSet<RawTracepoint>,
    pub(crate) perf_events: HashSet<PerfEvent>,
    pub(crate) perf_events_array: HashSet<PerfEventArray>,
    pub(crate) xdp: HashSet<XDP>,
    pub(crate) socket: Option<Socket>,
    perf_readers: Vec<PerfReader>,
    sym_caches: HashMap<pid_t, SymbolCache>,
    cflags: Vec<CString>,
    functions: HashMap<String, i32>,
    debug: BccDebug,
}

// helper function that converts non-alphanumeric characters to underscores
pub(crate) fn make_alphanumeric(s: &str) -> String {
    s.replace(
        |c| !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')),
        "_",
    )
}

// create a mutable pointer from a vector of bytes
fn null_or_mut_ptr<T>(s: &mut Vec<u8>) -> *mut T {
    if s.capacity() == 0 {
        ptr::null_mut()
    } else {
        s.as_mut_ptr() as *mut T
    }
}

/// A builder struct which allows one to initialize a BPF module with additional
/// options.
pub struct BPFBuilder {
    code: CString,
    cflags: Vec<CString>,
    device: Option<CString>,
    debug: BccDebug,
    usdt_contexts: Vec<USDTContext>,
    attach_usdt_ignore_pid: bool,
}

impl BPFBuilder {
    /// Create a new builder with the given code
    pub fn new(code: &str) -> Result<Self, BccError> {
        Ok(Self {
            code: to_cstring(code, "code")?,
            cflags: Vec::new(),
            device: None,
            debug: Default::default(),
            usdt_contexts: Vec::new(),
            attach_usdt_ignore_pid: false,
        })
    }

    /// Set CFLAGS to be used
    pub fn cflags<T: AsRef<str>>(mut self, cflags: &[T]) -> Result<Self, BccError> {
        self.cflags.clear();
        for f in cflags {
            let cs = to_cstring(f.as_ref(), "cflags")?;
            self.cflags.push(cs);
        }
        Ok(self)
    }

    /// Set the device to load the BPF program on, if applicable.
    /// For example a network device if running XDP in hardware mode.
    pub fn device<T: AsRef<str>>(mut self, device: T) -> Result<Self, BccError> {
        self.device = Some(to_cstring(device.as_ref(), "device")?);
        Ok(self)
    }

    /// Set BCC's debug level
    pub fn debug(mut self, debug: BccDebug) -> Self {
        self.debug = debug;
        self
    }

    /// Sets whether or not to ignore the specified PID in a given USDT context when attaching this
    /// BPF program.
    ///
    /// If set to `true`, then any running process that matched the USDT probes would be captured,
    /// regardless of whether or not a specific PID was used to create the USDT context.  This can
    /// be useful in some cases where a user might want to specify the PID of a parent process as
    /// the target, but also hit the same tracepoints in the child processes they spawn i.e. daemon
    /// worker strategies based on `fork(2)`.
    ///
    /// Defaults to `false`.
    pub fn attach_usdt_ignore_pid(mut self, ignore: bool) -> Result<Self, BccError> {
        self.attach_usdt_ignore_pid = ignore;
        Ok(self)
    }

    /// Adds a USDT context to this program.
    pub fn add_usdt_context(mut self, context: USDTContext) -> Result<Self, BccError> {
        self.usdt_contexts.push(context);
        Ok(self)
    }

    #[cfg(any(
        feature = "v0_4_0",
        feature = "v0_5_0",
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
    ))]
    fn create_module(&self) -> Result<MutPointer, BccError> {
        let ptr = unsafe {
            bpf_module_create_c_from_string(
                self.code.as_ptr(),
                self.debug.bits(),
                self.cflags
                    .iter()
                    .map(|v| v.as_ptr())
                    .collect::<Vec<*const c_char>>()
                    .as_mut_ptr(),
                self.cflags.len().try_into().unwrap(),
            )
        };

        if ptr.is_null() {
            Err(BccError::Compilation)
        } else {
            Ok(ptr)
        }
    }

    #[cfg(any(feature = "v0_9_0", feature = "v0_10_0"))]
    fn create_module(&self) -> Result<MutPointer, BccError> {
        let ptr = unsafe {
            bpf_module_create_c_from_string(
                self.code.as_ptr(),
                self.debug.bits(),
                self.cflags
                    .iter()
                    .map(|v| v.as_ptr())
                    .collect::<Vec<*const c_char>>()
                    .as_mut_ptr(),
                self.cflags.len().try_into().unwrap(),
                true,
            )
        };

        if ptr.is_null() {
            Err(BccError::Compilation)
        } else {
            Ok(ptr)
        }
    }

    #[cfg(any(
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
        feature = "v0_16_0",
        feature = "v0_17_0",
        feature = "v0_18_0",
        not(feature = "specific")
    ))]
    fn create_module(&self) -> Result<MutPointer, BccError> {
        let ptr = unsafe {
            bpf_module_create_c_from_string(
                self.code.as_ptr(),
                self.debug.bits(),
                self.cflags
                    .iter()
                    .map(|v| v.as_ptr())
                    .collect::<Vec<*const c_char>>()
                    .as_mut_ptr(),
                self.cflags.len().try_into().unwrap(),
                true,
                self.device
                    .as_ref()
                    .map(|name| name.as_ptr())
                    .unwrap_or(ptr::null_mut()),
            )
        };

        if ptr.is_null() {
            Err(BccError::Compilation)
        } else {
            Ok(ptr)
        }
    }

    /// Try constructing a BPF module from the builder
    pub fn build(mut self) -> Result<BPF, BccError> {
        // If USDT is supported, we have to generate the argument parsing code
        // first and prepend it to our BPF program.
        let contexts = if self.usdt_contexts.is_empty() {
            Vec::new()
        } else {
            let (mut code, contexts) = usdt_generate_args(self.usdt_contexts.drain(..).collect())?;

            let base_code = self.code.to_str().map(|s| s.to_string())?;
            code.push_str(base_code.as_str());
            self.code = to_cstring(code.as_str(), "code")?;

            contexts
        };

        let attach_usdt_ignore_pid = self.attach_usdt_ignore_pid;

        let ptr = self.create_module()?;

        let mut bpf = BPF {
            p: AtomicPtr::new(ptr),
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
            raw_tracepoints: HashSet::new(),
            perf_events: HashSet::new(),
            perf_events_array: HashSet::new(),
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
            socket: None,
            xdp: HashSet::new(),
            cflags: self.cflags,
            functions: HashMap::new(),
            debug: self.debug,
        };

        // Attach all of our USDT probes as uprobes.
        for context in contexts {
            let _ = context.attach(&mut bpf, attach_usdt_ignore_pid)?;
        }

        Ok(bpf)
    }
}

impl BPF {
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
    pub fn new(code: &str) -> Result<BPF, BccError> {
        BPFBuilder::new(code)?.build()
    }

    // get access to the internal pointer for the bpf module
    fn ptr(&self) -> MutPointer {
        self.p.load(Ordering::SeqCst)
    }

    /// Get access to a named table within the running BPF program.
    pub fn table(&self, name: &str) -> Result<Table, BccError> {
        let cname = to_cstring(name, "name")?;
        let id = unsafe { bpf_table_id(self.ptr(), cname.as_ptr()) };
        Ok(Table::new(id, self.ptr()))
    }

    #[cfg(any(feature = "v0_9_0", feature = "v0_10_0",))]
    unsafe fn load_func_impl(
        &self,
        program: *mut ::std::os::raw::c_void,
        prog_type: ::std::os::raw::c_int,
        name: *const ::std::os::raw::c_char,
        insns: *const bpf_insn,
        prog_len: ::std::os::raw::c_int,
        license: *const ::std::os::raw::c_char,
        kern_version: ::std::os::raw::c_uint,
        log_level: ::std::os::raw::c_int,
        log_buf: *mut ::std::os::raw::c_char,
        log_buf_size: ::std::os::raw::c_uint,
        _dev_name: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int {
        bcc_func_load(
            program,
            prog_type,
            name,
            insns,
            prog_len,
            license,
            kern_version,
            log_level,
            log_buf,
            log_buf_size,
        )
    }

    #[cfg(any(
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
        feature = "v0_16_0",
        feature = "v0_17_0",
        feature = "v0_18_0",
        not(feature = "specific"),
    ))]
    unsafe fn load_func_impl(
        &self,
        program: *mut ::std::os::raw::c_void,
        prog_type: ::std::os::raw::c_int,
        name: *const ::std::os::raw::c_char,
        insns: *const bpf_insn,
        prog_len: ::std::os::raw::c_int,
        license: *const ::std::os::raw::c_char,
        kern_version: ::std::os::raw::c_uint,
        log_level: ::std::os::raw::c_int,
        log_buf: *mut ::std::os::raw::c_char,
        log_buf_size: ::std::os::raw::c_uint,
        dev_name: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int {
        bcc_func_load(
            program,
            prog_type,
            name,
            insns,
            prog_len,
            license,
            kern_version,
            log_level,
            log_buf,
            log_buf_size,
            dev_name,
        )
    }

    #[cfg(any(
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
    ))]
    pub fn load_func(&mut self, name: &str, bpf_prog_type: BpfProgType) -> Result<i32, BccError> {
        Err(BccError::BccVersionTooLow {
            cause: "load_func".to_owned(),
            min_version: "0.9.0".to_owned(),
        })
    }

    /// Load a BPF function and return its file descriptor. Useful in BPF tail-calls.
    #[cfg(any(
        feature = "v0_9_0",
        feature = "v0_10_0",
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
        feature = "v0_16_0",
        feature = "v0_17_0",
        feature = "v0_18_0",
        not(feature = "specific"),
    ))]
    pub fn load_func(&mut self, name: &str, bpf_prog_type: BpfProgType) -> Result<i32, BccError> {
        let name_cstring = CString::new(name).unwrap();
        let name_ptr = name_cstring.as_ptr();

        if let Some(fd) = self.functions.get(name) {
            return Ok(*fd);
        }

        let log_level = if self.debug.contains(BccDebug::BPF_REGISTER_STATE) {
            2
        } else if self.debug.contains(BccDebug::BPF) {
            1
        } else {
            0
        };

        unsafe {
            let f_start = bpf_function_start(self.ptr(), name_ptr);
            if f_start as usize == 0 {
                return Err(BccError::Loading {
                    name: name.to_string(),
                    message: String::from("The specified function could not be found."),
                });
            }

            let fd = self.load_func_impl(
                self.ptr(),
                bpf_prog_type as i32,
                name_ptr,
                f_start as *const bcc_sys::bccapi::bpf_insn,
                bpf_function_size(self.ptr(), name_ptr).try_into().unwrap(),
                bpf_module_license(self.ptr()),
                bpf_module_kern_version(self.ptr()),
                log_level,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            );

            self.functions.insert(name.to_string(), fd);
            Ok(fd)
        }
    }

    // Get the table file descriptor
    pub(crate) fn table_fd(&self, name: &str) -> Result<i32, BccError> {
        let cname = to_cstring(name, "name")?;
        Ok(unsafe { bpf_table_fd(self.ptr(), cname.as_ptr()) })
    }

    /// Load a network traffic-control action which has the provided name within
    /// the BPF program
    pub fn load_net(&mut self, name: &str) -> Result<File, BccError> {
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT, 0, 0)
    }

    #[cfg(feature = "v0_4_0")]
    /// load the named BPF program from within the compiled BPF code
    pub fn load(
        &mut self,
        name: &str,
        prog_type: u32,
        _log_level: i32,
        log_size: u32,
    ) -> Result<File, BccError> {
        let cname = to_cstring(name, "name")?;
        unsafe {
            let start: *mut bpf_insn =
                bpf_function_start(self.ptr(), cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.ptr(), cname.as_ptr()) as i32;
            let license = bpf_module_license(self.ptr());
            let version = bpf_module_kern_version(self.ptr());
            if start.is_null() {
                return Err(BccError::Loading {
                    name: name.to_string(),
                    message: String::from("start instruction is null"),
                });
            }
            let mut log_buf: Vec<u8> = Vec::with_capacity(log_size as usize);
            // TODO: we're ignoring any changes bpf_prog_load made to log_buf right now
            // We should instead do something with this log buffer (I'm not clear on what it's for
            // yet though)
            let fd = bpf_prog_load(
                prog_type,
                start,
                size,
                license,
                version,
                null_or_mut_ptr(&mut log_buf),
                log_buf.capacity() as u32,
            );
            if fd < 0 {
                return Err(BccError::Loading {
                    name: name.to_string(),
                    message: Error::last_os_error().to_string(),
                });
            }
            Ok(File::from_raw_fd(fd))
        }
    }

    #[cfg(any(
        feature = "v0_5_0",
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0"
    ))]
    /// load the named BPF program from within the compiled BPF code
    pub fn load(
        &mut self,
        name: &str,
        prog_type: u32,
        log_level: i32,
        log_size: u32,
    ) -> Result<File, BccError> {
        let cname = to_cstring(name, "name")?;
        unsafe {
            let start: *mut bpf_insn =
                bpf_function_start(self.ptr(), cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.ptr(), cname.as_ptr()) as i32;
            let license = bpf_module_license(self.ptr());
            let version = bpf_module_kern_version(self.ptr());
            if start.is_null() {
                return Err(BccError::Loading {
                    name: name.to_string(),
                    message: String::from("start instruction is null"),
                });
            }
            let mut log_buf: Vec<u8> = Vec::with_capacity(log_size as usize);
            // TODO: we're ignoring any changes bpf_prog_load made to log_buf right now
            // We should instead do something with this log buffer (I'm not clear on what it's for
            // yet though)
            let fd = bpf_prog_load(
                prog_type,
                cname.as_ptr(),
                start,
                size,
                license,
                version,
                log_level,
                null_or_mut_ptr(&mut log_buf),
                log_buf.capacity() as u32,
            );
            if fd < 0 {
                return Err(BccError::Loading {
                    name: name.to_string(),
                    message: Error::last_os_error().to_string(),
                });
            }
            Ok(File::from_raw_fd(fd))
        }
    }

    #[cfg(any(
        feature = "v0_9_0",
        feature = "v0_10_0",
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
        feature = "v0_16_0",
        feature = "v0_17_0",
        feature = "v0_18_0",
        not(feature = "specific"),
    ))]
    /// load the named BPF program from within the compiled BPF code
    pub fn load(
        &mut self,
        name: &str,
        prog_type: u32,
        log_level: i32,
        log_size: u32,
    ) -> Result<File, BccError> {
        let cname = to_cstring(name, "name")?;
        unsafe {
            let start: *mut bpf_insn =
                bpf_function_start(self.ptr(), cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.ptr(), cname.as_ptr()) as i32;
            let license = bpf_module_license(self.ptr());
            let version = bpf_module_kern_version(self.ptr());
            if start.is_null() {
                return Err(BccError::Loading {
                    name: name.to_string(),
                    message: String::from("start instruction is null"),
                });
            }
            let mut log_buf: Vec<u8> = Vec::with_capacity(log_size as usize);
            // TODO: we're ignoring any changes bpf_prog_load made to log_buf right now
            // We should instead do something with this log buffer (I'm not clear on what it's for
            // yet though)
            let fd = bcc_prog_load(
                prog_type,
                cname.as_ptr(),
                start,
                size,
                license,
                version,
                log_level,
                null_or_mut_ptr(&mut log_buf),
                log_buf.capacity() as u32,
            );
            if fd < 0 {
                return Err(BccError::Loading {
                    name: name.to_string(),
                    message: Error::last_os_error().to_string(),
                });
            }
            Ok(File::from_raw_fd(fd))
        }
    }

    /// Returns the syscall prefix for the running kernel
    pub fn get_syscall_prefix(&mut self) -> String {
        for prefix in SYSCALL_PREFIXES.iter() {
            if self.ksymname(&format!("{}bpf", prefix)).is_ok() {
                return (*prefix).to_string();
            }
        }

        SYSCALL_PREFIXES[0].to_string()
    }

    /// Converts a syscall function name to a fully-qualified function name
    pub fn get_syscall_fnname(&mut self, name: &str) -> String {
        self.get_syscall_prefix() + name
    }

    /// Returns a list of kernel functions matching a provided regular
    /// expression
    pub fn get_kprobe_functions(&mut self, event_re: &str) -> Result<Vec<String>, BccError> {
        crate::kprobe::get_kprobe_functions(event_re)
    }

    /// Resolves the name to a kernel symbol
    pub fn ksymname(&mut self, name: &str) -> Result<u64, BccError> {
        self.sym_caches
            .entry(-1)
            .or_insert_with(|| SymbolCache::new(-1));
        let cache = self.sym_caches.get(&-1).unwrap();
        cache.resolve_name("", name)
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
        feature = "v0_16_0",
        feature = "v0_17_0",
        feature = "v0_18_0",
        not(feature = "specific"),
    ))]
    /// Returns true if raw tracepoints are supported by the running kernel
    pub fn support_raw_tracepoint(&mut self) -> bool {
        self.ksymname("bpf_find_raw_tracepoint").is_ok()
            || self.ksymname("bpf_get_raw_tracepoint").is_ok()
    }

    pub fn init_perf_map<F>(&mut self, table: Table, cb: F) -> Result<(), BccError>
    where
        F: Fn() -> Box<dyn FnMut(&[u8]) + Send>,
    {
        let perf_map = PerfMapBuilder::new(table, cb).build()?;
        self.perf_readers.extend(perf_map.readers);
        Ok(())
    }

    pub fn perf_map_poll(&mut self, timeout: i32) {
        unsafe {
            perf_reader_poll(
                self.perf_readers.len() as i32,
                self.perf_readers.as_ptr() as *mut *mut perf_reader,
                timeout,
            );
        };
    }

    pub fn get_socket_fd(self) -> Option<i32> {
        match &self.socket {
            Some(socket) => Some(socket.sock_fd),
            None => None,
        }
    }
}

impl Drop for BPF {
    fn drop(&mut self) {
        unsafe {
            bpf_module_destroy(self.ptr());
            for (_, fd) in self.functions.iter() {
                File::from_raw_fd(*fd);
            }
        };
    }
}
