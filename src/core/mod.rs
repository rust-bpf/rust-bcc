mod kprobe;
mod perf_event;
mod perf_event_array;
mod raw_tracepoint;
mod tracepoint;
mod uprobe;

use bcc_sys::bccapi::*;

pub(crate) use self::kprobe::Kprobe;
pub(crate) use self::perf_event::PerfEvent;
pub(crate) use self::perf_event_array::PerfEventArray;
pub(crate) use self::raw_tracepoint::RawTracepoint;
pub(crate) use self::tracepoint::Tracepoint;
pub(crate) use self::uprobe::Uprobe;
use crate::perf_event::PerfReader;
use crate::symbol::SymbolCache;
use crate::table::Table;
use crate::BccError;

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ffi::CString;
use std::fs::File;
use std::ops::Drop;
use std::os::raw::c_char;
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
    perf_readers: Vec<PerfReader>,
    sym_caches: HashMap<pid_t, SymbolCache>,
    cflags: Vec<CString>,
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
}

impl BPFBuilder {
    /// Create a new builder with the given code
    pub fn new(code: &str) -> Result<Self, BccError> {
        let code = CString::new(code)?;
        Ok(Self {
            code,
            cflags: Vec::new(),
        })
    }

    /// Set CFLAGS to be used
    pub fn cflags<T: AsRef<str>>(mut self, cflags: &[T]) -> Result<Self, BccError> {
        self.cflags.clear();
        for f in cflags {
            let cs = CString::new(f.as_ref())?;
            self.cflags.push(cs);
        }
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
    /// Try constructing a BPF module from the builder
    pub fn build(self) -> Result<BPF, BccError> {
        let cflags_ptr = if self.cflags.is_empty() {
            ptr::null_mut()
        } else {
            self.cflags.as_ptr() as *mut *const c_char
        };

        let ptr = unsafe {
            bpf_module_create_c_from_string(
                self.code.as_ptr(),
                2,
                self.cflags.as_ptr() as *mut *const c_char,
                self.cflags.len().try_into().unwrap(),
            )
        };

        if ptr.is_null() {
            return Err(BccError::Compilation);
        }

        Ok(BPF {
            p: AtomicPtr::new(ptr),
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
            raw_tracepoints: HashSet::new(),
            perf_events: HashSet::new(),
            perf_events_array: HashSet::new(),
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
            cflags: self.cflags,
        })
    }

    // 0.9.0 changes the API for bpf_module_create_c_from_string()
    #[cfg(any(feature = "v0_9_0", feature = "v0_10_0"))]
    /// Try constructing a BPF module from the builder
    pub fn build(self) -> Result<BPF, BccError> {
        let cflags_ptr = if self.cflags.is_empty() {
            ptr::null_mut()
        } else {
            self.cflags.as_ptr() as *mut *const c_char
        };

        let ptr = unsafe {
            bpf_module_create_c_from_string(
                self.code.as_ptr(),
                2,
                cflags_ptr,
                self.cflags.len().try_into().unwrap(),
                true,
            )
        };

        if ptr.is_null() {
            return Err(BccError::Compilation);
        }

        Ok(BPF {
            p: AtomicPtr::new(ptr),
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
            raw_tracepoints: HashSet::new(),
            perf_events: HashSet::new(),
            perf_events_array: HashSet::new(),
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
            cflags: self.cflags,
        })
    }

    // 0.11.0 changes the API for bpf_module_create_c_from_string()
    #[cfg(any(
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
        not(feature = "specific"),
    ))]
    /// Try constructing a BPF module from the builder
    pub fn build(self) -> Result<BPF, BccError> {
        let cflags_ptr = if self.cflags.is_empty() {
            ptr::null_mut()
        } else {
            self.cflags.as_ptr() as *mut *const c_char
        };

        let ptr = unsafe {
            bpf_module_create_c_from_string(
                self.code.as_ptr(),
                2,
                cflags_ptr,
                self.cflags.len().try_into().unwrap(),
                true,
                ptr::null_mut(),
            )
        };

        if ptr.is_null() {
            return Err(BccError::Compilation);
        }

        Ok(BPF {
            p: AtomicPtr::new(ptr),
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
            raw_tracepoints: HashSet::new(),
            perf_events: HashSet::new(),
            perf_events_array: HashSet::new(),
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
            cflags: self.cflags,
        })
    }
}

impl BPF {
    #[cfg(any(
        feature = "v0_4_0",
        feature = "v0_5_0",
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
    ))]
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
    pub fn new(code: &str) -> Result<BPF, BccError> {
        BPFBuilder::new(code)?.build()
    }

    // 0.9.0 changes the API for bpf_module_create_c_from_string()
    #[cfg(any(feature = "v0_9_0", feature = "v0_10_0",))]
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
    pub fn new(code: &str) -> Result<BPF, BccError> {
        BPFBuilder::new(code)?.build()
    }

    // 0.11.0 changes the API for bpf_module_create_c_from_string()
    #[cfg(any(
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
        not(feature = "specific"),
    ))]
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
    pub fn new(code: &str) -> Result<BPF, BccError> {
        BPFBuilder::new(code)?.build()
    }

    // get access to the interal pointer for the bpf module
    fn ptr(&self) -> *mut c_void {
        self.p.load(Ordering::SeqCst)
    }

    /// Get access to a named table within the running BPF program.
    pub fn table(&self, name: &str) -> Table {
        // TODO: clean up this unwrap (and all the rest in this file)
        let cname = CString::new(name).unwrap();
        let id = unsafe { bpf_table_id(self.ptr(), cname.as_ptr()) };
        Table::new(id, self.ptr())
    }

    // Get the table file descriptor
    pub(crate) fn table_fd(&self, name: &str) -> i32 {
        let cname = CString::new(name).unwrap();
        unsafe { bpf_table_fd(self.ptr(), cname.as_ptr()) }
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
        let cname = CString::new(name).unwrap();
        unsafe {
            let start: *mut bpf_insn =
                bpf_function_start(self.ptr(), cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.ptr(), cname.as_ptr()) as i32;
            let license = bpf_module_license(self.ptr());
            let version = bpf_module_kern_version(self.ptr());
            if start.is_null() {
                return Err(BccError::Loading {
                    name: name.to_string(),
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
        let cname = CString::new(name).unwrap();
        unsafe {
            let start: *mut bpf_insn =
                bpf_function_start(self.ptr(), cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.ptr(), cname.as_ptr()) as i32;
            let license = bpf_module_license(self.ptr());
            let version = bpf_module_kern_version(self.ptr());
            if start.is_null() {
                return Err(BccError::Loading {
                    name: name.to_string(),
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
        let cname = CString::new(name).unwrap();
        unsafe {
            let start: *mut bpf_insn =
                bpf_function_start(self.ptr(), cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.ptr(), cname.as_ptr()) as i32;
            let license = bpf_module_license(self.ptr());
            let version = bpf_module_kern_version(self.ptr());
            if start.is_null() {
                return Err(BccError::Loading {
                    name: name.to_string(),
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
                });
            }
            Ok(File::from_raw_fd(fd))
        }
    }

    /// Returns the syscall prefix for the running kernel
    pub fn get_syscall_prefix(&mut self) -> String {
        for prefix in SYSCALL_PREFIXES.iter() {
            if self.ksymname(prefix).is_ok() {
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

    /// Resulves the name to a kernel symbol
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
        let perf_map = crate::perf_event::init_perf_map(table, cb)?;
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
}

impl Drop for BPF {
    fn drop(&mut self) {
        unsafe {
            bpf_module_destroy(self.ptr());
        };
    }
}
