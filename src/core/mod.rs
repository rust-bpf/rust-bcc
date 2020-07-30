mod kprobe;
mod perf_event;
mod raw_tracepoint;
mod tracepoint;
mod uprobe;

pub use crate::core::kprobe::{KernelProbe, KernelReturnProbe};
pub use crate::core::perf_event::PerfEventProbe;
pub use crate::core::raw_tracepoint::RawTracepointProbe;
pub use crate::core::uprobe::{UserspaceProbe, UserspaceReturnProbe};

use bcc_sys::bccapi::*;

use self::kprobe::Kprobe;
use self::perf_event::PerfEvent;
use self::raw_tracepoint::RawTracepoint;
use self::tracepoint::Tracepoint;
use self::uprobe::Uprobe;
use crate::perf::{self, PerfReader};
use crate::symbol::SymbolCache;
use crate::table::Table;
use crate::BccError;

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::ops::Drop;
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
pub struct BPF {
    p: AtomicPtr<c_void>,
    kprobes: HashSet<Kprobe>,
    uprobes: HashSet<Uprobe>,
    tracepoints: HashSet<Tracepoint>,
    raw_tracepoints: HashSet<RawTracepoint>,
    perf_events: HashSet<PerfEvent>,
    perf_readers: Vec<PerfReader>,
    sym_caches: HashMap<pid_t, SymbolCache>,
}

fn make_alphanumeric(s: &str) -> String {
    s.replace(
        |c| !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')),
        "_",
    )
}

fn null_or_mut_ptr<T>(s: &mut Vec<u8>) -> *mut T {
    if s.capacity() == 0 {
        ptr::null_mut()
    } else {
        s.as_mut_ptr() as *mut T
    }
}

impl BPF {
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
    #[cfg(any(
        feature = "v0_4_0",
        feature = "v0_5_0",
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
    ))]
    pub fn new(code: &str) -> Result<BPF, BccError> {
        let cs = CString::new(code)?;
        let ptr = unsafe { bpf_module_create_c_from_string(cs.as_ptr(), 2, ptr::null_mut(), 0) };
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
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
        })
    }

    // 0.9.0 changes the API for bpf_module_create_c_from_string()
    #[cfg(any(feature = "v0_9_0", feature = "v0_10_0",))]
    pub fn new(code: &str) -> Result<BPF, BccError> {
        let cs = CString::new(code)?;
        let ptr =
            unsafe { bpf_module_create_c_from_string(cs.as_ptr(), 2, ptr::null_mut(), 0, true) };
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
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
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
    pub fn new(code: &str) -> Result<BPF, BccError> {
        let cs = CString::new(code)?;
        let ptr = unsafe {
            bpf_module_create_c_from_string(
                cs.as_ptr(),
                2,
                ptr::null_mut(),
                0,
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
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
        })
    }

    fn ptr(&self) -> *mut c_void {
        self.p.load(Ordering::SeqCst)
    }

    pub fn table(&self, name: &str) -> Table {
        // TODO: clean up this unwrap (and all the rest in this file)
        let cname = CString::new(name).unwrap();
        let id = unsafe { bpf_table_id(self.ptr(), cname.as_ptr()) };
        Table::new(id, self.ptr())
    }

    pub fn load_net(&mut self, name: &str) -> Result<File, BccError> {
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT, 0, 0)
    }

    pub fn load_tracepoint(&mut self, name: &str) -> Result<File, BccError> {
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT, 0, 0)
    }

    #[cfg(feature = "v0_4_0")]
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

    pub fn get_syscall_prefix(&mut self) -> String {
        for prefix in SYSCALL_PREFIXES.iter() {
            if self.ksymname(prefix).is_ok() {
                return (*prefix).to_string();
            }
        }

        SYSCALL_PREFIXES[0].to_string()
    }

    pub fn get_syscall_fnname(&mut self, name: &str) -> String {
        self.get_syscall_prefix() + name
    }

    pub fn get_kprobe_functions(&mut self, event_re: &str) -> Result<Vec<String>, BccError> {
        crate::core::kprobe::get_kprobe_functions(event_re)
    }

    pub fn attach_tracepoint(
        &mut self,
        subsys: &str,
        name: &str,
        file: File,
    ) -> Result<(), BccError> {
        let tracepoint = Tracepoint::attach_tracepoint(subsys, name, file)?;
        self.tracepoints.insert(tracepoint);
        Ok(())
    }

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
    pub fn support_raw_tracepoint(&mut self) -> bool {
        self.ksymname("bpf_find_raw_tracepoint").is_ok()
            || self.ksymname("bpf_get_raw_tracepoint").is_ok()
    }

    pub fn init_perf_map<F>(&mut self, table: Table, cb: F) -> Result<(), BccError>
    where
        F: Fn() -> Box<dyn FnMut(&[u8]) + Send>,
    {
        let perf_map = perf::init_perf_map(table, cb)?;
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
