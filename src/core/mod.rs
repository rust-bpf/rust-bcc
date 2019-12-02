mod kprobe;
mod raw_tracepoint;
mod tracepoint;
mod uprobe;

use bcc_sys::bccapi::*;
use failure::*;

use self::kprobe::Kprobe;
use self::raw_tracepoint::RawTracepoint;
use self::tracepoint::Tracepoint;
use self::uprobe::Uprobe;
use crate::perf::{self, PerfReader};
use crate::symbol::SymbolCache;
use crate::table::Table;
use crate::types::MutPointer;

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::ops::Drop;
use std::os::unix::prelude::*;
use std::ptr;

#[derive(Debug)]
pub struct BPF {
    p: MutPointer,
    kprobes: HashSet<Kprobe>,
    uprobes: HashSet<Uprobe>,
    tracepoints: HashSet<Tracepoint>,
    raw_tracepoints: HashSet<RawTracepoint>,
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
    pub fn new(code: &str) -> Result<BPF, Error> {
        let cs = CString::new(code)?;
        let ptr = unsafe { bpf_module_create_c_from_string(cs.as_ptr(), 2, ptr::null_mut(), 0) };
        if ptr.is_null() {
            return Err(format_err!("couldn't create BPF program"));
        }

        Ok(BPF {
            p: ptr,
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
            raw_tracepoints: HashSet::new(),
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
        })
    }

    // 0.9.0 changes the API for bpf_module_create_c_from_string()
    #[cfg(any(
        feature = "v0_9_0",
        feature = "v0_10_0",
    ))]
    pub fn new(code: &str) -> Result<BPF, Error> {
        let cs = CString::new(code)?;
        let ptr =
            unsafe { bpf_module_create_c_from_string(cs.as_ptr(), 2, ptr::null_mut(), 0, true) };
        if ptr.is_null() {
            return Err(format_err!("couldn't create BPF program"));
        }

        Ok(BPF {
            p: ptr,
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
            raw_tracepoints: HashSet::new(),
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
        })
    }

    // 0.11.0 changes the API for bpf_module_create_c_from_string()
    #[cfg(any(
        feature = "v0_11_0",
        not(feature = "specific"),
    ))]
    pub fn new(code: &str) -> Result<BPF, Error> {
        let cs = CString::new(code)?;
        let ptr =
            unsafe { bpf_module_create_c_from_string(cs.as_ptr(), 2, ptr::null_mut(), 0, true, ptr::null_mut()) };
        if ptr.is_null() {
            return Err(format_err!("couldn't create BPF program"));
        }

        Ok(BPF {
            p: ptr,
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
            raw_tracepoints: HashSet::new(),
            perf_readers: Vec::new(),
            sym_caches: HashMap::new(),
        })
    }

    pub fn table(&self, name: &str) -> Table {
        // TODO: clean up this unwrap (and all the rest in this file)
        let cname = CString::new(name).unwrap();
        let id = unsafe { bpf_table_id(self.p as MutPointer, cname.as_ptr()) };
        Table::new(id, self.p)
    }

    pub fn load_net(&mut self, name: &str) -> Result<File, Error> {
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT, 0, 0)
    }

    pub fn load_kprobe(&mut self, name: &str) -> Result<File, Error> {
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0)
    }

    pub fn load_uprobe(&mut self, name: &str) -> Result<File, Error> {
        // it's BPF_PROG_TYPE_KPROBE even though it's a uprobe, it's weird
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0)
    }

    pub fn load_tracepoint(&mut self, name: &str) -> Result<File, Error> {
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT, 0, 0)
    }

    #[cfg(any(
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
        feature = "v0_9_0",
        feature = "v0_10_0",
        feature = "v0_11_0",
        not(feature = "specific"),
    ))]
    pub fn load_raw_tracepoint(&mut self, name: &str) -> Result<File, Error> {
        self.load(name, bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT, 0, 0)
    }

    #[cfg(feature = "v0_4_0")]
    pub fn load(
        &mut self,
        name: &str,
        prog_type: u32,
        _log_level: i32,
        log_size: u32,
    ) -> Result<File, Error> {
        let cname = CString::new(name).unwrap();
        unsafe {
            let start: *mut bpf_insn = bpf_function_start(self.p, cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.p, cname.as_ptr()) as i32;
            let license = bpf_module_license(self.p);
            let version = bpf_module_kern_version(self.p);
            if start.is_null() {
                return Err(format_err!("Error in bpf_function_start for {}", name));
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
                return Err(format_err!("error loading BPF program: {}", name));
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
    ) -> Result<File, Error> {
        let cname = CString::new(name).unwrap();
        unsafe {
            let start: *mut bpf_insn = bpf_function_start(self.p, cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.p, cname.as_ptr()) as i32;
            let license = bpf_module_license(self.p);
            let version = bpf_module_kern_version(self.p);
            if start.is_null() {
                return Err(format_err!("Error in bpf_function_start for {}", name));
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
                return Err(format_err!("error loading BPF program: {}", name));
            }
            Ok(File::from_raw_fd(fd))
        }
    }

    #[cfg(any(
        feature = "v0_9_0",
        feature = "v0_10_0",
        feature = "v0_11_0",
        not(feature = "specific"),
    ))]
    pub fn load(
        &mut self,
        name: &str,
        prog_type: u32,
        log_level: i32,
        log_size: u32,
    ) -> Result<File, Error> {
        let cname = CString::new(name).unwrap();
        unsafe {
            let start: *mut bpf_insn = bpf_function_start(self.p, cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.p, cname.as_ptr()) as i32;
            let license = bpf_module_license(self.p);
            let version = bpf_module_kern_version(self.p);
            if start.is_null() {
                return Err(format_err!("Error in bpf_function_start for {}", name));
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
                return Err(format_err!("error loading BPF program: {}", name));
            }
            Ok(File::from_raw_fd(fd))
        }
    }

    pub fn attach_uretprobe(
        &mut self,
        binary_path: &str,
        symbol: &str,
        file: File,
        pid: pid_t,
    ) -> Result<(), Error> {
        let uprobe = Uprobe::attach_uretprobe(binary_path, symbol, file, pid)?;
        self.uprobes.insert(uprobe);
        Ok(())
    }

    pub fn attach_kprobe(&mut self, function: &str, file: File) -> Result<(), Error> {
        let kprobe = Kprobe::attach_kprobe(function, file)?;
        self.kprobes.insert(kprobe);
        Ok(())
    }

    pub fn attach_kretprobe(&mut self, function: &str, file: File) -> Result<(), Error> {
        let kretprobe = Kprobe::attach_kretprobe(function, file)?;
        self.kprobes.insert(kretprobe);
        Ok(())
    }

    pub fn get_kprobe_functions(&mut self, event_re: &str) -> Result<Vec<String>, Error> {
        Kprobe::get_kprobe_functions(event_re)
    }

    pub fn attach_uprobe(
        &mut self,
        binary_path: &str,
        symbol: &str,
        file: File,
        pid: pid_t,
    ) -> Result<(), Error> {
        let uprobe = Uprobe::attach_uprobe(binary_path, symbol, file, pid)?;
        self.uprobes.insert(uprobe);
        Ok(())
    }

    pub fn attach_tracepoint(&mut self, subsys: &str, name: &str, file: File) -> Result<(), Error> {
        let tracepoint = Tracepoint::attach_tracepoint(subsys, name, file)?;
        self.tracepoints.insert(tracepoint);
        Ok(())
    }

    #[cfg(any(
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
        feature = "v0_9_0",
        feature = "v0_10_0",
        feature = "v0_11_0",
        not(feature = "specific"),
    ))]
    pub fn attach_raw_tracepoint(&mut self, name: &str, file: File) -> Result<(), Error> {
        let raw_tracepoint = RawTracepoint::attach_raw_tracepoint(name, file)?;
        self.raw_tracepoints.insert(raw_tracepoint);
        Ok(())
    }

    pub fn ksymname(&mut self, name: &str) -> Result<u64, Error> {
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
        not(feature = "specific"),
    ))]
    pub fn support_raw_tracepoint(&mut self) -> bool {
        self.ksymname("bpf_find_raw_tracepoint").is_ok()
            || self.ksymname("bpf_get_raw_tracepoint").is_ok()
    }

    pub fn init_perf_map<F>(&mut self, table: Table, cb: F) -> Result<(), Error>
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
            bpf_module_destroy(self.p);
        };
    }
}
