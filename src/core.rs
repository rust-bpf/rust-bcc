
use failure::Error;
use bcc_sys::bccapi::*;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;

use symbol;
use table::Table;
use types::MutPointer;

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;
use std::ptr;

#[derive(Debug)]
pub struct BPF {
    p: MutPointer,
    kprobes: HashSet<Kprobe>,
    uprobes: HashSet<Uprobe>,
    tracepoints: HashSet<Tracepoint>,
}

impl Drop for BPF {
    fn drop(&mut self) {
        for uprobe in &self.uprobes {
            self.detach_uprobe_inner(&uprobe);
        }
        for tracepoint in &self.tracepoints {
            self.detach_tracepoint_inner(&tracepoint);
        }
    }
}

#[derive(Debug)]
pub struct Uprobe {
    code_fd: File,
    name: String,
    p: MutPointer,
}

impl Drop for Uprobe {
    fn drop(&mut self) {
        // TODO
    }
}

impl Eq for Uprobe {}

impl Hash for Uprobe {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for Uprobe {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

#[derive(Debug)]
pub struct Kprobe {
    code_fd: File,
    name: CString,
    p: MutPointer,
}

impl Kprobe {
    fn new(name: &str, attach_type: u32, function: &str, code: File) -> Result<Self, Error> {
        let cname = CString::new(name).map_err(|_| {
            format_err!("Nul byte in Kprobe name: {}", name)
        })?;
        let cfunction = CString::new(function).map_err(|_| {
            format_err!("Nul byte in Kprobe function: {}", function)
        })?;
        let (pid, cpu, group_fd) = (-1, 0, -1);
        let ptr = unsafe {
            bpf_attach_kprobe(
                code.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cfunction.as_ptr(),
                pid,
                cpu,
                group_fd,
                None,
                ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            Err(format_err!("Failed to attach Kprobe: {}", name))
        } else {
            Ok(Self {
                p: ptr,
                name: cname,
                code_fd: code,
            })
        }
    }

    pub fn attach_kprobe(function: &str, code: File) -> Result<Self, Error> {
        let name = format!("p_{}", &make_alphanumeric(function));
        Kprobe::new(&name, BPF_PROBE_ENTRY, function, code)
            .map_err(|_| format_err!("Failed to attach Kprobe: {}", name))
    }

    pub fn attach_kretprobe(function: &str, code: File) -> Result<Self, Error> {
        let name = format!("r_{}", &make_alphanumeric(function));
        Kprobe::new(&name, BPF_PROBE_RETURN, function, code)
            .map_err(|_| format_err!("Failed to attach Kretprobe: {}", name))
    }
}

impl Drop for Kprobe {
    fn drop(&mut self) {
        unsafe {
            bpf_detach_kprobe(self.name.as_ptr());
        }
    }
}

impl Eq for Kprobe {}

impl Hash for Kprobe {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for Kprobe {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

#[derive(Debug)]
pub struct Tracepoint {
    subsys: String,
    name: String,
    code_fd: File,
    p: MutPointer,
}

impl PartialEq for Tracepoint {
    fn eq(&self, other: &Tracepoint) -> bool {
        self.subsys == other.subsys && self.name == other.name
    }
}

impl Eq for Tracepoint {}

impl Hash for Tracepoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.subsys.hash(state);
        self.name.hash(state);
    }
}

impl Drop for Tracepoint {
    fn drop(&mut self) {
        // TODO
    }
}

fn make_alphanumeric(s: &str) -> String {
    s.replace(|c| {
        !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
    }, "_")
}

impl BPF {
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
    pub fn new(code: &str) -> Result<BPF, Error> {
        let cs = CString::new(code)?;
        let ptr =
            unsafe { bpf_module_create_c_from_string(cs.as_ptr(), 2, ptr::null_mut(), 0) };
        if ptr.is_null() {
            return Err(format_err!("couldn't create BPF program"));
        }

        Ok(BPF {
            p: ptr,
            uprobes: HashSet::new(),
            kprobes: HashSet::new(),
            tracepoints: HashSet::new(),
        })
    }

    pub fn table(&self, name: &str) -> Table {
        // TODO: clean up this unwrap (and all the rest in this file)
        let cname = CString::new(name).unwrap();
        let id = unsafe { bpf_table_id(self.p as MutPointer, cname.as_ptr()) };
        Table::new(id, self.p)
    }

    pub fn load_net(&mut self, name: &str) -> Result<File, Error> {
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT, 0, 0);
    }

    pub fn load_kprobe(&mut self, name: &str) -> Result<File, Error> {
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0);
    }

    pub fn load_uprobe(&mut self, name: &str) -> Result<File, Error> {
        // it's BPF_PROG_TYPE_KPROBE even though it's a uprobe, it's weird
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0);
    }

    pub fn load_tracepoint(&mut self, name: &str) -> Result<File, Error> {
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT, 0, 0);
    }

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
                log_buf.as_mut_ptr() as *mut i8,
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
        name: &str,
        symbol: &str,
        file: File,
        pid: pid_t,
    ) -> Result<(), Error> {
        let (path, addr) = symbol::resolve_symbol_path(name, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        self.attach_uprobe_inner(
            &ev_name,
            bpf_probe_attach_type_BPF_PROBE_RETURN,
            &path,
            addr,
            file,
            pid,
        )
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

    pub fn attach_uprobe(
        &mut self,
        binary_path: &str,
        symbol: &str,
        file: File,
        pid: pid_t,
    ) -> Result<(), Error> {
        let (path, addr) = symbol::resolve_symbol_path(binary_path, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(&path);
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        self.attach_uprobe_inner(
            &ev_name,
            bpf_probe_attach_type_BPF_PROBE_ENTRY,
            &path,
            addr,
            file,
            pid,
        )
    }

    pub fn attach_tracepoint(&mut self, category: &str, name: &str, file: File) -> Result<(), Error> {
        self.attach_tracepoint_inner(
            &make_alphanumeric(category),
            &make_alphanumeric(name),
            file,
        )
    }

    fn attach_uprobe_inner(
        &mut self,
        name: &str,
        attach_type: u32,
        path: &str,
        addr: u64,
        file: File,
        pid: pid_t,
    ) -> Result<(), Error> {
        let cname = CString::new(name).unwrap();
        let cpath = CString::new(path).unwrap();
        // TODO: maybe pass in the CPU & PID instead of
        let (cpu, group_fd) = (0, -1);
        let uprobe_ptr = unsafe {
            bpf_attach_uprobe(
                file.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cpath.as_ptr(),
                addr,
                pid,
                cpu,
                group_fd,
                None,
                ptr::null_mut(),
            )
        };
        if uprobe_ptr.is_null() {
            return Err(format_err!("Failed to attach uprobe: {}", name));
        }
        self.uprobes.insert(
            Uprobe {
                p: uprobe_ptr,
                name: name.to_string(),
                code_fd: file,
            },
        );
        Ok(())
    }

    fn attach_tracepoint_inner(
        &mut self,
        subsys: &str,
        name: &str,
        file: File,
    ) -> Result<(), Error> {
        let cname = CString::new(name).unwrap();
        let csubsys = CString::new(subsys).unwrap();
        // NOTE: BPF events are system-wide and do not support CPU filter
        let (pid, cpu, group_fd) = (-1, 0, -1);
        let ptr = unsafe {
            bpf_attach_tracepoint(
                file.as_raw_fd(),
                csubsys.as_ptr(),
                cname.as_ptr(),
                pid,
                cpu,
                group_fd,
                None,
                ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            return Err(format_err!("Failed to attach tracepoint: {}:{}", subsys, name));
        }

        self.tracepoints.insert(
            Tracepoint {
                subsys: subsys.to_string(),
                name: name.to_string(),
                p: ptr,
                code_fd: file,
            },
        );
        Ok(())
    }

    fn detach_kprobe_inner(
        &self,
        kprobe: &Kprobe,
    ) {
        let cname = CString::new(kprobe.name.clone()).unwrap();
        unsafe {
            bpf_detach_kprobe(cname.as_ptr());
        }
    }

    fn detach_uprobe_inner(
        &self,
        uprobe: &Uprobe,
    ) {
        let cname = CString::new(uprobe.name.clone()).unwrap();
        unsafe {
            bpf_detach_uprobe(cname.as_ptr());
        }
    }

    fn detach_tracepoint_inner(
        &self,
        tracepoint: &Tracepoint,
    ) {
        let csubsys = CString::new(tracepoint.subsys.clone()).unwrap();
        let cname = CString::new(tracepoint.name.clone()).unwrap();
        unsafe {
            bpf_detach_tracepoint(csubsys.as_ptr(), cname.as_ptr());
        }
    }
}
