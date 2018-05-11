use bcc_sys::bccapi::*;
use failure::Error;

use core::{Kprobe, Tracepoint, Uprobe};
use table::Table;
use types::MutPointer;

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::prelude::*;
use std::ptr;

#[derive(Debug)]
pub struct BPF {
    p: MutPointer,
    kprobes: HashSet<Kprobe>,
    uprobes: HashSet<Uprobe>,
    tracepoints: HashSet<Tracepoint>,
}

impl BPF {
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
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

    pub fn attach_tracepoint(
        &mut self,
        subsystem: &str,
        name: &str,
        file: File,
    ) -> Result<(), Error> {
        let tracepoint = Tracepoint::attach_tracepoint(subsystem, name, file)?;
        self.tracepoints.insert(tracepoint);
        Ok(())
    }

    pub fn attach_kprobe(&mut self, function: &str, file: File) -> Result<(), Error> {
        let kprobe = Kprobe::attach_kprobe(function, file)?;
        self.kprobes.insert(kprobe);
        Ok(())
    }

    pub fn attach_kretprobe(&mut self, function: &str, file: File) -> Result<(), Error> {
        let kprobe = Kprobe::attach_kretprobe(function, file)?;
        self.kprobes.insert(kprobe);
        Ok(())
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

    pub fn attach_uretprobe(
        &mut self,
        name: &str,
        symbol: &str,
        file: File,
        pid: pid_t,
    ) -> Result<(), Error> {
        let uretprobe = Uprobe::attach_uretprobe(name, symbol, file, pid)?;
        self.uprobes.insert(uretprobe);
        Ok(())
    }
}
