
use failure::Error;
use bcc_sys::bccapi::*;

use symbol;
use table::Table;
use types::MutPointer;

use std::ffi::CString;
use std::collections::HashMap;
use std::fs::File;
use std::os::unix::prelude::*;
use std::ptr;

// TODO: implement `Drop` for this type
#[derive(Debug)]
pub struct BPF {
    p: MutPointer,
    uprobes: HashMap<String, Uprobe>,
    kprobes: HashMap<String, Kprobe>,
}

#[derive(Debug)]
pub struct Uprobe {
    code_fd: File,
    p: MutPointer,
}

impl Drop for Uprobe {
    fn drop(&mut self) {
        // TODO
    }
}

#[derive(Debug)]
pub struct Kprobe {
    code_fd: File,
    p: MutPointer,
}

impl Drop for Kprobe {
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
            uprobes: HashMap::new(),
            kprobes: HashMap::new(),
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
        let alpha_path = make_alphanumeric(function);
        let ev_name = format!("p_{}", &alpha_path);
        self.attach_kprobe_inner(
            &ev_name,
            bpf_probe_attach_type_BPF_PROBE_ENTRY,
            function,
            file,
        )
    }

    pub fn attach_kretprobe(&mut self, function: &str, file: File) -> Result<(), Error> {
        let alpha_path = make_alphanumeric(function);
        let ev_name = format!("r_{}", &alpha_path);
        self.attach_kprobe_inner(
            &ev_name,
            bpf_probe_attach_type_BPF_PROBE_RETURN,
            function,
            file,
        )
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

    fn attach_kprobe_inner(
        &mut self,
        name: &str,
        attach_type: u32,
        function: &str,
        file: File,
    ) -> Result<(), Error> {
        let cname = CString::new(name).unwrap();
        let cfunction = CString::new(function).unwrap();
        // println!("{}, {}", cname.as_ptr() as u64, cfunction.as_ptr() as u64);
        let (pid, cpu, group_fd) = (-1, 0, -1);
        let kprobe_ptr = unsafe {
            bpf_attach_kprobe(
                file.as_raw_fd(),
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
        if kprobe_ptr.is_null() {
            return Err(format_err!("Failed to attach kprobe: {}", name));
        }
        self.kprobes.insert(
            name.to_string(),
            Kprobe {
                p: kprobe_ptr,
                code_fd: file,
            },
        );
        Ok(())
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
            name.to_string(),
            Uprobe {
                p: uprobe_ptr,
                code_fd: file,
            },
        );
        Ok(())
    }
}
