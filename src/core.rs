//use libc::*;
use std::ffi::CString;

use failure::Error;
use bcc_sys::bccapi::*;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use symbol;
use table::Table;

use types::*;

// TODO: implement `Drop` for this type
#[derive(Debug, Clone)]
pub struct BPF {
    p: MutPointer,
    uprobes: HashMap<String, MutPointer>,
    kprobes: HashMap<String, MutPointer>,
    // TODO: this should be a HashMap<String, File> so that the file gets closed properly
    funcs: HashMap<String, fd_t>,
}

fn make_alphanumeric(s: String) -> String {
    s.replace(|c| {
        !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
    }, "_")
}

impl BPF {
    /// `code` is a string containing C code. See https://github.com/iovisor/bcc for examples
    pub fn new(code: &str) -> Result<BPF, Error> {
        let cs = CString::new(code)?;
        let ptr =
            unsafe { bpf_module_create_c_from_string(cs.as_ptr(), 2, 0 as *mut *const i8, 0) };

        Ok(BPF {
            p: ptr,
            uprobes: HashMap::new(),
            kprobes: HashMap::new(),
            funcs: HashMap::new(),
        })
    }

    pub fn table(&self, name: &str) -> Table {
        // TODO: clean up this unwrap (and all the rest in this file)
        let cname = CString::new(name).unwrap();
        let id = unsafe { bpf_table_id(self.p as MutPointer, cname.as_ptr()) };
        Table::new(id, self.p)
    }

    pub fn load_net(&mut self, name: &str) -> Result<fd_t, Error> {
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT, 0, 0);
    }

    pub fn load_kprobe(&mut self, name: &str) -> Result<fd_t, Error> {
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0);
    }

    pub fn load_uprobe(&mut self, name: &str) -> Result<fd_t, Error> {
        // it's BPF_PROG_TYPE_KPROBE even though it's a uprobe, it's weird
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0);
    }

    pub fn load(
        &mut self,
        name: &str,
        prog_type: u32,
        log_level: i32,
        log_size: u32,
    ) -> Result<fd_t, Error> {
        let name_string = name.to_string();
        match self.funcs.entry(name_string.clone()) {
            Entry::Occupied(o) => {
                return Ok(o.into_mut().clone());
            }
            _ => {}
        };
        let fd = self.load_inner(name, prog_type, log_level, log_size)?;
        self.funcs.insert(name_string, fd);
        Ok(fd)
    }

    fn load_inner(
        &mut self,
        name: &str,
        prog_type: u32,
        log_level: i32,
        log_size: u32,
    ) -> Result<fd_t, Error> {
        let cname = CString::new(name).unwrap();
        unsafe {
            let start: *mut bpf_insn = bpf_function_start(self.p, cname.as_ptr()) as *mut bpf_insn;
            let size = bpf_function_size(self.p, cname.as_ptr()) as i32;
            let license = bpf_module_license(self.p);
            let version = bpf_module_kern_version(self.p);
            if start == 0 as *mut bpf_insn {
                return Err(format_err!("Error in bpf_function_start for {}", name));
            }
            let log_buf: Vec<u8> = Vec::with_capacity(log_size as usize);
            let fd = bpf_prog_load(
                prog_type,
                cname.as_ptr(),
                start,
                size,
                license,
                version,
                log_level,
                log_buf.as_ptr() as *mut i8,
                log_buf.capacity() as u32,
            );
            if fd < 0 {
                return Err(format_err!("error loading BPF program: {}", name));
            }
            Ok(fd)
        }
    }

    pub fn attach_uretprobe(
        &mut self,
        name: &str,
        symbol: &str,
        fd: fd_t,
        pid: pid_t,
    ) -> Result<(), Error> {
        let (path, addr) = symbol::resolve_symbol_path(name, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(path.clone());
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        self.attach_uprobe_inner(
            &ev_name,
            bpf_probe_attach_type_BPF_PROBE_RETURN,
            &path,
            addr,
            fd,
            pid,
        )
    }
    pub fn attach_uprobe(
        &mut self,
        name: &str,
        symbol: &str,
        fd: fd_t,
        pid: pid_t,
    ) -> Result<(), Error> {
        let (path, addr) = symbol::resolve_symbol_path(name, symbol, 0x0, pid)?;
        let alpha_path = make_alphanumeric(path.clone());
        let ev_name = format!("r_{}_0x{:x}", &alpha_path, addr);
        self.attach_uprobe_inner(
            &ev_name,
            bpf_probe_attach_type_BPF_PROBE_ENTRY,
            &path,
            addr,
            fd,
            pid,
        )
    }

    fn attach_uprobe_inner(
        &mut self,
        name: &str,
        attach_type: u32,
        path: &str,
        addr: u64,
        fd: i32,
        pid: pid_t,
    ) -> Result<(), Error> {
        let cname = CString::new(name).unwrap();
        let cpath = CString::new(path).unwrap();
        let group_fd = (-1 as i32) as MutPointer; // something is wrong with the type of this but it's a groupfd
        let uprobe = unsafe {
            bpf_attach_uprobe(
                fd,
                attach_type,
                cname.as_ptr(),
                cpath.as_ptr(),
                addr,
                pid,
                None, /* cpu */
                group_fd,
            )
        };
        if uprobe == 0 as MutPointer {
            return Err(format_err!("Failed to attach uprobe"));
        }
        self.uprobes.insert(name.to_string(), uprobe);
        Ok(())
    }
}
