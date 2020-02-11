use anyhow::{self, Result};
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::*;

use crate::core::make_alphanumeric;

use regex::Regex;

use std::ffi::CString;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::os::unix::prelude::*;

#[derive(Debug)]
pub struct Kprobe {
    code_fd: File,
    name: CString,
    p: i32,
}

impl Kprobe {
    fn new(name: &str, attach_type: u32, function: &str, code: File) -> Result<Self> {
        let cname =
            CString::new(name).map_err(|_| anyhow::anyhow!("Nul byte in Kprobe name: {}", name))?;
        let cfunction = CString::new(function)
            .map_err(|_| anyhow::anyhow!("Nul byte in Kprobe function: {}", function))?;
        let ptr = unsafe {
            bpf_attach_kprobe(
                code.as_raw_fd(),
                attach_type,
                cname.as_ptr(),
                cfunction.as_ptr(),
                0,
                -1,
            )
        };
        if ptr < 0 {
            Err(anyhow::anyhow!("Failed to attach Kprobe: {}", name))
        } else {
            Ok(Self {
                p: ptr,
                name: cname,
                code_fd: code,
            })
        }
    }

    pub fn attach_kprobe(function: &str, code: File) -> Result<Self> {
        let name = format!("p_{}", &make_alphanumeric(function));
        Kprobe::new(&name, BPF_PROBE_ENTRY, function, code)
            .map_err(|_| anyhow::anyhow!("Failed to attach Kprobe: {}", name))
    }

    pub fn attach_kretprobe(function: &str, code: File) -> Result<Self> {
        let name = format!("r_{}", &make_alphanumeric(function));
        Kprobe::new(&name, BPF_PROBE_RETURN, function, code)
            .map_err(|_| anyhow::anyhow!("Failed to attach Kretprobe: {}", name))
    }

    pub fn get_kprobe_functions(event_re: &str) -> Result<Vec<String>> {
        let mut fns: Vec<String> = vec![];

        enum Section {
            Unmatched,
            Begin,
            End,
        }

        let mut in_init_section = Section::Unmatched;
        let mut in_irq_section = Section::Unmatched;
        let re = Regex::new(r"^.*\.cold\.\d+$").unwrap();
        let avali = BufReader::new(File::open("/proc/kallsyms").unwrap());
        for line in avali.lines() {
            let line = line.unwrap();
            let cols: Vec<&str> = line.split_whitespace().collect();
            let (t, fname) = (cols[1].to_string().to_lowercase(), cols[2]);
            // Skip all functions defined between __init_begin and
            // __init_end
            match in_init_section {
                Section::Unmatched => {
                    if fname == "__init_begin" {
                        in_init_section = Section::Begin;
                        continue;
                    }
                }
                Section::Begin => {
                    if fname == "__init_end" {
                        in_init_section = Section::End;
                    }
                    continue;
                }
                Section::End => (),
            }
            // Skip all functions defined between __irqentry_text_start and
            // __irqentry_text_end
            match in_irq_section {
                Section::Unmatched => {
                    if fname == "__irqentry_text_start" {
                        in_irq_section = Section::Begin;
                        continue;
                    }
                }
                Section::Begin => {
                    if fname == "__irqentry_text_end" {
                        in_irq_section = Section::End;
                    }
                    continue;
                }
                Section::End => (),
            }
            // All functions defined as NOKPROBE_SYMBOL() start with the
            // prefix _kbl_addr_*, blacklisting them by looking at the name
            // allows to catch also those symbols that are defined in kernel
            // modules.
            if fname.starts_with("_kbl_addr_") {
                continue;
            }
            // Explicitly blacklist perf-related functions, they are all
            // non-attachable.
            else if fname.starts_with("__perf") || fname.starts_with("perf_") {
                continue;
            }
            // Exclude all gcc 8's extra .cold functions
            else if re.is_match(fname) {
                continue;
            }
            if (t == "t" || t == "w") && fname.contains(event_re) {
                fns.push(fname.to_owned());
            }
        }

        Ok(fns)
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
