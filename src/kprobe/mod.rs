use crate::core::make_alphanumeric;
use crate::core::BPF;
use crate::error::BccError;

use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
use bcc_sys::bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;
use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_KPROBE as BPF_PROG_TYPE_KPROBE;
use regex::Regex;

use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Default)]
/// A `KernelProbe` is used to configure and then attach a kprobe to a kernel
/// function on entry into that function. Must be attached to a `BPF` struct to
/// be useful.
pub struct Kprobe {
    name: Option<String>,
    function: Option<String>,
}

impl Kprobe {
    /// Create a new probe with the defaults. Further initialization is required
    /// before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// Specify the name of the probe handler within the BPF code. This is a
    /// required item.
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// Specify the name of the kernel function to be probed. This is a required
    /// function.
    pub fn function(mut self, function: &str) -> Self {
        self.function = Some(function.to_owned());
        self
    }

    /// Consumes the probe and attaches it to the `BPF` struct. May return an
    /// error if there is a incomplete configuration or error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.name.is_none() {
            return Err(BccError::IncompleteKernelProbe {
                message: "name is required".to_string(),
            });
        }
        if self.function.is_none() {
            return Err(BccError::IncompleteKernelProbe {
                message: "function is required".to_string(),
            });
        }
        let name = self.name.unwrap();
        let function = self.function.unwrap();
        let code_fd = bpf.load(&name, BPF_PROG_TYPE_KPROBE, 0, 0)?;
        let name = format!("p_{}", &make_alphanumeric(&function));
        let kprobe = crate::core::Kprobe::new(&name, BPF_PROBE_ENTRY, &function, code_fd)?;
        bpf.kprobes.insert(kprobe);
        Ok(())
    }
}

#[derive(Default)]
/// A `Kretprobe` is used to configure and then attach a probe to a kernel
/// function on return from that function. Must be attached to a `BPF` struct to
/// be useful.
pub struct Kretprobe {
    name: Option<String>,
    function: Option<String>,
}

impl Kretprobe {
    /// Create a new probe with the defaults. Further initialization is required
    /// before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// Specify the name of the probe handler within the BPF code. This is a
    /// required item.
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// Specify the name of the kernel function to be probed. This is a required
    /// function.
    pub fn function(mut self, function: &str) -> Self {
        self.function = Some(function.to_owned());
        self
    }

    /// Consumes the probe and attaches it to the `BPF` struct. May return an
    /// error if there is a incomplete configuration or error while loading or
    /// attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.name.is_none() {
            return Err(BccError::IncompleteKernelProbe {
                message: "name is required".to_string(),
            });
        }
        if self.function.is_none() {
            return Err(BccError::IncompleteKernelProbe {
                message: "function is required".to_string(),
            });
        }
        let name = self.name.unwrap();
        let function = self.function.unwrap();
        let code_fd = bpf.load(&name, BPF_PROG_TYPE_KPROBE, 0, 0)?;
        let name = format!("r_{}", &make_alphanumeric(&function));
        let kprobe = crate::core::Kprobe::new(&name, BPF_PROBE_RETURN, &function, code_fd)?;
        bpf.kprobes.insert(kprobe);
        Ok(())
    }
}

pub fn get_kprobe_functions(event_re: &str) -> Result<Vec<String>, BccError> {
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
        // prefix _kbl_addr_*, excluding them by looking at the name
        // allows to catch also those symbols that are defined in kernel
        // modules.
        if fname.starts_with("_kbl_addr_") {
            continue;
        }
        // Exclude perf-related functions, they are all non-attachable.
        if fname.starts_with("__perf") || fname.starts_with("perf_") {
            continue;
        }
        // Exclude all gcc 8's extra .cold functions
        if re.is_match(fname) {
            continue;
        }
        if (t == "t" || t == "w") && fname.contains(event_re) {
            fns.push(fname.to_owned());
        }
    }

    Ok(fns)
}