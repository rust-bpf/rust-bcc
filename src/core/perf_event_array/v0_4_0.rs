use crate::cpuonline;
use crate::types::MutPointer;

use bcc_sys::bccapi::*;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(Debug)]
pub struct PerfEventArray {
    name: String,
    ev_type: u32,
    ev_config: u32,
    table_fd: i32,
    cpu_fd: HashMap<usize, i32>,
}

impl PerfEventArray {
    pub fn new(name: String, ev_type: u32, ev_config: u32, table_fd: i32) -> Self {
        let hash_map: HashMap<usize, i32> = HashMap::new();
        Self {
            name,
            ev_type,
            ev_config,
            table_fd,
            cpu_fd: hash_map,
        }
    }

    pub fn close_all_cpu(&mut self) {
        self.cpu_fd.retain(|_, v| {
            if *v < 0 {
                unsafe { bpf_close_perf_event_fd(*v) };
            }

            false
        });
    }

    #[allow(dead_code)]
    pub fn close_on_cpu(&mut self, cpu: usize) {
        let fd = self.cpu_fd.remove(&cpu);
        if fd.is_some() {
            unsafe { bpf_close_perf_event_fd(fd.unwrap()) };
        }
    }

    pub fn open_all_cpu(&mut self) -> Result<(), String> {
        let cpus = cpuonline::get();

        if let Ok(cpus) = cpus {
            for cpu in cpus {
                let result = self.open_on_cpu(cpu);

                if let Err(e) = result {
                    self.close_all_cpu();
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    pub fn open_on_cpu(&mut self, cpu: usize) -> Result<(), String> {
        if self.cpu_fd.get(&cpu).is_some() {
            return Err("perf event is already open for cpu".to_string());
        }

        let fd =
            unsafe { bpf_open_perf_event(self.ev_type, self.ev_config.into(), -1, cpu as i32) };

        if fd < 0 {
            return Err("failed to open perf on cpu".to_string());
        }
        let mut cpu_bytes: [u8; 8] = cpu.to_ne_bytes();
        let mut fd_bytes: [u8; 4] = fd.to_ne_bytes();

        let errno = self.update(&mut cpu_bytes, &mut fd_bytes);
        if errno < 0 {
            unsafe { bpf_close_perf_event_fd(fd) };
            return Err(format!(
                "Unable to open perf event on CPU `{}`, errno {}",
                cpu, errno
            ));
        }
        self.cpu_fd.insert(cpu, fd);

        Ok(())
    }

    fn update(&mut self, key: &mut [u8], val: &mut [u8]) -> i32 {
        unsafe {
            bpf_update_elem(
                self.table_fd,
                key.as_mut_ptr() as MutPointer,
                val.as_mut_ptr() as MutPointer,
                0,
            )
        }
    }
}

impl Drop for PerfEventArray {
    fn drop(&mut self) {
        self.close_all_cpu();
    }
}

impl Eq for PerfEventArray {}

impl Hash for PerfEventArray {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.name).hash(state);
    }
}

impl PartialEq for PerfEventArray {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
