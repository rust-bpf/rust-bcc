use crate::cpuonline;

use bcc_sys::bccapi::*;

use core::ffi::c_void;
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

    pub fn close_all_cpu(&mut self) -> Result<(), ()> {
        self.cpu_fd.retain(|_, v| {
            if *v < 0 {
                unsafe { bpf_close_perf_event_fd(*v) };
            }
            
            false
        });

        Ok(())
    }

    pub fn close_on_cpu(&mut self, cpu: usize) -> Result<(), ()> {
        let fd = self.cpu_fd.remove(&cpu);
        if fd.is_none() {
            return Ok(());
        }

        unsafe { bpf_close_perf_event_fd(fd.unwrap()) };
        Ok(())
    }

    pub fn open_all_cpu(&mut self) -> Result<(), ()> {
        let cpus = cpuonline::get();

        if let Ok(cpus) = cpus {
            for cpu in cpus {
                let result = self.open_on_cpu(cpu);

                if let Err(_) = result {
                    // Close all cpus
                    return Err(());
                }
            }
        }

        Ok(())
    }

    pub fn open_on_cpu(&mut self, cpu: usize) -> Result<(), ()> {
        if self.cpu_fd.get(&cpu).is_some() {
            return Err(());
        }

        let fd = unsafe { bpf_open_perf_event(self.ev_type, self.ev_config.into(), -1, cpu as i32) };

        if fd < 0 {
            return Err(());
        }

        if !self.update(cpu, fd) {
            unsafe { bpf_close_perf_event_fd(fd) };
            return Err(());
        }
        self.cpu_fd.insert(cpu, fd);

        Ok(())
    }

    fn update(&self, cpu: usize, fd: i32) -> bool {
        (unsafe { bpf_update_elem(self.table_fd, cpu as *mut c_void, fd as *mut c_void, 0) }) >= 0
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
