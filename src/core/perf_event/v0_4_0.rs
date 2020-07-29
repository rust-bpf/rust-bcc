use crate::cpuonline;

use bcc_sys::bccapi::*;

use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;

#[derive(Debug)]
pub struct PerfEvent {
    ev_type: u32,
    ev_config: u32,
    code_fd: File,
    p: Vec<i32>,
}

impl PerfEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: File,
        ev_type: u32,
        ev_config: u32,
        sample_period: u64,
        sample_freq: u64,
        pid: i32,
        cpu: Option<usize>,
        group_fd: i32,
    ) -> Result<Self, ()> {
        let vec: Vec<i32> = vec![];

        if let Some(cpu) = cpu {
            let ptr = unsafe {
                bpf_attach_perf_event(
                    code.as_raw_fd(),
                    ev_type,
                    ev_config,
                    sample_period,
                    sample_freq,
                    pid,
                    cpu as i32,
                    group_fd,
                )
            };

            if ptr < 0 {
                return Err(());
            }
        } else if let Ok(cpus) = cpuonline::get() {
            for i in cpus {
                let ptr = unsafe {
                    bpf_attach_perf_event(
                        code.as_raw_fd(),
                        ev_type,
                        ev_config,
                        sample_period,
                        sample_freq,
                        pid,
                        i as i32,
                        group_fd,
                    )
                };

                if ptr < 0 {
                    return Err(());
                }
            }
        }

        Ok(Self {
            ev_type,
            ev_config,
            p: vec,
            code_fd: code,
        })
    }
}

impl Drop for PerfEvent {
    fn drop(&mut self) {
        for i in &self.p {
            unsafe {
                bpf_close_perf_event_fd(*i);
            }
        }
    }
}

impl Eq for PerfEvent {}

impl Hash for PerfEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.ev_config, self.ev_type).hash(state);
    }
}

impl PartialEq for PerfEvent {
    fn eq(&self, other: &Self) -> bool {
        self.ev_config == other.ev_config && self.ev_type == other.ev_type
    }
}
