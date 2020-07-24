use crate::cpuonline;
use crate::BccError;

use bcc_sys::bccapi::*;

use std::cmp::max;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;

// TODO:
//    - The enums below should probably generated in bcc-sys
//    - Find a way to map generated to

#[allow(dead_code)]
pub enum PerfEventType {
    // From perf_type_id in uapi/linux/perf_event.h
    Hardware = 0,
    Software = 1,
}

#[allow(dead_code)]
pub enum PerfEventHWConfig {
    // From perf_hw_id in uapi/linux/perf_event.h
    CpuCycles = 0,
    Instructions = 1,
    CacheReferences = 2,
    CacheMisses = 3,
    BranchInstructions = 4,
    BranchMisses = 5,
    BusCycles = 6,
    StalledCyclesFrontend = 7,
    StalledCyclesBackend = 8,
    RefCpuCycles = 9,
    HWMax = 10,
}

#[allow(dead_code)]
pub enum PerfEventSWConfig {
    // From perf_sw_id in uapi/linux/perf_event.h
    CpuClock = 0,
    TaskClock = 1,
    PageFaults = 2,
    ContextSwitches = 3,
    CpuMigrations = 4,
    PageFaultsMin = 5,
    PageFaultsMaj = 6,
    AlignmentFaults = 7,
    EmulationFaults = 8,
    Dummy = 9,
    BpfOutput = 10,
    SWMax = 11,
}

#[derive(Debug)]
pub struct PerfEvent {
    ev_type: u32,
    ev_config: u32,
    code_fd: File,
    p: Vec<i32>,
}

impl PerfEvent {
    fn new(
        code: File,
        ev_type: u32,
        ev_config: u32,
        sample_period: u64,
        sample_freq: u64,
        pid: i32,
        cpu: Option<usize>,
        group_fd: i32,
    ) -> Result<Self, BccError> {
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
                return Err(BccError::AttachPerfEvent { ev_type, ev_config });
            }
        } else {
            if let Ok(cpus) = cpuonline::get() {
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
                        return Err(BccError::AttachPerfEvent { ev_type, ev_config });
                    }
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

    pub fn attach_perf_event(
        code: File,
        event_type: Option<u32>,
        event_config: Option<u32>,
        sample_period: Option<u64>,
        sample_freq: Option<u64>,
        pid: Option<i32>,
        cpu: Option<usize>,
        group_fd: Option<i32>,
    ) -> Result<Self, BccError> {
        // Defaults
        let max_config = max(
            PerfEventHWConfig::HWMax as u32,
            PerfEventSWConfig::SWMax as u32,
        );
        let event_type = event_type.unwrap_or(max_config);
        let event_config = event_config.unwrap_or(max_config);
        let sample_period = sample_period.unwrap_or(0);
        let sample_freq = sample_freq.unwrap_or(0);
        let pid = pid.unwrap_or(-1);
        let group_fd = group_fd.unwrap_or(-1);
        PerfEvent::new(
            code,
            event_type,
            event_config,
            sample_period,
            sample_freq,
            pid,
            cpu,
            group_fd,
        )
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
