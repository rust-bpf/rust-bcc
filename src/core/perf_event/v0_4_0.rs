use crate::core::BPF;
use crate::cpuonline;
use crate::perf::{Event, EventType};
use crate::BccError;

use bcc_sys::bccapi::*;

use std::fs::File;
use std::hash::{Hash, Hasher};
use std::os::unix::prelude::*;

#[derive(Default)]
pub struct PerfEventBuilder {
    name: Option<String>,
    event: Option<Event>,
    sample_period: Option<u64>,
    sample_freq: Option<u64>,
    pid: Option<i32>,
    cpu: Option<usize>,
    group_fd: Option<i32>,
}

impl PerfEventBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    pub fn event(mut self, event: Event) -> Self {
        self.event = Some(event);
        self
    }

    pub fn sample_period(mut self, sample_period: Option<u64>) -> Self {
        self.sample_period = sample_period;
        self
    }

    pub fn sample_freq(mut self, sample_freq: Option<u64>) -> Self {
        self.sample_freq = sample_freq;
        self
    }

    pub fn pid(mut self, pid: Option<i32>) -> Self {
        self.pid = pid;
        self
    }

    pub fn cpu(mut self, cpu: Option<usize>) -> Self {
        self.cpu = cpu;
        self
    }

    pub fn group_fd(mut self, group_fd: Option<i32>) -> Self {
        self.group_fd = group_fd;
        self
    }

    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.event.is_none() {
            return Err(BccError::IncompletePerfEventBuilder {
                field: "event".to_string(),
            });
        }
        if self.name.is_none() {
            return Err(BccError::IncompletePerfEventBuilder {
                field: "name".to_string(),
            });
        }
        let name = self.name.unwrap();
        let event = self.event.unwrap();

        let code_fd = bpf.load_perf_event(&name)?;

        let ev_type = match event {
            Event::Hardware(_) => EventType::Hardware,
            Event::Software(_) => EventType::Software,
            Event::HardwareCache(_, _, _) => EventType::HardwareCache,
        } as u32;

        let ev_config = match event {
            Event::Hardware(hw_event) => hw_event as u32,
            Event::Software(sw_event) => sw_event as u32,
            Event::HardwareCache(id, op, result) => {
                ((result as u32) << 16) | ((op as u32) << 8) | (id as u32)
            }
        };
        let perf_event = PerfEvent::new(
            code_fd,
            ev_type,
            ev_config,
            self.sample_period.unwrap_or(0),
            self.sample_freq.unwrap_or(0),
            self.pid.unwrap_or(-1),
            self.cpu,
            self.group_fd.unwrap_or(-1),
        )?;
        bpf.perf_events.insert(perf_event);
        Ok(())
    }
}

#[derive(Debug)]
pub struct PerfEvent {
    ev_type: u32,
    ev_config: u32,
    code_fd: File,
    p: Vec<i32>,
}

impl PerfEvent {
    #[allow(clippy::too_many_arguments)]
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
                    return Err(BccError::AttachPerfEvent { ev_type, ev_config });
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

    #[allow(clippy::too_many_arguments)]
    pub fn attach_perf_event(
        code: File,
        event_type: u32,
        event_config: u32,
        sample_period: Option<u64>,
        sample_freq: Option<u64>,
        pid: Option<i32>,
        cpu: Option<usize>,
        group_fd: Option<i32>,
    ) -> Result<Self, BccError> {
        let event_type = event_type;
        let event_config = event_config;
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
