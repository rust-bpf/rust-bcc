mod v0_4_0;

pub use v0_4_0::*;

use crate::core::BPF;
use crate::error::BccError;
use crate::perf::{Event, EventType};

use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_PERF_EVENT;

#[derive(Default)]
pub struct PerfEventProbe {
    name: Option<String>,
    event: Option<Event>,
    sample_period: Option<u64>,
    sample_freq: Option<u64>,
    pid: Option<i32>,
    cpu: Option<usize>,
    group_fd: Option<i32>,
}

impl PerfEventProbe {
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
            return Err(BccError::IncompletePerfEventProbe {
                field: "event".to_string(),
            });
        }
        if self.name.is_none() {
            return Err(BccError::IncompletePerfEventProbe {
                field: "name".to_string(),
            });
        }
        let name = self.name.unwrap();
        let event = self.event.unwrap();

        let code_fd = bpf.load(&name, bpf_prog_type_BPF_PROG_TYPE_PERF_EVENT, 0, 0)?;

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
        ).map_err(|_| BccError::AttachPerfEvent{ event: event })?;
        bpf.perf_events.insert(perf_event);
        Ok(())
    }
}
