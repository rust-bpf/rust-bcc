use crate::core::BPF;
use crate::error::BccError;
use crate::perf_event::{Event, EventType};

use bcc_sys::bccapi::bpf_prog_type_BPF_PROG_TYPE_PERF_EVENT as BPF_PROG_TYPE_PERF_EVENT;

#[derive(Default)]
pub struct PerfEvent {
    name: Option<String>,
    event: Option<Event>,
    sample_period: Option<u64>,
    sample_frequency: Option<u64>,
    pid: Option<i32>,
    cpu: Option<usize>,
    group_fd: Option<i32>,
}

/// A `PerfEvent` is used to configure a BPF probe which instruments a hardware
/// or software event. This structure must be attached to the `BPF` structure to
/// be useful.
impl PerfEvent {
    /// Creates a new `PerfEvent` with the defaults. There are several mandatory
    /// fields which must be configured before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// This corresponds to the function name in the BPF code which will be
    /// called when the probe fires. This is required.
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// The `Event` which will cause a probe to fire, such as a hardware or
    /// software event. This is required.
    pub fn event(mut self, event: Event) -> Self {
        self.event = Some(event);
        self
    }

    /// Specifies that the probe should fire after `count` number of events have
    /// been counted. Exactly one of `sample_period` or `sample_frequency` must
    /// be provided.
    pub fn sample_period(mut self, count: Option<u64>) -> Self {
        self.sample_period = count;
        self
    }

    /// Causes the probe to run with a frequency specified in hertz (hz)
    /// equivalent to the number of sampling events per second. Exactly one of
    /// `sample_period` or `sample_frequency` must be provided.
    pub fn sample_frequency(mut self, hz: Option<u64>) -> Self {
        self.sample_frequency = hz;
        self
    }

    /// Restrict the scope of the probe to only a given process and its
    /// children. If this is set to `None` (the default), the probe will cover
    /// all processes on the system.
    pub fn pid(mut self, pid: Option<i32>) -> Self {
        self.pid = pid;
        self
    }

    /// Restrict the probe to only the given hardware thread. If this is set to
    /// `None` (the default), a probe will be created for each hardware thread
    /// on the system to provide system-wide coverage.
    pub fn cpu(mut self, cpu: Option<usize>) -> Self {
        self.cpu = cpu;
        self
    }

    /// This option groups sets of probes together. This will cause the
    /// multiplexing algorithm in the kernel to group the probes to be running
    /// on PMUs concurrently. Useful for grouping related probes to maintain
    /// accurate derived metrics. One example would be to schedule cycle and
    /// retired instruction probes together to calculate CPI.
    pub fn group_fd(mut self, group_fd: Option<i32>) -> Self {
        self.group_fd = group_fd;
        self
    }

    /// Consumes the probe and attaches it to the `BPF` struct. May return an
    /// error if there is an underlying failure when attaching the probe.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.event.is_none() {
            return Err(BccError::IncompletePerfEventProbe {
                message: "event is required".to_string(),
            });
        }
        if self.name.is_none() {
            return Err(BccError::IncompletePerfEventProbe {
                message: "name is required".to_string(),
            });
        }
        if (self.sample_period.unwrap_or(0) == 0) as i32
            ^ (self.sample_frequency.unwrap_or(0) == 0) as i32
            == 0
        {
            return Err(BccError::IncompletePerfEventProbe {
                message: "exactly one of sample period or sample frequency is required".to_string(),
            });
        }
        let name = self.name.unwrap();
        let event = self.event.unwrap();

        let code_fd = bpf.load(&name, BPF_PROG_TYPE_PERF_EVENT, 0, 0)?;

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
        let perf_event = crate::core::PerfEvent::new(
            code_fd,
            ev_type,
            ev_config,
            self.sample_period.unwrap_or(0),
            self.sample_frequency.unwrap_or(0),
            self.pid.unwrap_or(-1),
            self.cpu,
            self.group_fd.unwrap_or(-1),
        )
        .map_err(|_| BccError::AttachPerfEvent { event })?;
        bpf.perf_events.insert(perf_event);
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::core::PerfEventProbe;
//     use crate::core::BPF;
//     use crate::perf::Event;

//     #[test]
//     fn both_freq_and_period() {
//         use crate::perf::HardwareEvent;

//         let mut bpf = BPF::new("").unwrap();
//         let result = PerfEventProbe::new()
//             .name("name")
//             .event(Event::Hardware(HardwareEvent::CpuCycles))
//             .sample_frequency(Some(123))
//             .sample_period(Some(456))
//             .attach(&mut bpf);
//         assert!(result.is_err());
//     }

//     #[test]
//     fn no_freq_or_period() {
//         use crate::perf::HardwareEvent;

//         let mut bpf = BPF::new("").unwrap();
//         let result = PerfEventProbe::new()
//             .name("name")
//             .event(Event::Hardware(HardwareEvent::CpuCycles))
//             .attach(&mut bpf);
//         assert!(result.is_err());
//     }
// }
