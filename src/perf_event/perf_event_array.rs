use crate::core::BPF;
use crate::error::BccError;
use crate::perf_event::Event;

#[derive(Default)]
pub struct PerfEventArray {
    table: Option<String>,
    event: Option<Event>,
    cpu: Option<usize>,
}

/// A `PerfEventArray` is used to configure a BPF `PERF_EVENT_ARRAY` such that a call
/// `table.perf_read(CUR_CPU_IDENTIFIER) returns the hardware counter of the event
/// on the local cpu.
impl PerfEventArray {
    /// Creates a new `PerfEventArray` with defaults.There are several mandatory
    /// fields which must be configured before attaching.
    pub fn new() -> Self {
        Default::default()
    }

    /// Specify the name of the table within the BPF code. This is a
    /// required item.
    pub fn table(mut self, name: &str) -> Self {
        self.table = Some(name.to_owned());
        self
    }

    /// The `Event` which will cause a probe to fire, such as a hardware or
    /// software event. This is required.
    pub fn event(mut self, event: Event) -> Self {
        self.event = Some(event);
        self
    }

    /// Restrict the probe to only the given hardware thread. If this is set to
    /// `None` (the default), a probe will be created for each hardware thread
    /// on the system to provide system-wide coverage.
    pub fn cpu(mut self, cpu: Option<usize>) -> Self {
        self.cpu = cpu;
        self
    }

    /// Consumes the perf event and opens it. May return an error if there is a
    /// incomplete or invalid configuration or other error while loading or
    /// opening the event.
    pub fn attach(self, bpf: &mut BPF) -> Result<(), BccError> {
        if self.event.is_none() {
            return Err(BccError::InvalidPerfEvent {
                message: "event is required".to_string(),
            });
        }

        if self.table.is_none() {
            return Err(BccError::InvalidPerfEvent {
                message: "table is required".to_string(),
            });
        }

        let table = self.table.unwrap();
        let event = self.event.unwrap();

        let table_fd = bpf.table_fd(&table)?;

        let ev_type = event.ev_type();
        let ev_config = event.ev_config();

        let mut event_array = crate::core::PerfEventArray::new(table, ev_type, ev_config, table_fd);
        event_array
            .open_all_cpu()
            .map_err(|e| BccError::OpenPerfEvent { event, message: e })?;

        bpf.perf_events_array.insert(event_array);
        Ok(())
    }
}
