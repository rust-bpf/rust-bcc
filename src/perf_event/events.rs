// This file defines various perf_events

#[derive(Copy, Clone, Debug)]
/// An `Event` is a collection of event descriptors which are required to
/// initialize a `PerfEvent`.
pub enum Event {
    Hardware(HardwareEvent),
    Software(SoftwareEvent),
    HardwareCache(CacheId, CacheOp, CacheResult),
    Raw {
        event_code: u8,
        umask: u8,
        counter_mask: u8,
        invert: bool,
        any_thread: bool,
        edge_detect: bool,
    },
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
// Used interally and passed to the `bpf_attach_perf_event()` function
pub(crate) enum EventType {
    // From perf_type_id in uapi/linux/perf_event.h
    Hardware = 0,
    Software = 1,
    Tracepoint = 2,
    HardwareCache = 3,
    Raw = 4,
    Breakpoint = 5,

    Max, // non-ABI
}

#[derive(Copy, Clone, Debug)]
/// Used to specify a named hardware event.
pub enum HardwareEvent {
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
}

#[derive(Copy, Clone, Debug)]
/// Used to specify a named software event.
pub enum SoftwareEvent {
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
}

#[derive(Copy, Clone, Debug)]
/// Used to specify a particular cache for a hardware cache event.
pub enum CacheId {
    // From perf_hw_cache_id in uapi/linux/perf_event.h
    L1D = 0,
    L1I = 1,
    LL = 2,
    DTLB = 3,
    ITLB = 4,
    BPU = 5,
    NODE = 6,
}

#[derive(Copy, Clone, Debug)]
/// Used to specify a particular cache operation for a hardware cache event.
pub enum CacheOp {
    // From perf_hw_cache_op_id in uapi/linux/perf_event.h
    Read = 0,
    Write = 1,
    Prefetch = 2,
}

#[derive(Copy, Clone, Debug)]
/// Used to specify a particular cache result for a hardware cache event.
pub enum CacheResult {
    // From perf_hw_cache_op_result_id in uapi/linux/perf_event.h
    Access = 0,
    Miss = 1,
}

impl Event {
    pub fn ev_type(self) -> u32 {
        (match self {
            Event::Hardware(_) => EventType::Hardware,
            Event::Software(_) => EventType::Software,
            Event::HardwareCache(_, _, _) => EventType::HardwareCache,
            Event::Raw { .. } => EventType::Raw,
        }) as u32
    }

    pub fn ev_config(self) -> u32 {
        match self {
            Event::Hardware(hw_event) => hw_event as u32,
            Event::Software(sw_event) => sw_event as u32,
            Event::HardwareCache(id, op, result) => {
                ((result as u32) << 16) | ((op as u32) << 8) | (id as u32)
            }
            Event::Raw {
                event_code,
                umask,
                counter_mask,
                invert,
                any_thread,
                edge_detect,
            } => {
                (event_code as u32)
                    | ((umask as u32) << 8)
                    | ((counter_mask as u32) << 24)
                    | ((invert as u32) << 23)
                    | ((any_thread as u32) << 21)
                    | ((edge_detect as u32) << 18)
            }
        }
    }
}
