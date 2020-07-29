use bcc_sys::bccapi::*;
use byteorder::{NativeEndian, WriteBytesExt};

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::io::Cursor;

use crate::cpuonline;
use crate::table::Table;
use crate::types::*;
use crate::BccError;

#[derive(Copy, Clone, Debug)]
pub enum Event {
    Hardware(HardwareEvent),
    Software(SoftwareEvent),
    HardwareCache(CacheId, CacheOp, CacheResult),
}

#[derive(Copy, Clone, Debug)]
pub enum EventType {
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

    Max, // non-ABI
}

#[derive(Copy, Clone, Debug)]
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

    Max, // non-ABI
}

#[derive(Copy, Clone, Debug)]
pub enum CacheId {
    // From perf_hw_cache_id in uapi/linux/perf_event.h
    L1D = 0,
    L1I = 1,
    LL = 2,
    DTLB = 3,
    ITLB = 4,
    BPU = 5,
    NODE = 6,

    Max, // non-ABI
}

#[derive(Copy, Clone, Debug)]
pub enum CacheOp {
    // From perf_hw_cache_op_id in uapi/linux/perf_event.h
    Read = 0,
    Write = 1,
    Prefetch = 2,

    Max, // non-ABI
}

#[derive(Copy, Clone, Debug)]
pub enum CacheResult {
    // From perf_hw_cache_op_result_id in uapi/linux/perf_event.h
    Access = 0,
    Miss = 1,

    Max, // non-ABI
}

struct PerfCallback {
    raw_cb: Box<dyn FnMut(&[u8]) + Send>,
}

const BPF_PERF_READER_PAGE_CNT: i32 = 64;

unsafe extern "C" fn raw_callback(pc: MutPointer, ptr: MutPointer, size: i32) {
    let slice = std::slice::from_raw_parts(ptr as *const u8, size as usize);
    // prevent unwinding into C code
    // no custom panic hook set, panic will be printed as is
    let _ = std::panic::catch_unwind(|| (*(*(pc as *mut PerfCallback)).raw_cb)(slice));
}

// need this to be represented in memory as just a pointer!!
// very important!!
#[repr(C)]
#[derive(Debug)]
pub struct PerfReader {
    ptr: AtomicPtr<perf_reader>,
}

impl PerfReader {
    pub fn fd(&mut self) -> i32 {
        unsafe { perf_reader_fd(self.ptr()) }
    }

    fn ptr(&self) -> *mut perf_reader {
        self.ptr.load(Ordering::SeqCst)
    }
}

impl Drop for PerfReader {
    fn drop(&mut self) {
        unsafe { perf_reader_free(self.ptr() as *mut c_void) }
    }
}

#[allow(dead_code)]
pub struct PerfMap {
    pub readers: Vec<PerfReader>,
}

pub fn init_perf_map<F>(mut table: Table, cb: F) -> Result<PerfMap, BccError>
where
    F: Fn() -> Box<dyn FnMut(&[u8]) + Send>,
{
    let key_size = table.key_size();
    let leaf_size = table.leaf_size();
    let leaf = vec![0; leaf_size];

    if key_size != 4 || leaf_size != 4 {
        return Err(BccError::TableInvalidSize);
    }

    let mut readers: Vec<PerfReader> = vec![];
    let mut cur = Cursor::new(leaf);

    let cpus = cpuonline::get()?;
    for cpu in cpus.iter() {
        let mut reader = open_perf_buffer(*cpu, cb())?;
        let perf_fd = reader.fd() as u32;
        readers.push(reader);

        let mut key = vec![];
        key.write_u32::<NativeEndian>(*cpu as u32)?;
        cur.write_u32::<NativeEndian>(perf_fd)?;
        if table.set(&mut key, &mut cur.get_mut()).is_ok() {
            cur.set_position(0);
        } else {
            return Err(BccError::InitializePerfMap);
        }
    }
    Ok(PerfMap { readers })
}

impl PerfMap {
    pub fn poll(&mut self, timeout: i32) {
        unsafe {
            perf_reader_poll(
                self.readers.len() as i32,
                self.readers.as_ptr() as *mut *mut perf_reader,
                timeout,
            )
        };
    }
}

fn open_perf_buffer(
    cpu: usize,
    raw_cb: Box<dyn FnMut(&[u8]) + Send>,
) -> Result<PerfReader, BccError> {
    let callback = Box::new(PerfCallback { raw_cb });
    let reader = unsafe {
        bpf_open_perf_buffer(
            Some(raw_callback),
            None,
            Box::into_raw(callback) as MutPointer,
            -1, /* pid */
            cpu as i32,
            BPF_PERF_READER_PAGE_CNT,
        )
    };
    if reader.is_null() {
        return Err(BccError::OpenPerfBuffer);
    }
    Ok(PerfReader {
        ptr: AtomicPtr::new(reader as *mut perf_reader),
    })
}
