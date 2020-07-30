mod callback;
mod perf_event;
mod perf_map;
mod perf_reader;
mod events;

use crate::perf_event::callback::raw_callback;
use crate::types::MutPointer;
pub use callback::*;
pub use perf_event::*;
pub use perf_map::*;
pub use perf_reader::*;
pub use events::*;

use crate::BccError;

use bcc_sys::bccapi::*;

use std::sync::atomic::AtomicPtr;

const BPF_PERF_READER_PAGE_CNT: i32 = 64;

fn open_perf_buffer(
    cpu: usize,
    raw_cb: Box<dyn FnMut(&[u8]) + Send>,
) -> Result<PerfReader, BccError> {
    let callback = Box::new(PerfCallback::new(raw_cb));
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
        ptr: AtomicPtr::new(reader as *mut bcc_sys::bccapi::perf_reader),
    })
}