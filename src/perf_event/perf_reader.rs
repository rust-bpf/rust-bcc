use bcc_sys::bccapi::{perf_reader, perf_reader_fd, perf_reader_free};
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::types::MutPointer;

#[repr(C)]
#[derive(Debug)]
// need this to be represented in memory as just a pointer!!
// very important!!
pub struct PerfReader {
    pub(crate) ptr: AtomicPtr<perf_reader>,
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
        unsafe { perf_reader_free(self.ptr() as MutPointer) }
    }
}
