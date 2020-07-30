
use core::ffi::c_void;
use bcc_sys::bccapi::perf_reader_free;
use bcc_sys::bccapi::perf_reader_fd;
use bcc_sys::bccapi::perf_reader;
use core::sync::atomic::{AtomicPtr, Ordering};

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
        unsafe { perf_reader_free(self.ptr() as *mut c_void) }
    }
}