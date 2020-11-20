use crate::types::MutPointer;
use std::os::raw::c_int;

pub struct RingCallback {
    pub(crate) ring_cb: Box<dyn FnMut(&[u8]) + Send>,
}

impl RingCallback {
    pub fn new(ring_cb: Box<dyn FnMut(&[u8]) + Send>) -> Self {
        Self { ring_cb }
    }
}

#[allow(dead_code)]
pub(crate) unsafe extern "C" fn raw_callback(
    ctx: MutPointer,
    data: MutPointer,
    size: usize,
) -> c_int {
    let slice = std::slice::from_raw_parts(data as *const u8, size as usize);
    // prevent unwinding into C code
    // no custom panic hook set, panic will be printed as is
    let _ = std::panic::catch_unwind(|| (*(*(ctx as *mut RingCallback)).ring_cb)(slice));

    0
}
