use crate::types::MutPointer;

pub struct PerfCallback {
    raw_cb: Box<dyn FnMut(&[u8]) + Send>,
}

impl PerfCallback {
	pub fn new(raw_cb: Box<dyn FnMut(&[u8]) + Send>) -> Self {
		Self {
			raw_cb,
		}
	}
}

pub(crate) unsafe extern "C" fn raw_callback(pc: MutPointer, ptr: MutPointer, size: i32) {
    let slice = std::slice::from_raw_parts(ptr as *const u8, size as usize);
    // prevent unwinding into C code
    // no custom panic hook set, panic will be printed as is
    let _ = std::panic::catch_unwind(|| (*(*(pc as *mut PerfCallback)).raw_cb)(slice));
}