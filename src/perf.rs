use bcc_sys::bccapi::*;
use byteorder::{NativeEndian, WriteBytesExt};

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::io::Cursor;

use crate::cpuonline;
use crate::table::Table;
use crate::types::*;
use crate::BccError;

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
