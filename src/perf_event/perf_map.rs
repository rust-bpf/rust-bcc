use crate::cpuonline;
use crate::error::BccError;
use crate::perf_event::open_perf_buffer;
use crate::perf_event::perf_reader::PerfReader;
use crate::table::Table;
use bcc_sys::bccapi::perf_reader;
use bcc_sys::bccapi::perf_reader_poll;
use byteorder::NativeEndian;
use byteorder::WriteBytesExt;
use std::io::Cursor;

/// A builder type for producing `PerfMap`s
pub struct PerfMapBuilder<F: Fn() -> Box<dyn FnMut(&[u8]) + Send>> {
    table: Table,
    cb: F,
    page_count: i32,
}

impl<F: Fn() -> Box<dyn FnMut(&[u8]) + Send>> PerfMapBuilder<F> {
    /// Create a new builder for a given table and callback function
    pub fn new(table: Table, cb: F) -> Self {
        Self {
            table,
            cb,
            page_count: super::BPF_PERF_READER_PAGE_CNT,
        }
    }

    /// Set the page count for the ringbuffer
    pub fn page_count(mut self, page_count: i32) -> Self {
        self.page_count = page_count;
        self
    }

    /// Try constructing a `PerfMap` from the builder
    pub fn build(mut self) -> Result<PerfMap, BccError> {
        let key_size = self.table.key_size();
        let leaf_size = self.table.leaf_size();
        let leaf = vec![0; leaf_size];

        if key_size != 4 || leaf_size != 4 {
            return Err(BccError::TableInvalidSize);
        }

        let mut readers: Vec<PerfReader> = vec![];
        let mut cur = Cursor::new(leaf);

        let cpus = cpuonline::get()?;
        for cpu in cpus.iter() {
            let mut reader = open_perf_buffer(*cpu, (self.cb)(), self.page_count)?;
            let perf_fd = reader.fd() as u32;
            readers.push(reader);

            let mut key = vec![];
            key.write_u32::<NativeEndian>(*cpu as u32)?;
            cur.write_u32::<NativeEndian>(perf_fd)?;
            if self.table.set(&mut key, &mut cur.get_mut()).is_ok() {
                cur.set_position(0);
            } else {
                return Err(BccError::InitializePerfMap);
            }
        }
        Ok(PerfMap { readers })
    }
}

#[allow(dead_code)]
pub struct PerfMap {
    pub(crate) readers: Vec<PerfReader>,
}

/// Convenience function to initialize a `PerfMap` without using the builder
/// pattern. Will be deprecated in a future release.
#[deprecated(
    since = "0.0.30",
    note = "Please use PerfMapBuilder to create a new PerfMap instead"
)]
pub fn init_perf_map<F>(table: Table, cb: F) -> Result<PerfMap, BccError>
where
    F: Fn() -> Box<dyn FnMut(&[u8]) + Send>,
{
    PerfMapBuilder::new(table, cb).build()
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
