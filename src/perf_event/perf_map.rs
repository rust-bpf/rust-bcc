use crate::error::BccError;
use crate::perf_event::open_perf_buffer;
use byteorder::NativeEndian;
use bcc_sys::bccapi::perf_reader_poll;
use bcc_sys::bccapi::perf_reader;
use crate::table::Table;
use crate::perf_event::perf_reader::PerfReader;
use crate::cpuonline;
use std::io::Cursor;
use byteorder::WriteBytesExt;

#[allow(dead_code)]
pub struct PerfMap {
    pub(crate) readers: Vec<PerfReader>,
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