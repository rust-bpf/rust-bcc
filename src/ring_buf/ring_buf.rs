use crate::error::BccError;
use crate::ring_buf::callback::{raw_callback, RingCallback};
use crate::table::Table;
use crate::types::MutPointer;

use bcc_sys::bccapi::{
    bpf_add_ringbuf, bpf_consume_ringbuf, bpf_free_ringbuf, bpf_new_ringbuf, bpf_poll_ringbuf,
    ring_buffer,
};

/// A builder type for producing `PerfMap`s
pub struct RingBufBuilder {
    table_cb_pairs: Vec<(Table, RingCallback)>,
}

impl RingBufBuilder {
    /// Create a new builder for a given ring buffer and callback function
    pub fn new(table: Table, rcb: RingCallback) -> Self {
        Self {
            table_cb_pairs: vec![(table, rcb)],
        }
    }

    /// Add a ring buffer and callback function
    pub fn add(mut self, table: Table, rcb: RingCallback) -> Self {
        self.table_cb_pairs.push((table, rcb));
        self
    }

    /// Try constructing a `RingBuf` from the builder
    pub fn build(mut self) -> Result<RingBuf, BccError> {
        let ring_buf_manager = self
            .table_cb_pairs
            .get_mut(0)
            .ok_or(BccError::InitializeRingBuf)
            .and_then(|(table, rcb)| {
                let prcb: *mut _ = rcb;
                let rbm =
                    unsafe { bpf_new_ringbuf(table.fd(), Some(raw_callback), prcb as MutPointer) }
                        as *mut ring_buffer;
                if rbm.is_null() {
                    Err(BccError::OpenRingBuf {
                        message: format!("failed to open ring buffer of name: {}", table.name()),
                    })
                } else {
                    Ok(rbm)
                }
            })?;

        self.table_cb_pairs
            .iter_mut()
            .skip(1)
            .try_for_each(|(table, rcb)| {
                let prcb: *mut _ = rcb;
                let add_res = unsafe {
                    bpf_add_ringbuf(
                        ring_buf_manager,
                        table.fd(),
                        Some(raw_callback),
                        prcb as MutPointer,
                    )
                };
                if add_res < 0 {
                    Err(BccError::OpenRingBuf {
                        message: format!("failed to open ring buffer of name: {}", table.name()),
                    })
                } else {
                    Ok(())
                }
            })?;

        Ok(RingBuf {
            table_cb_pairs: self.table_cb_pairs,
            ring_buf_manager,
        })
    }
}

pub struct RingBuf {
    #[allow(dead_code)]
    table_cb_pairs: Vec<(Table, RingCallback)>,
    ring_buf_manager: *mut ring_buffer,
}

impl RingBuf {
    pub fn consume(&mut self) {
        unsafe { bpf_consume_ringbuf(self.ring_buf_manager) };
    }

    pub fn poll(&mut self, timeout_ms: i32) {
        unsafe { bpf_poll_ringbuf(self.ring_buf_manager, timeout_ms) };
    }
}

impl Drop for RingBuf {
    fn drop(&mut self) {
        unsafe { bpf_free_ringbuf(self.ring_buf_manager) }
    }
}
