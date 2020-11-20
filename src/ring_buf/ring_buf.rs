use crate::error::BccError;
use crate::ring_buf::callback::RingCallback;
use crate::table::Table;

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

    #[cfg(any(
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
        feature = "v0_9_0",
        feature = "v0_10_0",
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
    ))]
    /// Try constructing a `RingBuf` from the builder
    pub fn build(self) -> Result<RingBuf, BccError> {
        Err(BccError::BccVersionTooLow {
            cause: "ring buffer".to_owned(),
            min_version: "0.16.0".to_owned(),
        })
    }

    #[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
    /// Try constructing a `RingBuf` from the builder
    pub fn build(mut self) -> Result<RingBuf, BccError> {
        let ring_buf_manager = self
            .table_cb_pairs
            .get_mut(0)
            .ok_or(BccError::InitializeRingBuf)
            .and_then(|(table, rcb)| {
                let prcb: *mut _ = rcb;
                let rbm = unsafe {
                    bcc_sys::bccapi::bpf_new_ringbuf(
                        table.fd(),
                        Some(super::callback::raw_callback),
                        prcb as crate::types::MutPointer,
                    )
                } as *mut bcc_sys::bccapi::ring_buffer;
                if rbm.is_null() {
                    Err(BccError::OpenRingBuf {
                        message: format!("failed to open ring buffer ({})", table.name()),
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
                    bcc_sys::bccapi::bpf_add_ringbuf(
                        ring_buf_manager,
                        table.fd(),
                        Some(super::callback::raw_callback),
                        prcb as crate::types::MutPointer,
                    )
                };
                if add_res < 0 {
                    Err(BccError::OpenRingBuf {
                        message: format!("failed to open ring buffer ({})", table.name()),
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

    #[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
    ring_buf_manager: *mut bcc_sys::bccapi::ring_buffer,
}

impl RingBuf {
    pub fn consume(&mut self) {
        #[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
        unsafe {
            bcc_sys::bccapi::bpf_consume_ringbuf(self.ring_buf_manager)
        };
    }

    pub fn poll(&mut self, timeout_ms: i32) {
        #[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
        unsafe {
            bcc_sys::bccapi::bpf_poll_ringbuf(self.ring_buf_manager, timeout_ms)
        };
    }
}

impl Drop for RingBuf {
    fn drop(&mut self) {
        #[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
        unsafe {
            bcc_sys::bccapi::bpf_free_ringbuf(self.ring_buf_manager)
        }
    }
}
