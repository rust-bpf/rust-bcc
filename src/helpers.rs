use std::ffi::CString;

use crate::error::BccError;

/// Converts a string to a `CString`, with a user-friendly error message if invalid.
pub fn to_cstring<S: Into<String>>(value: S, field: &'static str) -> Result<CString, BccError> {
    CString::new(value.into()).map_err(|_| BccError::InvalidCString { field })
}
