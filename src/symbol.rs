use crate::BccError;

use bcc_sys::bccapi::*;
use libc::free;

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use std::ptr;

pub fn resolve_symbol_path(
    module: &str,
    symname: &str,
    addr: u64,
    pid: pid_t,
) -> Result<(String, u64), BccError> {
    let pid: pid_t = match pid {
        -1 => 0,
        x => x,
    };

    resolve_symname(module, symname, addr, pid)
}

pub fn resolve_symname(
    module: &str,
    symname: &str,
    addr: u64,
    pid: pid_t,
) -> Result<(String, u64), BccError> {
    let mut symbol = unsafe { mem::zeroed::<bcc_symbol>() };
    let cmodule = CString::new(module)?;
    let csymname = CString::new(symname)?;

    let res = unsafe {
        bcc_resolve_symname(
            cmodule.as_ptr(),
            csymname.as_ptr(),
            addr,
            pid,
            ptr::null_mut(),
            &mut symbol as *mut bcc_symbol,
        )
    };
    if res < 0 {
        Err(BccError::UnknownSymbol {
            name: symname.to_string(),
            module: module.to_string(),
        })
    } else {
        let module = unsafe {
            CStr::from_ptr(symbol.module as *mut i8)
                .to_str()?
                .to_string()
        };
        // symbol.module was allocated somewhere inside `bcc_resolve_symname`
        // so we need to free it manually
        unsafe { free(symbol.module as *mut c_void) };
        Ok((module, symbol.offset))
    }
}

#[derive(Debug)]
pub struct SymbolCache {
    cache: AtomicPtr<c_void>,
}

impl SymbolCache {
    pub fn new(pid: pid_t) -> SymbolCache {
        SymbolCache {
            cache: unsafe { AtomicPtr::new(bcc_symcache_new(pid, ptr::null_mut())) },
        }
    }

    pub fn resolve_name(&self, module: &str, name: &str) -> Result<u64, BccError> {
        let cmodule = CString::new(module)?;
        let cname = CString::new(name)?;
        let mut addr: u64 = 0;

        let res = unsafe {
            bcc_symcache_resolve_name(
                self.cache.load(Ordering::SeqCst),
                cmodule.as_ptr(),
                cname.as_ptr(),
                &mut addr as *mut u64,
            )
        };
        if res < 0 {
            Err(BccError::UnknownSymbol {
                name: name.to_string(),
                module: module.to_string(),
            })
        } else {
            Ok(addr)
        }
    }
}
