use bcc_sys::bccapi::*;
use failure::*;
use libc::{c_void, free};

use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use std::ptr;

pub fn resolve_symbol_path(
    module: &str,
    symname: &str,
    addr: u64,
    pid: pid_t,
) -> Result<(String, u64), Error> {
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
) -> Result<(String, u64), Error> {
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
        Err(format_err!(
            "unable to locate symbol {} in module {}: {}",
            &symname,
            module,
            res
        ))
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
    cache: *mut ::std::os::raw::c_void,
}

impl SymbolCache {
    pub fn new(pid: pid_t) -> SymbolCache {
        SymbolCache {
            cache: unsafe { bcc_symcache_new(pid, ptr::null_mut()) },
        }
    }

    pub fn resolve_name(&self, module: &str, name: &str) -> Result<u64, Error> {
        let cmodule = CString::new(module)?;
        let cname = CString::new(name)?;
        let mut addr: u64 = 0;

        let res = unsafe {
            bcc_symcache_resolve_name(
                self.cache,
                cmodule.as_ptr(),
                cname.as_ptr(),
                &mut addr as *mut u64,
            )
        };
        if res < 0 {
            Err(format_err!(
                "unable to locate symbol {} in module {}: {}",
                &name,
                module,
                res
            ))
        } else {
            Ok(addr)
        }
    }
}
