use std::ffi::CString;
extern crate bcc_sys;
use failure::Error;
use self::bcc_sys::bccapi::*;
use std::mem;

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
            0 as *mut bcc_symbol_option,
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
            CString::from_raw(symbol.module as *mut i8).to_str()?.to_string()
        };
        Ok((module, symbol.offset))
    }
}
