use bcc::ring_buf::{RingBufBuilder, RingCallback};
use bcc::BccError;
use bcc::{Tracepoint, BPF};

use core::sync::atomic::{AtomicBool, Ordering};
use std::os::raw::c_int;
use std::sync::Arc;

// BPF ring buffer output example
//
// Based on: https://github.com/iovisor/bcc/blob/master/examples/ringbuf/ringbuf_output.py

#[repr(C)]
struct event_t {
    filename: [u8; 16],
    dfd: c_int,
    flags: c_int,
    mode: c_int,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let code = "
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);
struct event {
    char filename[16];
    int dfd;
    int flags;
    int mode;
};

int openat_entry(struct tracepoint__syscalls__sys_enter_openat *args) {
    int zero = 0;
    struct event event = {};
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);
    event.dfd = args->dfd;
    event.flags = args->flags;
    event.mode = args->mode;
    buffer.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}
    ";

    // compile the above BPF code!
    let mut module = BPF::new(code)?;

    // tracepoints!
    Tracepoint::new()
        .handler("openat_entry")
        .subsystem("syscalls")
        .tracepoint("sys_enter_openat")
        .attach(&mut module)?;

    let cb = RingCallback::new(Box::new(ring_buf_callback));

    let table = module.table("buffer")?;
    let mut ring_buf = RingBufBuilder::new(table, cb).build()?;
    let timeout_ms = 200;

    println!(
        "{:-16} {:10} {:10} {:10}",
        "FILENAME", "DIR_FD", "FLAGS", "MODE"
    );
    while runnable.load(Ordering::SeqCst) {
        ring_buf.poll(timeout_ms);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}

fn parse_struct(x: &[u8]) -> event_t {
    unsafe { std::ptr::read(x.as_ptr() as *const event_t) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn ring_buf_callback(data: &[u8]) {
    let event = parse_struct(data);

    println!(
        "{:-16} {:10} {:10} {:10}",
        get_string(&event.filename),
        event.dfd,
        event.flags,
        event.mode
    );
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            std::process::exit(1);
        }
        _ => {}
    }
}
