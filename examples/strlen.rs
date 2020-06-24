extern crate bcc;
extern crate byteorder;
extern crate libc;

use bcc::core::BPF;
use bcc::BccError;
use byteorder::{NativeEndian, ReadBytesExt};

use core::sync::atomic::{AtomicBool, Ordering};
use std::io::Cursor;
use std::sync::Arc;

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let code = "
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
};
    ";
    let mut module = BPF::new(code)?;
    let uprobe_code = module.load_uprobe("count")?;
    module.attach_uprobe(
        "/lib/x86_64-linux-gnu/libc.so.6",
        "strlen",
        uprobe_code,
        -1, /* all PIDs */
    )?;
    let table = module.table("counts");
    while runnable.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        for e in &table {
            // key and value are each a Vec<u8> so we need to transform them into a string and
            // a u64 respectively
            let key = get_string(&e.key);
            let value = Cursor::new(e.value).read_u64::<NativeEndian>().unwrap();
            if value > 10 {
                println!("{:?} {:?}", key, value);
            }
        }
    }
    Ok(())
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
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
