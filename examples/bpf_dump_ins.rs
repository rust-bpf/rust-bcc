use bcc::perf_event::{Event, SoftwareEvent};
use bcc::{BccError, Instructions};
use bcc::{PerfEvent, PerfEventArray, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Arc;
use std::{thread, time};

const CONTENT: &str = r#"
#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

int trace_entry(struct pt_regs* ctx, int dfd, const char __user* filename) {
    bpf_trace_printk("hello from rust\\n");
    return 0;
}
"#;

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let cpus = bcc::cpuonline::get()?.len() as u32;
    let code = format!("{}\n{}", format!("#define NUM_CPU {}", cpus), CONTENT);
    let bpf = BPF::new(&code)?;
    let func_name = CString::new("trace_entry").unwrap();
    let dump = bpf.dump_func(func_name).unwrap();
    let instructions = Instructions::from_vec(dump);
    for ins in instructions.inner() {
        println!("{:?}", ins);
    }

    Ok(())
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}
