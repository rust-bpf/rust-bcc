use bcc::BPF;
use bcc::{trace_parse, trace_read, BccError, Kprobe};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let cpus = bcc::cpuonline::get()?.len() as u32;
    let code = format!(
        "{}\n{}",
        format!("#define NUM_CPU {}", cpus),
        include_str!("hello_bpf.c").to_string()
    );
    let mut bpf = BPF::new(&code)?;
    let r = bpf.get_syscall_fnname("clone");
    Kprobe::new()
        .handler("some_func")
        .function(&r)
        .attach(&mut bpf)?;
    while runnable.load(Ordering::SeqCst) {
        let r = trace_read();
        match r {
            Ok(s) => {
                let item = trace_parse(s);
                println!("{:?}", item);
            }
            Err(e) => println!("{:?}", e),
        }
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
