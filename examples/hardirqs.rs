use bcc::core::BPF;
use bcc::BccError;
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{mem, ptr, thread, time};

// A simple tool for reporting on time spent in hardirq handlers
//
// Based on: https://github.com/iovisor/bcc/blob/master/tools/hardirqs.py

#[repr(C)]
struct irq_key_t {
    name: [u8; 32],
    slot: u64,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("hardirqs")
        .about("Summarize hard IRQ event time")
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .value_name("Seconds")
                .help("Integration window duration and period for stats output")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("windows")
                .long("windows")
                .value_name("Count")
                .help("The number of intervals before exit")
                .takes_value(true),
        )
        .get_matches();

    let interval: usize = matches
        .value_of("interval")
        .unwrap_or("1")
        .parse()
        .expect("Invalid number of interval");

    let windows: Option<usize> = matches
        .value_of("windows")
        .map(|v| v.parse().expect("Invalud argument for windows"));

    let code = include_str!("hardirqs.c");
    let mut bpf = BPF::new(code)?;

    let hardirq_entry = bpf.load_kprobe("hardirq_entry")?;
    let hardirq_exit = bpf.load_kprobe("hardirq_exit")?;

    bpf.attach_kprobe("handle_irq_event_percpu", hardirq_entry)?;
    bpf.attach_kretprobe("handle_irq_event_percpu", hardirq_exit)?;

    let mut table = bpf.table("dist");
    let mut window = 0;

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(interval as u64, 0));
        println!("\n{:<-16} {:<-11}", "HARDIRQ", "time (ns)");

        for entry in table.iter() {
            let data = parse_struct(&entry.key);
            let value = entry.value;

            let mut v = [0_u8; 8];
            for i in 0..8 {
                v[i] = *value.get(i).unwrap_or(&0);
            }
            let time: u64 = unsafe { mem::transmute(v) };
            let name = get_string(&data.name);

            if time > 0 {
                println!("{:<-16} {:<-11}", name, time);
            }

            let mut key = [0; 40];
            key.copy_from_slice(&entry.key);
            let _ = table.set(&mut key, &mut [0_u8; 8]);
        }

        if let Some(windows) = windows {
            window += 1;
            if window >= windows {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn parse_struct(x: &[u8]) -> irq_key_t {
    unsafe { ptr::read(x.as_ptr() as *const irq_key_t) }
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
