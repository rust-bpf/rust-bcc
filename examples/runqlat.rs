use bcc::BccError;
use bcc::{Kprobe, RawTracepoint, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{mem, thread, time};

// A simple tool for reporting runqueue latency
//
// Based on: https://github.com/iovisor/bcc/blob/master/tools/runqlat.py

#[cfg(any(feature = "v0_4_0", feature = "v0_5_0",))]
fn attach_events(bpf: &mut BPF) -> Result<(), BccError> {
    Kprobe::new()
        .name("trace_run")
        .function("finish_task_switch")
        .attach(bpf)?;
    Kprobe::new()
        .name("trace_ttwu_do_wakeup")
        .function("ttwu_do_wakeup")
        .attach(bpf)?;
    Kprobe::new()
        .name("trace_wake_up_new_task")
        .function("wake_up_new_task")
        .attach(bpf)?;
    Ok(())
}

#[cfg(not(any(feature = "v0_4_0", feature = "v0_5_0")))]
fn attach_events(bpf: &mut BPF) -> Result<(), BccError> {
    if bpf.support_raw_tracepoint() {
        RawTracepoint::new()
            .handler("raw_tp__sched_wakeup")
            .tracepoint("sched_wakeup")
            .attach(bpf)?;
        RawTracepoint::new()
            .handler("raw_tp__sched_wakeup_new")
            .tracepoint("sched_wakeup_new")
            .attach(bpf)?;
        RawTracepoint::new()
            .handler("raw_tp__sched_switch")
            .tracepoint("sched_switch")
            .attach(bpf)?;
        Ok(())
    } else {
        // load + attach kprobes!
        Kprobe::new()
            .handler("trace_run")
            .function("finish_task_switch")
            .attach(bpf)?;
        Kprobe::new()
            .handler("trace_ttwu_do_wakeup")
            .function("ttwu_do_wakeup")
            .attach(bpf)?;
        Kprobe::new()
            .handler("trace_wake_up_new_task")
            .function("wake_up_new_task")
            .attach(bpf)?;
        Ok(())
    }
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("runqlat")
        .about("Reports distribution of scheduler latency")
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
        .expect("Invalid argument for interval");
    let windows: Option<usize> = matches
        .value_of("windows")
        .map(|v| v.parse().expect("Invalid argument for windows"));

    let code = if cfg!(any(feature = "v0_4_0", feature = "v0_5_0")) {
        include_str!("runqlat.c").replace("#define FEATURE_SUPPORT_RAW_TP", "")
    } else {
        include_str!("runqlat.c").to_string()
    };
    // compile the above BPF code!
    let mut bpf = BPF::new(&code)?;
    attach_events(&mut bpf)?;

    let table = bpf.table("dist")?;
    let mut window = 0;

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(interval as u64, 0));
        println!("======");
        let mut overflow = 0;
        for (power, entry) in table.iter().enumerate() {
            let value = entry.value;

            let mut v = [0_u8; 8];
            for i in 0..8 {
                v[i] = *value.get(i).unwrap_or(&0);
            }
            let count: u64 = unsafe { mem::transmute(v) };
            let value = 2_u64.pow(power as u32);
            if value < 1_000_000 {
                println!("{} uS: {}", 2_u64.pow(power as u32), count);
            } else {
                overflow += count;
            }
        }
        println!("> 1 S: {}", overflow);
        if let Some(windows) = windows {
            window += 1;
            if window >= windows {
                return Ok(());
            }
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

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            std::process::exit(1);
        }
        _ => {}
    }
}
