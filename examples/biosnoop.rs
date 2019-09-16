use bcc::core::BPF;
use bcc::perf::init_perf_map;
use clap::{App, Arg};
use failure::Error;

use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::sync::Arc;

// A simple tool for tracing block device I/O and print details including issuing PID.
//
// Based on: https://github.com/iovisor/bcc/blob/master/tools/biosnoop.py

#[repr(C)]
struct data_t {
    pid: u32,
    rwflag: u64,
    delta: u64,
    qdelta: u64,
    sector: u64,
    len: u64,
    ts: u64,
    disk_name: [u8; 32],
    name: [u8; 16],
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let matches = App::new("biosnoop")
        .about("Trace block I/O")
        .arg(
            Arg::with_name("queue")
                .short("Q")
                .long("queue")
                .help("include OS queued time"),
        )
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .value_name("Seconds")
                .help("The total duration to run this tool")
                .takes_value(true),
        )
        .get_matches();

    let duration: Option<std::time::Duration> = matches
        .value_of("duration")
        .map(|v| std::time::Duration::new(v.parse().expect("Invalid argument for duration"), 0));

    let code = include_str!("biosnoop.c");
    let code = if matches.is_present("queue") {
        code.replace("##QUEUE##", "1")
    } else {
        code.replace("##QUEUE##", "0")
    };
    // compile the above BPF code!
    let mut bpf = BPF::new(&code)?;
    // load + attach kprobes!
    let trace_pid_start = bpf.load_kprobe("trace_pid_start")?;
    let trace_mq_req_start = bpf.load_kprobe("trace_req_start")?;
    let trace_req_completion = bpf.load_kprobe("trace_req_completion")?;

    bpf.attach_kprobe("blk_account_io_start", trace_pid_start)?;
    bpf.attach_kprobe("blk_mq_start_request", trace_mq_req_start)?;
    bpf.attach_kprobe("blk_account_io_completion", trace_req_completion)?;

    if let Ok(funcs) = bpf.get_kprobe_functions("blk_start_request") {
        if funcs.len() > 0 {
            let trace_req_start = bpf.load_kprobe("trace_req_start")?;
            bpf.attach_kprobe("blk_start_request", trace_req_start)?;
        }
    }
    // the "events" table is where the "open file" events get sent
    let table = bpf.table("events");
    let mut perf_map = init_perf_map(table, perf_data_callback)?;
    // print a header
    println!(
        "{:<-11} {:<-14} {:<-6} {:<-7} {:<-1} {:<-10} {:>-7}",
        "TIME(s)", "COMM", "PID", "DISK", "T", "SECTOR", "BYTES"
    );
    let start = std::time::Instant::now();
    // this `.poll()` loop is what makes our callback get called
    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
        if let Some(d) = duration {
            if std::time::Instant::now() - start >= d {
                break;
            }
        }
    }
    Ok(())
}

static mut START_TS: u64 = 0;

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| unsafe {
        let data = parse_struct(x);
        if START_TS == 0 {
            START_TS = data.ts;
        }
        let rwflag = if data.rwflag == 1 { "W" } else { "R" };
        let delta = (data.ts - START_TS) as f64;
        println!(
            "{:<-11} {:<-14} {:<-6} {:<-7} {:<-1} {:<-10} {:>-7}",
            delta / 1000000 as f64,
            get_string(&data.name),
            data.pid,
            get_string(&data.disk_name),
            rwflag,
            data.sector,
            data.len
        );
    })
}

fn parse_struct(x: &[u8]) -> data_t {
    unsafe { ptr::read(x.as_ptr() as *const data_t) }
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

    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        eprintln!("{}", x.backtrace());
        std::process::exit(1);
    }
}
