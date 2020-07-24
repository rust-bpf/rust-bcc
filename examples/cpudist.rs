use bcc::core::BPF;
use bcc::BccError;
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

fn do_main(runnable: Arc<AtomicBool>)  -> Result<(), BccError> {
    let matches = App::new("cpudist")
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .short("i")
                .help("Sampling interval for the prog")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("windows")
                .long("windows")
                .short("w")
                .help("How many intervals to display")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("offcpu")
                .long("offcpu")
                .short("O")
                .help("measure time off cpu")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("pids")
                .long("pids")
                .short("P")
                .help("Print histogram per process id")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("tids")
                .long("tids")
                .short("T")
                .help("Print histogram per thread id")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("process")
                .long("pid")
                .short("p")
                .help("Trace this pid only")
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

    let code = include_str!("cpudist.c").to_string();
    let mut bpf = BPF::new(&code)?;
    bpf.attach_perf_event("do_perf_event", Some(1), Some(0), None, None, None, None, None)?;

    let mut window = 0;

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(interval as u64, 0));


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

    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}